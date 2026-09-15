"""Resolve and fetch the artifact a scan reads (`04-scanner-design.md` §2).

The crawler emits `source_spec` STRINGS (`crawler.registry.resolve_source`) and
this module is what reads them back. That seam had no reader until now, so
nothing verified the two halves agreed on a format — `tests/test_source.py`
round-trips every spec the crawler can produce, which is the only thing that
makes the contract real rather than asserted in two docstrings.

**Nothing here executes code from the fetched artifact.** No `npm install`, no
`pip install`, no build step, no git hook — `04` §9's central rule. Fetching is
download-and-unpack only, and the unpack is the dangerous half: see `_safe_extract`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from mcpwatchman.workers.crawler.registry import SourceKind
from mcpwatchman.workers.excluded import EXCLUDED_DIRS

# A published artifact that unpacks to more than this is not a plausible MCP
# server; it is a decompression bomb or a vendored toolchain. `04` §9 budgets
# 5 GB of scratch per job, so this sits an order of magnitude under it and fails
# the one job rather than the disk.
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 50_000

# A cap on ENTRY COUNT for a tree already on disk. `MAX_UNPACKED_BYTES` sums
# logical file lengths, so a repository of millions of empty files sits far
# under it while consuming inodes and allocated blocks without limit — a bound
# that measures the wrong resource is not a bound. Set above `inventory`'s
# `MAX_FILES` so a tree this large is refused here rather than silently
# truncated there.
MAX_TREE_ENTRIES = 250_000

# Per-step wall clock. `04` §9 gives a scan 15 minutes total; fetching is meant
# to be a small part of that, and a repository that cannot be cloned in two
# minutes is a finding about the repository.
FETCH_TIMEOUT_S = 120


# Which ref a clone actually landed on, keyed by checkout dir. `None` means the
# requested version matched no tag and the default branch was used — the
# Transparency signal `fetch()` surfaces as `ref_matched_version=False`.
_GIT_REF_USED: dict[Path, str | None] = {}


class FetchError(RuntimeError):
    """The artifact could not be obtained. Names the spec and the reason."""


class SourceUnreachableError(FetchError):
    """The DECLARED source does not exist, or is not public.

    Split from its parent because the two say opposite things about who is at
    fault, and only one of them is a finding. A timeout, a missing binary or a
    torn archive is **our** problem and should be retried. A registry entry
    pointing at a repository the world cannot read is **the publisher's**
    problem, it will not fix itself on retry, and it is a fact a reader of that
    server's page is entitled to: the source you were invited to audit is not
    there.

    ⚠ **This cannot distinguish "deleted" from "private", and must not claim
    to.** GitHub deliberately answers **404 rather than 403** for a private
    repository so as not to leak its existence, so both arrive here identically.
    The honest predicate is *not publicly reachable*, which is what the message
    says and what any surface built on it may assert.

    Measured 2026-09-15 over 200 registry entries: of the 95 classed scannable
    that declared a repository URL, **43 (45.3%) were not publicly reachable.**
    """


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """Where a scan's bytes come from.

    The string form is the wire format between crawler and scanner:
    `<kind>:<identifier>@<version>`, optionally `#<subfolder>` for a monorepo.
    """

    kind: SourceKind
    identifier: str
    version: str
    subfolder: str | None = None

    def __str__(self) -> str:
        base = f"{self.kind.value}:{self.identifier}@{self.version}"
        return f"{base}#{self.subfolder}" if self.subfolder else base

    @classmethod
    def parse(cls, spec: str) -> SourceSpec:
        """Read a spec string emitted by `crawler.registry.resolve_source`.

        Deliberately strict: an unparseable spec raises rather than degrading to
        a default. A wrong default here would fetch *something* and scan it, and
        the resulting score would be about the wrong artifact — a failure with no
        outward symptom, which is the worst kind this project can ship.
        """
        rest, _, subfolder = spec.partition("#")
        kind_str, sep, tail = rest.partition(":")
        if not sep or not tail:
            raise FetchError(f"malformed source spec, expected '<kind>:<id>@<version>': {spec!r}")
        identifier, at, version = tail.rpartition("@")
        if not at or not identifier or not version:
            raise FetchError(f"source spec has no @version: {spec!r}")
        try:
            kind = SourceKind(kind_str)
        except ValueError as exc:
            raise FetchError(f"unknown source kind {kind_str!r} in {spec!r}") from exc

        # Re-validate rather than trust the emitter. The crawler already rejects
        # a traversing subfolder, but this module joins these values onto a
        # filesystem path and passes them to git, and a second reader of the
        # same untrusted string is cheap. The crawler is not a trust boundary —
        # it reads the same public registry this is defending against.
        for field, value in (("identifier", identifier), ("subfolder", subfolder)):
            if not value:
                continue
            parts = [p for p in value.split("/") if p]
            if any(p == ".." for p in parts) or value.startswith(("-", "/")):
                raise FetchError(
                    f"{field} {value!r} traverses or looks like a flag: {spec!r}"
                )
            # An excluded directory as the scan ROOT defeats its own exclusion:
            # `_is_excluded` tests paths RELATIVE to the chosen root, so with
            # `#.git` the `.git` component is no longer in any relative path and
            # git metadata reports as scannable source.
            # ANY component, not just the first: `apps/server/dist` puts the
            # scan root inside `dist`, and `_is_excluded` then sees paths
            # relative to that root with the excluded component already gone.
            if field == "subfolder" and any(p in EXCLUDED_DIRS for p in parts):
                raise FetchError(
                    f"subfolder {value!r} names an excluded directory: {spec!r}"
                )
        if version.startswith("-"):
            raise FetchError(f"version {version!r} looks like a flag: {spec!r}")
        return cls(kind, identifier, version, subfolder or None)


@dataclass(frozen=True, slots=True)
class FetchResult:
    """What a fetch produced, and what the scan should actually read."""

    spec: SourceSpec
    root: Path
    # The directory to analyse. Differs from `root` for a monorepo subfolder, and
    # for a package whose tarball wraps everything in a single top-level dir.
    scan_root: Path
    bytes_on_disk: int
    file_count: int
    # False when a git source's published version matched no tag, so the default
    # branch was scanned instead. NOT an error — but the score then describes
    # the branch tip rather than the release, and the per-server page owes the
    # reader that distinction (`04` §2, Transparency).
    ref_matched_version: bool = True


# What a forge says when the thing is not there, or not ours to see. Matched on
# the transport's own words rather than on an exit code, because git exits 128
# for everything from a bad ref to a DNS failure.
#
# ⚠ The auth phrasings are here deliberately. A PRIVATE repository does not
# always answer "not found" — over HTTPS with prompts disabled git asks for a
# username and fails, and over SSH it reports access denied. Both mean exactly
# what a 404 means for our purposes: not publicly reachable. Leaving them out
# would classify the private half as an infrastructure fault and retry it.
_UNREACHABLE_SIGNS = (
    # ⚠ NOT a bare "not found". `fatal: Remote branch v1.2.3 not found in
    # upstream origin` is a missing TAG on a repository that answered us
    # perfectly well — and `fetch_git` retries those candidates by design, so
    # reading it as an absent repository both misreports and defeats the
    # fallback.
    "could not read from remote repository",
    "could not read username",
    "authentication failed",
    "terminal prompts disabled",
    "access denied",
    "does not appear to be a git repository",
)

# ⚠ Deliberately NOT in the list above, despite meaning "not public" over SSH:
# "permission denied" is a local-filesystem error at least as often as a remote
# one ("could not create work tree dir: Permission denied"). It only counts when
# git also names the remote side.
# ⚠ A REGEX, because git interposes the URL: the HTTPS form is
# `fatal: repository 'https://…' not found` while the SSH form is
# `ERROR: Repository not found.` — a literal "repository not found" matches only
# the second. The optional quoted group is what spans the gap, and requiring the
# word "repository" is what keeps `Remote branch v1.2.3 not found in upstream
# origin` — a missing TAG on a healthy repo — out of this class.
_REPO_NOT_FOUND_RE = re.compile(r"repository\s+(?:'[^']*'\s+|\S+\s+)?not found")

_UNREACHABLE_PAIRS = (
    ("permission denied", "remote"),
    ("permission denied", "publickey"),
)


def _is_unreachable(output: str, url: str | None = None) -> bool:
    """Whether git's output says the SOURCE is not public.

    ⚠ **The URL is redacted before matching, and that is a security property
    rather than tidiness.** git echoes the repository URL it was given, and that
    URL comes from a public registry entry — so a publisher who names their repo
    `.../access denied/` could turn any unrelated transient failure into a
    permanent published verdict about themselves or, worse, make our own DNS
    failure read as their fault. Matching on text the subject controls is how a
    classifier gets steered.
    """
    lowered = output.lower()
    if url:
        lowered = lowered.replace(url.lower(), "<url>")
    if _REPO_NOT_FOUND_RE.search(lowered):
        return True
    if any(sign in lowered for sign in _UNREACHABLE_SIGNS):
        return True
    return any(a in lowered and b in lowered for a, b in _UNREACHABLE_PAIRS)


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = FETCH_TIMEOUT_S,
    *,
    remote: bool = False,
    url: str | None = None,
) -> None:
    """Run a fetch command with no shell and a hard timeout.

    `shell=False` (the default, stated because it matters): every argument here
    contains attacker-influenced data — a repository name from a public registry
    — and a shell would make that an injection surface in the one tool whose
    subject is injection.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argument list, never a shell string
            cmd, cwd=cwd, timeout=timeout, capture_output=True, text=True, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"timed out after {timeout}s: {' '.join(cmd[:3])}") from exc
    except FileNotFoundError as exc:
        # The binary is absent from the image. Previously this escaped as a raw
        # FileNotFoundError past every FetchError handler, so a worker built
        # without git failed each job with a traceback rather than a scan result.
        raise FetchError(f"{cmd[0]} is not installed in this image") from exc
    if proc.returncode != 0:
        combined = (proc.stderr or "") + (proc.stdout or "")
        tail = combined.strip().splitlines()[-1:] or [""]
        detail = f"{cmd[0]} failed (rc={proc.returncode}): {tail[0][:200]}"
        # ⚠ Only a command that actually TALKS TO THE REMOTE may be blamed on
        # the publisher. `git gc`, `sparse-checkout`, `checkout` and
        # `symbolic-ref` all run AFTER the remote was reached successfully, and
        # their commonest failures are local: a read-only scratch mount or a
        # full disk both say "Permission denied", which this classifier read as
        # "your repository is not public". One bad mount would have flipped an
        # entire night's batch into a published accusation about named third
        # parties, and none of it would have been retried.
        if remote and _is_unreachable(combined, url=url):
            raise SourceUnreachableError(detail)
        raise FetchError(detail)


# Directories that are never the subject of a scan. `.git` is here because a
# shallow clone still leaves a packfile — measured on
# `modelcontextprotocol/servers`, it was the majority of a 1.9 MB checkout — and
# because semgrep matching inside object storage produces findings about bytes
# that are not source. `04` §3 names the rest.
# Re-exported so existing importers of this module keep working; the constant
# itself lives in `workers.excluded` because the crawler needs it too and cannot
# import this module without closing a cycle.
__all__ = ["EXCLUDED_DIRS"]


def _is_excluded(path: Path, root: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts)


def _tree_size(root: Path) -> tuple[int, int]:
    """(bytes, file count) for the SCANNABLE tree — symlinks and excluded
    directories omitted.

    Symlinks are skipped rather than followed: an archive can point one at
    `/etc/passwd` or at a parent directory, and following it would both inflate
    the measurement and read outside the workspace.
    """
    total = count = 0
    for p in root.rglob("*"):
        if p.is_symlink() or not p.is_file() or _is_excluded(p, root):
            continue
        total += p.stat().st_size
        count += 1
    return total, count


def _guard_members(names: Iterator[str], spec: SourceSpec) -> None:
    """Refuse an archive with too many members before unpacking any of them."""
    for i, _ in enumerate(names, 1):
        if i > MAX_MEMBERS:
            raise FetchError(f"archive exceeds {MAX_MEMBERS} members: {spec}")


def _guard_declared_size(sizes: Iterator[int], spec: SourceSpec) -> None:
    """Refuse an archive whose DECLARED uncompressed size exceeds the cap.

    **Before extraction, which is the whole point.** Checking the tree after
    unpacking means a highly compressible archive — a zip bomb — has already
    been written to the worker's scratch disk by the time the cap is consulted,
    so the guard reports a failure the attacker has already caused. A few
    hundred bytes of archive can declare gigabytes.

    Declared sizes are attacker-controlled and may lie LOW, so this is a cheap
    first gate rather than the only one; `_measure_all` re-checks after
    extraction for an archive that under-declared.
    """
    total = 0
    for size in sizes:
        total += size
        if total > MAX_UNPACKED_BYTES:
            raise FetchError(
                f"archive declares {total}+ bytes, over the "
                f"{MAX_UNPACKED_BYTES} cap: {spec}"
            )


def _measure_all(root: Path) -> int:
    """Total bytes on disk, INCLUDING excluded directories.

    Distinct from `_tree_size`, and the distinction was a bug: that function
    omits `node_modules`, `.git` and friends because they are not *scannable*,
    which is the right answer for "how much source is here" and the wrong one
    for "how much disk did this consume". A payload hidden under `node_modules/`
    was invisible to the resource cap while filling the scratch budget.

    ⚠ Bounded and early-exiting, which `sum(root.rglob("*"))` was neither. That
    form enumerated the whole tree before returning a total nobody could act on
    until it was complete, so for a git source — where no member cap applies,
    because a clone is not an archive — a hostile repository forced an unbounded
    walk before the size cap could fire.
    """
    total = 0
    visited = 0
    stack: list[Path] = [root]

    while stack:
        try:
            scanner = os.scandir(stack.pop())
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                visited += 1
                if visited > MAX_TREE_ENTRIES:
                    raise FetchError(
                        f"tree exceeds {MAX_TREE_ENTRIES} entries at {root}"
                    )
                if entry.is_symlink():
                    continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                        if total > MAX_UNPACKED_BYTES:
                            raise FetchError(
                                f"tree exceeds {MAX_UNPACKED_BYTES} bytes at {root}"
                            )
                except OSError:
                    continue
    return total


def _is_zip(archive: Path) -> bool:
    """Detect a zip by its MAGIC, not by the suffix we happened to write.

    PyPI sdists are usually `.tar.gz` and legitimately sometimes `.zip`; naming
    the download by assumption and then dispatching on that name meant a zip
    sdist was handed to `tarfile` and failed with `ReadError` — the package
    unfetchable for a reason that looks like corruption rather than a format we
    declined to notice.
    """
    with archive.open("rb") as fh:
        return fh.read(4) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


_EOCD_SIG = b"PK\x05\x06"
_ZIP64_LOCATOR_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_MAX_ZIP_COMMENT = 65_535


def _zip_entry_count(archive: Path) -> int | None:
    """Entry count read from the end-of-central-directory, in BOUNDED work.

    ⚠ This exists because `MAX_MEMBERS` could not reach the zip path at all.
    `zipfile.ZipFile(...)` parses the ENTIRE central directory and builds a
    `ZipInfo` for every entry in its constructor — so by the time `infolist()`
    returns and the member cap is consulted, the allocation has already
    happened. A ZIP64 archive of millions of empty entries compresses to almost
    nothing and stays far under the download cap.

    The tar path was given a lazy, guard-during-the-walk form at v0.7.2 and this
    one was left eager — the same asymmetry, the third instance in this file.

    Returns None when the record cannot be located, in which case `ZipFile` will
    fail to open the archive anyway. The count is attacker-controlled and may
    understate the truth, so `_guard_members` still runs afterwards as the
    second gate — exactly the arrangement the declared-size cap already uses.
    """
    size = archive.stat().st_size
    if size < 22:
        return None
    tail_len = min(size, _MAX_ZIP_COMMENT + 22)
    with archive.open("rb") as fh:
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)

        pos = tail.rfind(_EOCD_SIG)
        if pos < 0 or len(tail) - pos < 22:
            return None
        count = int.from_bytes(tail[pos + 10 : pos + 12], "little")
        if count != 0xFFFF:
            return count

        # ZIP64: the 16-bit field is saturated and the real count lives in the
        # ZIP64 end-of-central-directory, found via its locator.
        loc = tail.rfind(_ZIP64_LOCATOR_SIG, 0, pos)
        if loc < 0 or len(tail) - loc < 20:
            return None
        z64_offset = int.from_bytes(tail[loc + 8 : loc + 16], "little")
        if z64_offset >= size:
            return None
        fh.seek(z64_offset)
        head = fh.read(40)
        if len(head) < 40 or not head.startswith(_ZIP64_EOCD_SIG):
            return None
        return int.from_bytes(head[32:40], "little")


def _safe_extract(archive: Path, dest: Path, spec: SourceSpec) -> None:
    """Unpack an untrusted archive.

    **This is the most dangerous operation in the fetch path** and the reason it
    is one function rather than inlined twice. A published tarball is attacker
    controlled, and the classic failures are path traversal (a member named
    `../../etc/cron.d/x`), absolute paths, symlinks pointing outside the tree,
    and decompression bombs.

    `filter="data"` is the fix for the first three: it rejects absolute paths,
    `..` components, links escaping the destination, and device nodes. Doing it
    by hand is the CVE (CVE-2007-4559 sat in the stdlib for fifteen years
    precisely because every caller hand-rolled it).

    ⚠ **The explicit filter looks redundant on a modern interpreter and is not.**
    Measured 2026-09-14: on Python 3.14 the default already blocks traversal, so
    deleting this argument changes nothing locally — a negative control removing
    it came back green. On **3.12**, which `requires-python` promises and which
    CI actually runs, the default is `fully_trusted` and deleting it reopens the
    traversal. Do not "simplify" this on the evidence of a 3.14 test run; the
    interpreter that proves it matters is the one in CI.
    """
    dest.mkdir(parents=True, exist_ok=True)
    if _is_zip(archive):
        declared = _zip_entry_count(archive)
        if declared is not None and declared > MAX_MEMBERS:
            raise FetchError(
                f"archive declares {declared} members, over the "
                f"{MAX_MEMBERS} cap: {spec}"
            )
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            _guard_members((i.filename for i in infos), spec)
            _guard_declared_size((i.file_size for i in infos), spec)
            for member in infos:
                name = member.filename
                # zipfile has no `filter=`, so the traversal check is ours.
                if name.startswith("/") or ".." in Path(name).parts:
                    raise FetchError(f"archive member escapes destination: {name!r}")
            zf.extractall(dest)  # noqa: S202 - members validated immediately above
    else:
        with tarfile.open(archive) as tf:
            # Iterate LAZILY and bail on the first breach. `getmembers()` builds
            # a TarInfo for every entry before any limit is consulted, so an
            # archive of millions of zero-length headers — which compresses to
            # almost nothing — exhausts memory before the member cap can fire.
            # The guard has to run DURING the walk, not after it.
            declared = 0
            for count, member in enumerate(tf, 1):
                if count > MAX_MEMBERS:
                    raise FetchError(f"archive exceeds {MAX_MEMBERS} members: {spec}")
                declared += member.size
                if declared > MAX_UNPACKED_BYTES:
                    raise FetchError(
                        f"archive declares {declared}+ bytes, over the "
                        f"{MAX_UNPACKED_BYTES} cap: {spec}"
                    )
            tf.extractall(dest, filter="data")

    # Second gate: the declared sizes above are attacker-controlled and may lie
    # low. This measures what actually landed, and counts EXCLUDED directories
    # too — the resource question is "how much disk did this consume", not "how
    # much of it will we scan".
    size = _measure_all(dest)
    if size > MAX_UNPACKED_BYTES:
        raise FetchError(
            f"unpacked to {size} bytes, over the {MAX_UNPACKED_BYTES} cap: {spec}"
        )


def _single_wrapper_dir(root: Path) -> Path:
    """Descend through a lone wrapper directory.

    npm tarballs wrap everything in `package/`, sdists in `<name>-<version>/`.
    Returning the wrapper as the scan root would make every rule's file paths
    wrong by one component, which is a silent defect: the scan succeeds and the
    evidence trail points at paths that do not exist in the artifact.
    """
    entries = [p for p in root.iterdir() if not p.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def _confine(candidate: Path, root: Path) -> Path:
    """Assert a path stays inside the workspace, after symlink resolution.

    The LAST line of defence, and the only one that survives a bug in the two
    validations upstream. `scan_root` is what the file walk and the semgrep run
    are pointed at, so a value that escapes here aims the whole scanner at the
    host filesystem. Resolves first because a symlink inside the fetched tree
    can redirect a path that looks confined.
    """
    root_resolved = root.resolve()

    # ⚠ REFUSE A SYMLINKED COMPONENT BEFORE RESOLVING, because containment
    # cannot see this one. A repository may TRACK a symlink, so a declared
    # subfolder `server -> .git` resolves to a path that is still inside the
    # workspace — the check below passes, and the scanner is aimed at the git
    # object store. `_is_excluded` cannot catch it either: it tests the declared
    # name (`server`), and once `.git` becomes the scan ROOT it sits outside
    # every path taken relative to it, so the exclusion defeats itself.
    #
    # This is the third route to the same place. v0.7.1 closed traversal
    # (`../../../etc`), v0.7.2 closed the literal `#.git`, and both guards were
    # written without the symlink in mind. Resolving an internal link is never
    # something we want: the declared path is the contract, not wherever the
    # repository decides to point it.
    probe = root_resolved
    for part in candidate.relative_to(root).parts if candidate != root else ():
        probe = probe / part
        if probe.is_symlink():
            raise FetchError(
                f"subfolder component {part!r} is a symlink ({probe} -> "
                f"{probe.readlink()}); refusing to follow it"
            )

    resolved = candidate.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise FetchError(f"scan root {resolved} escapes the workspace {root_resolved}")
    if _is_excluded(resolved, root_resolved) or resolved.name in EXCLUDED_DIRS:
        raise FetchError(f"scan root {resolved} is an excluded directory")
    return resolved


def _head_is_detached(repo: Path) -> bool:
    """True when HEAD points at a commit rather than a branch — i.e. a tag.

    `git symbolic-ref HEAD` resolves for a branch checkout and fails for a
    detached one, which is exactly the tag-vs-branch discriminator `--branch`
    itself does not give us.
    """
    try:
        _run(["git", "symbolic-ref", "-q", "HEAD"], cwd=repo, timeout=30)
    except FetchError:
        return True
    return False


def _git_url(spec: SourceSpec) -> str:
    """The clone URL for a forge-hosted spec.

    A named seam rather than an inline f-string so a test can point `fetch_git`
    at a local remote and exercise real git ref resolution — which is where the
    branch-shadows-tag defect lives, and which no stubbed `_run` can reproduce.
    """
    host = {SourceKind.GITHUB: "github.com", SourceKind.GITLAB: "gitlab.com"}[spec.kind]
    return f"https://{host}/{spec.identifier}.git"


def fetch_git(spec: SourceSpec, dest: Path) -> Path:
    """Shallow, optionally sparse clone (`04` §2).

    `--depth 1 --no-tags` because static analysis needs the tree, not the
    history; maintenance signals come from the forge API instead. Sparse
    checkout when the server lives in a monorepo subdirectory — one repository
    in the registry holds dozens of servers.
    """
    url = _git_url(spec)

    # ⚠ THE REF MUST BE REQUESTED EXPLICITLY. `--single-branch` alone clones the
    # remote's default branch and SILENTLY IGNORES the version — so a scan of
    # `github:acme/repo@1.2.3` would read `main`, score it, and attach the score
    # to a released version it never looked at. Caught by fetching a real
    # repository; no unit test on this module would have seen it, because the
    # clone succeeds and returns a perfectly valid tree of the wrong code.
    #
    # The registry publishes a PACKAGE version; repositories tag it as either
    # `1.2.3` or `v1.2.3`. Try both, then fall back to the default branch — and
    # report which, because "no tag matches the published version" is itself a
    # Transparency finding (`04` §2: discrepancies between the published artifact
    # and the tagged source are a finding category).
    base = ["git", "clone", "--depth", "1", "--no-tags", "--single-branch"]
    if spec.subfolder:
        base += ["--filter=blob:none", "--sparse"]

    # `--` before the positional arguments: without it a URL or path beginning
    # with `-` is parsed as a flag. `SourceSpec.parse` already rejects those, so
    # this is the second layer — and it costs nothing.
    resolved_ref: str | None = None
    for candidate in (spec.version, f"v{spec.version}"):
        try:
            _run([*base, "--branch", candidate, "--", url, str(dest)], remote=True, url=url)
        except FetchError:
            shutil.rmtree(dest, ignore_errors=True)
            continue
        # ⚠ `--branch` accepts a TAG OR A BRANCH, so a successful clone does not
        # mean a release was found: a repository with a moving branch named
        # `1.2.3` would otherwise be reported as tagged-release source. A tag
        # produces a DETACHED head, a branch does not — so `symbolic-ref HEAD`
        # succeeding means we got a branch, and the version is unmatched.
        if _head_is_detached(dest):
            resolved_ref = candidate
            break
        shutil.rmtree(dest, ignore_errors=True)
    if resolved_ref is None:
        _run([*base, "--", url, str(dest)], remote=True, url=url)
        # ⚠ `--branch` resolves `refs/heads/` FIRST, so a repository carrying both
        # a branch and a tag named `1.2.3` hands back the branch above, the
        # detached-HEAD test correctly rejects it, and we land on the default
        # branch — having never asked for the tag that does exist. Scoring the
        # default branch and attaching the result to a release it never read is
        # the exact failure v0.7.0 fixed for the no-tag case; this is the same
        # failure by a different route. Name the namespace and the ambiguity
        # cannot arise.
        for candidate in (spec.version, f"v{spec.version}"):
            try:
                _run(
                    ["git", "fetch", "--depth", "1", "origin", f"refs/tags/{candidate}"],
                    cwd=dest,
                    remote=True,
                    url=url,
                )
                _run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=dest)
            except FetchError:
                continue
            resolved_ref = candidate
            break

    if spec.subfolder:
        # ⚠ CONE MODE, because `--no-cone` reads its argument as a
        # `.gitignore` PATTERN rather than a literal path. A perfectly valid
        # declared directory containing pattern metacharacters — `apps/[server]`,
        # or one whose name begins with `!` — is then matched wrongly or not at
        # all, while the code that follows goes looking for the literal path.
        # Cone mode takes directory paths literally, which is the contract this
        # call actually wants.
        _run(
            ["git", "sparse-checkout", "set", "--cone", "--", spec.subfolder],
            cwd=dest,
        )
    # Reclaim packfile space immediately; a job's 5 GB scratch is shared with
    # semgrep's own working set.
    _run(["git", "gc", "--prune=now", "--quiet"], cwd=dest, timeout=60)

    # A clone was the one fetch path with NO size ceiling: `MAX_UNPACKED_BYTES`
    # and `MAX_MEMBERS` were applied to archives only, and `_tree_size` merely
    # measured afterwards. A listed repository with a huge working tree could
    # therefore consume the whole scratch budget (`04` §9 allows 5 GB per job).
    # Enforced after the fact rather than before, because git offers no
    # pre-flight size for a tree — so this bounds the NEXT step rather than this
    # one, and says so instead of implying a guarantee it cannot give.
    cloned = _measure_all(dest)
    if cloned > MAX_UNPACKED_BYTES:
        raise FetchError(
            f"checkout is {cloned} bytes, over the {MAX_UNPACKED_BYTES} cap: {spec}"
        )
    _GIT_REF_USED[dest] = resolved_ref
    return _confine(dest / spec.subfolder, dest) if spec.subfolder else dest


def _download(url: str, dest: Path, timeout: int = FETCH_TIMEOUT_S) -> Path:
    """Stream a URL to disk, capped, without holding it in memory."""
    import httpx

    try:
        with httpx.stream(
            "GET", url, timeout=timeout, follow_redirects=True
        ) as response:
            response.raise_for_status()
            written = 0
            # ⚠ A WALL-CLOCK DEADLINE, because httpx's timeout is per network
            # OPERATION and resets on every one. A server that dribbles a byte
            # inside each interval never trips it, so a download could hold a
            # worker far past the 15-minute scan budget (`04` §9) while looking
            # healthy the whole time — the cap on SIZE cannot see a slow read.
            deadline = time.monotonic() + timeout
            with dest.open("wb") as fh:
                for chunk in response.iter_bytes(64 * 1024):
                    if time.monotonic() > deadline:
                        raise FetchError(
                            f"download exceeded {timeout}s wall clock: {url}"
                        )
                    written += len(chunk)
                    if written > MAX_UNPACKED_BYTES:
                        raise FetchError(f"download exceeded cap: {url}")
                    fh.write(chunk)
    except httpx.HTTPStatusError as exc:
        # A 404 on a published artefact is the package equivalent of a missing
        # repository: the version the registry advertises is not on the index.
        if exc.response.status_code in (401, 403, 404, 410):
            raise SourceUnreachableError(
                f"declared artefact is not available: {url} "
                f"(HTTP {exc.response.status_code})"
            ) from exc
        raise FetchError(f"download failed: {url} ({exc})") from exc
    except httpx.HTTPError as exc:
        raise FetchError(f"download failed: {url} ({exc})") from exc
    return dest


def fetch_npm(spec: SourceSpec, dest: Path, workdir: Path) -> Path:
    """Fetch and unpack a published npm tarball — never `npm install`.

    The tarball URL is derived from the registry's documented layout rather than
    read from the packument, so no metadata request is needed. Scoped packages
    (`@scope/name`) put the unscoped name in the filename, which is the one
    non-obvious part of that layout.
    """
    name = spec.identifier
    unscoped = name.rsplit("/", 1)[-1]
    url = f"https://registry.npmjs.org/{quote(name, safe='@/')}/-/{unscoped}-{spec.version}.tgz"
    archive = _download(url, workdir / "pkg.tgz")
    _safe_extract(archive, dest, spec)
    return _single_wrapper_dir(dest)


def fetch_pypi(spec: SourceSpec, dest: Path, workdir: Path) -> Path:
    """Fetch and unpack a PyPI distribution — never `pip install`.

    Prefers the sdist: a wheel is built output and may omit tests, configuration
    and sources a rule wants to read. Falls back to a wheel when no sdist exists,
    and records nothing about the difference here — `04` §5's no-lockfile
    fallback is the place that surfaces reduced coverage to the reader.
    """
    import httpx

    try:
        meta = httpx.get(
            f"https://pypi.org/pypi/{quote(spec.identifier)}/{quote(spec.version)}/json",
            timeout=FETCH_TIMEOUT_S,
            follow_redirects=True,
        )
        meta.raise_for_status()
        urls = meta.json().get("urls", [])
    except (httpx.HTTPError, ValueError) as exc:
        raise FetchError(f"pypi metadata unavailable for {spec}: {exc}") from exc

    chosen = next((u for u in urls if u.get("packagetype") == "sdist"), None) or next(
        (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
    )
    if not chosen:
        raise FetchError(f"no sdist or wheel published for {spec}")

    # Name the download after what PyPI actually published. `_is_zip` dispatches
    # on content so this is belt-and-braces, but a file named for its real
    # format is what makes a failure legible in a log.
    filename = chosen.get("filename") or chosen["url"].rsplit("/", 1)[-1]
    archive = _download(chosen["url"], workdir / Path(filename).name)
    _safe_extract(archive, dest, spec)
    return _single_wrapper_dir(dest)


def fetch(spec: SourceSpec, workspace: Path) -> FetchResult:
    """Obtain `spec` into `workspace` and report what to scan.

    `workspace` is the job's scratch directory and this function owns everything
    under it. The caller is responsible for creating and destroying it — see
    `scan_workspace`.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    checkout = workspace / "src"
    staging = workspace / "dl"
    staging.mkdir(exist_ok=True)

    if spec.kind in (SourceKind.GITHUB, SourceKind.GITLAB):
        scan_root = fetch_git(spec, checkout)
    elif spec.kind is SourceKind.NPM:
        scan_root = fetch_npm(spec, checkout, staging)
    elif spec.kind is SourceKind.PYPI:
        scan_root = fetch_pypi(spec, checkout, staging)
    else:
        # OCI is resolved by the crawler but deferred to v0.3 (`04` §2); anything
        # else means the crawler learned a kind this module has not.
        raise FetchError(f"no fetcher for {spec.kind.value} (spec: {spec})")

    shutil.rmtree(staging, ignore_errors=True)
    if not scan_root.is_dir():
        raise FetchError(f"fetch produced no directory at {scan_root}: {spec}")
    size, count = _tree_size(scan_root)
    return FetchResult(
        spec=spec,
        root=checkout,
        scan_root=scan_root,
        bytes_on_disk=size,
        file_count=count,
        ref_matched_version=_GIT_REF_USED.pop(checkout, "") is not None,
    )


class scan_workspace:  # noqa: N801 - a context manager used as a verb
    """Per-job scratch directory, removed on exit even when the scan raises.

    `04` §9 requires per-job isolation and a bounded scratch budget. Leaving a
    tree behind is not merely untidy: the next job inherits attacker-controlled
    files under a path it believes it owns.
    """

    def __init__(self, prefix: str = "mcpw-scan-") -> None:
        self._prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix=self._prefix))
        return self.path

    def __exit__(self, *exc: object) -> None:
        if self.path is not None:
            # A git clone leaves read-only objects; without this the cleanup
            # fails and the scratch leaks silently.
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
