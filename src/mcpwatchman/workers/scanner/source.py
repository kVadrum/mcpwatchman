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

import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from mcpwatchman.workers.crawler.registry import SourceKind

# A published artifact that unpacks to more than this is not a plausible MCP
# server; it is a decompression bomb or a vendored toolchain. `04` §9 budgets
# 5 GB of scratch per job, so this sits an order of magnitude under it and fails
# the one job rather than the disk.
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 50_000

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


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = FETCH_TIMEOUT_S) -> None:
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
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or [""]
        raise FetchError(f"{cmd[0]} failed (rc={proc.returncode}): {tail[0][:200]}")


# Directories that are never the subject of a scan. `.git` is here because a
# shallow clone still leaves a packfile — measured on
# `modelcontextprotocol/servers`, it was the majority of a 1.9 MB checkout — and
# because semgrep matching inside object storage produces findings about bytes
# that are not source. `04` §3 names the rest.
EXCLUDED_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__"}
)


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
    if archive.suffix == ".zip" or archive.name.endswith(".whl"):
        with zipfile.ZipFile(archive) as zf:
            _guard_members(iter(zf.namelist()), spec)
            for member in zf.infolist():
                name = member.filename
                # zipfile has no `filter=`, so the traversal check is ours.
                if name.startswith("/") or ".." in Path(name).parts:
                    raise FetchError(f"archive member escapes destination: {name!r}")
            zf.extractall(dest)  # noqa: S202 - members validated immediately above
    else:
        with tarfile.open(archive) as tf:
            _guard_members((m.name for m in tf), spec)
            tf.extractall(dest, filter="data")

    size, _ = _tree_size(dest)
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


def fetch_git(spec: SourceSpec, dest: Path) -> Path:
    """Shallow, optionally sparse clone (`04` §2).

    `--depth 1 --no-tags` because static analysis needs the tree, not the
    history; maintenance signals come from the forge API instead. Sparse
    checkout when the server lives in a monorepo subdirectory — one repository
    in the registry holds dozens of servers.
    """
    host = {SourceKind.GITHUB: "github.com", SourceKind.GITLAB: "gitlab.com"}[spec.kind]
    url = f"https://{host}/{spec.identifier}.git"

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

    resolved_ref: str | None = None
    for candidate in (spec.version, f"v{spec.version}"):
        try:
            _run([*base, "--branch", candidate, url, str(dest)])
            resolved_ref = candidate
            break
        except FetchError:
            shutil.rmtree(dest, ignore_errors=True)
    if resolved_ref is None:
        _run([*base, url, str(dest)])

    if spec.subfolder:
        _run(["git", "sparse-checkout", "set", "--no-cone", spec.subfolder], cwd=dest)
    # Reclaim packfile space immediately; a job's 5 GB scratch is shared with
    # semgrep's own working set.
    _run(["git", "gc", "--prune=now", "--quiet"], cwd=dest, timeout=60)
    _GIT_REF_USED[dest] = resolved_ref
    return dest / spec.subfolder if spec.subfolder else dest


def _download(url: str, dest: Path, timeout: int = FETCH_TIMEOUT_S) -> Path:
    """Stream a URL to disk, capped, without holding it in memory."""
    import httpx

    try:
        with httpx.stream(
            "GET", url, timeout=timeout, follow_redirects=True
        ) as response:
            response.raise_for_status()
            written = 0
            with dest.open("wb") as fh:
                for chunk in response.iter_bytes(64 * 1024):
                    written += len(chunk)
                    if written > MAX_UNPACKED_BYTES:
                        raise FetchError(f"download exceeded cap: {url}")
                    fh.write(chunk)
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

    suffix = ".whl" if chosen["packagetype"] == "bdist_wheel" else ".tar.gz"
    archive = _download(chosen["url"], workdir / f"pkg{suffix}")
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
