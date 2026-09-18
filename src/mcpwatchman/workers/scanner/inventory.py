"""Walk a fetched tree and classify what is in it (`04-scanner-design.md` §3).

The input every check consumes. `semgrep_check` needs to know which files are
source and in what language; `auth_check` and `transparency_check` need the MCP
manifest and the entry points rather than the whole tree; the evidence trail
needs a path and a hash per finding.

**The tree is attacker-controlled** — it was just fetched from a public registry
— so this module never follows a symlink, never opens a non-regular file, and
bounds both the file count and the bytes it will hash. The failure it exists to
avoid is a walk that wanders out of the workspace or blocks forever on a FIFO.

⚠ **Two deliberate deviations from `04` §3, flagged rather than silent:**

1. **`pygments` is not used.** §3 says "pygments plus extension heuristics".
   Extensions are the primary signal here and a shebang covers the extensionless
   case; pygments is an undeclared dependency whose `guess_lexer` is both slow
   at this file count and content-guessing on hostile input. The classification
   feeds filtering and reporting, not parsing — semgrep does its own language
   detection — so the accuracy pygments would add is not load-bearing. Revisit
   if a check ever needs a language we cannot name from the filename.
2. **The module is not in `02` §208's file map**, which lists the check modules
   and `runner.py` but names nothing for this phase. Folding it into `runner.py`
   would make the orchestrator a grab-bag; `04` §3 describes a distinct phase and
   this is it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from mcpwatchman.workers.excluded import EXCLUDED_DIRS

# `04` §3: "Files larger than 1 MB are flagged but not deeply inspected (they're
# typically generated, vendored, or data files)." Flagged, not dropped — the size
# itself is a signal, and a check may still want to know the file is there.
LARGE_FILE_BYTES = 1024 * 1024

# Bounds on the walk itself. A fetched tree is attacker-controlled and the
# archive caps in `source.py` bound what lands on disk, but a git clone is not an
# archive — nothing upstream bounds a repository's file count.
MAX_FILES = 100_000

# Hashing is the only per-byte work here. Files over the large-file threshold are
# hashed to this prefix rather than in full: the hash exists to pin evidence to a
# specific artifact, and a prefix of a 40 MB vendored blob does that as well as
# the whole thing while keeping a pathological tree from dominating the scan's
# 15-minute budget (`04` §9).
HASH_PREFIX_BYTES = LARGE_FILE_BYTES

# `package.json` and `pyproject.toml` are parsed whole, so unlike every other
# file here their size becomes resident memory. Both are attacker-controlled and
# `source.py`'s archive caps permit a single member far larger than this, so the
# read is bounded and an oversized manifest degrades to "nothing declared" —
# truncating it instead would hand the parser a guaranteed-invalid document and
# reach the same place by a route that looks like a parse bug.
MANIFEST_MAX_BYTES = 1024 * 1024


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    RUBY = "ruby"
    JAVA = "java"
    CSHARP = "csharp"
    SHELL = "shell"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    MARKDOWN = "markdown"
    DOCKERFILE = "dockerfile"
    UNKNOWN = "unknown"


class Role(StrEnum):
    """What a file is FOR, which decides which check reads it."""

    SOURCE = "source"
    ENTRY_POINT = "entry_point"
    MCP_MANIFEST = "mcp_manifest"
    PACKAGE_MANIFEST = "package_manifest"
    LOCKFILE = "lockfile"
    CONFIG = "config"
    DOCS = "docs"
    LICENSE = "license"
    TEST = "test"
    OTHER = "other"


_BY_EXTENSION: dict[str, Language] = {
    ".py": Language.PYTHON, ".pyi": Language.PYTHON,
    ".js": Language.JAVASCRIPT, ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT, ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".rb": Language.RUBY,
    ".java": Language.JAVA,
    ".cs": Language.CSHARP,
    ".sh": Language.SHELL, ".bash": Language.SHELL, ".zsh": Language.SHELL,
    ".json": Language.JSON,
    ".yaml": Language.YAML, ".yml": Language.YAML,
    ".toml": Language.TOML,
    ".md": Language.MARKDOWN, ".markdown": Language.MARKDOWN,
}

# Interpreters seen in a shebang, for files with no extension. Deliberately a
# small map: this covers `bin/server` and `Makefile`-adjacent scripts, and is not
# trying to be a language database.
_BY_INTERPRETER: dict[str, Language] = {
    "python": Language.PYTHON, "python3": Language.PYTHON,
    "node": Language.JAVASCRIPT, "nodejs": Language.JAVASCRIPT,
    "bash": Language.SHELL, "sh": Language.SHELL, "zsh": Language.SHELL,
    "ruby": Language.RUBY,
}

# `04` §3 names server.json/mcp.json as the MCP manifest — the file that says
# what the server CLAIMS to do, which auth_check and transparency_check compare
# against what the code does.
_MCP_MANIFEST_NAMES = frozenset({"server.json", "mcp.json", ".mcp.json"})

_PACKAGE_MANIFESTS = frozenset(
    {"package.json", "pyproject.toml", "setup.py", "go.mod", "Cargo.toml", "Gemfile"}
)
_LOCKFILES = frozenset(
    {
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
        "poetry.lock", "uv.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
        "requirements.txt",
    }
)
# ⚠ LOCKSTEP with `transparency_check._find`, which searches Role.DOCS for
# ("changelog", "changes", "history", "news"). Those last three reached DOCS
# only when the file happened to be `.md` — so a Python project shipping
# `CHANGES.rst` scored changelog 0 with the evidence "no CHANGELOG in the
# fetched source", a false negative worth 15% of Transparency. Same shape as the
# `EXCLUDED_DIRS` split `CLAUDE.md` records: one rule, two enforcers, and when
# they disagreed the disagreement was silent.
_DOC_PREFIXES = (
    "readme", "changelog", "changes", "history", "news",
    "contributing", "security", "codeowners",
)

# ⚠ **A DOC PREFIX ONLY COUNTS ON A DOC-SHAPED FILE**, and this guard is the
# other half of the fix above rather than a refinement of it. Widening the
# prefixes past markdown to catch `CHANGES.rst` also caught `history.py`,
# `news.ts`, `changes.go` and `security.rb` — ordinary source files whose names
# happen to start with a documentation word — and the damage was double: a false
# changelog 100 from a Python module, AND the file dropping out of
# `auth_check`'s and `transport_check`'s source sweeps, so a server whose main
# module is `history.py` lost its authentication detection entirely.
#
# Two conditions, because either alone still misclassifies. The EXTENSION test
# keeps `security.json` (a config file) and `news.ts` out; the LANGUAGE test
# covers the extensionless case, where `_language_of` reads a shebang and a
# script named `changes` is a script, not a changelog.
_DOC_EXTENSIONS = frozenset(
    {"", ".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".org", ".textile"}
)
_CODE_LANGUAGES = frozenset(
    {
        Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.GO,
        Language.RUST, Language.RUBY, Language.JAVA, Language.CSHARP,
        Language.SHELL, Language.DOCKERFILE,
    }
)
_LICENSE_PREFIXES = ("license", "licence", "copying", "notice")


@dataclass(frozen=True, slots=True)
class FileRecord:
    """One file, as `04` §3 specifies: `(path, language, size_bytes, sha256)`."""

    path: str  # POSIX, relative to the scan root — never absolute
    language: Language
    role: Role
    size_bytes: int
    sha256: str
    # True when over `LARGE_FILE_BYTES`. `04` §3: flagged, not deeply inspected.
    # The hash is then over the first `HASH_PREFIX_BYTES` only, so it identifies
    # the artifact without pinning every byte — say so rather than let a caller
    # assume a whole-file digest.
    oversized: bool = False


@dataclass(frozen=True, slots=True)
class Inventory:
    """What the tree contains, and what was left out of it."""

    files: tuple[FileRecord, ...] = ()
    mcp_manifest: FileRecord | None = None
    entry_points: tuple[str, ...] = ()
    total_bytes: int = 0
    # Why files were not recorded, counted by reason. Surfaced rather than
    # logged: "we skipped 4,000 files" is a fact a per-server page may owe its
    # reader, and a silent skip is indistinguishable from an empty repository.
    skipped: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    def by_language(self, language: Language) -> tuple[FileRecord, ...]:
        return tuple(f for f in self.files if f.language is language)

    def by_role(self, role: Role) -> tuple[FileRecord, ...]:
        return tuple(f for f in self.files if f.role is role)

    @property
    def scannable(self) -> tuple[FileRecord, ...]:
        """Files a static-analysis rule should actually read.

        Excludes oversized files (`04` §3 flags them as not deeply inspected)
        and anything whose language we could not name — semgrep would have
        nothing to parse either.
        """
        return tuple(
            f for f in self.files if not f.oversized and f.language is not Language.UNKNOWN
        )


def _language_of(path: Path) -> Language:
    """Extension first, then a shebang for the extensionless case."""
    by_ext = _BY_EXTENSION.get(path.suffix.lower())
    if by_ext is not None:
        return by_ext
    if path.name.lower().startswith("dockerfile"):
        return Language.DOCKERFILE
    if path.suffix:
        return Language.UNKNOWN
    return _language_from_shebang(path)


def _language_from_shebang(path: Path) -> Language:
    """Read the first line only, and only for a file with no extension.

    Bounded deliberately: this opens an attacker-controlled file, so it reads a
    fixed small prefix rather than a line of unbounded length, and treats any
    read failure as unknown rather than propagating.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(128)
    except OSError:
        return Language.UNKNOWN
    if not head.startswith(b"#!"):
        return Language.UNKNOWN
    first = head.split(b"\n", 1)[0].decode("utf-8", "replace")
    # `#!/usr/bin/env python3` and `#!/bin/bash` both end in the interpreter.
    for token in reversed(first.replace("#!", "").split()):
        name = token.rsplit("/", 1)[-1]
        if name in _BY_INTERPRETER:
            return _BY_INTERPRETER[name]
    return Language.UNKNOWN


# ⚠ DERIVED, not hand-listed. The hand-written tuple omitted every JSX/TSX
# variant — `component.test.tsx` does not end in `.test.ts` — so common React
# test files classified as served source and their findings would have scored as
# production risk. An enumeration that has to be kept in sync with the language
# table by hand will drift again; this one cannot.
_TEST_SUFFIXES: tuple[str, ...] = tuple(
    f".{kind}.{ext}"
    for kind in ("test", "spec")
    for ext in ("js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts")
) + ("_test.go", "_test.py", "_test.rb", "_spec.rb")

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "testdata"}


def _is_test(rel: Path, lower: str, parts_lower: set[str]) -> bool:
    return bool(
        parts_lower & _TEST_DIRS
        or lower.startswith(("test_", "spec_"))
        or lower.endswith(_TEST_SUFFIXES)
    )


def _role_of(rel: Path, language: Language) -> Role:
    name = rel.name
    lower = name.lower()
    parts_lower = {p.lower() for p in rel.parts[:-1]}

    # ⚠ LOCATION BEATS FILENAME, and this ordering is the whole point.
    # The filename roles used to run first, so `tests/fixtures/server.json`
    # returned `MCP_MANIFEST` and became `Inventory.mcp_manifest` — the auth and
    # transparency checks would then have assessed a deliberately-crafted test
    # fixture as the server's own declaration. That defeats the very separation
    # the comment below describes: `03` §3 grades what runs, and a fixture is
    # evidence of testing, not of risk. Same for a lockfile or a README under a
    # test tree — none of them is the served artifact.
    if _is_test(rel, lower, parts_lower):
        return Role.TEST

    if name in _MCP_MANIFEST_NAMES:
        return Role.MCP_MANIFEST
    if name in _LOCKFILES:
        return Role.LOCKFILE
    if name in _PACKAGE_MANIFESTS:
        return Role.PACKAGE_MANIFEST
    if any(lower.startswith(p) for p in _LICENSE_PREFIXES):
        return Role.LICENSE
    if language is Language.MARKDOWN or (
        any(lower.startswith(p) for p in _DOC_PREFIXES)
        and rel.suffix.lower() in _DOC_EXTENSIONS
        and language not in _CODE_LANGUAGES
    ):
        return Role.DOCS
    # Tests are separated so a finding in a fixture does not score like a finding
    # in the served code — `03` §3 grades what runs, and a deliberately-unsafe
    # test fixture is evidence of testing, not of risk.
    if _is_test(rel, lower, parts_lower):
        return Role.TEST
    if language in (Language.JSON, Language.YAML, Language.TOML):
        return Role.CONFIG
    if language is Language.UNKNOWN:
        return Role.OTHER
    return Role.SOURCE


def _sha256_of(path: Path, limit: int | None) -> tuple[str, int]:
    """Digest a file, optionally only its first `limit` bytes. Returns (hex, size)."""
    digest = hashlib.sha256()
    read = 0
    with path.open("rb") as fh:
        while chunk := fh.read(64 * 1024):
            if limit is not None and read + len(chunk) > limit:
                digest.update(chunk[: limit - read])
                read = limit
                break
            digest.update(chunk)
            read += len(chunk)
    return digest.hexdigest(), read


def _read_manifest(path: Path) -> str:
    """Read a manifest file, bounded by `MANIFEST_MAX_BYTES`.

    Returns "" for an oversized or unreadable file, which the callers' parse
    step turns into "nothing declared" — the same degradation a malformed
    manifest gets.
    """
    try:
        with path.open("rb") as fh:
            raw = fh.read(MANIFEST_MAX_BYTES + 1)
    except OSError:
        return ""
    if len(raw) > MANIFEST_MAX_BYTES:
        return ""
    return raw.decode("utf-8", "replace")


def _entry_points(root: Path) -> tuple[str, ...]:
    """Declared executables: `package.json` bin, `pyproject.toml` scripts.

    `04` §3 wants these so auth and transparency checks can start at the code
    that actually runs rather than at an arbitrary file. Both files are
    attacker-controlled, so every parse failure and every unexpected shape
    degrades to "no entry points declared" — never to an exception, which would
    fail the whole scan over a malformed manifest.
    """
    found: list[str] = []

    pkg = root / "package.json"
    if pkg.is_file() and not pkg.is_symlink():
        try:
            data = json.loads(_read_manifest(pkg))
        except (ValueError, OSError):
            data = {}
        if isinstance(data, dict):
            bin_field = data.get("bin")
            if isinstance(bin_field, str):
                found.append(bin_field)
            elif isinstance(bin_field, dict):
                found.extend(v for v in bin_field.values() if isinstance(v, str))
            main = data.get("main")
            if isinstance(main, str):
                found.append(main)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        try:
            data = tomllib.loads(_read_manifest(pyproject))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        # ⚠ Each level is checked separately. `data.get("project", {}).get(...)`
        # raises AttributeError on a syntactically VALID file whose `project` is
        # not a table (`project = "invalid"`), which this function's docstring
        # promises cannot happen — a malformed manifest must degrade to "nothing
        # declared", never fail the scan.
        project = data.get("project") if isinstance(data, dict) else None
        scripts = project.get("scripts") if isinstance(project, dict) else None
        if isinstance(scripts, dict):
            found.extend(v for v in scripts.values() if isinstance(v, str))

    # Deduplicate while preserving declaration order — the first-declared entry
    # point is the conventional one and checks may weight it.
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in found:
        if entry not in seen:
            seen.add(entry)
            ordered.append(entry)
    return tuple(ordered)


def enumerate_tree(root: Path) -> Inventory:
    """Walk `root` and classify every regular file under it (`04` §3).

    `root` is a fetched, attacker-controlled tree. The walk is bounded, never
    follows a symlink, and never opens anything that is not a regular file — a
    FIFO would block forever, and a symlink out of the tree would read the host.
    """
    root = root.resolve()
    records: list[FileRecord] = []
    skipped: dict[str, int] = {}
    total = 0
    truncated = False

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    # ⚠ `os.scandir` directly, not `os.walk` and not `rglob`. Three bounds
    # failures sit behind this loop's shape, each defeating the SAME advertised
    # cap in a different way:
    #
    # 1. `sorted(root.rglob("*"))` materialises the ENTIRE tree before the first
    #    cap check can run. A repository is not an archive — `source.py`'s
    #    member-count cap covers the npm and PyPI paths, and nothing upstream
    #    bounds a clone's file count.
    # 2. `os.walk` streams BETWEEN directories but builds the complete `dirnames`
    #    and `filenames` lists for EACH one before yielding, so a single
    #    directory holding millions of entries exhausts memory before the loop
    #    ever reaches a cap check. Fixing (1) with `os.walk` narrowed the bound
    #    from the whole tree to the widest directory and left it unbounded.
    # 3. The cap counted ACCEPTED records, so skipped entries never advanced it:
    #    a repository of >MAX_FILES symlinks or device nodes was walked in full
    #    and then reported `truncated=False` — the bound both absent and denied.
    #
    # Scanning entry-by-entry off the iterator fixes all three: it can stop in
    # the middle of a directory, and `visited` counts what the walk TOUCHED
    # rather than what it kept.
    #
    # Symlinks are refused explicitly rather than inherited from a traversal
    # helper's defaults. `rglob`'s non-descent into symlinked directories is
    # interpreter behaviour this box cannot test — the venv here is 3.14 and CI
    # runs 3.12, the same split the `filter="data"` note in `source.py` records.
    # A tree containing a symlink to `/` would have the walk enumerate the host.
    visited = 0
    stopped = False
    stack: list[Path] = [root]

    while stack and not stopped:
        current = stack.pop()
        try:
            scanner = os.scandir(current)
        except OSError:
            skip("unreadable")
            continue

        with scanner:
            for entry in scanner:
                if visited >= MAX_FILES:
                    truncated = True
                    stopped = True
                    break
                visited += 1

                path = Path(entry.path)
                rel = path.relative_to(root)

                # Before any type test: a type test on a symlink follows it.
                if entry.is_symlink():
                    skip("symlink")
                    continue
                if entry.name in EXCLUDED_DIRS:
                    continue  # not "skipped" — excluded by policy, not by failure
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        # FIFOs, sockets, devices. Opening one can block forever.
                        skip("not a regular file")
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                    oversized = size > LARGE_FILE_BYTES
                    language = _language_of(path)
                    digest, _ = _sha256_of(path, HASH_PREFIX_BYTES if oversized else None)
                except OSError:
                    skip("unreadable")
                    continue

                total += size
                records.append(
                    FileRecord(
                        path=rel.as_posix(),
                        language=language,
                        role=_role_of(rel, language),
                        size_bytes=size,
                        sha256=digest,
                        oversized=oversized,
                    )
                )

    # Sort by path COMPONENTS, which is how the original `sorted(rglob(...))`
    # ordered records — a plain string sort differs, because "/" (0x2f) sorts
    # after "." (0x2e) and so puts `a.py` before `a/b.py` where the component
    # comparison puts `a/b.py` first. Sorting after the walk rather than during
    # it is what lets the traversal stay unordered and therefore streaming; the
    # list is bounded by MAX_FILES, so this sort is too.
    records.sort(key=lambda r: r.path.split("/"))

    manifest = next((f for f in records if f.role is Role.MCP_MANIFEST), None)
    return Inventory(
        files=tuple(records),
        mcp_manifest=manifest,
        entry_points=_entry_points(root),
        total_bytes=total,
        skipped=skipped,
        truncated=truncated,
    )


# Per-file cap for the check modules' content reads. `enumerate_tree` hashes
# without holding a file resident; a check that greps source does hold it, so it
# gets its own bound. Generous enough that no realistic entry point is truncated
# and small enough that a hostile 2 GB "source file" cannot be read into memory.
SOURCE_READ_MAX_BYTES = 512 * 1024


def read_text(
    root: Path,
    rel_path: str,
    limit: int = SOURCE_READ_MAX_BYTES,
    truncate: bool = True,
) -> str:
    """Read a file from a fetched tree as text, bounded and confined.

    ⚠ **This is the FIFTH path in this repo that reads attacker-controlled
    input**, after the tar and zip extractors, `_measure_all`, and the walk
    above — and `CLAUDE.md` records that every bounds defect here has been a
    guard written in one and omitted from its neighbour. So the check modules do
    not open files themselves; they come through here, and the bound lives in
    one place rather than in each of them.

    Three refusals, each for a failure the tree can actually cause:

    - **Escape.** `rel_path` comes from an `Inventory` record and is relative by
      construction, but a caller may also pass a name it composed itself
      (`entry_points` holds strings from an attacker's `package.json`). The
      resolved path must stay under the resolved root.
    - **Symlink.** Resolving first and comparing would follow a link to
      `/etc/shadow` and then confirm the link's own location is fine.
    - **Non-regular.** Opening a FIFO blocks forever.

    Returns "" for all three, and for an unreadable or oversized file. Every
    caller treats absent content as "nothing declared", so a failure degrades to
    a missing signal rather than to an exception that fails the whole scan.
    """
    root = root.resolve()
    try:
        candidate = (root / rel_path).resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return ""
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return ""
        with candidate.open("rb") as fh:
            raw = fh.read(limit + 1)
    except OSError:
        return ""
    if len(raw) > limit:
        # Truncate rather than refuse: unlike a manifest, source is grepped for
        # patterns and a 512 KB prefix answers "does this import an HTTP
        # framework?" as well as the whole file would. A manifest is parsed
        # whole-or-not-at-all, which is why `read_manifest` passes
        # `truncate=False` and `_read_manifest` refuses instead.
        if not truncate:
            return ""
        raw = raw[:limit]
    return raw.decode("utf-8", "replace")


def read_manifest(root: Path, rel_path: str) -> str:
    """Read a manifest from a fetched tree, whole or not at all.

    ⚠ **A parsed file must never be truncated, and the distinction is not
    cosmetic.** `license_check` read `package.json` and `Cargo.toml` through
    `read_text`'s 512 KB SOURCE bound, which truncates — so a large but
    perfectly valid manifest arrived at `json.loads` as a guaranteed-invalid
    document and degraded to "nothing declared", by a route that looks like the
    publisher shipped a malformed file. Source is grepped and tolerates a
    prefix; a manifest is parsed and does not.

    Same bound and same refusal as `_read_manifest`, which `enumerate_tree` uses
    for the two manifests it reads itself — one rule, and now one behaviour,
    rather than two readers disagreeing about the same file (`CLAUDE.md`
    records that every bounds defect in this repo has been a guard written in
    one place and omitted from its neighbour).
    """
    return read_text(root, rel_path, limit=MANIFEST_MAX_BYTES, truncate=False)
