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
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from mcpwatchman.workers.scanner.source import EXCLUDED_DIRS

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
_DOC_PREFIXES = ("readme", "changelog", "contributing", "security", "codeowners")
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


def _role_of(rel: Path, language: Language) -> Role:
    name = rel.name
    lower = name.lower()
    parts_lower = {p.lower() for p in rel.parts[:-1]}

    if name in _MCP_MANIFEST_NAMES:
        return Role.MCP_MANIFEST
    if name in _LOCKFILES:
        return Role.LOCKFILE
    if name in _PACKAGE_MANIFESTS:
        return Role.PACKAGE_MANIFEST
    if any(lower.startswith(p) for p in _LICENSE_PREFIXES):
        return Role.LICENSE
    if any(lower.startswith(p) for p in _DOC_PREFIXES) or language is Language.MARKDOWN:
        return Role.DOCS
    # Tests are separated so a finding in a fixture does not score like a finding
    # in the served code — `03` §3 grades what runs, and a deliberately-unsafe
    # test fixture is evidence of testing, not of risk.
    if parts_lower & {"test", "tests", "__tests__", "spec", "e2e"} or lower.startswith(
        ("test_", "spec_")
    ) or lower.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go", "_test.py")):
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
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
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
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        scripts = data.get("project", {}).get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            found.extend(v for v in scripts.values() if isinstance(v, str))

    # Deduplicate while preserving declaration order — the first-declared entry
    # point is the conventional one and checks may weight it.
    seen: set[str] = set()
    return tuple(e for e in found if not (e in seen or seen.add(e)))


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

    for path in sorted(root.rglob("*")):
        if len(records) >= MAX_FILES:
            truncated = True
            break

        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue  # not "skipped" — excluded by policy, not by failure
        if path.is_symlink():
            skip("symlink")
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            # FIFOs, sockets, devices. `is_file()` is False for all of them, and
            # opening one can block the worker indefinitely.
            skip("not a regular file")
            continue

        try:
            size = path.stat().st_size
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

    manifest = next((f for f in records if f.role is Role.MCP_MANIFEST), None)
    return Inventory(
        files=tuple(records),
        mcp_manifest=manifest,
        entry_points=_entry_points(root),
        total_bytes=total,
        skipped=skipped,
        truncated=truncated,
    )
