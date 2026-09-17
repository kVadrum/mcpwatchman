"""semgrep execution and Code Safety scoring (`04` §4, `03` §3).

Code Safety is the largest axis (weight 30) and the only one `03` describes as
the project's differentiating asset. It is deduction-scored from findings, so
this module's output feeds `composite.axis_score` — **not** `axes.score_axis`,
which scores the sub-check axes and cannot express a finding at all.

Three things here are load-bearing and none of them are obvious from `04` §4.4's
one-line invocation. Each was measured on semgrep 1.177.0 before being written.

**1. A scanned repository can switch our scanner off, and we let it until now.**
semgrep honours a `.semgrepignore` found in the tree it is scanning — which is
attacker-controlled input, because that tree is a stranger's repository. Planting
one line naming your own source file takes the scan from 43 findings to **0
findings, 0 files, exit 0**, which is indistinguishable from a clean repository.
Measured both directions in a throwaway tree: with the file, 0; without it, 16.
So we neutralise repo-supplied scanner configuration before scanning — we own
the scratch copy, and `scan_workspace` throws it away afterwards.
⚠ This is the same class as `04` §6's `detect-secrets` defect (a documented
invocation that silently scanned nothing), and the same tell: the failure is a
confident zero, not an error.

**2. `--no-git-ignore`, because otherwise semgrep scans only tracked files.**
Its default target selection is `git ls-files`. A fetched *archive* (npm tarball,
PyPI sdist) has no `.git`, so everything is scanned; a fetched *clone* has one,
so the repository's own `.gitignore` gets a vote on what we audit. Two fetch
kinds scoring by different rules — with no signal saying which you got — is not
a defensible methodology, so we take the same superset in both cases.

**3. semgrep will not give us the evidence excerpt.** `extra.lines` comes back
as the literal string `requires login` for anonymous runs. `03` §3 commits us to
"matched code excerpt (~5 lines of context)" on every finding, so the excerpt is
read from our own copy of the file instead. That is the better answer anyway: no
vendor account in the scan path, and the bytes quoted are the bytes we scored.

**Unmapped rule ids raise.** `_meta/severity-mapping.yaml` is canonical for
(severity, confidence) and a finding whose rule is absent from it has no defined
deduction. Defaulting would either invent a severity or silently drop a real
finding; both are worse than a loud failure in a nightly batch that retries.
Same reasoning as `composite_published()` refusing to guess for an unknown
methodology version.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal
from enum import StrEnum
from pathlib import Path

import yaml

from mcpwatchman.workers.excluded import EXCLUDED_DIRS, HOSTILE_CONFIG_FILES
from mcpwatchman.workers.scanner.inventory import (
    Inventory,
    Language,
    Role,
    read_text,
)
from mcpwatchman.workers.scanner.reachability import redact_paths
from mcpwatchman.workers.scoring.composite import (
    AXIS_MAX,
    Confidence,
    Finding,
    Severity,
    axis_score,
    dec,
)
from mcpwatchman.workers.scoring.weights import (
    CURRENT_METHODOLOGY_VERSION,
    confidence_ceiling,
)

AXIS = "code_safety"

# `04` §4.4: "Timeout is 5 minutes per scan; OOM kill at 2 GB."
SEMGREP_TIMEOUT_S = 300
SEMGREP_MAX_MEMORY_MB = 2048

# Lines of context quoted with each finding (`03` §3: "~5 lines").
EVIDENCE_CONTEXT_LINES = 2

# A line this long in a web asset means the file is machine-generated: minified,
# bundled, or both. 500 is comfortably above hand-written code (this repository
# lints at 100) and far below a minified bundle, which routinely runs to tens of
# thousands of characters on one line.
MINIFIED_LINE_CHARS = 500
_MINIFIABLE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".css"}
# Only the head is read: a bundle's first line is already over the threshold,
# and this runs per file on trees of a few hundred.
_MINIFIED_PROBE_BYTES = 64 * 1024

# Languages the ruleset covers, keyed to the directory holding their rules.
# Derived from what is on disk rather than listed, so adding rules/rust/ is a
# directory and not a code change.
_META_DIR = "_meta"

_SEVERITIES = {s.value for s in Severity}
_CONFIDENCES = {c.value for c in Confidence}


class SemgrepStatus(StrEnum):
    """`04` §4.4 records a per-check status; a failure is recoverable."""

    OK = "ok"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class RulesetError(RuntimeError):
    """The ruleset is missing, unreadable, or disagrees with its mapping.

    Distinct from a scan failure: this is OUR defect, and every server scanned
    while it holds is scored against a ruleset we cannot describe.
    """


@dataclass(frozen=True, slots=True)
class CodeFinding:
    """One semgrep match, with the evidence `03` §10 commits us to publishing."""

    rule_id: str
    severity: Severity
    confidence: Confidence
    message: str
    path: str
    line: int
    excerpt: str
    mcp_pattern: str = ""
    cwe: str = ""
    # Set when `confidence` was lowered from the ruleset's declared value
    # because calibration has not run. Rendered, never silent: a reader
    # comparing two scans deserves to know the ceiling moved, not just the
    # number. See `weights.confidence_ceiling`.
    declared_confidence: Confidence | None = None

    @property
    def clamped(self) -> bool:
        return self.declared_confidence is not None

    def to_scoring(self) -> Finding:
        """The two-field projection `composite.axis_score` consumes."""
        return Finding(severity=self.severity, confidence=self.confidence)


@dataclass(frozen=True, slots=True)
class SemgrepResult:
    """Outcome of one semgrep run over one source tree.

    `score` is `None` when the scan did not happen or could not be trusted —
    NOT 100. A tool that failed to run has not established that a server is
    clean, and `03` §3's axis starts at 100 only for a scan that actually
    looked. This is the same distinction `axes.AxisResult` draws between an
    unassessed sub-check and a zero.
    """

    status: SemgrepStatus
    findings: tuple[CodeFinding, ...] = ()
    score: int | None = None
    files_scanned: int = 0
    # Files and directories deliberately not read — vendored trees and minified
    # bundles. Rendered, not silent: a reader comparing two servers deserves to
    # know one of them shipped 245 files and was scored on 12 of them.
    pruned: int = 0
    pruned_sample: tuple[str, ...] = ()
    # Files semgrep could not parse. The axis is scored on what it DID
    # read, and the share is published rather than rounded to 1.
    files_unparsed: int = 0
    assessed_weight: str = "1"
    ruleset_version: str = ""
    methodology_version: str = CURRENT_METHODOLOGY_VERSION
    reason: str = ""
    neutralised: tuple[str, ...] = ()

    @property
    def assessed(self) -> bool:
        return self.status is SemgrepStatus.OK


def rules_root(start: Path | None = None) -> Path:
    """Locate the ruleset directory.

    Walks up from this module looking for a `rules/` holding language
    directories. Raises rather than returning a default: a scanner that cannot
    find its rules must not fall through to `--config` of nothing, which exits
    0 having matched nothing at all.
    """
    here = (start or Path(__file__)).resolve()
    for parent in here.parents:
        candidate = parent / "rules"
        if candidate.is_dir() and any(_language_configs(candidate)):
            return candidate
    # The INSTALLED layout: `force-include` puts the ruleset inside the package
    # as `mcpwatchman/rules`, which is not above this file and so is never
    # reached by the walk. A checkout finds it above; a wheel finds it here.
    packaged = Path(__file__).resolve().parents[2] / "rules"
    if packaged.is_dir() and any(_language_configs(packaged)):
        return packaged
    raise RulesetError(
        f"no rules/ directory with language rule files found above {here}; "
        "the scanner cannot run without its ruleset"
    )


def _language_configs(root: Path) -> list[Path]:
    """Per-language rule directories, `_meta` excluded.

    ⚠ **`_meta` is excluded because semgrep CRASHES on it, and this is a
    deliberate, narrow deviation from `04` §4.4's `--config rules/`.**
    `severity-mapping.yaml` keys its `rules:` by id — a mapping, where semgrep
    requires a list — so pointing semgrep at `rules/` raises `KeyError: 0` out
    of its config loader before a single file is scanned. Renaming the key only
    converts the crash into "missing `rules` as top-level key"; the file is not
    a semgrep ruleset and does not belong in a tree semgrep is parsing as one.
    `04` §4.1's layout is kept intact and the invocation gives way instead.
    """
    return sorted(
        d for d in root.iterdir()
        if d.is_dir() and d.name != _META_DIR and any(d.glob("*.yaml"))
    )


def load_severity_mapping(root: Path | None = None) -> dict[str, dict[str, str]]:
    """Read `_meta/severity-mapping.yaml`, the canonical (severity, confidence).

    Validates on the way in. An unknown severity or confidence string here would
    otherwise surface as a `ValueError` from `StrEnum` deep inside a scan, per
    server, after the expensive part.
    """
    root = root or rules_root()
    path = root / _META_DIR / "severity-mapping.yaml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RulesetError(f"cannot read severity mapping at {path}: {exc}") from exc
    mapping = (raw or {}).get("rules")
    if not isinstance(mapping, dict) or not mapping:
        raise RulesetError(f"{path} has no `rules:` mapping of rule id to severity")
    for rule_id, entry in mapping.items():
        if not isinstance(entry, dict):
            raise RulesetError(f"{rule_id}: expected a mapping, got {type(entry).__name__}")
        if entry.get("severity") not in _SEVERITIES:
            raise RulesetError(f"{rule_id}: unknown severity {entry.get('severity')!r}")
        if entry.get("confidence") not in _CONFIDENCES:
            raise RulesetError(f"{rule_id}: unknown confidence {entry.get('confidence')!r}")
    return mapping


def declared_rule_ids(root: Path | None = None) -> set[str]:
    """Every rule id the ruleset actually defines, read from the rule files."""
    root = root or rules_root()
    ids: set[str] = set()
    for config in _language_configs(root):
        for path in sorted(config.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rules = doc.get("rules")
            if not isinstance(rules, list):
                raise RulesetError(f"{path}: `rules:` must be a list of rules")
            for rule in rules:
                rule_id = rule.get("id")
                if not rule_id:
                    raise RulesetError(f"{path}: a rule has no id")
                if "." in rule_id:
                    # semgrep namespaces check_id as `<dir>.<file>.<id>`, and we
                    # recover the bare id by taking the last dotted segment. A
                    # dot inside an id would make that recovery ambiguous.
                    raise RulesetError(f"{rule_id}: rule ids must not contain '.'")
                if rule_id in ids:
                    raise RulesetError(f"{rule_id}: declared twice")
                ids.add(rule_id)
    return ids


def ruleset_version(root: Path | None = None) -> str:
    """Ruleset version from `_meta/changelog.md`'s first version heading.

    `04` §4.3 requires every scan to record the ruleset version it used.
    """
    root = root or rules_root()
    changelog = root / _META_DIR / "changelog.md"
    try:
        for line in changelog.read_text(encoding="utf-8").splitlines():
            if line.startswith("## "):
                return line[3:].strip().split()[0]
    except OSError as exc:
        raise RulesetError(f"cannot read {changelog}: {exc}") from exc
    raise RulesetError(f"{changelog} declares no `## <version>` heading")


def _is_minified(path: Path) -> bool:
    """Whether a web asset is machine-generated rather than authored.

    Scoring a minified bundle is a false accusation with a score attached, and
    it is not hypothetical — it is what sent a real server to **0** on Code
    Safety during the first live run. `ac.tandem/docs-mcp` ships a built
    documentation site, and `guide/book/highlight-abc7f01d.js` — a minified
    highlight.js — matched the shell-exec rule four times on its single line 6.
    The server's own source was never the problem.

    Two signals, either sufficient: a build-artifact NAME (`*.min.js`, or a
    content hash before the extension, which is what every bundler emits), or a
    line long enough that no human wrote it.
    """
    # ⚠ THE EXTENSION GATE COMES FIRST, and it used to come last.
    # Both name rules ran before it, so they applied to EVERY file in the tree
    # — and that handed a stranger control over which of their own files we
    # read. Measured: `tools-deadbeef.py`, `handler-abcdef12.go` and
    # `settings.minimal.py` were all deleted from the scratch copy before
    # semgrep ran. A server could name its shell-injection module
    # `tools-deadbeef.py` and be scored on source nobody opened; an honest repo
    # with `settings.minimal.py` had it dropped and reported as a
    # machine-generated bundle. Minification is a property of web assets, so
    # the question is only ever asked about one.
    if path.suffix.lower() not in _MINIFIABLE_SUFFIXES:
        return False
    stem = path.stem.lower()
    # Dotted COMPONENTS, not substrings: `".min" in stem` also matched
    # `.minimal`, `.mine` and `.minify`, which are ordinary words.
    parts = set(stem.split("."))
    if parts & {"min", "bundle", "chunk"}:
        return True
    # `highlight-abc7f01d.js`, `book-a0b12cfe.js` — bundler content hashes.
    tail = stem.rsplit("-", 1)[-1] if "-" in stem else ""
    if len(tail) >= 8 and all(c in "0123456789abcdef" for c in tail):
        return True
    try:
        head = path.open("rb").read(_MINIFIED_PROBE_BYTES)
    except OSError:
        return False
    return any(len(line) > MINIFIED_LINE_CHARS for line in head.split(b"\n"))


def _prune_unscannable(root: Path) -> tuple[int, tuple[str, ...]]:
    """Remove from the scratch copy what must not be scored.

    Two categories, one mechanism:

    **`EXCLUDED_DIRS`.** That module exists because the crawler and the scanner
    must agree on what is off-limits, and it names itself a CONTRACT with two
    consumers. semgrep was a silent third consumer honouring none of it, so a
    repository that vendors its dependencies was scored on its dependencies'
    code. Passing `--exclude` per directory would work too; pruning keeps one
    mechanism for both categories and matches what we already do to
    `.semgrepignore`.

    **Minified bundles** — see `_is_minified` for the live failure that forced
    this.

    Safe because `root` is a scratch copy `scan_workspace` throws away, and it
    runs after `enumerate_tree`, so the inventory still records what shipped.
    Returns the count and a bounded sample for the per-server page: "we did not
    read these, and here is why" is a fact a reader is owed.
    """
    pruned: list[str] = []

    def removed(path: Path) -> bool:
        """Whether the path is really gone. `exists()` alone follows symlinks."""
        return not path.exists() and not path.is_symlink()

    for directory in sorted(EXCLUDED_DIRS):
        for found in root.rglob(directory):
            # ⚠ SYMLINK FIRST, and this ordering is the whole fix.
            # `shutil.rmtree` REFUSES to act on a symlink, and with
            # `ignore_errors=True` it refuses silently. A repository shipping
            # `node_modules` as a symlink therefore got counted as excluded
            # while remaining fully present and fully scannable — the exclusion
            # did not happen and the page told the reader it had. Same family
            # as the `.semgrepignore` evasion: repo-controlled input defeating
            # the scanner while the scanner reports success.
            #
            # Unlinked, never followed: removing the LINK is correct and
            # removing its target would be us deleting outside the scratch copy
            # on a stranger's instruction.
            if found.is_symlink():
                found.unlink(missing_ok=True)
            elif found.is_dir():
                shutil.rmtree(found, ignore_errors=True)
            else:
                continue
            # Counted only if it actually went. A prune count that includes
            # failures is a number the per-server page publishes as fact.
            if removed(found):
                pruned.append(f"{found.relative_to(root)}/")

    for path in sorted(root.rglob("*")):
        # `is_file()` follows symlinks, so this also gated a FIFO or device
        # node reached through one — and `_is_minified` OPENS what it is given,
        # where a FIFO blocks the worker forever. Regular files only; a symlink
        # carries no content of its own to scan.
        if path.is_symlink() or not path.is_file():
            continue
        if _is_minified(path):
            path.unlink(missing_ok=True)
            if removed(path):
                pruned.append(str(path.relative_to(root)))

    return len(pruned), tuple(sorted(pruned)[:20])


def _neutralise_hostile_config(root: Path) -> tuple[str, ...]:
    """Remove scanner configuration supplied by the scanned repository.

    Returns what was removed, so the per-server page can say so — a repo that
    shipped a `.semgrepignore` excluding its own source is itself a finding a
    reader is owed, even though this function's job is only to defang it.
    """
    removed: list[str] = []
    for name in HOSTILE_CONFIG_FILES:
        for path in root.rglob(name):
            if path.is_file():
                path.unlink()
                removed.append(str(path.relative_to(root)))
    return tuple(sorted(removed))


def _error_paths(errors: list) -> list:
    """Every dict carrying a `path` anywhere inside semgrep's error payloads.

    `errors[].type` may be `["PartialParsing", [{"path": …}, …]]`, so the file
    a parse failure refers to is nested rather than top-level.
    """
    found: list = []
    stack: list = list(errors)
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "path" in item:
                found.append(item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _error_kind(error: dict) -> str:
    """The NAME of a semgrep error, from a `type` that may not be a string."""
    raw = error.get("type") or error.get("level") or "error"
    while isinstance(raw, list) and raw:
        raw = raw[0]
    return str(raw) if isinstance(raw, str | int | float) else "error"


def _excerpt(root: Path, rel_path: str, line: int) -> str:
    """Read ~5 lines of context around a match from OUR copy of the file."""
    # Through `inventory.read_text`, which is the repo's canonical bounded and
    # CONFINED reader — it refuses an escape, a symlink and an oversized file,
    # and its own docstring says the check modules do not open files
    # themselves. Reading directly here made this the sixth path walking
    # attacker-controlled input with none of those refusals, and `CLAUDE.md`
    # says a bound added to one is owed to the others.
    try:
        text = read_text(root, rel_path)
    except (OSError, ValueError):
        return ""
    lines = text.splitlines()
    lo = max(0, line - 1 - EVIDENCE_CONTEXT_LINES)
    hi = min(len(lines), line + EVIDENCE_CONTEXT_LINES)
    return "\n".join(lines[lo:hi])


def _scannable_source_files(inventory: Inventory) -> int:
    """Files the ruleset could match: source in a language we carry rules for."""
    covered = {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.GO}
    return sum(
        1 for f in inventory.files
        if f.language in covered and f.role in (Role.SOURCE, Role.ENTRY_POINT)
    )


def run_semgrep(
    root: Path,
    *,
    rules: Path | None = None,
    inventory: Inventory | None = None,
    version: str = CURRENT_METHODOLOGY_VERSION,
    timeout_s: int = SEMGREP_TIMEOUT_S,
) -> SemgrepResult:
    """Scan one fetched source tree and score `03` §3's Code Safety axis.

    `root` must be a scratch copy we own — this MUTATES it, deleting any
    scanner configuration the repository shipped (see the module docstring).
    """
    rules = rules or rules_root()
    mapping = load_severity_mapping(rules)
    configs = _language_configs(rules)
    if not configs:
        raise RulesetError(f"{rules} holds no language rule directories")

    if shutil.which("semgrep") is None:
        return SemgrepResult(
            status=SemgrepStatus.UNAVAILABLE,
            reason="semgrep is not on PATH; it ships in the `workers` extra",
        )

    neutralised = _neutralise_hostile_config(root)
    pruned_count, pruned_sample = _prune_unscannable(root)

    # `--disable-nosem` is the third door in the same room as `.semgrepignore`
    # and `--no-git-ignore`, and it was open. semgrep honours inline `nosem` /
    # `# nosemgrep` comments BY DEFAULT, and the scanned tree is a stranger's
    # repository: one comment on the offending line suppresses the finding, the
    # scan still reports files scanned, and Code Safety publishes 100.
    # Measured with a negative control — `subprocess.run(f"cat {arg}",
    # shell=True)  # nosemgrep` is invisible by default and flagged with this
    # flag. A deleted config FILE cannot reach a comment inside a source line,
    # so neutralising `.semgrepignore` never touched this.
    cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
           "--disable-nosem",
           "--max-memory", str(SEMGREP_MAX_MEMORY_MB), "--timeout", "0"]
    for config in configs:
        cmd += ["--config", str(config)]
    cmd.append(str(root))

    try:
        proc = subprocess.run(  # noqa: S603 - argv form, no shell; `cmd` is
            # built here from a fixed binary name and our own rule paths.
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired:
        return SemgrepResult(
            status=SemgrepStatus.FAILED,
            reason=f"semgrep exceeded {timeout_s}s",
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Deliberately NOT falling through to "no findings": semgrep exits
        # non-zero with no JSON on a config error, and reading that as a clean
        # repository is how a broken scanner publishes a perfect score.
        return SemgrepResult(
            status=SemgrepStatus.FAILED,
            # Redacted at CONSTRUCTION: this string reaches the public page,
            # and subprocess stderr routinely names our scratch directory.
            reason=redact_paths(
                f"semgrep produced no JSON (exit {proc.returncode}): "
                f"{proc.stderr.strip()[:200]}"
            ),
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )

    scanned = len(payload.get("paths", {}).get("scanned", []))
    # ⚠ NO SUBTRACTION. This read `> pruned_count`, which compared two DISJOINT
    # sets: `_scannable_source_files` counts from the inventory, and
    # `enumerate_tree` already skips EXCLUDED_DIRS, so it can never count a
    # file that pruning removes. Every git clone prunes `.git`, so
    # `pruned_count >= 1` always — and for a small server (one covered source
    # file, one pruned path) `1 > 1` is False and the control silently did not
    # fire. Seven of the forty published servers were in exactly that state.
    # The genuinely-all-vendored case does not need the subtraction: it is
    # caught upstream in `assess_code_safety`, which returns UNAVAILABLE before
    # semgrep is invoked at all.
    if inventory is not None and scanned == 0 and _scannable_source_files(inventory):
        # The positive control, wired in rather than left to a test: the
        # inventory says there was source in a language we cover, and semgrep
        # looked at nothing. That is a scanner defect, and reporting it as a
        # clean scan would publish a 100 for a server nobody audited.
        return SemgrepResult(
            status=SemgrepStatus.FAILED,
            reason=(
                f"semgrep scanned 0 files but the inventory holds "
                f"{_scannable_source_files(inventory)} source file(s) in a "
                "covered language"
            ),
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )

    # semgrep reports per-target parse failures, per-rule timeouts and OOM kills
    # in `errors[]` while still exiting 0 with valid JSON and `results: []`. Read
    # as "no findings" that publishes 100 for a repo whose covered source the
    # parser never got through — the fixtures in this repo's own tests carried
    # `"errors": []` in every payload, so the field was seen and then dropped.
    scan_errors = payload.get("errors") or []
    # ⚠ PARTIAL COVERAGE, NOT A VOID — and the first cut got this wrong in the
    # other direction. It failed the whole scan on ANY error, so 47 of 48 files
    # parsing meant no Code Safety score at all; three of thirty-two published
    # servers lost a weight-30 axis to a single unparseable file.
    #
    # The repo already owns the vocabulary for "found it, cannot place it":
    # `_deps_axis` renders `assessed_weight` for exactly this shape. semgrep's
    # errors carry a per-error `path`, so parsed-vs-unparsed is countable
    # rather than binary. A void is still right when NOTHING parsed.
    unparsed = {
        e["path"] for e in _error_paths(scan_errors)
        if isinstance(e, dict) and e.get("path")
    }
    # ⚠ AN ERROR THAT NAMES NO FILE MUST STILL COUNT. `unparsed` is built only
    # from path-bearing error dicts, so a Timeout or a rule-config error — which
    # carry no `path` — vanished from the denominator AND from `files_unparsed`,
    # publishing an errored scan as fully measured, perfect score, nothing to
    # say. The repo's own negative-control fixture uses `{"type": "Timeout"}`
    # and only still failed because it sets `scanned: []`.
    unattributed = [
        e for e in scan_errors
        if isinstance(e, dict) and not _error_paths([e])
    ]
    if scan_errors and (scanned == 0 or unattributed):
        kinds = sorted({_error_kind(e) for e in scan_errors})
        return SemgrepResult(
            status=SemgrepStatus.FAILED,
            reason=redact_paths(
                f"semgrep reported {len(scan_errors)} error(s) "
                f"({', '.join(kinds)}) that cannot be attributed to specific "
                "files, so the share of the tree actually read is unknown"
                if unattributed and scanned else
                f"semgrep reported {len(scan_errors)} error(s) "
                f"({', '.join(kinds)}) and parsed nothing"
            ),
            files_scanned=scanned,
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )

    ceiling = Confidence(confidence_ceiling(version))
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    findings: list[CodeFinding] = []
    for result in payload.get("results", []):
        rule_id = result.get("check_id", "").rsplit(".", 1)[-1]
        entry = mapping.get(rule_id)
        if entry is None:
            raise RulesetError(
                f"semgrep reported rule {rule_id!r}, absent from "
                f"{_META_DIR}/severity-mapping.yaml — it has no defined deduction"
            )
        declared = Confidence(entry["confidence"])
        effective = declared if order.index(declared) <= order.index(ceiling) else ceiling
        extra = result.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        # FAIL CLOSED, but resolve first — semgrep reports a path relative to
        # the target when the target is relative, and absolute when it is not.
        # The old `else path` branch passed an absolute path straight through,
        # and `root / "/etc/passwd"` is `/etc/passwd`, so the excerpt reader
        # would have published five lines of it while `Evidence.path` carried a
        # local filesystem path onto the page.
        #
        # ⚠ The first cut of this guard tested `is_relative_to` on the RAW
        # value, which is False for every relative path — it would have dropped
        # every finding from any run where semgrep reported relative paths, and
        # an empty finding set is a clean 100. Caught by four existing tests
        # whose fixtures use relative paths, which is the shape a real run can
        # produce.
        raw = Path(result.get("path", ""))
        candidate = raw if raw.is_absolute() else root / raw
        try:
            rel = str(candidate.resolve().relative_to(root.resolve()))
        except ValueError:
            continue
        line = int(result.get("start", {}).get("line", 0))
        findings.append(
            CodeFinding(
                rule_id=rule_id,
                severity=Severity(entry["severity"]),
                confidence=effective,
                message=" ".join((extra.get("message") or "").split()),
                path=rel,
                line=line,
                excerpt=_excerpt(root, rel, line),
                mcp_pattern=str(meta.get("mcp_pattern", "")),
                cwe=str(meta.get("cwe", "")),
                declared_confidence=declared if effective is not declared else None,
            )
        )

    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    # ⚠ THE DENOMINATOR IS `scanned`, NOT `scanned + unparsed`. Measured
    # against real semgrep 1.177.0: a file that fails to parse is listed in
    # `paths.scanned` AND named in `errors[]`, so adding them counted it twice
    # and OVER-claimed coverage — 3/(3+1)=0.75 published where the truth was
    # 2/3=0.67. The previous test asserted 0.75 on a hand-built payload whose
    # bad file was deliberately absent from `paths.scanned`, codifying the
    # assumption instead of testing it. Positive-controlled: one `.ts` file
    # with a syntax error appears in both lists.
    total = scanned
    parsed = max(0, scanned - len(unparsed))
    if unparsed and total and (dec(parsed) / dec(total)) < Decimal("0.005"):
        # Rounds to "0.00": a score measured on none of the axis. `_deps_axis`
        # already refuses this shape — "a score carries positive coverage" — and
        # Code Safety had no equivalent, so 1 file read of 201 published 100.
        return SemgrepResult(
            status=SemgrepStatus.FAILED,
            reason=(
                f"semgrep parsed {parsed} of {total} file(s); the share read is "
                "too small to support a score"
            ),
            files_scanned=scanned,
            files_unparsed=len(unparsed),
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )
    if not unparsed:
        weight = "1"
    else:
        # ⚠ ROUND DOWN, AND NEVER REACH 1. 1276 of 1277 files parsed quantizes
        # to "1.00" under half-up, which publishes an incomplete scan as fully
        # measured — and the site tests `Number(w) < 1`, so "1.00" is read as
        # complete and the server drops out of the partly-measured tally. Every
        # other rounding decision in this codebase rounds the PUBLISHED value
        # half-up; this one is a coverage CLAIM, where the honest direction is
        # down. Capped just under 1 so "some files were not read" can never
        # render as "all files were read".
        # ROUND_DOWN is the protection. `total > scanned` whenever this
        # branch runs, so the ratio is strictly < 1 and a cap could never bind
        # — the earlier `min(ratio, 0.99)` was a guard whose condition cannot
        # be true, which is this repo's own named failure shape. Removed rather
        # than kept as decoration that misattributes what is load-bearing.
        weight = format(
            (dec(parsed) / dec(total)).quantize(
                Decimal("0.01"), rounding=ROUND_DOWN
            ),
            "f",
        )
    return SemgrepResult(
        status=SemgrepStatus.OK,
        findings=tuple(findings),
        score=axis_score(f.to_scoring() for f in findings),
        files_scanned=scanned,
        ruleset_version=ruleset_version(rules),
        methodology_version=version,
        neutralised=neutralised,
        pruned=pruned_count,
        pruned_sample=pruned_sample,
        files_unparsed=len(unparsed),
        assessed_weight=weight,
    )


def assess_code_safety(
    root: Path,
    inventory: Inventory | None = None,
    *,
    rules: Path | None = None,
    version: str = CURRENT_METHODOLOGY_VERSION,
) -> SemgrepResult:
    """Code Safety for one server — the entry point a scan runner calls.

    A server with no source in a covered language is `UNAVAILABLE` with a
    reason, not a 100: `03` §3 scores what was examined, and nothing was.
    """
    if inventory is not None and not _scannable_source_files(inventory):
        return SemgrepResult(
            status=SemgrepStatus.UNAVAILABLE,
            reason="no source files in a language the ruleset covers "
                   "(python, javascript, typescript, go)",
            methodology_version=version,
        )
    return run_semgrep(root, rules=rules, inventory=inventory, version=version)


__all__ = [
    "AXIS",
    "AXIS_MAX",
    "CodeFinding",
    "RulesetError",
    "SemgrepResult",
    "SemgrepStatus",
    "assess_code_safety",
    "declared_rule_ids",
    "load_severity_mapping",
    "rules_root",
    "ruleset_version",
    "run_semgrep",
]
