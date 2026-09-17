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
from enum import StrEnum
from pathlib import Path

import yaml

from mcpwatchman.workers.excluded import EXCLUDED_DIRS
from mcpwatchman.workers.scanner.inventory import Inventory, Language, Role
from mcpwatchman.workers.scoring.composite import (
    AXIS_MAX,
    Confidence,
    Finding,
    Severity,
    axis_score,
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

# Scanner configuration a scanned repository may not supply. See the module
# docstring: these are the files that let a repo decide what we look at.
HOSTILE_CONFIG_FILES = (".semgrepignore",)

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
    stem = path.stem.lower()
    if ".min" in stem or ".bundle" in stem or ".chunk" in stem:
        return True
    # `highlight-abc7f01d.js`, `book-a0b12cfe.js` — bundler content hashes.
    tail = stem.rsplit("-", 1)[-1] if "-" in stem else ""
    if len(tail) >= 8 and all(c in "0123456789abcdef" for c in tail):
        return True
    if path.suffix.lower() not in _MINIFIABLE_SUFFIXES:
        return False
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
    for directory in sorted(EXCLUDED_DIRS):
        for found in root.rglob(directory):
            if found.is_dir():
                pruned.append(f"{found.relative_to(root)}/")
                shutil.rmtree(found, ignore_errors=True)
    for path in sorted(root.rglob("*")):
        if path.is_file() and _is_minified(path):
            pruned.append(str(path.relative_to(root)))
            path.unlink(missing_ok=True)
    return len(pruned), tuple(pruned[:20])


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


def _excerpt(root: Path, rel_path: str, line: int) -> str:
    """Read ~5 lines of context around a match from OUR copy of the file."""
    try:
        text = (root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
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

    cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
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
            reason=f"semgrep produced no JSON (exit {proc.returncode}): "
                   f"{proc.stderr.strip()[:200]}",
            neutralised=neutralised,
            pruned=pruned_count,
            pruned_sample=pruned_sample,
        )

    scanned = len(payload.get("paths", {}).get("scanned", []))
    if (inventory is not None and scanned == 0
            and _scannable_source_files(inventory) > pruned_count):
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
        path = result.get("path", "")
        rel = str(Path(path).relative_to(root)) if Path(path).is_relative_to(root) else path
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
