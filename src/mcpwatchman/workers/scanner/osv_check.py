"""osv-scanner execution and Dependency Health scoring (`04` §5, `03` §6).

Dependency Health is the second deduction-scored axis (weight 20) and it does
**not** share Code Safety's table. `03` §6 keys its deductions on
(severity, direct-vs-transitive) where `03` §3 keys on (severity, confidence),
and the values differ in every row. Both axes are "findings with stacking", so
calling `composite.axis_score` here would compile, run, and return a confidently
wrong number — which is why this module owns `dependency_axis_score` and why
`composite.axis_score`'s docstring names this module as the other table's owner.
What IS shared is the stacking ladder, and that has one home:
`composite.stacked_deduction`.

**Four things measured against osv-scanner 2.6.0 (2026-09-17) before writing
this, three of which contradict `04` §5.**

**The specified invocation produces no JSON.** `osv-scanner --format json
--recursive <dir>` is the v1 CLI; on v2 it prints a filesystem-walk log to
stdout — beginning, alarmingly, `Starting filesystem walk for root: /` — and
emits no JSON at all. The v2 form is `osv-scanner scan source --format json -r`.
Third specified invocation in this repository to have been silently wrong (after
`detect-secrets` and semgrep's `--config rules/`), and the same tell each time:
the failure reads as an absence of findings rather than as an error.

**Exit code 1 is SUCCESS.** osv-scanner exits 1 when it finds vulnerabilities
and 0 when it finds none, so `check=True` would turn every vulnerable server
into a scan failure and every clean one into a pass. Errors are 127 (bad path)
and 128 (nothing scannable), both with empty stdout.

**Count GROUPS, not vulnerabilities.** A group is one distinct vulnerability;
its aliases (PYSEC-…, GHSA-…, CVE-…) each appear as a separate entry in
`vulnerabilities`. Measured: jinja2 2.10 reports 12 vulnerabilities and 6
groups. Scoring the vulnerability list double-counts aliases and roughly doubles
the deduction — a false accusation that scales with how well-catalogued a CVE is.

**The CVSS score lives on the group, not the vulnerability.** Each
`vulnerabilities[].severity` came back `null`; `groups[].max_severity` carries
the score `03` §6 bands on.

**A missing CVSS is ABSTAINED, not assumed.** `03` §6 bands on CVSS and says
nothing about a vulnerability that has no score. Scoring it Low invents a band
the methodology does not define; scoring it Critical accuses on no evidence. It
is reported as a finding, excluded from the arithmetic, and counted in
`unscored_findings` so a surface cannot render the score as if it covered
everything.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path

from mcpwatchman.workers.excluded import HOSTILE_CONFIG_FILES
from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_manifest
from mcpwatchman.workers.scanner.reachability import redact_paths
from mcpwatchman.workers.scoring.composite import (
    AXIS_MAX,
    Severity,
    dec,
    round_half_up,
    stacked_deduction,
)
from mcpwatchman.workers.scoring.weights import CURRENT_METHODOLOGY_VERSION

AXIS = "dependency_health"

# `04` §7: "osv-scanner gets 3" of the 15-minute per-scan budget.
OSV_TIMEOUT_S = 180

# osv-scanner exits 1 when it FINDS something. Only these two mean "it ran".
_OK_RETURNCODES = (0, 1)

# `03` §6. Keyed on (severity, direct?) — NOT on confidence. Direct dependencies
# are penalised harder because the maintainer can simply update them, and
# because transitive vulnerabilities more often sit in code paths a given
# consumer never reaches.
DEDUCTIONS: dict[Severity, dict[str, int]] = {
    Severity.CRITICAL: {"direct": 25, "transitive": 15},
    Severity.HIGH: {"direct": 15, "transitive": 8},
    Severity.MEDIUM: {"direct": 6, "transitive": 3},
    Severity.LOW: {"direct": 2, "transitive": 1},
}

# `03` §6's CVSS bands, ascending by floor.
_CVSS_BANDS: tuple[tuple[Decimal, Severity], ...] = (
    (Decimal("9.0"), Severity.CRITICAL),
    (Decimal("7.0"), Severity.HIGH),
    (Decimal("4.0"), Severity.MEDIUM),
    (Decimal("0"), Severity.LOW),
)


class OsvStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class DependencyFinding:
    """One vulnerable dependency (`03` §6's evidence list)."""

    package: str
    ecosystem: str
    version: str
    osv_id: str
    severity: Severity | None
    cvss: Decimal | None
    # None = the ecosystem's manifest is one we cannot parse, so directness
    # is UNKNOWN. Not a synonym for transitive — see `parsed_ecosystems`.
    direct: bool | None
    lockfile: str
    fixed_version: str = ""
    cve_id: str = ""
    aliases: tuple[str, ...] = ()

    @property
    def scored(self) -> bool:
        """False when the finding cannot be placed in `03` §6's table.

        Two independent ways that happens: no CVSS was published, so no
        severity band applies; or the ecosystem's manifest is one we cannot
        parse, so we do not know whether the dependency is direct. Either
        leaves a cell of the table undetermined, and `03` §6 gives no value
        for an undetermined cell.
        """
        return self.severity is not None and self.direct is not None

    def deduction(self) -> int:
        if self.severity is None:
            raise ValueError(
                f"{self.osv_id} has no CVSS score and therefore no band in "
                "`03` §6; it must be excluded from scoring, not deducted"
            )
        if self.direct is None:
            raise ValueError(
                f"{self.osv_id} is in an ecosystem whose manifest we cannot "
                "parse, so direct-vs-transitive is unknown and `03` §6 has no "
                "row for it; exclude it rather than assuming transitive"
            )
        return DEDUCTIONS[self.severity]["direct" if self.direct else "transitive"]


@dataclass(frozen=True, slots=True)
class OsvResult:
    status: OsvStatus
    findings: tuple[DependencyFinding, ...] = ()
    score: int | None = None
    # `04` §5: without a lockfile we see declared direct dependencies at best
    # and no transitive closure at all. The per-server page must say so.
    transitive_coverage: bool = False
    lockfiles: tuple[str, ...] = ()
    unscored_findings: int = 0
    neutralised: tuple[str, ...] = ()
    methodology_version: str = CURRENT_METHODOLOGY_VERSION
    reason: str = ""

    @property
    def assessed(self) -> bool:
        return self.status is OsvStatus.OK


def severity_from_cvss(score: Decimal | float | str | None) -> Severity | None:
    """Band a CVSS base score per `03` §6, or `None` when there is no score.

    Returning `None` rather than a default is the whole point: `03` §6 defines
    bands for scores, and an unscored vulnerability has no band. See the module
    docstring.
    """
    if score is None or score == "":
        return None
    try:
        value = dec(score) if not isinstance(score, str) else Decimal(score)
    except (InvalidOperation, ArithmeticError, ValueError):
        return None
    if value < 0 or value > 10:
        return None
    for floor, severity in _CVSS_BANDS:
        if value >= floor:
            return severity
    return None


def dependency_axis_score(findings: list[DependencyFinding] | tuple[DependencyFinding, ...]) -> int:
    """Score `03` §6's axis: starts at 100, floors at 0.

    ⚠ **Not `composite.axis_score`, and not interchangeable with it.** Different
    table, different second dimension. The stacking ladder they genuinely share
    comes from `composite.stacked_deduction`.

    Grouping is by SEVERITY, matching `03` §3's rule that the confidence (here,
    direct-vs-transitive) tiers within a severity row are the same finding class
    seen with more or less force — so a critical/direct and a critical/transitive
    share one group and the second is discounted.
    """
    by_severity: dict[Severity, list[int]] = {}
    for f in findings:
        # Narrowed on the FIELDS rather than on `f.scored`, which says the same
        # thing but through a property a type checker cannot see through. The
        # guard is load-bearing — `deduction()` raises on either undetermined
        # cell — so it should be checkable rather than merely correct today.
        #
        # `direct is None` means the ecosystem's manifest is one we cannot
        # parse. Excluded, never defaulted: `transitive` is the LOWER deduction,
        # so defaulting would score the ecosystems we support least the kindest.
        if f.severity is None or f.direct is None:
            continue
        by_severity.setdefault(f.severity, []).append(f.deduction())
    total = stacked_deduction(by_severity.values())
    # Round the SCORE, never the deduction — `03` §6 inherits §3's rule, and
    # rounding a deduction turns half-up into half-down on the published value.
    return max(0, round_half_up(AXIS_MAX - total))


def _requirements_names(text: str) -> set[str]:
    names = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "[", ";", " @ "):
            line = line.split(sep, 1)[0]
        if line.strip():
            names.add(line.strip().lower())
    return names


# Which OSV ecosystem each manifest lets us recover a DIRECT set for. The
# mapping is the point: directness is a fact about an ecosystem, not about a
# repository, and the first version of this guard tested repository filenames.
#
# ⚠ That version could not fire for Poetry — the ecosystem its own published
# reason named to the reader. `poetry.lock` only matters when `pyproject.toml`
# is absent, and Poetry cannot produce a lock without one, so the condition was
# unreachable by construction; meanwhile the parser read only PEP 621
# `[project].dependencies` and never `[tool.poetry.dependencies]`, so every
# Poetry project's findings were labelled transitive at the LOWER `03` §6 rate.
# It was also defeated by any `package.json` anywhere in the tree — a `www/`
# demo was enough to make a Rust repo "supported".
_MANIFEST_ECOSYSTEM: dict[str, str] = {
    "package.json": "npm",
    "pyproject.toml": "PyPI",
    "requirements.txt": "PyPI",
    "go.mod": "Go",
}


def parsed_ecosystems(inventory: Inventory) -> set[str]:
    """OSV ecosystems whose direct-dependency set this module can recover."""
    names = {Path(f.path).name for f in inventory.files}
    return {eco for name, eco in _MANIFEST_ECOSYSTEM.items() if name in names}


def direct_dependencies(root: Path, inventory: Inventory) -> set[str]:
    """Dependency names the project DECLARES, lowercased.

    `03` §6 needs direct-vs-transitive and osv-scanner reports a flat package
    list, so the distinction is recovered by reading the manifests: a package
    the project names is direct, anything else came in underneath one.

    Deliberately name-only and ecosystem-blind. A name collision across
    ecosystems (`requests` on PyPI and npm) would misclassify a transitive as
    direct — which errs toward the HARSHER deduction, so it is stated here
    rather than left implicit. It needs a server declaring two ecosystems with
    a shared package name to bite.
    """
    names: set[str] = set()
    for record in inventory.files:
        if record.role not in (Role.PACKAGE_MANIFEST, Role.LOCKFILE):
            continue
        name = Path(record.path).name
        # Through the inventory's bounded, confined reader. These are
        # attacker-controlled manifests, and a fetched tree may legally approach
        # the source cap — reading one whole and then parsing an expanded copy
        # of it is two allocations of a size the publisher chooses. Same rule
        # `_excerpt` was moved onto: a bound added to one hostile-input reader
        # is owed to the others.
        # `read_manifest` returns "" on refusal rather than raising, so an
        # over-cap or unreadable manifest arrives as "no dependencies" — the
        # kinder-score direction, silently. Skip it explicitly instead.
        text = read_manifest(root, record.path)
        if not text:
            continue
        if name == "package.json":
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                continue
            for table in ("dependencies", "devDependencies",
                          "optionalDependencies", "peerDependencies"):
                names.update(k.lower() for k in (doc.get(table) or {}))
        elif name == "pyproject.toml":
            try:
                doc = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            project = doc.get("project") or {}
            for spec in project.get("dependencies") or []:
                names.update(_requirements_names(spec))
            for group in (project.get("optional-dependencies") or {}).values():
                for spec in group:
                    names.update(_requirements_names(spec))
            # Poetry keeps its dependencies somewhere else entirely, and a
            # Poetry project has no `[project].dependencies` at all — so
            # reading only PEP 621 returned an empty direct set for every one
            # of them and scored their vulnerabilities at the transitive rate.
            poetry = ((doc.get("tool") or {}).get("poetry") or {})
            for table in ("dependencies", "dev-dependencies"):
                names.update(
                    k.lower() for k in (poetry.get(table) or {}) if k.lower() != "python"
                )
            for group in (poetry.get("group") or {}).values():
                names.update(
                    k.lower() for k in (group.get("dependencies") or {})
                    if k.lower() != "python"
                )
        elif name == "requirements.txt":
            names.update(_requirements_names(text))
        elif name == "go.mod":
            # go.mod marks transitives explicitly, which is the one ecosystem
            # that hands us the answer instead of making us infer it.
            for raw in text.splitlines():
                line = raw.strip()
                if line.startswith(("module", "go ", "require (", ")", "//")) or not line:
                    continue
                if "// indirect" in line:
                    continue
                token = line.removeprefix("require ").split()
                if token:
                    names.add(token[0].lower())
    return names


def run_osv(
    root: Path,
    inventory: Inventory | None = None,
    *,
    version: str = CURRENT_METHODOLOGY_VERSION,
    timeout_s: int = OSV_TIMEOUT_S,
) -> OsvResult:
    """Scan one fetched tree for vulnerable dependencies."""
    binary = shutil.which("osv-scanner")
    if binary is None:
        return OsvResult(
            status=OsvStatus.UNAVAILABLE,
            reason="osv-scanner is not on PATH; it is a Go binary installed in "
                   "the worker image, not a Python dependency",
            methodology_version=version,
        )

    lockfiles = tuple(
        sorted(f.path for f in inventory.files if f.role is Role.LOCKFILE)
    ) if inventory is not None else ()
    if inventory is not None and not lockfiles:
        # `04` §5's lockfile-generation fallback is NOT implemented: it would
        # mean running npm/pip against an untrusted manifest, which `04` §7
        # forbids outright ("no code execution from scanned source"). Measured:
        # a bare package.json with no lockfile makes osv-scanner 2.6.0 exit 128
        # with empty stdout, so there is nothing to parse either.
        return OsvResult(
            status=OsvStatus.UNAVAILABLE,
            reason="no lockfile in the fetched source; dependency versions are "
                   "unresolved, so no vulnerability can be attributed",
            lockfiles=(),
            transitive_coverage=False,
            methodology_version=version,
        )

    # A scanned repository can suppress its own vulnerabilities: osv-scanner
    # discovers an `osv-scanner.toml` in the tree it is scanning and honours
    # its `[[IgnoredVulns]]`. Measured — 6 groups became 5 with one entry. The
    # same shape as semgrep's `.semgrepignore`, which is why the list is shared
    # rather than restated. `root` is a scratch copy we own.
    neutralised = _neutralise_hostile_config(root)

    cmd = [binary, "scan", "source", "--format", "json", "-r", str(root)]
    try:
        proc = subprocess.run(  # noqa: S603 - argv form, no shell, fixed binary
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired:
        return OsvResult(
            status=OsvStatus.FAILED,
            reason=f"osv-scanner exceeded {timeout_s}s",
            lockfiles=lockfiles,
            methodology_version=version,
        )

    if proc.returncode not in _OK_RETURNCODES:
        return OsvResult(
            status=OsvStatus.FAILED,
            # Redacted at CONSTRUCTION: osv-scanner's own 127 message is
            # literally `open /tmp/mcpw-scan-…: no such file or directory`,
            # which is the exact string that produced v0.16.1.
            reason=redact_paths(
                f"osv-scanner exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:200]}"
            ),
            lockfiles=lockfiles,
            methodology_version=version,
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # NOT an empty finding set. osv-scanner emits nothing on stdout when it
        # has nothing to scan, and reading that as "no vulnerabilities" awards
        # a clean 100 to a server nobody examined.
        return OsvResult(
            status=OsvStatus.FAILED,
            reason=f"osv-scanner produced no JSON (exit {proc.returncode})",
            lockfiles=lockfiles,
            methodology_version=version,
        )

    direct = direct_dependencies(root, inventory) if inventory is not None else set()
    known = parsed_ecosystems(inventory) if inventory is not None else set()
    findings: list[DependencyFinding] = []
    for result in payload.get("results", []):
        source = result.get("source", {}) or {}
        path = source.get("path", "")
        rel = str(Path(path).relative_to(root)) if Path(path).is_relative_to(root) else path
        for package in result.get("packages", []):
            info = package.get("package", {}) or {}
            name = info.get("name", "")
            by_id = {v.get("id"): v for v in package.get("vulnerabilities", [])}
            # One GROUP is one distinct vulnerability; its aliases each appear
            # separately in `vulnerabilities`. See the module docstring.
            for group in package.get("groups", []):
                ids = group.get("ids") or []
                aliases = tuple(group.get("aliases") or ())
                osv_id = ids[0] if ids else (aliases[0] if aliases else "")
                cvss = severity_from_cvss(group.get("max_severity"))
                vuln = by_id.get(osv_id, {})
                findings.append(
                    DependencyFinding(
                        package=name,
                        ecosystem=info.get("ecosystem", ""),
                        version=info.get("version", ""),
                        osv_id=osv_id,
                        severity=cvss,
                        cvss=_as_decimal(group.get("max_severity")),
                        # None = UNKNOWN. Defaulting an unparsed ecosystem
                        # to `transitive` is not neutral — it is the lower
                        # deduction, so the ecosystems we support least
                        # scored kindest.
                        direct=(name.lower() in direct)
                        if info.get("ecosystem") in known else None,
                        lockfile=rel,
                        fixed_version=_fixed_version(vuln),
                        cve_id=next((a for a in aliases if a.startswith("CVE-")), ""),
                        aliases=aliases,
                    )
                )

    findings.sort(key=lambda f: (f.package, f.osv_id))
    # Counts BOTH undetermined cells: no CVSS, and unknown directness.
    unscored = sum(1 for f in findings if not f.scored)
    return OsvResult(
        status=OsvStatus.OK,
        findings=tuple(findings),
        score=dependency_axis_score(findings),
        transitive_coverage=bool(lockfiles),
        lockfiles=lockfiles,
        unscored_findings=unscored,
        neutralised=neutralised,
        methodology_version=version,
    )


def _neutralise_hostile_config(root: Path) -> tuple[str, ...]:
    """Remove scanner configuration the scanned repository supplied.

    Mirrors `semgrep_check._neutralise_hostile_config` deliberately: both read
    the one shared `HOSTILE_CONFIG_FILES` list, so a new scanner-config file
    added there defends both scanners at once.
    """
    removed: list[str] = []
    for name in HOSTILE_CONFIG_FILES:
        for path in root.rglob(name):
            # A symlink counts: following it is not required to remove it,
            # and leaving it would leave the config discoverable.
            if not (path.is_symlink() or path.is_file()):
                continue
            path.unlink(missing_ok=True)
            removed.append(str(path.relative_to(root)))
    return tuple(sorted(removed))


def _as_decimal(value: object) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ArithmeticError, ValueError):
        return None


def _fixed_version(vuln: dict) -> str:
    """First `fixed` event in the vulnerability's affected ranges, if any."""
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def assess_dependency_health(
    root: Path,
    inventory: Inventory | None = None,
    *,
    version: str = CURRENT_METHODOLOGY_VERSION,
) -> OsvResult:
    """Dependency Health for one server — the entry point a scan runner calls."""
    return run_osv(root, inventory, version=version)


__all__ = [
    "AXIS",
    "DEDUCTIONS",
    "DependencyFinding",
    "OsvResult",
    "OsvStatus",
    "assess_dependency_health",
    "dependency_axis_score",
    "direct_dependencies",
    "run_osv",
    "severity_from_cvss",
]
