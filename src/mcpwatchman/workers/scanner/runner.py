"""One server, all five axes, one serialisable report (`02` §208, `04` §2).

The orchestrator every surface reads from: resolve a registry entry's declared
source, fetch it, inventory it, run the five axes, and hand back a structure
that renders without needing any of them again.

**Two invariants, and both exist to stop a surface publishing more than we
measured.**

**The composite is absent from the report, not merely unrendered.** `03` §9
gates it on calibration and `weights.composite_published()` is False, so the
report carries no composite field at all. A surface cannot omit what it was
never handed, and a template that wanted one would have to fail rather than
quietly print an uncalibrated number.

**Every axis is `AxisScore`, and `score=None` is a first-class answer.** A
server whose repository 404s, one written in Rust, one with no lockfile — each
produces a real reason and no number. `None` and `0` are opposite claims about a
server and collapsing them is the failure this whole codebase is shaped against.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from mcpwatchman import __version__
from mcpwatchman.workers.crawler.registry import RegistryEntry, resolve_source
from mcpwatchman.workers.scanner.auth_check import assess_auth, scan_secrets
from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.maintenance_check import assess_maintenance
from mcpwatchman.workers.scanner.osv_check import assess_dependency_health
from mcpwatchman.workers.scanner.reachability import (
    SourceAvailability,
    SourceState,
    from_exception,
)
from mcpwatchman.workers.scanner.semgrep_check import assess_code_safety
from mcpwatchman.workers.scanner.source import SourceSpec, fetch
from mcpwatchman.workers.scanner.transparency_check import assess_transparency
from mcpwatchman.workers.scanner.transport_check import assess_transport
from mcpwatchman.workers.scoring.axes import AxisResult
from mcpwatchman.workers.scoring.weights import (
    CURRENT_METHODOLOGY_VERSION,
    composite_published,
)

AXES = (
    "code_safety",
    "auth_posture",
    "maintenance",
    "dependency_health",
    "transparency",
)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One artefact backing a score (`03` §10: no point without a trail)."""

    label: str
    detail: str = ""
    path: str = ""
    line: int = 0
    excerpt: str = ""
    url: str = ""


@dataclass(frozen=True, slots=True)
class AxisScore:
    """One axis's published result.

    `score is None` means NOT ASSESSED and `reason` then says why. It never
    means zero. `assessed_weight` is the share of the axis actually measured,
    as a string so the exact fraction survives JSON — a surface printing
    `score` without it is publishing a number it cannot support.
    """

    axis: str
    score: int | None
    reason: str = ""
    assessed_weight: str = "1"
    evidence: tuple[Evidence, ...] = ()

    @property
    def assessed(self) -> bool:
        return self.score is not None

    @property
    def partial(self) -> bool:
        return self.assessed and self.assessed_weight not in ("1", "1.00")


@dataclass(frozen=True, slots=True)
class ServerReport:
    """Everything a per-server page needs, and nothing it may not publish."""

    name: str
    version: str
    slug: str
    scanned_at: str
    methodology_version: str = CURRENT_METHODOLOGY_VERSION
    scanner_version: str = __version__
    ruleset_version: str = ""
    repository_url: str = ""
    source_state: str = SourceState.NOT_ATTEMPTED.value
    source_reason: str = ""
    transport: str = ""
    transport_mismatch: bool = False
    files_scanned: int = 0
    files_pruned: int = 0
    axes: dict[str, AxisScore] = field(default_factory=dict)

    @property
    def assessed_axes(self) -> int:
        return sum(1 for a in self.axes.values() if a.assessed)

    @property
    def is_non_assessment(self) -> bool:
        """No axis could be scored — the explicit non-assessment (`STATE`, ruling
        2026-09-15): such a server gets a page stating what was not evaluated and
        why, rather than a score or an absence."""
        return self.assessed_axes == 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready. Deliberately carries no composite — see the module docstring."""
        # A tripwire, not a runtime condition: no input can reach it. It fires
        # the day calibration flips the gate, which is exactly when this report
        # shape needs revisiting — a raise rather than an `assert`, because
        # `python -O` strips asserts and would remove the tripwire silently.
        if composite_published(self.methodology_version):
            raise RuntimeError(
                f"composite_published({self.methodology_version}) is now True, but "
                "ServerReport carries no composite field. Decide deliberately how "
                "the composite reaches a surface before shipping this."
            )
        payload = asdict(self)
        payload["axes"] = {k: asdict(v) for k, v in self.axes.items()}
        return payload


def slugify(name: str) -> str:
    """A URL-safe slug for a registry name like `io.github.owner/server`."""
    out = []
    for ch in name.lower():
        out.append(ch if ch.isalnum() else "-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def _from_axis_result(result: AxisResult, reason_when_unassessed: str = "") -> AxisScore:
    """Project a sub-check-scored axis (`03` §4, §5, §7) onto the report shape."""
    evidence = tuple(
        Evidence(
            label=sub.name,
            detail=(
                sub.reason if sub.score is None
                else f"scored {sub.score}"
            ),
            path=sub.evidence[0] if sub.evidence else "",
        )
        for sub in result.subchecks
    )
    reason = ""
    if result.score is None:
        unassessed = [s.reason for s in result.unassessed if s.reason]
        reason = reason_when_unassessed or (unassessed[0] if unassessed else "")
    return AxisScore(
        axis=result.axis,
        score=result.score,
        reason=reason,
        assessed_weight=_fmt(result.assessed_weight),
        evidence=evidence,
    )


def _fmt(value: Decimal) -> str:
    return format(value.normalize(), "f")


def scan_entry(
    entry: RegistryEntry,
    workspace: Path | None = None,
    *,
    version: str = CURRENT_METHODOLOGY_VERSION,
) -> ServerReport:
    """Scan one registry entry end to end and return its publishable report.

    Never raises for a server's own defects. A repository that cannot be read is
    an OUTCOME — `reachability` decides whose fault it was — and the report says
    so on every axis that needed the source, which is all five.
    """
    scanned_at = datetime.now(UTC).isoformat(timespec="seconds")
    resolution = resolve_source(entry)
    repo_url = entry.repository.url if entry.repository else ""

    owned = workspace is None
    ws = Path(tempfile.mkdtemp(prefix="mcpw-scan-")) if owned else workspace

    availability = SourceAvailability(SourceState.NOT_ATTEMPTED, repo_url)
    root: Path | None = None
    try:
        if not (resolution.scannable and resolution.primary):
            availability = SourceAvailability(
                SourceState.NOT_DECLARED, repo_url,
                detail=resolution.skip_reason or "",
            )
        else:
            try:
                fetched = fetch(SourceSpec.parse(resolution.primary), ws)
                root = fetched.scan_root
                availability = SourceAvailability(SourceState.FETCHED, repo_url)
            except Exception as exc:  # noqa: BLE001 - classified, never swallowed
                availability = from_exception(exc, repo_url)

        return _assemble(entry, resolution, availability, root, scanned_at, version)
    finally:
        if owned:
            shutil.rmtree(ws, ignore_errors=True)


def _assemble(
    entry, resolution, availability, root, scanned_at, version
) -> ServerReport:
    inventory = enumerate_tree(root) if root is not None else None

    transport = assess_transport(entry, root, inventory)
    secrets = scan_secrets(root) if root is not None else None
    auth = assess_auth(entry, transport, root, inventory, secrets)
    transparency = assess_transparency(root, inventory, availability)
    # `03` §5's forge signals need an API fetch that is not built; the axis
    # reports that rather than guessing a maintenance score from the tree.
    maintenance = assess_maintenance()

    code = assess_code_safety(root, inventory, version=version) if root else None
    deps = assess_dependency_health(root, inventory, version=version) if root else None

    axes: dict[str, AxisScore] = {
        "auth_posture": _from_axis_result(auth, availability.reason),
        "maintenance": _from_axis_result(maintenance),
        "transparency": _from_axis_result(transparency, availability.reason),
        "code_safety": _code_axis(code, availability),
        "dependency_health": _deps_axis(deps, availability),
    }

    return ServerReport(
        name=entry.name,
        version=entry.version,
        slug=slugify(entry.name),
        scanned_at=scanned_at,
        methodology_version=version,
        ruleset_version=(code.ruleset_version if code else ""),
        repository_url=entry.repository.url if entry.repository else "",
        source_state=availability.state.value,
        source_reason=availability.reason,
        transport=transport.declared.value if transport.declared else "",
        transport_mismatch=bool(transport.mismatch),
        files_scanned=(code.files_scanned if code else 0),
        files_pruned=(code.pruned if code else 0),
        axes={k: axes[k] for k in AXES},
    )


def _code_axis(result, availability) -> AxisScore:
    if result is None:
        return AxisScore("code_safety", None, availability.reason, "0")
    if not result.assessed:
        return AxisScore("code_safety", None, result.reason, "0")
    evidence = tuple(
        Evidence(
            label=f"{f.rule_id} ({f.severity}/{f.confidence})",
            detail=f.message,
            path=f.path,
            line=f.line,
            excerpt=f.excerpt,
        )
        for f in result.findings
    )
    reason = ""
    if result.pruned:
        # Rendered, never silent. A reader comparing two servers deserves to
        # know that one shipped 245 files and was scored on a dozen of them.
        reason = (
            f"{result.pruned} vendored or minified path"
            f"{'' if result.pruned == 1 else 's'} were excluded before scanning; "
            "machine-generated bundles are not the server's own code"
        )
    return AxisScore("code_safety", result.score, reason, "1", evidence)


def _deps_axis(result, availability) -> AxisScore:
    if result is None:
        return AxisScore("dependency_health", None, availability.reason, "0")
    if not result.assessed:
        return AxisScore("dependency_health", None, result.reason, "0")
    evidence = tuple(
        Evidence(
            label=f"{f.package} {f.version} — {f.osv_id}",
            detail=(
                f"{'direct' if f.direct else 'transitive'}"
                + (f", CVSS {f.cvss}" if f.cvss is not None else ", no CVSS published")
                + (f", fixed in {f.fixed_version}" if f.fixed_version else "")
            ),
            path=f.lockfile,
            url=f"https://osv.dev/vulnerability/{f.osv_id}" if f.osv_id else "",
        )
        for f in result.findings
    )
    reason = ""
    if result.unscored_findings:
        reason = (
            f"{result.unscored_findings} vulnerabilit"
            f"{'y' if result.unscored_findings == 1 else 'ies'} carried no CVSS "
            "score and are listed but not scored"
        )
    return AxisScore("dependency_health", result.score, reason, "1", evidence)


__all__ = ["AXES", "AxisScore", "Evidence", "ServerReport", "scan_entry", "slugify"]
