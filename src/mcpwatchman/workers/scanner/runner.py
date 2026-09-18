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
from dataclasses import KW_ONLY, asdict, dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_DOWN, Decimal
from pathlib import Path
from typing import Any

from mcpwatchman import __version__
from mcpwatchman.workers.crawler.registry import (
    RegistryEntry,
    SourceKind,
    resolve_source,
)
from mcpwatchman.workers.scanner.auth_check import assess_auth, scan_secrets
from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.maintenance_check import assess_maintenance
from mcpwatchman.workers.scanner.osv_check import assess_dependency_health
from mcpwatchman.workers.scanner.reachability import (
    Fault,
    SourceAvailability,
    SourceState,
    from_exception,
)
from mcpwatchman.workers.scanner.semgrep_check import assess_code_safety
from mcpwatchman.workers.scanner.source import SourceSpec, fetch
from mcpwatchman.workers.scanner.transparency_check import assess_transparency
from mcpwatchman.workers.scanner.transport_check import assess_transport
from mcpwatchman.workers.scoring.axes import AxisResult
from mcpwatchman.workers.scoring.composite import dec
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
    # ⚠ EVERYTHING BELOW IS KEYWORD-ONLY, and it is not a style preference.
    # This class is built positionally throughout — `AxisScore("code_safety",
    # None, reason, "0")` — so inserting `fault` as a fifth field silently
    # reinterpreted the two five-positional calls that passed `evidence`
    # there: the evidence tuple landed in `fault` and the evidence went empty,
    # on the only two axes that carry findings. **824 tests passed**, because
    # `test_findings_carry_the_evidence_they_claim` iterates the evidence list
    # and an empty one iterates vacuously. mypy caught it; nothing else did.
    # The keyword boundary makes the next field insertion unable to do this.
    _: KW_ONLY
    # WHOSE gap this is, when `score is None`. Meaningless when a score
    # exists, and read only for the unassessed case.
    #
    # ⚠ **THE ATTRIBUTION WAS COMPUTED AND DISCARDED FOR AS LONG AS THIS
    # REPORT HAS EXISTED.** `reachability.SourceState.publisher_fault` has
    # drawn the ours-vs-theirs line since the fetch stage was written, and
    # nothing read it; one stage later `SemgrepStatus.UNAVAILABLE` meant both
    # "semgrep is not on PATH" (ours) and "no source in a covered language"
    # (theirs), and this class flattened them into an identical `score=None`
    # plus a sentence. The sentence is the damage: a run with no scanner
    # binaries would have published *"semgrep is not on PATH; it ships in the
    # `workers` extra"* as the reason 500 third-party servers went unscored.
    #
    # `cohort.publication_errors` refuses `environment` and `unattributed`.
    # The default being the refused one is deliberate — a new axis that
    # forgets to attribute costs a failed run, not a public page.
    # ⚠ `None` WHEN A SCORE EXISTS, not the default token. Emitting a word
    # here on a scored axis published `fault: "publisher"` beside a real
    # number — an attribution for a gap that does not exist — while the JSON
    # API's own note told agents only two values appear and only on gaps.
    # That is the `llms.txt` class of defect this repo has paid for once
    # already: a confident claim on a machine surface, addressed to the
    # audience least able to notice it is wrong.
    fault: str | None = None
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
    # WHAT was unreachable — "repository", "package", or "".
    #
    # ⚠ `source_state` alone was not enough, and the gap reached the live
    # site as a false statement about a named third party. An npm 404 sets
    # state=unreachable, and four surfaces re-expressed that as "declares a
    # repository nobody can read" — including for a server whose GitHub
    # repository resolves fine. Its own page said "package" correctly while
    # the roster, the homepage tally and llms.txt said "repository": the
    # site contradicted itself, and `08-disclosure-policy.md` requires
    # factual. One judgement expressed at five sites, fixed at one.
    source_subject: str = ""
    source_reason: str = ""
    transport: str = ""
    transport_mismatch: bool = False
    # False when neither version tag resolved and `fetch_git` fell back to the
    # default branch; **None when nothing was fetched at all.**
    #
    # ⚠ It defaulted to `True`, so 7 of 40 published servers asserted "this IS
    # the released version" about a revision nobody read — an affirmative claim
    # on a path that never established it. The page hides the field when true;
    # the JSON API, a primary surface, serves it verbatim.
    ref_matched_version: bool | None = None
    # What the REGISTRY said about this server when this report was published,
    # which is a different question from whether its source could be read.
    #
    # `"listed"` on every report the scanner produces, because a report is
    # produced from a registry entry. The publisher sets `"delisted"` when a
    # pinned server has left the registry's listing: its page stays — the URL
    # is a promise (`mcpwatchman.cohort`) — carrying the last scan taken while
    # it was listed, and `registry_note` says so with both dates. Silence there
    # would leave an old scan reading as a current one.
    registry_state: str = "listed"
    registry_note: str = ""
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


def _gap_fault(default: Fault, availability: SourceAvailability) -> Fault:
    """`default`, unless our own fetch failed — then it is ours, whatever else.

    An ENVIRONMENT fault upstream cannot be reported downstream as the
    publisher's gap: if we never got their source for reasons on our side,
    every axis that needed it is unassessed because of us. `reachability`
    already says so in prose — *"reasons on our side … retryable and not a
    finding about the server"* — and published it anyway.
    """
    upstream = availability.state.fault
    return upstream if upstream is Fault.ENVIRONMENT else default


def _from_axis_result(
    result: AxisResult,
    reason_when_unassessed: str = "",
    *,
    fault: Fault = Fault.UNATTRIBUTED,
) -> AxisScore:
    """Project a sub-check-scored axis (`03` §4, §5, §7) onto the report shape."""
    evidence = tuple(
        Evidence(
            label=sub.name,
            # ⚠ THE EVIDENCE PROSE GOES IN `detail`, and putting it anywhere
            # else has now failed in both directions. It was first assigned to
            # `path`, so the page rendered "declared endpoint(s) are HTTPS: …"
            # as a file location; the fix filtered non-paths out of that field
            # and carried the prose NOWHERE, leaving a scored sub-check with
            # `detail: "scored 80"` and no trail at all. `03` §10 owes a reason
            # for every point, and for these three axes the prose IS the
            # evidence — there is no file to cite.
            detail=(
                "; ".join(sub.evidence) if sub.evidence
                else (sub.reason if sub.score is None else f"scored {sub.score}")
            ),
            # `path` only when the string genuinely names an artefact.
            path=_as_path(sub.evidence[0]) if sub.evidence else "",
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
        fault=None if result.score is not None else fault.value,
        evidence=evidence,
    )


_BARE_ARTEFACTS = frozenset(
    {"LICENSE", "LICENCE", "COPYING", "NOTICE", "README", "DOCKERFILE",
     "MAKEFILE", "CHANGELOG", "SECURITY", "CODEOWNERS"}
)


def _as_path(value: str) -> str:
    """The evidence string if it plausibly names a file, else empty.

    Deliberately conservative: prose in a path field is worse than an empty
    path field, because the page renders one as a location a reader could go
    and check.
    """
    candidate = value.strip()
    if not candidate or " " in candidate or len(candidate) > 200:
        return ""
    if "/" in candidate or "." in candidate:
        return candidate
    # Extensionless artefacts are real files and the dot-or-slash test drops
    # them: `Dockerfile` and `LICENSE` are exactly the kind of thing a
    # sub-check would cite. Named rather than inferred, because a bare word
    # with no separator is otherwise indistinguishable from a one-word
    # sentence fragment.
    return candidate if candidate.upper() in _BARE_ARTEFACTS else ""


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

    # Bound to a concrete Path before use: the ternary form left it
    # `Path | None`, which is true of the expression and false of the value —
    # and the one place that difference bites is `shutil.rmtree`, which would
    # be handed None only if the invariant were ever broken.
    ws = workspace if workspace is not None else Path(tempfile.mkdtemp(prefix="mcpw-scan-"))
    ref_matched: bool | None = None
    owned = workspace is None

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
                spec = SourceSpec.parse(resolution.primary)
                fetched = fetch(spec, ws)
                root = fetched.scan_root
                # `fetch_git` falls back to the default branch when neither
                # version tag resolves, and says so in `ref_matched_version`.
                # Dropping that published a score for BRANCH-TIP code under the
                # released version's number, with nothing on the page to say
                # which revision was actually read — the precise failure
                # `CLAUDE.md`'s refs/tags rule exists to prevent, reintroduced
                # one layer up by discarding the signal that detects it.
                ref_matched = fetched.ref_matched_version
                availability = SourceAvailability(SourceState.FETCHED, repo_url)
            except Exception as exc:  # noqa: BLE001 - classified, never swallowed
                # Attribute the failure to what was actually FETCHED. The
                # primary may be an npm or PyPI package, and a 404 there says
                # nothing about the declared repository — which may be healthy,
                # or may not exist. Blaming it would be a published accusation
                # about a party we never contacted.
                from_a_repo = resolution.kind in (SourceKind.GITHUB, SourceKind.GITLAB)
                attributed = repo_url if from_a_repo else resolution.primary
                availability = from_exception(exc, attributed)

        return _assemble(
            entry, resolution, availability, root, scanned_at, version, ref_matched
        )
    finally:
        if owned:
            shutil.rmtree(ws, ignore_errors=True)


def _assemble(
    entry, resolution, availability, root, scanned_at, version, ref_matched=None
) -> ServerReport:
    # Derived from what was actually FETCHED, which is the only thing that
    # licenses a claim about it.
    subject = ""
    if availability.state is SourceState.UNREACHABLE:
        subject = (
            "repository"
            if resolution.kind in (SourceKind.GITHUB, SourceKind.GITLAB)
            else "package"
        )

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
        # These three abstain only when there was nothing of the publisher's
        # to read — an unreachable repository, or a fetched tree whose every
        # file was oversized or excluded. Both are theirs. `_gap_fault` takes
        # it back if OUR fetch is what failed.
        "auth_posture": _from_axis_result(
            auth, availability.reason, fault=_gap_fault(Fault.PUBLISHER, availability)
        ),
        # `03` §5's forge signals need a retrieval this project has not built,
        # so Maintenance is dark on every server for a reason of OURS — but a
        # systematic, disclosed one: the roster and `llms.txt` say so in our
        # own voice, and a reader is never left inferring that the server is
        # at fault. That is PROJECT, and it is publishable; ENVIRONMENT is the
        # accidental kind and is not.
        "maintenance": _from_axis_result(maintenance, fault=Fault.PROJECT),
        "transparency": _from_axis_result(
            transparency,
            availability.reason,
            fault=_gap_fault(Fault.PUBLISHER, availability),
        ),
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
        source_subject=subject,
        source_reason=availability.reason,
        transport=transport.declared.value if transport.declared else "",
        transport_mismatch=bool(transport.mismatch),
        ref_matched_version=ref_matched,
        files_scanned=(code.files_scanned if code else 0),
        files_pruned=(code.pruned if code else 0),
        axes={k: axes[k] for k in AXES},
    )


def _code_axis(result, availability) -> AxisScore:
    if result is None:
        # No tree to scan, so the fetch stage owns the attribution.
        return AxisScore(
            "code_safety", None, availability.reason, "0",
            fault=availability.state.fault.value,
        )
    if not result.assessed:
        # semgrep knows which of the two it was — a missing binary or a repo
        # with no source in a covered language — and now says so.
        return AxisScore(
            "code_safety", None, result.reason, "0",
            fault=_gap_fault(result.fault, availability).value,
        )
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
        plural = "" if result.pruned == 1 else "s"
        verb = "was" if result.pruned == 1 else "were"
        reason = (
            f"{result.pruned} vendored or minified path{plural} {verb} excluded "
            "before scanning; machine-generated bundles are not the server's "
            "own code"
        )
    if result.files_unparsed:
        note = (
            f"{result.files_unparsed} file"
            f"{'' if result.files_unparsed == 1 else 's'} could not be parsed "
            f"and {'was' if result.files_unparsed == 1 else 'were'} not scanned"
        )
        reason = f"{reason}; {note}" if reason else note
    return AxisScore(
        "code_safety", result.score, reason, result.assessed_weight,
        evidence=evidence,
    )


def _deps_axis(result, availability) -> AxisScore:
    if result is None:
        return AxisScore(
            "dependency_health", None, availability.reason, "0",
            fault=availability.state.fault.value,
        )
    if not result.assessed:
        return AxisScore(
            "dependency_health", None, result.reason, "0",
            fault=_gap_fault(result.fault, availability).value,
        )
    evidence = tuple(
        Evidence(
            label=f"{f.package} {f.version} — {f.osv_id}",
            detail=(
                # ⚠ `None` IS FALSY, so this rendered "transitive" — the exact
                # cell the scorer was changed to stop defaulting to. The axis
                # reason correctly said the finding could not be placed in
                # `03` §6's table while the evidence beside it asserted the one
                # fact we had just said we did not know. A tri-state read as a
                # boolean, one layer below the tri-state that was fixed.
                (
                    "direct" if f.direct
                    else "transitive" if f.direct is False
                    else "direct or transitive unknown — no parseable manifest "
                         "for this ecosystem"
                )
                + (f", CVSS {f.cvss}" if f.cvss is not None else ", no CVSS published")
                + (f", fixed in {f.fixed_version}" if f.fixed_version else "")
            ),
            path=f.lockfile,
            url=f"https://osv.dev/vulnerability/{f.osv_id}" if f.osv_id else "",
        )
        for f in result.findings
    )
    # ⚠ `assessed_weight` was hardcoded "1" here, which is the one field the
    # whole product promises not to overstate. A vulnerability excluded from
    # the arithmetic for want of a CVSS is precisely the "of what we could
    # measure" case — narrating it in prose while the meter drew a fully
    # measured axis is the misreading `AxisMeter` exists to prevent, and the
    # site's own "partly-measured" tally counted these servers as complete.
    reason = ""
    scored = len(result.findings) - result.unscored_findings
    weight = "1"
    if result.findings and scored == 0:
        # EVERY finding lacked a CVSS. `dependency_axis_score` deducts nothing
        # from an empty set and returns 100 — a perfect score measured on none
        # of the vulnerabilities actually found, which is the worst possible
        # combination: a clean number over known-unassessed risk. It also
        # violated this report's own invariant that a score carries positive
        # coverage.
        return AxisScore(
            "dependency_health", None,
            f"{len(result.findings)} vulnerabilit"
            f"{'y was' if len(result.findings) == 1 else 'ies were'} found and "
            "none could be placed in `03` §6's table — no CVSS score, or an "
            "ecosystem whose manifest we cannot parse for direct-vs-transitive",
            # PROJECT: `03` §6 bands on a CVSS and defines nothing for its
            # absence, so this abstention is our methodology declining to
            # invent a band — disclosed, and nothing to do with this server.
            "0", fault=Fault.PROJECT.value, evidence=evidence,
        )
    if result.unscored_findings:
        plural = "y" if result.unscored_findings == 1 else "ies"
        verb = "is" if result.unscored_findings == 1 else "are"
        reason = (
            f"{result.unscored_findings} vulnerabilit{plural} could not be "
            f"placed in `03` §6's table and {verb} listed but not scored"
        )
        # ⚠ QUANTIZED, AND ROUNDED **DOWN** — both halves were missing, and
        # the result is live on the site today: two servers publish an
        # `assessed_weight` of 28 significant digits, because this was the one
        # coverage claim computed by an ad-hoc division rather than through
        # the convention `semgrep_check` already states at length. It only
        # surfaced when a wider cohort produced a server with 4,155
        # dependency findings, i.e. the first non-terminating division — at 40
        # servers the axis was scored once and divided evenly.
        #
        # Down, not half-up: `CLAUDE.md` is explicit that a coverage CLAIM is
        # the exception to rounding the published value, because 4110 of 4155
        # rounds UP to "0.99" and then to "1.00" at two more findings, which
        # publishes a partly-measured axis as fully measured — and the site
        # keys its partly-measured banner on `Number(w) < 1`, so the
        # over-claim erases its own disclosure.
        weight = _fmt(
            (dec(scored) / dec(len(result.findings))).quantize(
                Decimal("0.01"), rounding=ROUND_DOWN
            )
        )
    return AxisScore(
        "dependency_health", result.score, reason, weight, evidence=evidence
    )


__all__ = ["AXES", "AxisScore", "Evidence", "ServerReport", "scan_entry", "slugify"]
