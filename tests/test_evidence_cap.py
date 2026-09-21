"""The published evidence cap (`runner.MAX_EVIDENCE_PER_AXIS`).

A surface-size decision, not a methodological one — which is exactly why it
needs pinning. The cap changes what a page SHOWS and must not change what the
score IS, and a truncation that does not announce itself is a false claim about
the basis of a number on a page whose whole premise is that every claim is
checkable.
"""

from __future__ import annotations

from decimal import Decimal

from mcpwatchman.workers.scanner.osv_check import DependencyFinding
from mcpwatchman.workers.scanner.reachability import SourceAvailability, SourceState
from mcpwatchman.workers.scanner.runner import (
    MAX_EVIDENCE_PER_AXIS,
    _code_axis,
    _deps_axis,
)
from mcpwatchman.workers.scanner.semgrep_check import CodeFinding
from mcpwatchman.workers.scoring.composite import Confidence, Severity

READABLE = SourceAvailability(SourceState.FETCHED, "https://github.com/a/b")


class _CodeResult:
    assessed = True
    assessed_weight = "1"
    reason = ""
    pruned = 0
    files_unparsed = 0
    ruleset_version = "0.1.0"
    score = 40

    def __init__(self, findings) -> None:
        self.findings = findings


class _DepsResult:
    assessed = True
    reason = ""
    score = 0
    unscored_findings = 0

    def __init__(self, findings) -> None:
        self.findings = findings


def _code(severity: Severity, confidence: Confidence, n: int) -> CodeFinding:
    return CodeFinding(
        rule_id=f"rule-{n}", severity=severity, confidence=confidence,
        message="m", path=f"src/f{n}.py", line=n, excerpt="x",
    )


def _dep(severity: Severity | None, cvss: Decimal | None, n: int) -> DependencyFinding:
    return DependencyFinding(
        package=f"pkg{n}", ecosystem="PyPI", version="1.0",
        osv_id=f"OSV-{n}", severity=severity, cvss=cvss, direct=True,
        lockfile="poetry.lock",
    )


def test_a_short_list_is_published_whole_and_says_nothing_was_omitted() -> None:
    """The positive control. A cap that always fires is indistinguishable from
    a scanner that always finds fifty things."""
    axis = _code_axis(_CodeResult([_code(Severity.HIGH, Confidence.HIGH, i)
                                   for i in range(5)]), READABLE)
    assert len(axis.evidence) == 5
    assert axis.evidence_omitted == 0


def test_a_long_list_is_capped_and_the_count_is_published() -> None:
    findings = [_code(Severity.MEDIUM, Confidence.HIGH, i) for i in range(400)]
    axis = _code_axis(_CodeResult(findings), READABLE)
    assert len(axis.evidence) == MAX_EVIDENCE_PER_AXIS
    assert axis.evidence_omitted == 400 - MAX_EVIDENCE_PER_AXIS
    # ⚠ The arithmetic is untouched. `03`'s ladder diminishes to a TENTH of a
    # finding's weight and never to zero, so "the rest changed nothing" would
    # be false — the honest claim is that the score saw them and the page does
    # not list them.
    assert axis.score == 40


def test_the_survivors_are_the_worst_ones() -> None:
    """A cap that kept whichever findings semgrep emitted first would drop a
    critical to publish fifty informationals, on the axis a reader reads for
    exactly one reason."""
    findings = [_code(Severity.INFORMATIONAL, Confidence.LOW, i) for i in range(200)]
    findings.append(_code(Severity.CRITICAL, Confidence.HIGH, 999))
    axis = _code_axis(_CodeResult(findings), READABLE)
    assert "critical" in axis.evidence[0].label
    assert axis.evidence_omitted == 201 - MAX_EVIDENCE_PER_AXIS


def test_ordering_does_not_depend_on_the_list_length() -> None:
    """⚠ Sorting only when the cap bites would order two servers' pages by
    different rules — and the rule would be "how many findings did you have".
    """
    findings = [
        _code(Severity.LOW, Confidence.HIGH, 1),
        _code(Severity.CRITICAL, Confidence.HIGH, 2),
        _code(Severity.MEDIUM, Confidence.HIGH, 3),
    ]
    axis = _code_axis(_CodeResult(findings), READABLE)
    assert [e.label.split(" ")[0] for e in axis.evidence] == ["rule-2", "rule-3", "rule-1"]
    assert axis.evidence_omitted == 0


def test_confidence_breaks_a_severity_tie_by_rank_not_alphabet() -> None:
    """`Severity` and `Confidence` are StrEnums, so sorting on the VALUE puts
    "high" after "medium". Both ranks are derived from declaration order."""
    findings = [
        _code(Severity.CRITICAL, Confidence.MEDIUM, 1),
        _code(Severity.CRITICAL, Confidence.HIGH, 2),
    ]
    axis = _code_axis(_CodeResult(findings), READABLE)
    assert axis.evidence[0].label.startswith("rule-2")


def test_dependency_health_caps_on_its_own_dimension() -> None:
    """⚠ Severity is the only key the two axes share, and the deduction TABLE
    must not be. `03` §3 keys on (severity, confidence) and `03` §6 on
    (severity, direct-vs-transitive); borrowing one for the other compiles and
    returns a confidently wrong number.
    """
    findings = [_dep(Severity.HIGH, Decimal("7.5"), i) for i in range(120)]
    findings.append(_dep(Severity.CRITICAL, Decimal("9.8"), 999))
    # A vulnerability with no CVSS sorts last within its severity: it is the
    # one `03` §6 cannot place in its table at all.
    findings.append(_dep(Severity.CRITICAL, None, 1000))
    axis = _deps_axis(_DepsResult(findings), READABLE)

    assert len(axis.evidence) == MAX_EVIDENCE_PER_AXIS
    assert axis.evidence_omitted == 122 - MAX_EVIDENCE_PER_AXIS
    assert "OSV-999" in axis.evidence[0].label
    assert "OSV-1000" in axis.evidence[1].label


def test_the_count_survives_serialisation() -> None:
    """It reaches the API through `asdict`, so a field that is not on the
    dataclass is a field no consumer can see — and a consumer that cannot see
    it reads a capped list as a complete one."""
    from dataclasses import asdict

    axis = _code_axis(
        _CodeResult([_code(Severity.HIGH, Confidence.HIGH, i) for i in range(80)]),
        READABLE,
    )
    assert asdict(axis)["evidence_omitted"] == 30
