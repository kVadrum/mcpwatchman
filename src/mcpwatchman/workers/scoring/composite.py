"""Axis scoring and the composite formula (methodology `03` §3, §8).

Pure functions over plain values: no I/O, no database, no network. That is
deliberate — this is the module the gold-set calibration runs against, so it has
to be cheap to call a few thousand times and trivial to reason about.

**The composite is computed here and gated elsewhere.** `weights.composite_published()`
decides whether a *surface* may render it; it must never gate this computation,
because calibration's whole job is to compare composites while they are still
unpublished. Wiring the gate in here would make the thing that lifts the gate
impossible to run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from mcpwatchman.workers.scoring.weights import (
    CURRENT_METHODOLOGY_VERSION,
    weights_for,
)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    """The scoring-relevant projection of a finding.

    Deliberately not the persisted row (`05-data-model.md` owns that): scoring
    depends on exactly these two fields, and saying so keeps the calibration
    harness from having to build database objects.
    """

    severity: Severity
    confidence: Confidence


# `03` §3. Severities whose deduction varies by confidence; the Low-confidence
# value is DERIVED from these rows rather than listed (see `deduction_for`).
_GRADED_DEDUCTIONS: dict[Severity, dict[Confidence, int]] = {
    Severity.CRITICAL: {Confidence.HIGH: 30, Confidence.MEDIUM: 20},
    Severity.HIGH: {Confidence.HIGH: 20, Confidence.MEDIUM: 12},
    Severity.MEDIUM: {Confidence.HIGH: 8, Confidence.MEDIUM: 5},
}

# `03` §3 scores these "Any" confidence — the row has one value, not a range.
_FLAT_DEDUCTIONS: dict[Severity, int] = {
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}

# `03` §3: "after the first, each subsequent same-severity finding contributes
# 75% of its full deduction, then 50%, then 25%, then 10% from the fifth on."
#
# Decimal, not float, throughout the arithmetic below — see `_round_half_up`.
_STACKING = (Decimal("1"), Decimal("0.75"), Decimal("0.50"), Decimal("0.25"))
_STACKING_TAIL = Decimal("0.10")

AXIS_MAX = 100


def deduction_for(severity: Severity, confidence: Confidence) -> int:
    """Full (unstacked) deduction for one finding.

    Low confidence is "deducted at the floor of their severity row" (`03` §3),
    which is derived from the row rather than tabulated separately — a future
    weight change to the row cannot leave a hardcoded floor behind disagreeing
    with it.
    """
    if severity in _FLAT_DEDUCTIONS:
        return _FLAT_DEDUCTIONS[severity]
    row = _GRADED_DEDUCTIONS[severity]
    if confidence is Confidence.LOW:
        return min(row.values())
    return row[confidence]


def _stacking_multiplier(position: int) -> Decimal:
    """Multiplier for the Nth finding (0-indexed) within one severity group."""
    return _STACKING[position] if position < len(_STACKING) else _STACKING_TAIL


def axis_score(findings: Iterable[Finding]) -> int:
    """Score one axis from its findings: starts at 100, floors at 0 (`03` §3)."""
    by_severity: dict[Severity, list[int]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(
            deduction_for(f.severity, f.confidence)
        )

    total = Decimal(0)
    for deductions in by_severity.values():
        # Grouping is per SEVERITY and ordering within a group is largest-first:
        # both are specified in `03` §3, which also carries the worked example
        # and the reason. Cited rather than restated — the doc is canonical, and
        # a second copy here would be free to drift from it.
        for position, deduction in enumerate(sorted(deductions, reverse=True)):
            total += deduction * _stacking_multiplier(position)

    # Round the SCORE, not the deduction. Rounding the deduction first inverts
    # half-up into half-down for the thing we actually publish: two critical/high
    # findings deduct 52.5, so the axis is 47.5 and must round to 48 — subtracting
    # a deduction rounded to 53 gives 47.
    return max(0, _round_half_up(AXIS_MAX - total))


def composite_score(
    axis_scores: Mapping[str, float],
    version: str = CURRENT_METHODOLOGY_VERSION,
) -> int:
    """Weighted sum of the five axis scores (`03` §8).

    Every axis the methodology version declares must be present. Absence raises
    rather than defaulting: a missing axis silently scored as 0 reads as a very
    unsafe server, and scored as 100 hides one.
    """
    weights = weights_for(version)
    missing = sorted(set(weights) - set(axis_scores))
    if missing:
        raise ValueError(f"missing axis score(s) for {version}: {', '.join(missing)}")

    # Decimal via str(), not float: the weights are decimal fractions that have
    # no exact binary representation, so `0.30 * 31 + 0.20 * 1` is 9.499999…
    # rather than 9.5 and rounds DOWN. Measured before this was written: 13 of
    # 51,005 sampled composites came out a point low that way, and one point
    # crosses a grade and a colour band (80→79 is B→C, green→yellow).
    total = sum(
        (_dec(weight) * _dec(axis_scores[axis]) for axis, weight in weights.items()),
        Decimal(0),
    )
    return min(AXIS_MAX, max(0, _round_half_up(total)))


def _dec(value: float | int | Decimal) -> Decimal:
    """Exact Decimal for a value written as a decimal literal.

    Via `str()` deliberately: `Decimal(0.3)` is the binary float 0.299999…,
    `Decimal(str(0.3))` is 0.3. The weights are decimal fractions and calibration
    will keep rewriting them, so the arithmetic has to be exact by construction
    rather than by luck about which values happen to avoid a .5 boundary.
    """
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _round_half_up(value: Decimal) -> int:
    """Round half away from zero, not Python's default half-to-even.

    `round()` would make 78.5 → 78 and 79.5 → 80, so two servers half a point
    apart can round in opposite directions across a letter-grade boundary.
    "Rounded to the nearest integer" (`03` §8) is the everyday meaning.

    Takes a Decimal: handed a float this would faithfully round the float's
    error, which is exactly the bug it looks like it prevents.
    """
    return int(_dec(value).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


# `03` §8 — presentation only, derived from the composite, never stored as the
# primary representation.
def letter_grade(composite: int) -> str:
    """A–F band for a composite score."""
    for floor, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if composite >= floor:
            return grade
    return "F"


def color(composite: int) -> str:
    """Traffic-light band for a composite score."""
    for floor, name in ((80, "green"), (60, "yellow"), (40, "orange")):
        if composite >= floor:
            return name
    return "red"
