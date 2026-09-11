"""Scoring-engine invariants (methodology `03` §3, §8).

Every expected value here is computed by hand from the spec, not from the
implementation — a test that re-derives the code's own arithmetic pins nothing.
"""

from __future__ import annotations

import pytest

from mcpwatchman.workers.scoring.composite import (
    Confidence,
    Finding,
    Severity,
    axis_score,
    color,
    composite_score,
    deduction_for,
    letter_grade,
)

CRITICAL_HIGH = Finding(Severity.CRITICAL, Confidence.HIGH)  # -30


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        (Severity.CRITICAL, Confidence.HIGH, 30),
        (Severity.CRITICAL, Confidence.MEDIUM, 20),
        (Severity.HIGH, Confidence.HIGH, 20),
        (Severity.HIGH, Confidence.MEDIUM, 12),
        (Severity.MEDIUM, Confidence.HIGH, 8),
        (Severity.MEDIUM, Confidence.MEDIUM, 5),
        (Severity.LOW, Confidence.HIGH, 2),
        (Severity.LOW, Confidence.MEDIUM, 2),
        (Severity.INFORMATIONAL, Confidence.HIGH, 0),
    ],
)
def test_deduction_table_matches_the_methodology(
    severity: Severity, confidence: Confidence, expected: int
) -> None:
    assert deduction_for(severity, confidence) == expected


@pytest.mark.parametrize(
    ("severity", "expected"),
    [(Severity.CRITICAL, 20), (Severity.HIGH, 12), (Severity.MEDIUM, 5)],
)
def test_low_confidence_takes_the_floor_of_its_severity_row(
    severity: Severity, expected: int
) -> None:
    # "deducted at the floor of their severity row" — the rule that lives in
    # §3's prose rather than its table, and so is the one most likely to be lost.
    assert deduction_for(severity, Confidence.LOW) == expected


def test_clean_axis_scores_100() -> None:
    assert axis_score([]) == 100


def test_single_finding_deducts_its_full_value() -> None:
    assert axis_score([CRITICAL_HIGH]) == 70


def test_same_severity_stacks_with_diminishing_returns() -> None:
    # 30 * (1 + .75 + .5 + .25) = 75  ->  100 - 75
    assert axis_score([CRITICAL_HIGH] * 4) == 25
    # fifth and beyond contribute 10%: 75 + 3 = 78
    assert axis_score([CRITICAL_HIGH] * 5) == 22
    assert axis_score([CRITICAL_HIGH] * 6) == 19


def test_stacking_is_per_severity_not_across_severities() -> None:
    # One critical and one high are each the FIRST of their own group, so both
    # take an undiminished hit: 100 - 30 - 20.
    assert axis_score([CRITICAL_HIGH, Finding(Severity.HIGH, Confidence.HIGH)]) == 50


def test_worst_finding_in_a_group_takes_the_undiminished_hit() -> None:
    # Order within a severity group is unspecified by §3; we sort largest-first
    # so the worst offender is not discounted. 30*1 + 20*0.75 = 45.
    # Smallest-first would give 20 + 22.5 = 42.5 -> 58, so this pins the choice.
    findings = [Finding(Severity.CRITICAL, Confidence.MEDIUM), CRITICAL_HIGH]
    assert axis_score(findings) == 55


def test_axis_floors_at_zero() -> None:
    assert axis_score([CRITICAL_HIGH] * 50) == 0


def test_informational_findings_never_deduct() -> None:
    noise = [Finding(Severity.INFORMATIONAL, Confidence.HIGH)] * 10
    assert axis_score(noise) == 100


def test_composite_is_the_weighted_sum() -> None:
    # .30*80 + .20*60 + .15*40 + .20*100 + .15*20 = 24+12+6+20+3 = 65
    assert (
        composite_score(
            {
                "code_safety": 80,
                "auth_posture": 60,
                "maintenance": 40,
                "dependency_health": 100,
                "transparency": 20,
            }
        )
        == 65
    )


def test_perfect_axes_give_a_perfect_composite() -> None:
    assert composite_score(dict.fromkeys(
        ("code_safety", "auth_posture", "maintenance", "dependency_health", "transparency"),
        100,
    )) == 100


def test_composite_rounds_half_up_not_half_to_even() -> None:
    # .30*81 + .20*60 + .15*40 + .20*100 + .15*20 = 24.3+12+6+20+3 = 65.3 -> 65
    scores = {
        "code_safety": 81,
        "auth_posture": 60,
        "maintenance": 40,
        "dependency_health": 100,
        "transparency": 20,
    }
    assert composite_score(scores) == 65
    # 78.5 must go UP; Python's round() would give 78.
    half = dict.fromkeys(scores, 78.5)
    assert composite_score(half) == 79


def test_missing_axis_raises_rather_than_defaulting() -> None:
    with pytest.raises(ValueError, match="transparency"):
        composite_score(
            {
                "code_safety": 80,
                "auth_posture": 60,
                "maintenance": 40,
                "dependency_health": 100,
            }
        )


@pytest.mark.parametrize(
    ("composite", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"),
     (69, "D"), (60, "D"), (59, "F"), (0, "F")],
)
def test_letter_grade_boundaries(composite: int, grade: str) -> None:
    assert letter_grade(composite) == grade


@pytest.mark.parametrize(
    ("composite", "name"),
    [(100, "green"), (80, "green"), (79, "yellow"), (60, "yellow"),
     (59, "orange"), (40, "orange"), (39, "red"), (0, "red")],
)
def test_color_boundaries(composite: int, name: str) -> None:
    assert color(composite) == name
