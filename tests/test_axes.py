"""Invariants for sub-check-weighted axis scoring (`03` §4, §5, §7).

The load-bearing behaviour here is what an UNASSESSED sub-check does, because
both obvious answers publish something untrue: scoring it 0 accuses a server of
a fault we never looked for, scoring it 100 hides one. These tests pin the third
answer — renormalise, and carry the coverage.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from mcpwatchman.workers.scoring.axes import AxisResult, SubCheck, ladder, score_axis
from mcpwatchman.workers.scoring.weights import (
    AXIS_WEIGHTS,
    CURRENT_METHODOLOGY_VERSION,
    SUBCHECK_WEIGHTS,
    subcheck_weights_for,
)

AUTH = "auth_posture"


def _auth(**scores: int | None) -> list[SubCheck]:
    """Every declared auth sub-check, defaulting to 100 unless overridden."""
    return [
        SubCheck(name, scores.get(name, 100),
                 reason="not assessed" if scores.get(name, 100) is None else "")
        for name in subcheck_weights_for(AUTH)
    ]


# ── the weight tables themselves ────────────────────────────────────────────

@pytest.mark.parametrize("version", sorted(SUBCHECK_WEIGHTS))
def test_subcheck_weights_sum_to_one(version: str) -> None:
    # Decimal, not approx: a set summing to 0.99 silently rescales every axis
    # score, and float addition is exactly what would hide it.
    for axis, weights in SUBCHECK_WEIGHTS[version].items():
        total = sum((Decimal(str(w)) for w in weights.values()), Decimal(0))
        assert total == Decimal(1), f"{version}/{axis} sums to {total}"


@pytest.mark.parametrize("version", sorted(SUBCHECK_WEIGHTS))
def test_subcheck_axes_are_declared_axes(version: str) -> None:
    assert set(SUBCHECK_WEIGHTS[version]) <= set(AXIS_WEIGHTS[version])


def test_deduction_scored_axes_have_no_subcheck_table() -> None:
    # `03` §3 and §6 score by deduction from findings. A sub-check table for
    # them would give `score_axis` something to return, and a deduction axis
    # scored as a vacuously perfect 100 is the failure that hides.
    for version, by_axis in SUBCHECK_WEIGHTS.items():
        assert "code_safety" not in by_axis, version
        assert "dependency_health" not in by_axis, version


def test_unknown_axis_raises_rather_than_returning_empty() -> None:
    with pytest.raises(ValueError, match="no sub-check weights"):
        subcheck_weights_for("code_safety")
    with pytest.raises(ValueError, match="unknown methodology version"):
        subcheck_weights_for(AUTH, version="9.9.9")


# ── unassessed sub-checks ───────────────────────────────────────────────────

def test_unassessed_subcheck_is_renormalised_away_not_scored_zero() -> None:
    # A server perfect on everything we could measure scores 100, not 80,
    # despite one fifth of the axis being unmeasurable.
    result = score_axis(AUTH, _auth(secret_handling=None))
    assert result.score == 100
    assert result.assessed_weight == Decimal("0.80")
    assert not result.fully_assessed


def test_assessed_weight_is_reported_so_a_surface_cannot_hide_it() -> None:
    result = score_axis(AUTH, _auth(secret_handling=None, authorization_granularity=None))
    assert result.assessed_weight == Decimal("0.65")
    assert {s.name for s in result.unassessed} == {
        "secret_handling", "authorization_granularity"
    }


def test_nothing_assessable_scores_none_not_zero() -> None:
    result = score_axis(AUTH, _auth(**dict.fromkeys(subcheck_weights_for(AUTH))))
    assert result.score is None
    assert result.assessed_weight == Decimal(0)


def test_fully_assessed_axis_weights_normally() -> None:
    result = score_axis(AUTH, [
        SubCheck("authentication_model", 100),
        SubCheck("transport_security", 80),
        SubCheck("secret_handling", 70),
        SubCheck("authorization_granularity", 0),
    ])
    # 0.40*100 + 0.25*80 + 0.20*70 + 0.15*0 = 74
    assert result.score == 74
    assert result.fully_assessed


def test_renormalisation_is_exact_decimal_not_float() -> None:
    # 0.30 and 0.20 have no exact binary form; the same class of error that cost
    # a point in composite_score would cost one here.
    result = score_axis(AUTH, [
        SubCheck("authentication_model", 31),
        SubCheck("transport_security", 31),
        SubCheck("secret_handling", None, reason="x"),
        SubCheck("authorization_granularity", None, reason="x"),
    ])
    assert result.score == 31


def test_half_rounds_up_on_the_axis_score() -> None:
    # 0.40*60 + 0.25*60 + 0.20*60 + 0.15*63 = 60.45 -> 60; nudge to a .5 case:
    result = score_axis(AUTH, [
        SubCheck("authentication_model", 60),
        SubCheck("transport_security", 60),
        SubCheck("secret_handling", 60),
        SubCheck("authorization_granularity", 63),  # 60.45
    ])
    assert result.score == 60
    result = score_axis(AUTH, [
        SubCheck("authentication_model", 60),
        SubCheck("transport_security", 62),
        SubCheck("secret_handling", 60),
        SubCheck("authorization_granularity", 60),  # 60.5 -> 61, not 60
    ])
    assert result.score == 61


# ── the fail-loud contract ──────────────────────────────────────────────────

def test_missing_subcheck_raises_rather_than_being_treated_as_unassessed() -> None:
    # An omitted sub-check and an unassessable one are different facts. Collapsed
    # together, a detector that forgets to emit one renormalises it away with no
    # reason recorded anywhere.
    with pytest.raises(ValueError, match="missing sub-check"):
        score_axis(AUTH, [SubCheck("authentication_model", 100)])


def test_unknown_subcheck_name_raises() -> None:
    with pytest.raises(ValueError, match="no such sub-check"):
        score_axis(AUTH, [*_auth(), SubCheck("licence_quality", 100)])


def test_duplicate_subcheck_raises_rather_than_last_one_winning() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        score_axis(AUTH, [*_auth(), SubCheck("transport_security", 0)])


def test_generator_input_is_not_consumed_twice() -> None:
    # A generator read once for the dict and again for the duplicate check sees
    # nothing the second time, which would make both checks vacuous.
    assert score_axis(AUTH, (s for s in _auth())).score == 100


def test_unassessed_subcheck_must_carry_a_reason() -> None:
    with pytest.raises(ValueError, match="must say why"):
        SubCheck("secret_handling", None)


@pytest.mark.parametrize("score", [-1, 101])
def test_subcheck_score_is_bounded(score: int) -> None:
    with pytest.raises(ValueError, match="outside"):
        SubCheck("secret_handling", score)


def test_subchecks_render_in_methodology_order_not_caller_order() -> None:
    reversed_input = list(reversed(_auth()))
    result = score_axis(AUTH, reversed_input)
    assert [s.name for s in result.subchecks] == list(subcheck_weights_for(AUTH))


def test_result_records_the_methodology_version() -> None:
    assert score_axis(AUTH, _auth()).methodology_version == CURRENT_METHODOLOGY_VERSION


# ── the ladder primitive ────────────────────────────────────────────────────

RECENCY = ((30, 100), (90, 80), (180, 60), (365, 30))


@pytest.mark.parametrize(
    ("days", "expected"),
    [(0, 100), (30, 100), (31, 80), (90, 80), (91, 60), (180, 60), (181, 30),
     (365, 30), (366, 0), (10_000, 0)],
)
def test_ladder_boundaries_are_inclusive(days: int, expected: int) -> None:
    # "within 30 days" includes day 30 — `03` §5's own wording.
    assert ladder(days, RECENCY) == expected


def test_ladder_refuses_a_missing_value() -> None:
    # Answering `floor` for missing data is the score-the-unknown-as-zero
    # mistake the whole module exists to prevent.
    with pytest.raises(ValueError, match="cannot score a missing value"):
        ladder(None, RECENCY)


def test_ladder_refuses_unsorted_rungs() -> None:
    with pytest.raises(ValueError, match="must ascend"):
        ladder(5, ((90, 80), (30, 100)))


def test_axis_result_is_immutable() -> None:
    result: AxisResult = score_axis(AUTH, _auth())
    with pytest.raises(AttributeError):
        result.score = 0  # type: ignore[misc]
