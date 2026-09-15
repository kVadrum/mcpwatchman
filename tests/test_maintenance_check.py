"""Maintenance ladders (`03` §5).

The axis answers one question — "if I file an issue tomorrow, will anyone read
it?" — so the tests that matter most are the ones separating *no signal* from
*a bad signal*. An API failure must never render as neglect.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from mcpwatchman.workers.scanner.maintenance_check import (
    MaintenanceSignals,
    assess_maintenance,
    score_bus_factor,
    score_issue_responsiveness,
    score_recency,
    score_release_cadence,
    score_repository_signals,
)

AS_OF = date(2026, 9, 15)


def _sub(axis, name):
    return next(s for s in axis.subchecks if s.name == name)


# ── recency ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("days", "expected"),
    [(0, 100), (30, 100), (31, 80), (90, 80), (91, 60), (180, 60), (181, 30),
     (365, 30), (366, 0)],
)
def test_recency_ladder(days: int, expected: int) -> None:
    signals = MaintenanceSignals(last_commit=date.fromordinal(AS_OF.toordinal() - days))
    assert score_recency(signals, AS_OF).score == expected


def test_future_dated_commit_is_clamped_not_rewarded() -> None:
    # A forged or clock-skewed timestamp is clamped to today.
    #
    # ⚠ The SCORE is 100 either way — `ladder(-108, ...)` already returns the
    # top band — so asserting the score alone is vacuous, which the second
    # negative control caught. What the clamp actually changes is the published
    # evidence, which would otherwise read "last commit -108 day(s) before".
    result = score_recency(MaintenanceSignals(last_commit=date(2027, 1, 1)), AS_OF)
    assert result.score == 100
    assert "-" not in result.evidence[0].split("before")[0]
    assert "0 day(s)" in result.evidence[0]


def test_missing_commit_date_abstains() -> None:
    assert score_recency(MaintenanceSignals(), AS_OF).score is None


# ── release cadence ─────────────────────────────────────────────────────────

def test_a_recent_release_scores_full_whatever_the_history() -> None:
    # `03` §5's top band is a disjunction: recent release OR tight median.
    signals = MaintenanceSignals(last_release=date(2026, 9, 1), median_release_gap_days=900)
    assert score_release_cadence(signals, AS_OF).score == 100


@pytest.mark.parametrize(("gap", "expected"), [(60, 100), (61, 80), (120, 80),
                                               (121, 60), (240, 60), (241, 30)])
def test_release_gap_ladder(gap: int, expected: int) -> None:
    # Released inside the year but not inside the 30-day window.
    signals = MaintenanceSignals(last_release=date(2026, 5, 1), median_release_gap_days=gap)
    assert score_release_cadence(signals, AS_OF).score == expected


def test_no_release_within_a_year_is_zero() -> None:
    signals = MaintenanceSignals(last_release=date(2025, 1, 1), median_release_gap_days=30)
    assert score_release_cadence(signals, AS_OF).score == 0


def test_no_release_history_abstains() -> None:
    assert score_release_cadence(MaintenanceSignals(), AS_OF).score is None


# ── issue responsiveness ────────────────────────────────────────────────────

@pytest.mark.parametrize(("median", "expected"), [(1, 100), (3, 100), (4, 80), (7, 80),
                                                  (8, 60), (21, 60), (22, 30), (60, 30),
                                                  (61, 0)])
def test_issue_response_ladder(median: float, expected: int) -> None:
    signals = MaintenanceSignals(median_first_response_days=median, issues_sampled=10)
    assert score_issue_responsiveness(signals).score == expected


def test_small_sample_falls_back_to_the_lifetime_median() -> None:
    signals = MaintenanceSignals(
        median_first_response_days=1.0,   # two issues, both answered fast
        issues_sampled=2,
        lifetime_first_response_days=40.0,
    )
    result = score_issue_responsiveness(signals)
    assert result.score == 30  # the lifetime median, per `03` §5
    assert "lifetime median" in result.evidence[0]


def test_no_issues_filed_is_not_an_unanswered_issue() -> None:
    # ⚠ The distinction the axis turns on. A repository nobody has filed against
    # has not failed to answer anything; a 0 here would penalise a server for
    # being uncontroversial.
    result = score_issue_responsiveness(MaintenanceSignals(issues_sampled=0))
    assert result.score is None
    assert "has not failed to answer" in result.reason


# ── bus factor ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("authors", "expected"), [(5, 100), (3, 100), (2, 80), (1, 50)])
def test_bus_factor_ladder(authors: int, expected: int) -> None:
    signals = MaintenanceSignals(authors_12mo=authors, last_commit=date(2026, 9, 10))
    assert score_bus_factor(signals, AS_OF).score == expected


def test_sole_maintainer_gone_quiet_drops_to_thirty() -> None:
    signals = MaintenanceSignals(authors_12mo=1, last_commit=date(2026, 1, 1))
    assert score_bus_factor(signals, AS_OF).score == 30


def test_nobody_above_the_commit_bar_uses_the_weakest_described_band() -> None:
    # `03` §5's ladder starts at one author; a repo with four commits from one
    # person is below it. Applying §5's weakest band beats inventing one.
    signals = MaintenanceSignals(authors_12mo=0, contributors_12mo=1,
                                 last_commit=date(2026, 9, 10))
    result = score_bus_factor(signals, AS_OF)
    assert result.score == 30
    assert "weakest described band" in result.evidence[0]


def test_missing_contributor_history_abstains() -> None:
    assert score_bus_factor(MaintenanceSignals(), AS_OF).score is None


# ── repository signals ──────────────────────────────────────────────────────

@pytest.mark.parametrize(("quartile", "expected"), [(1, 100), (2, 75), (3, 50), (4, 25)])
def test_quartile_scoring(quartile: int, expected: int) -> None:
    signals = MaintenanceSignals(category_quartile=quartile)
    assert score_repository_signals(signals).score == expected


def test_quartile_abstains_and_names_why_it_cannot_be_computed_per_server() -> None:
    result = score_repository_signals(MaintenanceSignals())
    assert result.score is None
    assert "post-pass" in result.reason


def test_out_of_range_quartile_raises() -> None:
    with pytest.raises(ValueError, match="must be 1-4"):
        score_repository_signals(MaintenanceSignals(category_quartile=5))


# ── the axis ────────────────────────────────────────────────────────────────

def test_nothing_retrieved_abstains_entirely() -> None:
    axis = assess_maintenance()
    assert axis.score is None
    assert axis.assessed_weight == Decimal(0)


def test_partial_retrieval_scores_what_it_brought_back() -> None:
    # A repository whose commits are readable but whose issues are not still
    # scores recency, cadence and bus factor.
    axis = assess_maintenance(
        MaintenanceSignals(last_commit=date(2026, 9, 10), authors_12mo=3), as_of=AS_OF
    )
    assert axis.score == 100
    assert axis.assessed_weight == Decimal("0.45")  # recency .30 + bus factor .15
    assert {s.name for s in axis.unassessed} == {
        "issue_responsiveness", "release_cadence", "repository_signals"}


def test_scoring_is_reproducible_against_a_fixed_as_of() -> None:
    # A re-scan of stored signals must reproduce the score it gave at the time,
    # which is the whole reason `as_of` is a parameter rather than a clock read.
    signals = MaintenanceSignals(last_commit=date(2026, 6, 1), authors_12mo=2)
    first = assess_maintenance(signals, as_of=AS_OF)
    assert first.score == assess_maintenance(signals, as_of=AS_OF).score
    assert first.score != assess_maintenance(signals, as_of=date(2027, 6, 1)).score
