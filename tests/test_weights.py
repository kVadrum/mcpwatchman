"""Invariants for the versioned axis weights.

`weights.py` documents two rules and enforced neither: that each version's
weights sum to 1.0, and that the composite gate has an entry per version.
Both are hand-edited constants, so CI is the right place to hold them.
"""

from __future__ import annotations

import pytest

from mcpwatchman.workers.scoring.weights import (
    AXIS_WEIGHTS,
    COMPOSITE_PUBLISHED,
    CURRENT_METHODOLOGY_VERSION,
    RULESET_CALIBRATED,
    composite_published,
    confidence_ceiling,
    ruleset_calibrated,
    weights_for,
)


@pytest.mark.parametrize("version", sorted(AXIS_WEIGHTS))
def test_weights_sum_to_one(version: str) -> None:
    # Composites are compared across methodology versions; a version summing to
    # 0.95 silently rescales every score rather than failing.
    assert sum(AXIS_WEIGHTS[version].values()) == pytest.approx(1.0)


@pytest.mark.parametrize("version", sorted(AXIS_WEIGHTS))
def test_every_version_declares_its_composite_gate(version: str) -> None:
    # The accessor fails closed, so a missing entry is safe but invisible.
    # This is the thing that makes it visible.
    assert version in COMPOSITE_PUBLISHED


def test_current_version_is_known() -> None:
    assert CURRENT_METHODOLOGY_VERSION in AXIS_WEIGHTS


def test_composite_stays_unpublished_until_calibration() -> None:
    # Pins the project's first "Do not": no composite on any public surface
    # until gold-set calibration passes. When that legitimately flips, this
    # test fails — which is the point. Flipping it should be deliberate and
    # reviewed, not a constant edited in passing.
    assert composite_published() is False


def test_unknown_version_fails_closed_not_loud() -> None:
    assert composite_published("99.0.0") is False


def test_weights_for_names_the_known_versions() -> None:
    with pytest.raises(ValueError, match="known: 0.2.0"):
        weights_for("99.0.0")


@pytest.mark.parametrize("version", sorted(AXIS_WEIGHTS))
def test_every_version_declares_its_ruleset_gate(version: str) -> None:
    # Same shape as the composite gate above and for the same reason: the
    # accessor fails closed, so a missing entry is safe and invisible.
    assert version in RULESET_CALIBRATED


def test_ruleset_stays_uncalibrated_until_the_gold_set_exists() -> None:
    # `03` §3 defines high confidence as a measured false-positive rate on a
    # gold set that has not been built. Flipping this should be deliberate and
    # reviewed — it raises every deduction the scanner makes.
    assert ruleset_calibrated() is False
    assert confidence_ceiling() == "medium"


def test_unknown_version_gets_the_lower_ceiling() -> None:
    assert ruleset_calibrated("99.0.0") is False
    assert confidence_ceiling("99.0.0") == "medium"
