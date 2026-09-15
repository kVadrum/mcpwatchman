"""Versioned axis weights for the mcpwatchman composite score.

These are PROVISIONAL starting values informed by the threat literature, not
calibration outputs. The composite they produce MUST NOT be published on public
surfaces until gold-set calibration validates the weights for a given
methodology version — until then the site, badges, and CLI render per-axis
scores only (the `COMPOSITE_PUBLISHED` gate below).

Weights are versioned in lockstep with the scoring methodology version, and
each version's weights sum to 1.0.
"""

from __future__ import annotations

AXIS_WEIGHTS: dict[str, dict[str, float]] = {
    "0.2.0": {
        "code_safety": 0.30,
        "auth_posture": 0.20,
        "maintenance": 0.15,
        "dependency_health": 0.20,
        "transparency": 0.15,
    },
}

# Sub-check weights WITHIN an axis (`03` §4, §5, §7). Versioned in lockstep with
# AXIS_WEIGHTS and for the same reason: `03` §11 classes "weight changes,
# sub-check additions" as a MINOR methodology bump, so a version's sub-check
# weights are as much a part of that version as its axis weights.
#
# Only three axes appear here, and the omission is structural rather than an
# oversight: `03` §3 (Code Safety) and §6 (Dependency Health) score by DEDUCTION
# from findings, not by weighted sub-checks. They have no sub-check table to
# version. `composite.axis_score` is their scorer; `axes.score_axis` is this
# set's. Asking this map for an axis it does not hold raises rather than
# returning an empty weighting, which would score a deduction axis as a
# vacuously perfect 100.
SUBCHECK_WEIGHTS: dict[str, dict[str, dict[str, float]]] = {
    "0.2.0": {
        # `03` §4
        "auth_posture": {
            "authentication_model": 0.40,
            "transport_security": 0.25,
            "secret_handling": 0.20,
            "authorization_granularity": 0.15,
        },
        # `03` §5
        "maintenance": {
            "recency": 0.30,
            "issue_responsiveness": 0.25,
            "release_cadence": 0.20,
            "bus_factor": 0.15,
            "repository_signals": 0.10,
        },
        # `03` §7
        "transparency": {
            "license": 0.25,
            "readme_quality": 0.25,
            "declared_scopes": 0.20,
            "changelog": 0.15,
            "security_contact": 0.15,
        },
    },
}

CURRENT_METHODOLOGY_VERSION = "0.2.0"

# Per-version gate: composite is exposed publicly only once calibration passes.
COMPOSITE_PUBLISHED: dict[str, bool] = {
    "0.2.0": False,
}


def weights_for(version: str = CURRENT_METHODOLOGY_VERSION) -> dict[str, float]:
    """Return the axis-weight map for a methodology version."""
    try:
        return AXIS_WEIGHTS[version]
    except KeyError:
        known = ", ".join(sorted(AXIS_WEIGHTS))
        raise ValueError(f"unknown methodology version {version!r}; known: {known}") from None


def composite_published(version: str = CURRENT_METHODOLOGY_VERSION) -> bool:
    """Whether the composite may be shown publicly for this methodology version.

    Fails CLOSED: an unknown version answers False rather than raising, so a
    version added to AXIS_WEIGHTS and forgotten here cannot publish an
    uncalibrated composite. The omission is caught in CI by test_weights.py
    instead — safe in production, loud where a human is looking.

    Exists so no caller indexes COMPOSITE_PUBLISHED directly: a caller supplying
    its own `.get(version, True)` default would reintroduce exactly the failure
    this gate prevents.
    """
    return COMPOSITE_PUBLISHED.get(version, False)


def subcheck_weights_for(
    axis: str, version: str = CURRENT_METHODOLOGY_VERSION
) -> dict[str, float]:
    """Return the sub-check weight map for one axis of a methodology version.

    Raises for an unknown axis rather than returning `{}`. An empty weighting
    scores every sub-check as unassessable, which `axes.score_axis` would report
    as "nothing to assess" — indistinguishable from a genuinely unscannable
    server, and reached by a typo.
    """
    try:
        by_axis = SUBCHECK_WEIGHTS[version]
    except KeyError:
        known = ", ".join(sorted(SUBCHECK_WEIGHTS))
        raise ValueError(
            f"unknown methodology version {version!r}; known: {known}"
        ) from None
    try:
        return by_axis[axis]
    except KeyError:
        known = ", ".join(sorted(by_axis))
        raise ValueError(
            f"axis {axis!r} has no sub-check weights at {version}; "
            f"sub-check-scored axes are: {known}"
        ) from None
