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

CURRENT_METHODOLOGY_VERSION = "0.2.0"

# Per-version gate: composite is exposed publicly only once calibration passes.
COMPOSITE_PUBLISHED: dict[str, bool] = {
    "0.2.0": False,
}


def weights_for(version: str = CURRENT_METHODOLOGY_VERSION) -> dict[str, float]:
    """Return the axis-weight map for a methodology version."""
    return AXIS_WEIGHTS[version]
