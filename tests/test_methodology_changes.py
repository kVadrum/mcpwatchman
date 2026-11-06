"""Announced methodology changes keep `03` §11's notice periods.

`site/src/data/methodology-changes.json` is the one home for an announced
change: the methodology page and `/feed/methodology.xml` render it, and this
gate holds it to §11. A minor version is announced at least 14 days before it
deploys, a major one 30. Because a `sync` deploys everything on `dev`, the
change itself may not even reach `dev` before its `not_before` date. Holding
it there would block every other sync, so this test fails CI instead
(operator ruling 2026-11-06).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from mcpwatchman.workers.scoring.weights import CURRENT_METHODOLOGY_VERSION

CHANGES = Path(__file__).resolve().parents[1] / "site" / "src" / "data" / "methodology-changes.json"
NOTICE_DAYS = {"patch": 0, "minor": 14, "major": 30}


def _version(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def _changes() -> list[dict]:
    return json.loads(CHANGES.read_text())["changes"]


@pytest.mark.parametrize("change", _changes(), ids=lambda c: c["version"])
def test_an_announced_change_gives_the_notice_its_level_requires(change: dict) -> None:
    announced = date.fromisoformat(change["announced"])
    not_before = date.fromisoformat(change["not_before"])
    assert (not_before - announced).days >= NOTICE_DAYS[change["level"]]


@pytest.mark.parametrize("change", _changes(), ids=lambda c: c["version"])
def test_a_change_is_current_only_once_its_date_has_passed(change: dict) -> None:
    """The retirement lands on `dev` only after `not_before`; landing it marks
    the entry `landed` in the same commit."""
    today = datetime.now(UTC).date()
    current = _version(CURRENT_METHODOLOGY_VERSION)
    target = _version(change["version"])
    if change["status"] == "announced":
        assert current < target, (
            f"{change['version']} is still only announced, but the methodology is "
            f"already at {CURRENT_METHODOLOGY_VERSION}")
    else:
        assert change["status"] == "landed"
        assert current >= target
        assert today >= date.fromisoformat(change["not_before"])


def test_every_change_states_what_it_is() -> None:
    for change in _changes():
        assert change["level"] in NOTICE_DAYS
        assert change["title"] and change["summary"] and change["points"]
