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


def _level_of(version: str) -> str:
    """`03` §11's level, read off the version itself: 0.x → 1.0 is major,
    0.2 → 0.3 minor, 0.2 → 0.2.1 patch."""
    major, minor, patch = (*_version(version), 0, 0)[:3]
    if minor == 0 and patch == 0:
        return "major"
    return "minor" if patch == 0 else "patch"


@pytest.mark.parametrize("change", _changes(), ids=lambda c: c["version"])
def test_an_announced_change_gives_the_notice_its_level_requires(change: dict) -> None:
    """The notice is owed by the VERSION, not by the hand-entered `level`: a
    minor change labelled `patch` would otherwise pass with no notice at all
    (Codex leg, 2026-11-09)."""
    assert change["level"] == _level_of(change["version"]), (
        f"{change['version']} is a {_level_of(change['version'])} change by `03` §11, "
        f"but is labelled {change['level']}")
    announced = date.fromisoformat(change["announced"])
    not_before = date.fromisoformat(change["not_before"])
    assert (not_before - announced).days >= NOTICE_DAYS[_level_of(change["version"])]


@pytest.mark.parametrize(("version", "level"), [
    ("0.2.1", "patch"), ("0.3.0", "minor"), ("0.3", "minor"), ("1.0.0", "major"),
    ("1.0", "major"), ("2.0.0", "major"), ("1.4.0", "minor"),
])
def test_the_level_is_read_off_the_version(version: str, level: str) -> None:
    assert _level_of(version) == level


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
