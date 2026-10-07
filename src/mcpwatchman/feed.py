"""When a finding first appeared — the data behind `/feed/high-severity.xml`.

`06` §4's feed carries "new high-severity or critical findings introduced since
the last build". A static build cannot see the last build, so publication stamps
each finding with the date it first appeared (`Evidence.first_seen`) by
comparing a page's new report with the one it replaces, and the site renders the
feed from that field alone.

⚠ **`None` means "there when tracking began", never "new".** A page's first
tracked report is a baseline: stamping it with today would announce every
finding on every page as new on the day this shipped, and every finding on a
newly pinned server as new on the day it was grown — a flood that buries the
items the feed exists for. So a date is stamped only on a page whose previous
report was itself tracked (`TRACKED_SINCE`), and only for a finding that report
did not carry.

A finding is the same finding while its axis, its rule or vulnerability, and its
file are — the line is left out, because an unrelated edit above it would
otherwise announce it as new.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any

# The report-level stamp: the date this page's findings began to be tracked.
TRACKED_SINCE = "findings_tracked_since"

# What `06` §4's high-severity feed carries.
FEED_SEVERITIES = frozenset({"critical", "high"})


def _key(axis: str, item: dict[str, Any]) -> tuple[str, str, str] | None:
    finding = item.get("finding")
    if not finding:
        return None  # sub-check prose, not a finding
    return axis, str(finding), str(item.get("path", ""))


def _first_seen_by_key(report: dict[str, Any]) -> dict[tuple[str, str, str], str | None]:
    seen: dict[tuple[str, str, str], str | None] = {}
    for axis, score in (report.get("axes") or {}).items():
        for item in score.get("evidence") or ():
            key = _key(axis, item)
            if key is not None and key not in seen:
                seen[key] = item.get("first_seen")
    return seen


def stamp_first_seen(
    previous: dict[str, Any] | None, current: dict[str, Any], today: str
) -> dict[str, Any]:
    """`current` with every finding's `first_seen` set, and the page's stamp.

    Returns a copy; neither argument is modified.
    """
    stamped = copy.deepcopy(current)
    since = previous.get(TRACKED_SINCE) if previous is not None else None
    tracked = previous is not None and bool(since)
    stamped[TRACKED_SINCE] = since if tracked else today
    before = _first_seen_by_key(previous) if previous is not None and tracked else {}

    for axis, score in (stamped.get("axes") or {}).items():
        for item in score.get("evidence") or ():
            key = _key(axis, item)
            if key is None:
                continue
            if not tracked:
                item["first_seen"] = None
            elif key in before:
                item["first_seen"] = before[key]
            else:
                item["first_seen"] = today
    return stamped


def feed_items(reports: Iterable[dict[str, Any]]) -> list[tuple[dict, str, dict]]:
    """(report, axis, finding) for every dated high-severity finding, newest first.

    The Python twin of the site's feed endpoint, which the build gate compares
    the built feed against.
    """
    items = [
        (report, axis, item)
        for report in reports
        for axis, score in (report.get("axes") or {}).items()
        for item in score.get("evidence") or ()
        if item.get("first_seen") and item.get("severity") in FEED_SEVERITIES
        and item.get("deducts", True)
    ]
    items.sort(key=lambda t: (t[2]["first_seen"], t[0]["slug"]), reverse=True)
    return items
