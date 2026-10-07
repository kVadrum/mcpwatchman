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

⚠ **"Absent from the previous report" is evidence of "new" only where that
report could have shown it** (`_comparable`). An axis whose evidence list was
capped hid findings it still scored — on a server showing 50 of 4,659 a fixed
critical lets a hidden one surface, announced as new on the day the server got
safer. An axis that was not scored showed nothing. And a scanner or ruleset
release changes what is found, not what the server did. In each case a
finding the previous report did not show keeps its known date or becomes
baseline; it is never dated today.
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


def _comparable(previous: dict[str, Any], current: dict[str, Any], axis: str) -> bool:
    """Whether a finding missing from `previous` on `axis` is evidence it is new."""
    before = (previous.get("axes") or {}).get(axis) or {}
    if before.get("score") is None or before.get("evidence_omitted", 0):
        return False
    keys = ("scanner_version", "ruleset_version") if axis == "code_safety" else ("scanner_version",)
    return all(previous.get(k) == current.get(k) for k in keys)


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
        comparable = tracked and previous is not None and _comparable(previous, current, axis)
        for item in score.get("evidence") or ():
            key = _key(axis, item)
            if key is None:
                continue
            if key in before:
                item["first_seen"] = before[key]
            else:
                item["first_seen"] = today if comparable else None
    return stamped


def feed_items(reports: Iterable[dict[str, Any]]) -> list[tuple[dict, str, dict]]:
    """(report, axis, finding) for every dated high-severity finding, newest first.

    The Python twin of the site's feed endpoint, which the build gate compares
    the built feed against.
    """
    items = []
    seen: set[tuple[str, str, str, str]] = set()
    for report in reports:
        for axis, score in (report.get("axes") or {}).items():
            for item in score.get("evidence") or ():
                if not (item.get("first_seen") and item.get("severity") in FEED_SEVERITIES
                        and item.get("deducts", True)):
                    continue
                # One entry per finding key: two hits of a rule in one file
                # share an Atom id, and a reader would keep one anyway.
                key = (report["slug"], axis, str(item["finding"]), str(item.get("path", "")))
                if key not in seen:
                    seen.add(key)
                    items.append((report, axis, item))
    items.sort(key=lambda t: (t[2]["first_seen"], t[0]["slug"]), reverse=True)
    return items
