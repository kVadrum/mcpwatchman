"""Score history — the time series behind trend charts, `/api/servers/<slug>/history.json`,
`mcpwatchman trend` and `/feed/score-drops.xml`.

`05` §3.7 specifies a `score_history` table: one row per (server, axis, day,
methodology version), the latest scan of a day winning. There is no database
yet, so this is the same relation kept as a static file the site build reads:
`site/src/data/history.json`. It is DERIVED data — a pure function of the
`scans.json` versions committed to git — so it can always be rebuilt from git
(`ops/score_history.py --rebuild`) and nothing is lost if it is deleted.

⚠ **A point is a SCAN, never a day the page was merely served.** A page kept
from an earlier night (a timeout, a withheld row) keeps its `scanned_at`, so it
adds no point; a gap in the series is a night we did not measure, and a chart
must show it as a gap, never interpolate across it.

⚠ **A score never travels without its `assessed_weight`** (CLAUDE.md), and a
point records the scanner, ruleset and methodology that produced it: scores
under different contracts are different measurements, so a reader can mark the
seam instead of drawing a trend through it.

Storage is compact (an array per point, axes in `AXES` order) because the file
grows by one point per server per night; `expand` gives the published shape.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, timedelta
from typing import Any

# The published axis order; goldset.AXES is the canonical tuple.
from mcpwatchman.goldset import AXES

SCHEMA = 1

# A drop this large on one axis is a feed item (`06` §4 names 10 points for the
# composite; the composite is withheld, so the threshold applies per axis).
DROP_THRESHOLD = 10

# How long a drop stays in the published list.
DROP_WINDOW_DAYS = 90

# The axes whose drops are EVENTS. Maintenance is left out: its score decays as
# time passes since a server's last commit, release or answered issue, so most
# of its falls are the calendar, not something the server did — 131 of the 167
# drops in the published data of 2026-09-17 → 11-03. A feed that fires for an expected
# condition trains its readers to skip it (base.md § Signal design); the decay
# stays visible on the server's own chart, where it reads as a trend.
DROP_AXES = tuple(a for a in AXES if a != "maintenance")

_SCANNED, _METHOD, _RULES, _SCANNER = 0, 1, 2, 3
_AXES_AT = 4


def empty() -> dict[str, Any]:
    return {"schema": SCHEMA, "axes": list(AXES), "through": None, "servers": {}, "drops": []}


def _axis_cell(axis: Mapping[str, Any] | None) -> list[Any]:
    if not axis:
        return [None, "0", None]
    return [axis.get("score"), str(axis.get("assessed_weight", "0")), axis.get("fault")]


def point(report: Mapping[str, Any]) -> list[Any]:
    """One scan, compact. Records written before `fault` existed read it as None."""
    axes = report.get("axes") or {}
    return [
        report["scanned_at"],
        report.get("methodology_version"),
        report.get("ruleset_version"),
        report.get("scanner_version"),
        *(_axis_cell(axes.get(key)) for key in AXES),
    ]


def _day(p: list[Any]) -> str:
    return str(p[_SCANNED])[:10]


def merge(history: dict[str, Any], reports: Iterable[Mapping[str, Any]]) -> int:
    """Add each report's scan to `history` in place; return how many points changed.

    Idempotent: a report already recorded (same `scanned_at`) adds nothing, and
    a second scan on one UTC day replaces the first only if it is later (`05`
    §3.7: the latest scan of a day wins).
    """
    if history.get("schema") != SCHEMA:
        raise ValueError(f"history schema {history.get('schema')!r}, expected {SCHEMA}")
    if list(history.get("axes", [])) != list(AXES):
        raise ValueError("history axes differ from goldset.AXES; rebuild it")
    servers: dict[str, list[list[Any]]] = history["servers"]
    changed = 0
    for report in reports:
        if not report.get("scanned_at") or not report.get("slug"):
            continue
        new = point(report)
        series = servers.setdefault(report["slug"], [])
        same_day = [i for i, p in enumerate(series) if _day(p) == _day(new)]
        if same_day:
            i = same_day[-1]
            if series[i] == new or str(series[i][_SCANNED]) >= str(new[_SCANNED]):
                continue
            series[i] = new
        else:
            series.append(new)
            series.sort(key=lambda p: str(p[_SCANNED]))
        changed += 1
    return changed


def expand(slug: str, name: str, series: list[list[Any]]) -> dict[str, Any]:
    """The published shape of one server's history (`/api/servers/<slug>/history.json`)."""
    return {
        "slug": slug,
        "name": name,
        "points": [
            {
                "date": _day(p),
                "scanned_at": p[_SCANNED],
                "methodology_version": p[_METHOD],
                "ruleset_version": p[_RULES],
                "scanner_version": p[_SCANNER],
                "axes": {
                    key: {"score": cell[0], "assessed_weight": cell[1], "fault": cell[2]}
                    for key, cell in zip(AXES, p[_AXES_AT:], strict=True)
                },
            }
            for p in series
        ],
    }


def _comparable(a: list[Any], b: list[Any], index: int) -> bool:
    """Two scores on one axis measure the same thing only under one contract
    and one measured share. A scanner or ruleset release changes what is found,
    not what the server did (the rule `feed._comparable` applies to findings),
    and a different `assessed_weight` is a different fraction of the axis."""
    return (
        a[_SCANNER] == b[_SCANNER]
        and a[_RULES] == b[_RULES]
        and a[_METHOD] == b[_METHOD]
        and a[index][1] == b[index][1]
        and a[index][0] is not None
        and b[index][0] is not None
    )


def drops(
    history: Mapping[str, Any],
    names: Mapping[str, str],
    today: str,
    threshold: int = DROP_THRESHOLD,
    window_days: int = DROP_WINDOW_DAYS,
    axes: tuple[str, ...] = DROP_AXES,
) -> list[dict[str, Any]]:
    """Per-axis falls of `threshold` or more between consecutive comparable scans,
    newest first, within `window_days` of `today` (YYYY-MM-DD)."""
    cutoff = (date.fromisoformat(today) - timedelta(days=window_days)).isoformat()
    out: list[dict[str, Any]] = []
    for slug, series in history["servers"].items():
        if slug not in names:
            continue
        for before, after in zip(series, series[1:], strict=False):
            if _day(after) < cutoff:
                continue
            for offset, key in enumerate(AXES):
                if key not in axes:
                    continue
                i = _AXES_AT + offset
                if not _comparable(before, after, i):
                    continue
                fall = before[i][0] - after[i][0]
                if fall >= threshold:
                    out.append({
                        "slug": slug,
                        "name": names[slug],
                        "axis": key,
                        "date": _day(after),
                        "scanned_at": after[_SCANNED],
                        "before": before[i][0],
                        "after": after[i][0],
                        "assessed_weight": after[i][1],
                        "previous_scanned_at": before[_SCANNED],
                    })
    out.sort(key=lambda d: (d["scanned_at"], d["slug"], d["axis"]), reverse=True)
    return out


__all__ = ["AXES", "DROP_AXES", "DROP_THRESHOLD", "DROP_WINDOW_DAYS", "SCHEMA", "drops",
           "empty", "expand", "merge", "point"]
