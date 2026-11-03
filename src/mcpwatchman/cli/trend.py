"""`mcpwatchman trend` — per-axis score history as sparklines (`07` §5).

Reads `/api/servers/<slug>/history.json`: `{"slug", "name", "points": [{"date",
"scanned_at", "methodology_version", "ruleset_version", "scanner_version",
"axes": {<key>: {"score", "assessed_weight", "fault"}}}]}`, one point per day,
ascending. `07` §5 draws the composite; it is withheld, so this draws each axis.

Three things a sparkline would otherwise misstate:
- A `null` score is a gap glyph, never a low bar — not assessed is not zero.
- The scale is fixed at 0–100, never fitted to the window, which would turn a
  two-point wobble into a cliff.
- Scores either side of a methodology or ruleset change were computed under
  different rules and are not comparable; a marker sits at the change and a
  legend line names it.
One column is one published point, so a day with no scan takes no column; the
header gives the point count and date span so the compression is visible.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import click

from mcpwatchman.cli import api
from mcpwatchman.cli.api import (
    AXES,
    EXIT_NETWORK,
    EXIT_NOT_FOUND,
    CliError,
    base_url,
    clean,
    load,
    unicode_ok,
    weight,
)

LEVELS_UNICODE = "▁▂▃▄▅▆▇█"
LEVELS_ASCII = "_-=+*#%@"


def _today() -> dt.date:
    return dt.datetime.now(dt.UTC).date()


def parse_points(history: dict[str, Any], url: str) -> list[dict[str, Any]]:
    points = history.get("points")
    if not isinstance(points, list):
        raise CliError(f"{url} returned an unexpected shape", EXIT_NETWORK)
    out = []
    for point in points:
        if not isinstance(point, dict) or not isinstance(point.get("axes"), dict):
            raise CliError(f"{url} returned an unexpected shape", EXIT_NETWORK)
        try:
            day = dt.date.fromisoformat(str(point.get("date")))
        except ValueError as exc:
            raise CliError(f"{url} carries an unreadable date", EXIT_NETWORK) from exc
        out.append({**point, "date": day})
    return sorted(out, key=lambda p: p["date"])


def _contract(point: dict[str, Any]) -> tuple[str, str, str]:
    """What produced a score. Scores under a different scanner, ruleset or
    methodology are different measurements (the history endpoint's own note;
    `mcpwatchman.history` never compares them for a drop), so a change in any
    of the three is a seam."""
    return (
        str(point.get("methodology_version") or ""),
        str(point.get("ruleset_version") or ""),
        str(point.get("scanner_version") or ""),
    )


def contract_changes(points: list[dict[str, Any]]) -> list[str]:
    """One phrase per change of scanner, ruleset or methodology between consecutive points."""
    changes = []
    for before, after in zip(points, points[1:], strict=False):
        (m0, r0, s0), (m1, r1, s1) = _contract(before), _contract(after)
        parts = []
        if m0 != m1:
            parts.append(f"methodology {m0 or 'none'}→{m1 or 'none'}")
        if r0 != r1:
            parts.append(f"ruleset {r0 or 'none'}→{r1 or 'none'}")
        if s0 != s1:
            parts.append(f"scanner {s0 or 'none'}→{s1 or 'none'}")
        if parts:
            changes.append(f"{' and '.join(parts)} on {after['date'].isoformat()}")
    return [clean(c, one_line=True) for c in changes]


def _axis(point: dict[str, Any], key: str) -> dict[str, Any]:
    axis = point["axes"].get(key)
    return axis if isinstance(axis, dict) else {}


def _score(point: dict[str, Any], key: str) -> int | None:
    score = _axis(point, key).get("score")
    return score if isinstance(score, int) and not isinstance(score, bool) else None


def sparkline(points: list[dict[str, Any]], key: str, *, unicode_ok: bool) -> str:
    levels = LEVELS_UNICODE if unicode_ok else LEVELS_ASCII
    gap, mark = ("·", "│") if unicode_ok else (".", "|")
    out = []
    for i, point in enumerate(points):
        if i and _contract(point) != _contract(points[i - 1]):
            out.append(mark)
        score = _score(point, key)
        if score is None:
            out.append(gap)
        else:
            out.append(levels[min(len(levels) - 1, max(0, score) * len(levels) // 100)])
    return "".join(out)


def _latest(points: list[dict[str, Any]], key: str) -> str:
    last = points[-1]
    score = _score(last, key)
    if score is None:
        return "latest: not assessed"
    text = f"latest {score}/100 measured {round(weight(_axis(last, key)) * 100)}%"
    measured = [round(weight(_axis(p, key)) * 100) for p in points if _score(p, key) is not None]
    if min(measured) != max(measured):
        text += f" (measured {min(measured)}–{max(measured)}% across the window)"
    return text


def render(name: str, points: list[dict[str, Any]], keys: list[str], days: int) -> str:
    uni = unicode_ok()
    first, last = points[0]["date"].isoformat(), points[-1]["date"].isoformat()
    lines = [
        f"{clean(name, one_line=True)} · last {days} days · "
        f"{len(points)} scan{'s' if len(points) != 1 else ''}, {first} to {last}",
        "",
    ]
    for key, label, _ in AXES:
        if key in keys:
            spark = sparkline(points, key, unicode_ok=uni)
            lines.append(f"{label:<19}{spark}  {_latest(points, key)}")
    lines.append("")
    gap, mark = ("·", "│") if uni else (".", "|")
    lines.append(
        f"Fixed 0–100 scale, one column per scan; {gap} = not assessed, which is not zero."
    )
    changes = contract_changes(points)
    if changes:
        lines.append(
            f"{mark} = scanner, ruleset or methodology changed ({'; '.join(changes)}): "
            "scores either side are not comparable."
        )
    return "\n".join(lines)


def run(server: str, days: int, axis: str | None) -> None:
    base = base_url()
    data = load(server, base)
    url = f"{base}/api/servers/{data['slug']}/history.json"
    history = api.get_json(url)
    if history is None:
        raise CliError(
            f"score history is not published for {data['name']} yet; "
            f"`mcpwatchman check {data['slug']}` shows its current scan.",
            EXIT_NOT_FOUND,
        )
    if history.get("slug") != data["slug"]:
        raise CliError(f"{url} describes a different server", EXIT_NETWORK)
    cutoff = _today() - dt.timedelta(days=days)
    all_points = parse_points(history, url)
    points = [p for p in all_points if p["date"] > cutoff]
    if not points:
        since = f" (latest: {all_points[-1]['date'].isoformat()})" if all_points else ""
        click.echo(f"No published scans of {clean(data['name'], one_line=True)} "
                   f"in the last {days} days{since}.")
        return
    keys = [axis] if axis else [key for key, _, _ in AXES]
    click.echo(render(data["name"], points, keys, days))
