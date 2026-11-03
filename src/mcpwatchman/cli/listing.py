"""`mcpwatchman list` — the published servers from `/api/index.json` (`07` §6).

`07` §6 sorts and filters by the composite, which is withheld until calibration
(`composite_published()`), so nothing here computes, prints or sorts by one.
The default is alphabetical by name. `--axis` sorts by one named axis, highest
first; a score filter needs that axis, and applies only to servers where it was
scored — `null` is "not assessed", never 0, so an unassessed server neither
passes `--max-score 10` nor fails `--min-score 10`. Every score printed carries
its `assessed_weight`.

`07` §6's `--category` and `--lang` are absent: the published data has no such
fields, and a filter over nothing would match nothing.
"""

from __future__ import annotations

import json
from typing import Any

import click

from mcpwatchman.cli.api import (
    AXES,
    AXIS_LABEL,
    EXIT_USAGE,
    CliError,
    base_url,
    clean,
    get_index,
    unicode_ok,
    weight,
)

CELL = 9


def _score(entry: dict[str, Any], key: str) -> int | None:
    axis = (entry.get("axes") or {}).get(key) or {}
    score = axis.get("score")
    return score if isinstance(score, int) and not isinstance(score, bool) else None


def select(
    entries: list[dict[str, Any]],
    axis: str | None,
    min_score: int | None,
    max_score: int | None,
) -> list[dict[str, Any]]:
    """Filter and order the index; pure, so the null-is-not-zero rule is testable."""
    by_name = sorted(entries, key=lambda e: str(e.get("name", "")))
    if axis is None:
        return by_name
    scored = [e for e in by_name if _score(e, axis) is not None]
    if min_score is not None or max_score is not None:
        lo = 0 if min_score is None else min_score
        hi = 100 if max_score is None else max_score
        scored = [e for e in scored if lo <= (_score(e, axis) or 0) <= hi]
        unscored: list[dict[str, Any]] = []
    else:
        unscored = [e for e in by_name if _score(e, axis) is None]
    # Stable sort over the name order: ties stay alphabetical.
    return sorted(scored, key=lambda e: -(_score(e, axis) or 0)) + unscored


def _cell(entry: dict[str, Any], key: str, gap: str) -> str:
    axis = (entry.get("axes") or {}).get(key) or {}
    score = _score(entry, key)
    return gap if score is None else f"{score}@{weight(axis):.2f}"


def render_pretty(
    rows: list[dict[str, Any]], total: int, axis: str | None, filtered: bool
) -> str:
    gap = "·" if unicode_ok() else "-"
    header = "".join(f"{short.upper():<{CELL}}" for _, _, short in AXES) + "SERVER"
    lines = [header]
    for entry in rows:
        cells = "".join(f"{_cell(entry, key, gap):<{CELL}}" for key, _, _ in AXES)
        name = clean(entry.get("name", ""), one_line=True)
        state = entry.get("registry_state", "listed")
        note = f"  ({clean(state, one_line=True)})" if state and state != "listed" else ""
        lines.append(f"{cells}{name}{note}")
    if not rows:
        lines.append("(no published server matches)")
    lines.append("")
    if axis is None:
        order = "alphabetical by name"
    else:
        order = f"by {AXIS_LABEL[axis]} score, highest first"
        if filtered:
            order += f"; only servers where {AXIS_LABEL[axis]} was scored"
        else:
            order += f"; servers where {AXIS_LABEL[axis]} was not assessed come last"
    lines.append(f"{len(rows)} of {total} shown, {order}.")
    lines.append(
        f"Cells are score@assessed_weight — a score covers only the measured share of "
        f"its axis. {gap} = not assessed, which is not zero."
    )
    lines.append("No composite score: it is withheld until a hand-audited gold set "
                 "validates the weights.")
    return "\n".join(lines)


def render_json(
    rows: list[dict[str, Any]],
    total: int,
    base: str,
    axis: str | None,
    min_score: int | None,
    max_score: int | None,
) -> str:
    payload = {
        "composite_published": False,
        "sort": axis or "name",
        "min_score": min_score,
        "max_score": max_score,
        "total_matching": total,
        "count": len(rows),
        "servers": [
            {
                "name": e.get("name"),
                "slug": e.get("slug"),
                "version": e.get("version"),
                "registry_state": e.get("registry_state", "listed"),
                "axes": {
                    key: {
                        "score": _score(e, key),
                        "assessed_weight": ((e.get("axes") or {}).get(key) or {}).get(
                            "assessed_weight"
                        ),
                        "fault": ((e.get("axes") or {}).get(key) or {}).get("fault"),
                    }
                    for key, _, _ in AXES
                },
                "url": f"{base}/servers/{e.get('slug')}/",
                "api_url": f"{base}/api/servers/{e.get('slug')}.json",
            }
            for e in rows
        ],
    }
    return json.dumps(payload, indent=2)


def run(
    min_score: int | None, max_score: int | None, axis: str | None, limit: int, fmt: str
) -> None:
    filtered = min_score is not None or max_score is not None
    if filtered and axis is None:
        raise CliError(
            "--min-score and --max-score need --axis: there is no composite to filter "
            "on until a hand-audited gold set validates the weights.",
            EXIT_USAGE,
        )
    if min_score is not None and max_score is not None and min_score > max_score:
        raise CliError("--min-score is above --max-score; nothing could match", EXIT_USAGE)
    base = base_url()
    rows = select(get_index(base), axis, min_score, max_score)
    total = len(rows)
    if limit:
        rows = rows[:limit]
    if fmt == "json":
        click.echo(render_json(rows, total, base, axis, min_score, max_score))
    else:
        click.echo(render_pretty(rows, total, axis, filtered))
