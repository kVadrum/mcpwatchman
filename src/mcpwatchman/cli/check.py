"""`mcpwatchman check` — read a server's published scan from the static API.

Stdlib only, and imported lazily from `main.check`: this is the command people
run BEFORE installing something, so its startup path stays click + stdlib
(`tests/test_cli_lazy_imports.py`). It reads the same JSON the site publishes —
`/api/servers/<slug>.json` for one server, `/api/index.json` to resolve a
package name or repository URL, both through `cli.api` — so there is no second
source of truth and no server to run.

`07` §3 is the spec. Two deliberate departures, both toward saying less:
- No bare per-axis score. `07`'s JSON sample predates the rule that a score
  never travels without its `assessed_weight` (`CLAUDE.md`), and 80 of a
  quarter of an axis printed as "80" is the misreading this project exists to
  prevent. Every format carries the weight beside the score.
- No `--fresh`. It means an on-demand scan, and no worker serves one yet; a
  flag that silently did nothing would be worse than its absence.
"""

from __future__ import annotations

import json
from typing import Any

import click

from mcpwatchman.cli.api import (
    AXES,
    EXIT_BELOW_THRESHOLD,
    EXIT_NETWORK,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_USAGE,
    CliError,
    base_url,
    clean,
    load,
    unicode_ok,
)
from mcpwatchman.cli.api import weight as _weight

# The names this module exported before the fetch and resolve code moved to
# `cli.api`, where every command shares it.
CheckError = CliError
__all__ = [
    "EXIT_BELOW_THRESHOLD", "EXIT_NETWORK", "EXIT_NOT_FOUND", "EXIT_OK", "EXIT_USAGE",
    "CheckError", "render_compact", "render_json", "render_pretty", "run",
]

BAR_WIDTH = 20


def _bar(score: int | None, weight: float, *, unicode_ok: bool) -> str:
    """The site's three regions — scored, lost, never measured — in text."""
    full, lost, void = ("▓", "░", "╱") if unicode_ok else ("#", "-", "/")
    measured = round(BAR_WIDTH * weight)
    scored = 0 if score is None else round(measured * score / 100)
    return full * scored + lost * (measured - scored) + void * (BAR_WIDTH - measured)


def render_pretty(server: dict[str, Any], url: str) -> str:
    uni = unicode_ok()
    # Names, versions, reasons and notes are registry or scanned-repo text:
    # `clean` keeps an ESC sequence or a bidi override from reaching the terminal.
    head = f"{clean(server['name'], one_line=True)}  v{clean(server['version'], one_line=True)}"
    scanned = f"scanned {server['scanned_at'][:10]}"
    lines = [f"{head}{scanned:>{max(1, 72 - len(head))}}", ("─" if uni else "-") * 72]
    for key, label, _ in AXES:
        axis = server["axes"][key]
        if axis["score"] is None:
            whose = " (a limit of mcpwatchman)" if axis.get("fault") == "project" else ""
            reason = clean(axis.get("reason") or "no reason recorded", one_line=True)
            lines.append(f"{label:<19}not assessed — {reason}{whose}")
            continue
        weight = _weight(axis)
        lines.append(
            f"{label:<19}{_bar(axis['score'], weight, unicode_ok=uni)}  "
            f"{axis['score']:>3}/100  measured {round(weight * 100)}%"
        )
    lines.append("")
    if server.get("registry_state", "listed") != "listed":
        note = clean(server.get("registry_note", ""), one_line=True)
        lines.append(f"Registry: {clean(server['registry_state'], one_line=True)} — {note}")
    lines.append(
        "No composite score: it is withheld until a hand-audited gold set "
        "validates the weights. A score covers only the measured share of its axis."
    )
    lines.append(f"Details: {url}")
    return "\n".join(lines)


def render_json(server: dict[str, Any], url: str, api_url: str) -> str:
    payload = {
        "server": server["name"],
        "slug": server["slug"],
        "version": server["version"],
        "composite_score": None,
        "grade": None,
        "composite_published": False,
        "axes": {
            key: {
                "score": server["axes"][key]["score"],
                "assessed_weight": server["axes"][key]["assessed_weight"],
                "fault": server["axes"][key].get("fault"),
                "reason": server["axes"][key].get("reason", ""),
            }
            for key, _, _ in AXES
        },
        "registry_state": server.get("registry_state", "listed"),
        "registry_note": server.get("registry_note", ""),
        "methodology_version": server.get("methodology_version"),
        "scanned_at": server["scanned_at"],
        "url": url,
        "api_url": api_url,
    }
    return json.dumps(payload, indent=2)


def render_compact(server: dict[str, Any]) -> str:
    parts = [f"{clean(server['name'], one_line=True)}@{clean(server['version'], one_line=True)}"]
    for key, _, short in AXES:
        axis = server["axes"][key]
        parts.append(
            f"{short}=null" if axis["score"] is None
            else f"{short}={axis['score']}@{_weight(axis):.2f}"
        )
    parts.append("composite=withheld")
    return "  ".join(parts)


def run(server: str, fmt: str, threshold: int | None, version: str | None) -> None:
    base = base_url()
    data = load(server, base, version)
    url = f"{base}/servers/{data['slug']}/"
    api_url = f"{base}/api/servers/{data['slug']}.json"
    if fmt == "json":
        click.echo(render_json(data, url, api_url))
    elif fmt == "compact":
        click.echo(render_compact(data))
    else:
        click.echo(render_pretty(data, url))
    if threshold is not None:
        # `07` §14.1: a threshold compares the composite, which is withheld, so
        # it is a no-op with a notice — never a silent pass that reads as one.
        click.echo(
            "notice: --threshold is disabled until the composite is published; "
            "exiting 0 regardless of score.",
            err=True,
        )
