"""`mcpwatchman info` — one server's per-axis breakdown with its evidence (`07` §4).

Reads `/api/servers/<slug>.json`, the record `check` reads. Two kinds of item
live in an axis's `evidence`, and they are filtered differently:
- a FINDING (`finding` set: a rule id, or `package:OSV-id`) carries a severity
  and is what `--severity` filters — critical and high by default, per `07` §4;
- a SUB-CHECK NOTE (`finding` empty: `recency`, `license`, …) explains how a
  part of the axis was scored or why it was not, and is always shown, since it
  is the breakdown itself rather than a finding in it.

Two counts are never folded into silence. Findings the filter hides are counted
and named as hidden. And the published list is capped (`evidence_omitted`):
the score was computed over every finding, so a capped list printed without
saying so reads as the complete set — the misreading `api-notes`' own
`evidence_omitted_note` warns agents against.

`07` §4's "remediation suggestion" has no field in the published record, so
none is printed; the finding's `detail` says why it matters.
"""

from __future__ import annotations

import json
from typing import Any

import click

from mcpwatchman.cli.api import AXES, base_url, clean, load, weight

# `--severity X` shows X and everything more severe; `all` adds the findings
# no severity band could be given (a vulnerability with no CVSS, `03` §6).
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_CHOICES = ("critical", "high", "medium", "low", "all")


def _shown(item: dict[str, Any], severity: str) -> bool:
    if severity == "all":
        return True
    return SEVERITY_RANK.get(item.get("severity") or "", 0) >= SEVERITY_RANK[severity]


def split_evidence(
    axis: dict[str, Any], severity: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """(findings shown, sub-check notes, findings hidden by the filter)."""
    findings: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    hidden = 0
    for item in axis.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if not item.get("finding"):
            notes.append(item)
        elif _shown(item, severity):
            findings.append(item)
        else:
            hidden += 1
    return findings, notes, hidden


def _omitted(axis: dict[str, Any]) -> int:
    try:
        return max(0, int(axis.get("evidence_omitted") or 0))
    except (TypeError, ValueError):
        return 0


def _filter_words(severity: str) -> str:
    return {
        "critical": "critical",
        "high": "critical and high",
        "medium": "critical, high and medium",
        "low": "critical, high, medium and low",
        "all": "all",
    }[severity]


def _finding_lines(item: dict[str, Any]) -> list[str]:
    sev = clean(item.get("severity") or "unrated", one_line=True)
    path = clean(item.get("path") or "", one_line=True)
    line = item.get("line") or 0
    where = f"{path}:{line}" if path and isinstance(line, int) and line > 0 else path
    head = f"  [{sev}] {where}  {clean(item.get('label') or item['finding'], one_line=True)}"
    if item.get("deducts") is False:
        head += "  (listed, not deducted)"
    out = [head.rstrip()]
    if item.get("detail"):
        out.append(f"      {clean(item['detail'], one_line=True)}")
    for text in clean(item.get("excerpt") or "").splitlines():
        out.append(f"      | {text}")
    if item.get("url"):
        out.append(f"      {clean(item['url'], one_line=True)}")
    return out


def render_axis(label: str, axis: dict[str, Any], severity: str) -> list[str]:
    findings, notes, hidden = split_evidence(axis, severity)
    omitted = _omitted(axis)
    if axis.get("score") is None:
        fault = axis.get("fault")
        whose = f" (fault: {clean(fault, one_line=True)})" if fault else ""
        reason = clean(axis.get("reason") or "no reason recorded", one_line=True)
        lines = [f"{label} — not assessed{whose}", f"  {reason}"]
    else:
        lines = [f"{label} — {axis['score']}/100, measured {round(weight(axis) * 100)}%"]
        if axis.get("reason"):
            lines.append(f"  {clean(axis['reason'], one_line=True)}")
    for note in notes:
        lines.append(
            f"  · {clean(note.get('label') or '', one_line=True)}: "
            f"{clean(note.get('detail') or '', one_line=True)}"
        )
    if findings or hidden or omitted:
        lines.append(f"  Findings ({_filter_words(severity)}):")
        for item in findings:
            lines.extend(_finding_lines(item))
        if not findings:
            lines.append("  none at this severity")
    if hidden:
        lines.append(
            f"  {hidden} more published finding{'s' if hidden != 1 else ''} below this "
            "severity filter not shown; --severity all lists them."
        )
    if omitted:
        lines.append(
            f"  {omitted} more finding{'s' if omitted != 1 else ''} not shown in published "
            "evidence: the published list is capped, most severe first, and the score "
            "was computed over all of them."
        )
    return lines


def render_pretty(data: dict[str, Any], keys: list[str], severity: str, url: str) -> str:
    head = f"{clean(data['name'], one_line=True)}  v{clean(data['version'], one_line=True)}"
    lines = [
        head,
        f"scanned {data['scanned_at'][:10]} · methodology {data.get('methodology_version') or '?'}"
        f" · ruleset {data.get('ruleset_version') or 'none'}",
    ]
    if data.get("registry_state", "listed") != "listed":
        lines.append(
            f"Registry: {clean(data['registry_state'], one_line=True)} — "
            f"{clean(data.get('registry_note', ''), one_line=True)}"
        )
    for key, label, _ in AXES:
        if key in keys:
            lines.append("")
            lines.extend(render_axis(label, data["axes"][key], severity))
    lines.append("")
    lines.append(
        "No composite score: it is withheld until a hand-audited gold set "
        "validates the weights. A score covers only the measured share of its axis."
    )
    lines.append(f"Details: {url}")
    return "\n".join(lines)


def render_json(
    data: dict[str, Any], keys: list[str], severity: str, url: str, api_url: str
) -> str:
    axes = {}
    for key, _, _ in AXES:
        if key not in keys:
            continue
        axis = data["axes"][key]
        findings, notes, hidden = split_evidence(axis, severity)
        axes[key] = {
            "score": axis.get("score"),
            "assessed_weight": axis.get("assessed_weight"),
            "fault": axis.get("fault"),
            "reason": axis.get("reason", ""),
            "unmeasured_faults": axis.get("unmeasured_faults"),
            "findings": findings,
            "findings_hidden_by_filter": hidden,
            "evidence_omitted": _omitted(axis),
            "notes": notes,
        }
    payload = {
        "server": data["name"],
        "slug": data["slug"],
        "version": data["version"],
        "composite_score": None,
        "composite_published": False,
        "severity_filter": severity,
        "registry_state": data.get("registry_state", "listed"),
        "registry_note": data.get("registry_note", ""),
        "methodology_version": data.get("methodology_version"),
        "ruleset_version": data.get("ruleset_version"),
        "scanned_at": data["scanned_at"],
        "axes": axes,
        "url": url,
        "api_url": api_url,
    }
    return json.dumps(payload, indent=2)


def run(server: str, axis: str | None, severity: str, fmt: str, version: str | None) -> None:
    base = base_url()
    data = load(server, base, version)
    keys = [axis] if axis else [key for key, _, _ in AXES]
    url = f"{base}/servers/{data['slug']}/"
    if fmt == "json":
        api_url = f"{base}/api/servers/{data['slug']}.json"
        click.echo(render_json(data, keys, severity, url, api_url))
    else:
        click.echo(render_pretty(data, keys, severity, url))
