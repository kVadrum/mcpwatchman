"""`mcpwatchman info` (`07` §4) against a stubbed static API.

What is pinned: the severity filter's default and its counts, the published
evidence cap being SAID rather than read as a complete list, sub-check notes
surviving the filter, and third-party text never reaching the terminal raw.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import api as cli_api
from mcpwatchman.cli import info as info_mod
from mcpwatchman.cli import main as main_mod
from mcpwatchman.cli.main import cli

BASE = "https://example.test"


def _finding(rule, severity, *, path="src/a.ts", line=3, deducts=True, **extra):
    item = {
        "label": f"{rule} ({severity or 'unrated'})", "detail": f"why {rule} matters",
        "path": path, "line": line, "excerpt": "const a = 1;\nrun(a);", "url": "",
        "finding": rule, "severity": severity, "first_seen": None, "deducts": deducts,
    }
    item.update(extra)
    return item


def _note(label, detail):
    return {"label": label, "detail": detail, "path": "", "line": 0, "excerpt": "", "url": "",
            "finding": "", "severity": "", "first_seen": None, "deducts": True}


def _record(*, omitted=766, code_evidence=None):
    code_evidence = code_evidence if code_evidence is not None else [
        _finding("rule-crit", "critical"),
        _finding("rule-high", "high", line=9),
        _finding("rule-med", "medium"),
        _finding("rule-low-test", "low", path="test/x.ts", deducts=False),
    ]
    axes = {
        "code_safety": {"score": 12, "assessed_weight": "0.98", "fault": None,
                        "reason": "", "evidence_omitted": omitted, "evidence": code_evidence,
                        "unmeasured_faults": ["publisher"]},
        "auth_posture": {"score": 80, "assessed_weight": "0.25", "fault": None, "reason": "",
                         "evidence_omitted": 0, "unmeasured_faults": ["publisher"],
                         "evidence": [_note("transport_security", "declared endpoint is HTTPS")]},
        "dependency_health": {
            "score": 60, "assessed_weight": "1", "fault": None, "reason": "",
            "evidence_omitted": 0, "unmeasured_faults": [],
            "evidence": [
                _finding("anyio:PYSEC-1", "critical", path="uv.lock", line=0,
                         url="https://osv.dev/vulnerability/PYSEC-1"),
                _finding("left:GHSA-1", "", path="uv.lock", line=0),
            ],
        },
        "maintenance": {"score": None, "assessed_weight": "0", "fault": "publisher",
                        "reason": "repository not publicly reachable", "evidence_omitted": 0,
                        "unmeasured_faults": ["publisher"],
                        "evidence": [_note("recency", "no last-commit date was retrieved")]},
        "transparency": {"score": 40, "assessed_weight": "1", "fault": None, "reason": "",
                         "evidence_omitted": 0, "unmeasured_faults": [], "evidence": []},
    }
    return {"server": {
        "name": "io.example/tool", "slug": "io-example-tool", "version": "1.2.0",
        "scanned_at": "2026-10-29T06:00:00+00:00", "methodology_version": "0.2.0",
        "ruleset_version": "0.1.2", "registry_state": "listed", "registry_note": "",
        "axes": axes,
    }}


@pytest.fixture
def api(monkeypatch):
    docs = {f"{BASE}/api/servers/io-example-tool.json": _record(),
            f"{BASE}/api/index.json": {"servers": []}}
    monkeypatch.setenv("MCPWATCHMAN_API_URL", BASE)
    monkeypatch.setattr(cli_api, "get_json", lambda url: docs.get(url))
    return docs


def run(*args):
    return CliRunner().invoke(cli, ["info", *args])


def test_default_shows_critical_and_high_and_counts_what_it_hides(api) -> None:
    result = run("io.example/tool")
    assert result.exit_code == 0, result.output
    assert "rule-crit" in result.output and "rule-high" in result.output
    assert "rule-med" not in result.output and "rule-low-test" not in result.output
    assert "2 more published findings below this severity filter" in result.output
    assert "src/a.ts:9" in result.output   # file:line
    assert "| run(a);" in result.output    # the excerpt


def test_a_capped_evidence_list_says_it_is_capped(api) -> None:
    result = run("io.example/tool")
    assert "766 more findings not shown in published evidence" in result.output


def test_an_uncapped_list_makes_no_cap_claim(api) -> None:
    """Negative control: the cap line must come from the data, not be boilerplate."""
    api[f"{BASE}/api/servers/io-example-tool.json"] = _record(omitted=0)
    result = run("io.example/tool")
    assert "not shown in published evidence" not in result.output


def test_severity_all_lists_everything_including_unrated(api) -> None:
    result = run("io.example/tool", "--severity", "all")
    assert result.exit_code == 0
    for rule in ("rule-crit", "rule-high", "rule-med", "rule-low-test", "left:GHSA-1"):
        assert rule in result.output
    assert "(listed, not deducted)" in result.output
    assert "below this severity filter" not in result.output


def test_severity_critical_hides_high(api) -> None:
    result = run("io.example/tool", "--severity", "critical")
    assert "rule-crit" in result.output and "rule-high" not in result.output


def test_sub_check_notes_survive_the_severity_filter(api) -> None:
    result = run("io.example/tool", "--severity", "critical")
    assert "recency: no last-commit date was retrieved" in result.output
    assert "transport_security: declared endpoint is HTTPS" in result.output


def test_every_score_carries_its_coverage_and_null_is_not_assessed(api) -> None:
    result = run("io.example/tool")
    assert "Auth Posture — 80/100, measured 25%" in result.output
    assert "Maintenance — not assessed (fault: publisher)" in result.output
    assert "No composite score" in result.output


def test_axis_accepts_the_short_name(api) -> None:
    result = run("io.example/tool", "--axis", "deps")
    assert result.exit_code == 0, result.output
    assert "Dependency Health" in result.output and "Code Safety" not in result.output
    assert "https://osv.dev/vulnerability/PYSEC-1" in result.output


def test_json_counts_hidden_and_omitted_and_has_no_composite(api) -> None:
    result = run("io.example/tool", "--format", "json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["composite_score"] is None and payload["composite_published"] is False
    code = payload["axes"]["code_safety"]
    assert [f["finding"] for f in code["findings"]] == ["rule-crit", "rule-high"]
    assert code["findings_hidden_by_filter"] == 2
    assert code["evidence_omitted"] == 766
    for axis in payload["axes"].values():
        assert {"score", "assessed_weight"} <= set(axis)


def test_third_party_text_cannot_drive_the_terminal(api) -> None:
    """Paths and excerpts come from scanned repositories; an ESC must not reach a tty."""
    api[f"{BASE}/api/servers/io-example-tool.json"] = _record(code_evidence=[
        _finding("rule-x", "critical", path="evil\x1b]0;pwned\x07.ts",
                 excerpt="ok\x1b[2J\u202egnp.exe"),
    ])
    result = run("io.example/tool")
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "\u202e" not in result.output
    assert "evil\ufffd]0;pwned\ufffd.ts" in result.output


def test_not_published_is_exit_1(api) -> None:
    result = run("io.example/unknown")
    assert result.exit_code == cli_api.EXIT_NOT_FOUND
    assert "not a judgement" in result.output


def test_a_bad_severity_is_a_usage_error_5(api) -> None:
    assert run("io.example/tool", "--severity", "urgent").exit_code == 5


def test_the_axis_names_main_spells_match_the_api_axes() -> None:
    """`main` spells the names so `--help` stays off urllib; they must not drift."""
    keys = tuple(key for key, _, _ in cli_api.AXES)
    shorts = tuple(short for _, _, short in cli_api.AXES)
    assert keys + shorts == main_mod.AXIS_NAMES
    assert all(main_mod._axis_key(s) == k for k, _, s in cli_api.AXES)


def test_split_evidence_separates_notes_from_findings() -> None:
    axis = {"evidence": [_note("license", "MIT"), _finding("r", "medium"), _finding("s", "high")]}
    findings, notes, hidden = info_mod.split_evidence(axis, "high")
    assert [f["finding"] for f in findings] == ["s"]
    assert [n["label"] for n in notes] == ["license"]
    assert hidden == 1
