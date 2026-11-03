"""`mcpwatchman trend` (`07` §5) over a stubbed `/api/servers/<slug>/history.json`.

Pinned: a null score is a gap, never a low bar; the scale is fixed at 0–100; a
methodology or ruleset change is marked and named; a missing history endpoint
is a clear not-found, not a crash.
"""

from __future__ import annotations

import datetime as dt

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import api as cli_api
from mcpwatchman.cli import trend as trend_mod
from mcpwatchman.cli.main import cli

BASE = "https://example.test"
TODAY = dt.date(2026, 11, 3)


def _point(day, code, *, ruleset="0.1.2", weight="1"):
    axes = {key: {"score": 70, "assessed_weight": "1", "fault": None}
            for key, _, _ in cli_api.AXES}
    axes["code_safety"] = {"score": code, "assessed_weight": "0" if code is None else weight,
                           "fault": "publisher" if code is None else None}
    return {"date": day, "scanned_at": f"{day}T06:00:00+00:00", "methodology_version": "0.2.0",
            "ruleset_version": ruleset, "scanner_version": "0.38.28", "axes": axes}


HISTORY = {"slug": "io-example-tool", "name": "io.example/tool", "points": [
    _point("2026-06-01", 10),                      # outside a 90-day window
    _point("2026-10-30", 100, ruleset="0.1.1"),
    _point("2026-10-31", None),
    _point("2026-11-01", 0, weight="0.5"),
    _point("2026-11-02", 50),
]}
RECORD = {"server": {"name": "io.example/tool", "slug": "io-example-tool", "version": "1",
                     "scanned_at": "2026-11-02T06:00:00+00:00", "axes": {}}}


@pytest.fixture
def api(monkeypatch):
    docs = {
        f"{BASE}/api/servers/io-example-tool.json": RECORD,
        f"{BASE}/api/servers/io-example-tool/history.json": HISTORY,
        f"{BASE}/api/index.json": {"servers": []},
    }
    monkeypatch.setenv("MCPWATCHMAN_API_URL", BASE)
    monkeypatch.setattr(cli_api, "get_json", lambda url: docs.get(url))
    monkeypatch.setattr(trend_mod, "_today", lambda: TODAY)
    return docs


def run(*args):
    return CliRunner().invoke(cli, ["trend", *args])


def _line(output: str, label: str) -> str:
    return next(line for line in output.splitlines() if line.startswith(label))


def test_a_null_is_a_gap_and_a_contract_change_is_marked(api) -> None:
    result = run("io.example/tool", "--axis", "code")
    assert result.exit_code == 0, result.output
    # 100, |change|, null, 0, 50 — the June point is outside the window.
    assert _line(result.output, "Code Safety").split()[2] == "█│·▁▅"
    assert "ruleset 0.1.1→0.1.2 on 2026-10-31" in result.output
    assert "not comparable" in result.output
    assert "4 scans, 2026-10-30 to 2026-11-02" in result.output


def test_a_scanner_release_alone_is_a_seam() -> None:
    """The endpoint says scanner releases are different measurements; the drop
    feed refuses to compare across one; so the sparkline does not join one."""
    second = {**_point("2026-11-02", 50), "scanner_version": "0.43.0"}
    points = trend_mod.parse_points({"points": [_point("2026-11-01", 50), second]}, "u")
    assert trend_mod.sparkline(points, "code_safety", unicode_ok=False) == "*|*"
    assert trend_mod.contract_changes(points) == ["scanner 0.38.28→0.43.0 on 2026-11-02"]


def test_the_latest_score_travels_with_its_coverage(api) -> None:
    result = run("io.example/tool", "--axis", "code_safety")
    line = _line(result.output, "Code Safety")
    assert "latest 50/100 measured 100%" in line
    assert "measured 50–100% across the window" in line


def test_default_draws_all_five_axes(api) -> None:
    result = run("io.example/tool")
    for _, label, _ in cli_api.AXES:
        assert any(line.startswith(label) for line in result.output.splitlines())


def test_days_narrows_the_window(api) -> None:
    result = run("io.example/tool", "--days", "3", "--axis", "code")
    assert _line(result.output, "Code Safety").split()[2] == "▁▅"
    assert "not comparable" not in result.output  # no change inside the window


def test_an_empty_window_says_so(api) -> None:
    api[f"{BASE}/api/servers/io-example-tool/history.json"] = {
        **HISTORY, "points": [_point("2026-01-01", 50)],
    }
    result = run("io.example/tool", "--days", "7")
    assert result.exit_code == 0
    assert "No published scans" in result.output and "latest: 2026-01-01" in result.output


def test_no_history_endpoint_is_not_found_with_a_clear_message(api) -> None:
    del api[f"{BASE}/api/servers/io-example-tool/history.json"]
    result = run("io.example/tool")
    assert result.exit_code == cli_api.EXIT_NOT_FOUND
    assert "score history is not published for io.example/tool yet" in result.output


def test_a_history_for_another_server_is_refused(api) -> None:
    api[f"{BASE}/api/servers/io-example-tool/history.json"] = {**HISTORY, "slug": "other"}
    assert run("io.example/tool").exit_code == cli_api.EXIT_NETWORK


def test_a_malformed_history_is_a_network_error_not_a_crash(api) -> None:
    api[f"{BASE}/api/servers/io-example-tool/history.json"] = {
        "slug": "io-example-tool", "points": [{"date": "yesterday", "axes": {}}],
    }
    assert run("io.example/tool").exit_code == cli_api.EXIT_NETWORK


def test_the_sparkline_scale_is_fixed_not_fitted() -> None:
    """A 50→54 wobble must not draw as a cliff."""
    points = trend_mod.parse_points({"points": [_point("2026-11-01", 50),
                                                _point("2026-11-02", 54)]}, "u")
    assert trend_mod.sparkline(points, "code_safety", unicode_ok=False) == "**"
    assert trend_mod.sparkline(points, "code_safety", unicode_ok=True) == "▅▅"


def test_ascii_fallback_keeps_gap_and_marker_distinct_from_bars() -> None:
    points = trend_mod.parse_points({"points": [
        _point("2026-11-01", 0, ruleset="a"), _point("2026-11-02", None, ruleset="b"),
    ]}, "u")
    assert trend_mod.sparkline(points, "code_safety", unicode_ok=False) == "_|."
