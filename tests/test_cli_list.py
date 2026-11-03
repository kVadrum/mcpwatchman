"""`mcpwatchman list` (`07` §6) over a stubbed `/api/index.json`.

The rule under test is that `null` is "not assessed", never 0: an unassessed
axis neither satisfies a low `--max-score` nor fails a `--min-score`; it is
simply outside a score filter, and last in an axis sort.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import api as cli_api
from mcpwatchman.cli import listing
from mcpwatchman.cli.main import cli

BASE = "https://example.test"


def _entry(name, code, weight="1", state="listed"):
    axes = {key: {"score": 50, "assessed_weight": "1", "fault": None}
            for key, _, _ in cli_api.AXES}
    axes["code_safety"] = {"score": code, "assessed_weight": "0" if code is None else weight,
                           "fault": "publisher" if code is None else None}
    slug = name.replace("/", "-").replace(".", "-")
    return {"name": name, "slug": slug, "version": "1.0.0", "registry_state": state, "axes": axes}


INDEX = {"servers": [
    _entry("io.example/delta", 90),
    _entry("io.example/alpha", None),
    _entry("io.example/charlie", 5, weight="0.25", state="deprecated"),
    _entry("io.example/bravo", 60),
]}


@pytest.fixture
def api(monkeypatch):
    asked: list[str] = []

    def get_json(url):
        asked.append(url)
        return INDEX if url == f"{BASE}/api/index.json" else None

    monkeypatch.setenv("MCPWATCHMAN_API_URL", BASE)
    monkeypatch.setattr(cli_api, "get_json", get_json)
    return asked


def run(*args):
    return CliRunner().invoke(cli, ["list", *args])


def _names(output: str) -> list[str]:
    return [line.split("io.example/")[1].split()[0]
            for line in output.splitlines() if "io.example/" in line]


def test_default_is_alphabetical_with_weights_beside_scores(api) -> None:
    result = run()
    assert result.exit_code == 0, result.output
    assert api == [f"{BASE}/api/index.json"]
    assert _names(result.output) == ["alpha", "bravo", "charlie", "delta"]
    assert "5@0.25" in result.output       # the weight travels with the score
    assert "(deprecated)" in result.output
    assert "No composite score" in result.output


def test_axis_sorts_highest_first_and_unassessed_last(api) -> None:
    result = run("--axis", "code")
    assert _names(result.output) == ["delta", "bravo", "charlie", "alpha"]
    assert "not assessed come last" in result.output


def test_a_low_max_score_does_not_match_an_unassessed_axis(api) -> None:
    """The null-is-not-zero rule: alpha's Code Safety was never measured."""
    result = run("--axis", "code_safety", "--max-score", "10")
    assert _names(result.output) == ["charlie"]


def test_min_score_filters_only_scored_servers(api) -> None:
    result = run("--axis", "code", "--min-score", "50")
    assert _names(result.output) == ["delta", "bravo"]
    assert "2 of 2 shown" in result.output


def test_a_score_filter_without_an_axis_is_a_usage_error(api) -> None:
    result = run("--min-score", "50")
    assert result.exit_code == 5
    assert "no composite" in result.output
    assert api == []  # refused before any request


def test_min_above_max_is_a_usage_error(api) -> None:
    assert run("--axis", "code", "--min-score", "80", "--max-score", "20").exit_code == 5


def test_limit_caps_rows_and_reports_the_total(api) -> None:
    result = run("--limit", "2")
    assert _names(result.output) == ["alpha", "bravo"]
    assert "2 of 4 shown" in result.output


def test_json_carries_weights_and_no_composite(api) -> None:
    result = run("--format", "json", "--axis", "code")
    payload = json.loads(result.output)
    assert payload["composite_published"] is False and payload["sort"] == "code_safety"
    assert payload["total_matching"] == 4
    first = payload["servers"][0]
    assert first["name"] == "io.example/delta"
    assert first["url"] == f"{BASE}/servers/io-example-delta/"
    for server in payload["servers"]:
        for axis in server["axes"].values():
            assert {"score", "assessed_weight"} <= set(axis)
            assert "composite" not in json.dumps(server)


def test_select_never_reads_null_as_zero() -> None:
    entries = INDEX["servers"]
    assert [e["name"] for e in listing.select(entries, "code_safety", 0, 100)] == [
        "io.example/delta", "io.example/bravo", "io.example/charlie",
    ]
