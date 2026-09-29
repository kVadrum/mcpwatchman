"""`mcpwatchman check` against the static API (`07` §3).

The network is stubbed at `get_json`, the one function that touches it, so
these pin what the CLI does with an answer: which URL it asks, what it prints,
and — the part a CI pipeline depends on — which `07` §3.5 exit code it returns.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import check as chk
from mcpwatchman.cli.main import cli

BASE = "https://example.test"


def _server(**overrides):
    axes = {
        "code_safety": {"score": 95, "assessed_weight": "1", "fault": None, "reason": ""},
        "auth_posture": {"score": 80, "assessed_weight": "0.25", "fault": None, "reason": ""},
        "dependency_health": {
            "score": None, "assessed_weight": "0", "fault": "publisher",
            "reason": "no lockfile in the fetched source",
        },
        "maintenance": {"score": 70, "assessed_weight": "0.45", "fault": None, "reason": ""},
        "transparency": {"score": 40, "assessed_weight": "1", "fault": None, "reason": ""},
    }
    record = {
        "name": "io.example/tool", "slug": "io-example-tool", "version": "1.2.0",
        "scanned_at": "2026-09-21T06:00:00+00:00", "methodology_version": "0.2.0",
        "registry_state": "listed", "registry_note": "", "axes": axes,
    }
    record.update(overrides)
    return {"server": record}


INDEX = {
    "servers": [
        {"name": "io.example/tool", "slug": "io-example-tool",
         "package": "npm:@example/tool@1.2.0", "repository_url": "https://github.com/Example/Tool"},
        {"name": "io.example/py", "slug": "io-example-py",
         "package": "pypi:Example_Py@0.3", "repository_url": ""},
    ]
}


@pytest.fixture
def api(monkeypatch):
    """A fake API: URL → document. Records every URL asked."""
    docs = {
        f"{BASE}/api/servers/io-example-tool.json": _server(),
        f"{BASE}/api/servers/io-example-py.json": _server(
            name="io.example/py", slug="io-example-py",
        ),
        f"{BASE}/api/index.json": INDEX,
    }
    asked: list[str] = []

    def get_json(url):
        asked.append(url)
        return docs.get(url)

    monkeypatch.setenv("MCPWATCHMAN_API_URL", BASE)
    monkeypatch.setattr(chk, "get_json", get_json)
    return asked


def run(*args):
    return CliRunner().invoke(cli, ["check", *args])


def test_a_registry_name_is_one_request_to_its_own_record(api) -> None:
    result = run("io.example/tool")
    assert result.exit_code == 0, result.output
    assert api == [f"{BASE}/api/servers/io-example-tool.json"]
    assert "Code Safety" in result.output
    assert "measured 25%" in result.output  # the weight travels with the score
    assert "not assessed — no lockfile" in result.output
    assert "No composite score" in result.output


def test_json_carries_no_score_without_its_weight(api) -> None:
    """`07` §3.3's sample had a bare `scores` map; CLAUDE.md's later rule wins."""
    result = run("io.example/tool", "--format", "json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["composite_score"] is None and payload["composite_published"] is False
    assert "scores" not in payload
    for axis in payload["axes"].values():
        assert set(axis) >= {"score", "assessed_weight"}
    assert payload["axes"]["auth_posture"] == {
        "score": 80, "assessed_weight": "0.25", "fault": None, "reason": "",
    }


def test_compact_is_one_line_with_weights(api) -> None:
    result = run("io-example-tool", "--format", "compact")
    assert result.exit_code == 0
    assert result.output.strip().count("\n") == 0
    assert "auth=80@0.25" in result.output and "deps=null" in result.output


@pytest.mark.parametrize(
    ("query", "slug"),
    [
        ("@example/tool", "io-example-tool"),              # npm name
        ("example-py", "io-example-py"),                   # PyPI, PEP 503-normalised
        ("https://github.com/example/tool.git", "io-example-tool"),  # repo URL
    ],
)
def test_package_names_and_repo_urls_resolve_through_the_index(api, query, slug) -> None:
    result = run(query, "--format", "compact")
    assert result.exit_code == 0, result.output
    assert api[-1] == f"{BASE}/api/servers/{slug}.json"
    assert f"{BASE}/api/index.json" in api


def test_not_published_is_exit_1_and_says_absence_is_not_a_judgement(api) -> None:
    result = run("io.example/unknown")
    assert result.exit_code == chk.EXIT_NOT_FOUND
    assert "not a judgement" in result.output


def test_a_version_we_do_not_hold_is_not_found(api) -> None:
    result = run("io.example/tool", "--version", "9.9.9")
    assert result.exit_code == chk.EXIT_NOT_FOUND
    assert "is for version 1.2.0" in result.output


def test_threshold_is_a_noop_with_a_notice_until_the_composite_ships(api) -> None:
    """`07` §14.1 — never a silent pass that reads as a real comparison."""
    result = run("io.example/tool", "--threshold", "99")
    assert result.exit_code == 0
    assert "--threshold is disabled" in result.output


def test_a_usage_error_is_5_never_2(api) -> None:
    """Exit 2 means "below threshold" to a CI pipeline; a typo must not look like it."""
    result = run("io.example/tool", "--format", "bogus")
    assert result.exit_code == 5


def test_a_network_failure_is_4(monkeypatch) -> None:
    def down(url):
        raise chk.CheckError(f"could not reach {url}", chk.EXIT_NETWORK)

    monkeypatch.setattr(chk, "get_json", down)
    result = run("io.example/tool")
    assert result.exit_code == chk.EXIT_NETWORK


def test_a_non_listed_server_shows_its_registry_note(api, monkeypatch) -> None:
    """Anything other than `listed` explains itself — on this surface too."""
    record = _server(registry_state="delisted", registry_note="no longer listed since 2026-09-20")
    monkeypatch.setattr(chk, "get_json", lambda url: record)
    result = run("io.example/tool")
    assert "Registry: delisted — no longer listed since 2026-09-20" in result.output


def test_the_bar_draws_three_regions() -> None:
    """Scored, lost, never measured — the site's meter in text."""
    assert chk._bar(50, 0.5, unicode_ok=False) == "#####-----" + "/" * 10
    assert chk._bar(None, 0.0, unicode_ok=False) == "/" * 20


def test_the_api_override_refuses_a_non_http_scheme(monkeypatch) -> None:
    """`urlopen` honours `file:`; an override must not turn scans into local reads."""
    monkeypatch.setenv("MCPWATCHMAN_API_URL", "file:///etc")
    result = run("io.example/tool")
    assert result.exit_code == 5
    assert "http(s)" in result.output
