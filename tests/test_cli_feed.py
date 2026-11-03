"""`mcpwatchman feed` (`07` §8): Atom read defensively, missing feeds reported.

The parse refuses any DTD before the parser runs — the entity-expansion
defence — and the body must be UTF-8, so a declared foreign encoding cannot
smuggle a DOCTYPE past the screen.
"""

from __future__ import annotations

import datetime as dt

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import api as cli_api
from mcpwatchman.cli import feeds
from mcpwatchman.cli.main import cli

BASE = "https://example.test"
NOW = dt.datetime(2026, 11, 3, 12, tzinfo=dt.UTC)


def _atom(*entries: tuple[str, str, str]) -> bytes:
    body = "".join(
        f"<entry><id>{i}</id><title>{title}</title><updated>{updated}</updated>"
        f'<link rel="alternate" type="text/html" href="{href}"/></entry>'
        for i, (title, updated, href) in enumerate(entries)
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<feed xmlns="http://www.w3.org/2005/Atom"><id>x</id>{body}</feed>'
    ).encode()


HIGH = _atom(
    ("io.example/a: high finding", "2026-11-02T00:00:00Z", f"{BASE}/servers/a/#f1"),
    ("io.example/old: critical finding", "2026-10-01T00:00:00Z", f"{BASE}/servers/old/"),
)
DROPS = _atom(("io.example/b: Code Safety dropped 20", "2026-11-03T00:00:00Z", f"{BASE}/b/"))


@pytest.fixture
def served(monkeypatch):
    docs = {f"{BASE}/feed/high-severity.xml": HIGH, f"{BASE}/feed/score-drops.xml": DROPS}

    def get_bytes(url, *, cap, accept):
        assert cap == feeds.MAX_FEED_BYTES
        return docs.get(url)

    monkeypatch.setenv("MCPWATCHMAN_API_URL", BASE)
    monkeypatch.setattr(feeds, "get_bytes", get_bytes)
    monkeypatch.setattr(feeds, "_now", lambda: NOW)
    return docs


def run(*args):
    return CliRunner().invoke(cli, ["feed", *args])


def test_both_feeds_interleave_newest_first_within_the_window(served) -> None:
    result = run()
    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line[:4] == "2026"]
    assert [line.split()[1] for line in lines] == ["score-drops", "high-severity"]
    assert "io.example/old" not in result.stdout          # older than 7 days
    assert f"{BASE}/servers/a/#f1" in result.stdout


def test_days_widens_the_window(served) -> None:
    assert "io.example/old" in run("--days", "40").stdout


def test_a_missing_score_drops_feed_is_reported_and_the_other_still_read(served) -> None:
    del served[f"{BASE}/feed/score-drops.xml"]
    result = run()
    assert result.exit_code == 0
    assert "score-drops feed is not published yet" in result.stderr
    assert "io.example/a: high finding" in result.stdout


def test_only_a_missing_feed_requested_is_not_found(served) -> None:
    del served[f"{BASE}/feed/score-drops.xml"]
    result = run("--type", "score-drops")
    assert result.exit_code == cli_api.EXIT_NOT_FOUND


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
<feed xmlns="http://www.w3.org/2005/Atom"><title>&lol2;</title></feed>"""


@pytest.mark.parametrize("body", [
    BILLION_LAUGHS,
    BILLION_LAUGHS.replace(b"DOCTYPE", b"doctype"),
    b'<feed xmlns="http://www.w3.org/2005/Atom"><!ENTITY x "y"></feed>',
])
def test_any_dtd_is_refused_before_parsing(body, monkeypatch) -> None:
    def explode(*_a, **_k):
        raise AssertionError("the parser must never see a DTD")

    monkeypatch.setattr(feeds.ET, "fromstring", explode)
    with pytest.raises(cli_api.CliError) as caught:
        feeds.parse_atom(body, "u")
    assert caught.value.exit_code == cli_api.EXIT_NETWORK
    assert "DOCTYPE or ENTITY" in caught.value.message


def test_a_dtd_hidden_in_a_foreign_encoding_is_refused() -> None:
    body = BILLION_LAUGHS.replace(b'version="1.0"', b'version="1.0" encoding="utf-16"')
    with pytest.raises(cli_api.CliError, match="not UTF-8"):
        feeds.parse_atom(body.decode().encode("utf-16"), "u")


def test_a_hostile_dtd_end_to_end_exits_4(served) -> None:
    served[f"{BASE}/feed/high-severity.xml"] = BILLION_LAUGHS
    assert run().exit_code == cli_api.EXIT_NETWORK


def test_a_clean_feed_parses() -> None:
    """Positive control for the refusal tests: the screen passes a real feed."""
    entries, skipped = feeds.parse_atom(HIGH, "u")
    assert skipped == 0
    assert [e.title for e in entries] == [
        "io.example/a: high finding", "io.example/old: critical finding",
    ]
    assert entries[0].updated == dt.datetime(2026, 11, 2, tzinfo=dt.UTC)


def test_an_undated_entry_is_counted_not_silently_dropped(served) -> None:
    served[f"{BASE}/feed/high-severity.xml"] = _atom(("x", "not a date", "u"))
    result = run("--type", "high-severity")
    assert "1 high-severity entry had no readable date" in result.stderr


def test_titles_cannot_drive_the_terminal(served) -> None:
    """XML 1.0 forbids ESC itself, but not C1 CSI (U+009B) or a bidi override."""
    served[f"{BASE}/feed/high-severity.xml"] = _atom(
        ("evil&#155;2J &#8238;title", "2026-11-02T00:00:00Z", "u"),
    )
    result = run("--type", "high-severity")
    assert "\x9b" not in result.output and "\u202e" not in result.output
    assert "evil\ufffd2J \ufffdtitle" in result.output
