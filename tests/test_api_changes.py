"""Announced API changes keep their notice, and paging does what it promises.

`site/src/data/api-changes.json` is the one home for an announced change to
the JSON API: the `/api/` page, `/feed/api.xml` and the `api_changes` field of
every JSON response render it (operator ruling 2026-11-16). A breaking change
is announced at least 30 days ahead. The publication gate that refuses a
published set larger than one page before then lives in `test_site_scans.py`,
because the nightly runs that file.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import date
from pathlib import Path

import pytest

from mcpwatchman import store
from mcpwatchman.cohort import published_limit

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
CHANGES = SITE / "src" / "data" / "api-changes.json"
ASTRO = SITE / "node_modules" / ".bin" / "astro"
NOTICE_DAYS = {"additive": 0, "breaking": 30}
BASE = "https://mcpwatchman.com/"


def _changes() -> dict:
    return json.loads(CHANGES.read_text())


@pytest.mark.parametrize("change", _changes()["changes"], ids=lambda c: c["id"])
def test_an_announced_change_gives_the_notice_its_level_requires(change: dict) -> None:
    announced = date.fromisoformat(change["announced"])
    not_before = date.fromisoformat(change["not_before"])
    assert (not_before - announced).days >= NOTICE_DAYS[change["level"]]


def test_every_change_states_what_it_is() -> None:
    ids = [c["id"] for c in _changes()["changes"]]
    assert len(set(ids)) == len(ids)
    for change in _changes()["changes"]:
        assert change["level"] in NOTICE_DAYS
        assert change["status"] in {"announced", "landed"}
        assert change["title"] and change["summary"] and change["points"]
        # The date is the notice: re-dating `not_before` must carry the summary.
        assert change["not_before"] in change["summary"], change["id"]


def test_the_paging_notice_promises_the_page_size_the_site_uses() -> None:
    """The notice is prose; the paging reads `page_size`. A page size changed
    in one and not the other would announce one thing and ship another."""
    changes = _changes()
    paging = next(c for c in changes["changes"] if c["id"] == "servers-json-pages")
    size = changes["page_size"]
    assert isinstance(size, int) and size > 0
    text = " ".join([paging["summary"], *paging["points"]])
    assert f"first {size} servers" in paging["summary"]
    assert f"{size} servers per page" in text


def test_the_paging_change_cannot_land_before_what_landing_owes() -> None:
    """A tripwire. While the change is announced, the page limit keeps every
    record on page 1, which keeps four sentences true that landing makes false:
    the notice's own "every server published today fits on page 1", the
    homepage's "as one file", and its schema.org Dataset naming
    /api/servers.json as the whole download. Nothing would tell a reader it
    landed either: /api/ prints no status, and the feed entry's <updated> stays
    the announcement date. Rewrite those with the flip, then this test."""
    paging = next(c for c in _changes()["changes"] if c["id"] == "servers-json-pages")
    assert paging["status"] == "announced", (
        "landing the paging change owes: the notice's summary and points, the "
        "homepage's 'as one file' link and Dataset distribution "
        "(site/src/pages/index.astro), a status on /api/ and a landing date as "
        "the feed entry's <updated>"
    )


@pytest.mark.parametrize(("status", "not_before", "limit"), [
    ("announced", "2026-11-17", 500),  # the date alone does not land it
    ("landed", "2026-11-18", 500),     # nor the flag before the notice has run
    ("landed", "2026-11-17", None),    # both: no limit, from that day on
])
def test_the_page_limit_lifts_only_when_the_change_has_landed_and_its_notice_run(
    status: str, not_before: str, limit: int | None,
) -> None:
    changes = {"page_size": 500, "changes": [
        {"id": "servers-json-pages", "status": status, "not_before": not_before}]}
    assert published_limit(changes, date(2026, 11, 17)) == limit


@pytest.mark.skipif(not ASTRO.exists(), reason="needs the site's installed deps (CI's `site` job)")
def test_a_reader_following_next_gets_every_record_once_in_order(tmp_path: Path) -> None:
    """At 492 servers and 500 a page there is one page, so the paging path
    never runs in the real build. A real build of a repo-shaped copy with a
    page size small enough for ten pages or more runs it, page numbers of two
    digits included (sorted as text, `10.json` comes before `2.json`)."""
    for entry in ROOT.iterdir():
        if entry.name not in {"site", ".git"}:
            (tmp_path / entry.name).symlink_to(entry)
    site = tmp_path / "site"
    shutil.copytree(SITE, site, symlinks=True,
                    ignore=shutil.ignore_patterns("node_modules", "dist", ".astro", ".wrangler"))
    (site / "node_modules").symlink_to(SITE / "node_modules")
    reports = store.read_reports(site / "src" / "data" / "scans.json")
    size = 45
    assert len(reports) > 9 * size, "the copy needs ten pages or more to mean anything"
    changes = _changes()
    changes["page_size"] = size
    (site / "src" / "data" / "api-changes.json").write_text(json.dumps(changes))

    proc = subprocess.run(  # noqa: S603 - fixed executable, this test's own copy
        [str(ASTRO), "build"], cwd=site, capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]

    dist = site / "dist"
    pages, url = [], f"{BASE}api/servers.json"
    while url:
        assert len(pages) < 100
        pages.append(json.loads((dist / url.removeprefix(BASE)).read_text()))
        url = pages[-1]["next"]
    expected_pages = -(-len(reports) // size)
    assert len(pages) == expected_pages
    assert [len(p["servers"]) for p in pages] == \
        [size] * (expected_pages - 1) + [len(reports) - size * (expected_pages - 1)]
    assert all(p["count"] == len(reports) and p["page_count"] == expected_pages for p in pages)
    assert [s for p in pages for s in p["servers"]] == reports
    assert all("api_changes" in p and "pages_note" in p for p in pages)
    assert sorted(f.name for f in (dist / "api" / "pages" / "servers").glob("*.json")) == \
        sorted(f"{n}.json" for n in range(2, expected_pages + 1))
