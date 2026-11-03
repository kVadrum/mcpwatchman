"""The built history surfaces agree with the data they are derived from:
`/api/servers/<slug>/history.json` and `/feed/score-drops.xml`."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from mcpwatchman import history as h

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "site/src/data"
DIST = ROOT / "site/dist"
ATOM = "{http://www.w3.org/2005/Atom}"

needs_dist = pytest.mark.skipif(not DIST.is_dir(), reason="site not built")


def _rows() -> list[dict]:
    return json.loads((DATA / "scans.json").read_text())


@needs_dist
def test_every_page_has_a_history_ending_on_the_scan_it_shows() -> None:
    for row in _rows():
        doc = json.loads((DIST / "api/servers" / row["slug"] / "history.json").read_text())
        points = doc["points"]
        assert points, row["slug"]
        assert points[-1]["scanned_at"] == row["scanned_at"], row["slug"]
        assert [p["scanned_at"] for p in points] == sorted(p["scanned_at"] for p in points)
        assert len({p["date"] for p in points}) == len(points), "one point per day"
        for p in points:
            assert set(p["axes"]) == set(h.AXES)
            for axis in p["axes"].values():
                assert set(axis) == {"score", "assessed_weight", "fault"}


@needs_dist
def test_the_drops_feed_is_the_python_derivation_and_never_maintenance() -> None:
    hist = json.loads((DATA / "history.json").read_text())
    published = {r["slug"] for r in _rows()}
    expected = [d for d in hist["drops"] if d["slug"] in published][:100]
    feed = ET.parse(DIST / "feed/score-drops.xml").getroot()  # noqa: S314 - our own build output
    entries = feed.findall(f"{ATOM}entry")
    assert len(entries) == len(expected)
    for entry, drop in zip(entries, expected, strict=True):
        title = entry.findtext(f"{ATOM}title") or ""
        assert f"fell {drop['before']} → {drop['after']}" in title
        assert "measured" in title  # the share travels with the score
        assert drop["axis"] != "maintenance"
        assert entry.findtext(f"{ATOM}updated") == drop["scanned_at"]


@needs_dist
def test_agents_are_pointed_at_both_new_surfaces_and_told_nothing_is_unbuilt() -> None:
    llms = (DIST / "llms.txt").read_text()
    assert "/feed/score-drops.xml" in llms and "/history.json" in llms
    assert "NOT BUILT" not in llms


def test_feeds_are_served_as_atom() -> None:
    headers = (ROOT / "site/public/_headers").read_text()
    block = headers.split("/feed/*", 1)[1].split("\n\n", 1)[0]
    assert "application/atom+xml" in block


@needs_dist
def test_every_page_with_two_scans_draws_one_trace_per_axis_with_a_reading() -> None:
    import re

    for row in _rows():
        doc = json.loads((DIST / "api/servers" / row["slug"] / "history.json").read_text())
        page = (DIST / "servers" / row["slug"] / "index.html").read_text()
        if len(doc["points"]) < 2:
            assert 'class="record"' not in page
            continue
        section = page.split('class="record"', 1)[1].split("</section>", 1)[0]
        labels = re.findall(r'class="trace-plot"[^>]*aria-label="([^"]+)"', section)
        assert len(labels) == len(h.AXES), row["slug"]
        assert all(f"{len(doc['points'])} recorded scans" in label for label in labels)
        assert f'/api/servers/{row["slug"]}/history.json' in section


def _block(path: str) -> str:
    headers = (ROOT / "site/public/_headers").read_text()
    return headers.split(f"\n{path}\n", 1)[1].split("\n\n", 1)[0]


def test_the_public_api_and_feeds_are_readable_from_any_origin_without_credentials() -> None:
    headers = (ROOT / "site/public/_headers").read_text()
    for path in ("/api/*", "/feed/*"):
        assert "Access-Control-Allow-Origin: *" in _block(path), path
    rules = [line.strip() for line in headers.splitlines() if not line.strip().startswith("#")]
    assert not [r for r in rules if r.lower().startswith("access-control-allow-credentials")]
    assert "Cross-Origin-Resource-Policy: cross-origin" in _block("/badge/*")
