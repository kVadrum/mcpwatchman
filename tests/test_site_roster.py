"""The roster's search, filter and sort (`site/public/roster.js`) read only what
the built page carries, so the page must carry each server's scores exactly —
an unassessed axis as an empty attribute, never a 0 (CLAUDE.md, "Unassessed is
not zero": the script lists it last in both directions)."""

from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest

from mcpwatchman import history as h

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "site/dist"
needs_dist = pytest.mark.skipif(not DIST.is_dir(), reason="site not built")


def _rows() -> list[dict]:
    return json.loads((ROOT / "site/src/data/scans.json").read_text())


@needs_dist
def test_every_row_carries_its_scores_and_null_is_empty_not_zero() -> None:
    page = (DIST / "servers/index.html").read_text()
    items = re.findall(r"<li ([^>]*data-name=[^>]*)>", page)
    by_name = {r["name"].lower(): r for r in _rows()}
    assert len(items) == len(by_name)
    nulls = 0
    for attrs in items:
        # An empty value renders as a bare attribute, which getAttribute reads as "".
        a = {k: unescape(v) for k, v in re.findall(r'(data-[\w-]+)(?:="([^"]*)")?', attrs)}
        row = by_name[a["data-name"]]
        for axis in h.AXES:
            want = row["axes"][axis]["score"]
            shown = a[f"data-score-{axis}"]
            assert shown == ("" if want is None else str(want)), (row["slug"], axis)
            assert a[f"data-weight-{axis}"] == str(row["axes"][axis]["assessed_weight"])
            nulls += want is None
    assert nulls, "no unassessed axis in the data — the empty-attribute case went untested"


@needs_dist
def test_the_controls_ship_hidden_and_the_script_is_a_file_not_inline() -> None:
    page = (DIST / "servers/index.html").read_text()
    assert re.search(r'<div class="roster-controls" hidden', page)
    assert re.search(r'<script type="module" src="/roster\.js"', page)
    assert (DIST / "roster.js").is_file()

