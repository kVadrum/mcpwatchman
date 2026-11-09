"""The reference pages and the badge must agree with the engine that scores.

`site/src/lib/methodology.json` holds every weight, deduction and band the
methodology pages print, because Astro cannot import Python. That makes it a
copy, and a copy of a scoring constant on a public page is the drift
`tests/test_site_example.py` exists for: change the table, and the page keeps
publishing the old one with nothing failing. So every value is compared here
with the constant it copies.

The badge is checked against the published data directly: it is the one
surface that leaves this site and sits in other people's READMEs, where a
wrong number cannot be corrected, and `06` §2's original design (a composite
badge) is exactly the number this project withholds.
"""

from __future__ import annotations

import json
import re
from decimal import ROUND_FLOOR, Decimal
from pathlib import Path
from xml.etree import ElementTree

import pytest

from mcpwatchman import store
from mcpwatchman.workers.scanner import (
    auth_check,
    forge,
    maintenance_check,
    osv_check,
    transparency_check,
)
from mcpwatchman.workers.scanner.runner import MAX_EVIDENCE_PER_AXIS
from mcpwatchman.workers.scoring import composite, weights

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
METHOD = SITE / "src" / "lib" / "methodology.json"
DATA = SITE / "src" / "data" / "scans.json"
DIST = SITE / "dist"
SVG = "{http://www.w3.org/2000/svg}"

pytestmark = pytest.mark.skipif(not METHOD.is_file(), reason="site/ not present in this checkout")
needs_dist = pytest.mark.skipif(not DIST.is_dir(), reason="site not built")

# The reference pages, listed here independently of `site/src/lib/pages.ts`:
# a page dropped from that list must fail this test, not shrink it.
DOC_PAGES = [
    "/methodology/",
    "/methodology/code-safety/",
    "/methodology/auth-posture/",
    "/methodology/maintenance/",
    "/methodology/dependency-health/",
    "/methodology/transparency/",
    "/disclosure/",
    "/about/",
    "/api/",
    "/cli/",
]


@pytest.fixture(scope="module")
def m() -> dict:
    return json.loads(METHOD.read_text())


@pytest.fixture(scope="module")
def reports() -> list[dict]:
    return store.read_reports(DATA)


# ── methodology.json equals the engine ─────────────────────────────────────


def test_versions_and_gates_match_the_engine(m) -> None:
    version = weights.CURRENT_METHODOLOGY_VERSION
    assert m["methodology_version"] == version
    assert m["composite_published"] is weights.composite_published(version)
    assert m["ruleset_calibrated"] is weights.ruleset_calibrated(version)
    assert m["confidence_ceiling"] == weights.confidence_ceiling(version)
    assert m["evidence_cap_per_axis"] == MAX_EVIDENCE_PER_AXIS


def test_axis_weights_match_the_engine(m) -> None:
    engine = weights.weights_for()
    site = {a["key"]: Decimal(a["weight"]) for a in m["axes"]}
    assert site == {k: Decimal(str(v)) for k, v in engine.items()}
    assert len(m["axes"]) == len(engine), "an axis is listed twice"


def test_subcheck_weights_match_the_engine(m) -> None:
    site_axes = m["subcheck_weights"]
    engine_axes = weights.SUBCHECK_WEIGHTS[weights.CURRENT_METHODOLOGY_VERSION]
    assert set(site_axes) == set(engine_axes)
    for axis, rows in site_axes.items():
        site = {r["key"]: Decimal(r["weight"]) for r in rows}
        engine = {k: Decimal(str(v)) for k, v in weights.subcheck_weights_for(axis).items()}
        assert site == engine, axis


def test_code_safety_deductions_match_the_engine(m) -> None:
    Sev, Conf = composite.Severity, composite.Confidence
    rows = {r["severity"]: r for r in m["code_safety_deductions"]}
    assert set(rows) == {s.value for s in Sev}, "a severity is missing from the page"
    for sev in Sev:
        row = rows[sev.value]
        if "any" in row:
            for conf in Conf:
                assert composite.deduction_for(sev, conf) == row["any"], (sev, conf)
        else:
            assert composite.deduction_for(sev, Conf.HIGH) == row["high"], sev
            assert composite.deduction_for(sev, Conf.MEDIUM) == row["medium"], sev
            # The page says low confidence deducts at the row's floor.
            assert composite.deduction_for(sev, Conf.LOW) == min(row["high"], row["medium"]), sev


def test_dependency_deductions_and_cvss_bands_match_the_engine(m) -> None:
    rows = m["dependency_deductions"]
    assert {r["severity"] for r in rows} == {s.value for s in osv_check.DEDUCTIONS}
    for r in rows:
        engine = osv_check.DEDUCTIONS[composite.Severity(r["severity"])]
        assert (r["direct"], r["transitive"]) == (engine["direct"], engine["transitive"]), r
    bands = {sev.value: floor for floor, sev in osv_check._CVSS_BANDS}
    assert {r["severity"]: Decimal(r["cvss_min"]) for r in rows} == bands


def test_the_stacking_ladder_matches_the_engine(m) -> None:
    assert tuple(Decimal(x) for x in m["stacking"]) == composite._STACKING
    assert Decimal(m["stacking_tail"]) == composite._STACKING_TAIL


def test_maintenance_bands_and_fetch_bounds_match_the_engine(m) -> None:
    b = m["maintenance_bands"]
    assert tuple(map(tuple, b["recency_days"])) == maintenance_check.RECENCY_DAYS
    assert tuple(map(tuple, b["release_gap_days"])) == maintenance_check.RELEASE_GAP_DAYS
    assert tuple(map(tuple, b["issue_response_days"])) == maintenance_check.ISSUE_RESPONSE_DAYS
    assert b["recent_release_days"] == maintenance_check.RECENT_RELEASE_DAYS
    assert b["issue_sample_min"] == maintenance_check.ISSUE_SAMPLE_MIN
    assert b["bus_factor_min_commits"] == maintenance_check.BUS_FACTOR_MIN_COMMITS
    assert b["bus_factor_stale_days"] == maintenance_check.BUS_FACTOR_STALE_DAYS
    f = m["forge_bounds"]
    assert f["issue_sample_size"] == forge.ISSUE_SAMPLE_SIZE
    assert f["tag_sample_size"] == forge.TAG_SAMPLE_SIZE
    assert f["commit_page_size"] == forge.COMMIT_PAGE_SIZE
    assert f["max_commit_pages"] == forge.MAX_COMMIT_PAGES


def test_transparency_and_auth_thresholds_match_the_engine(m) -> None:
    assert m["readme_min_bytes"] == transparency_check.README_MIN_BYTES
    assert m["readme_intro_words"] == transparency_check.INTRO_WORDS
    assert m["granularity_tool_threshold"] == auth_check.GRANULARITY_TOOL_THRESHOLD


def _band(m: dict, score: int) -> str:
    for band in m["color_bands"]:  # descending by floor
        if score >= band["min"]:
            return band["name"]
    raise AssertionError(f"no colour band for {score}")


def test_the_badge_colour_bands_are_the_methodologys(m) -> None:
    """`06` §2's thresholds are `03` §8's, and `composite.color` is their home.
    Every integer is checked, so a boundary moved by one fails here."""
    floors = [b["min"] for b in m["color_bands"]]
    assert floors == sorted(floors, reverse=True) and floors[-1] == 0
    for score in range(0, 101):
        assert _band(m, score) == composite.color(score), score


# ── the built reference pages ──────────────────────────────────────────────


def _page(path: str) -> Path:
    return DIST / path.strip("/") / "index.html"


@needs_dist
def test_every_reference_page_is_built_and_indexed() -> None:
    sitemap = (DIST / "sitemap.xml").read_text()
    llms = (DIST / "llms.txt").read_text()
    for path in DOC_PAGES:
        assert _page(path).is_file(), f"{path} was not built"
        url = f"https://mcpwatchman.com{path}"
        assert f"<loc>{url}</loc>" in sitemap, f"{path} missing from sitemap.xml"
        assert f"({url})" in llms, f"{path} missing from llms.txt"


@needs_dist
def test_no_built_reference_page_is_left_out_of_the_index() -> None:
    """The other direction: a page added under these sections and forgotten in
    `pages.ts` would be built, reachable and absent from both indexes."""
    built = {
        "/" + p.parent.relative_to(DIST).as_posix() + "/"
        for section in ("methodology", "disclosure", "about", "api", "cli")
        for p in (DIST / section).rglob("index.html")
        if not p.relative_to(DIST).as_posix().startswith("api/servers")
    }
    assert built, "no reference pages built — the gate would pass vacuously"
    assert built <= set(DOC_PAGES), f"built but unlisted: {sorted(built - set(DOC_PAGES))}"


@needs_dist
def test_the_methodology_pages_print_the_engines_weights(m) -> None:
    overview = _page("/methodology/").read_text()
    for axis in m["axes"]:
        pct = int(Decimal(axis["weight"]) * 100)
        page = _page(f"/methodology/{axis['slug']}/").read_text()
        assert f"Provisional weight {pct}%" in page, axis["key"]
        assert f"{pct}%</td>" in overview, axis["key"]
    code = _page("/methodology/code-safety/").read_text()
    for row in m["code_safety_deductions"]:
        if "any" not in row:
            assert f"−{row['medium']}</td>" in code, row


@needs_dist
def test_every_page_links_the_reference_pages_from_its_footer() -> None:
    for page in (DIST / "index.html", _page("/servers/"), _page("/methodology/")):
        nav = re.search(r'<nav class="site-foot-nav"[^>]*>(.*?)</nav>', page.read_text(), re.S)
        assert nav, f"{page}: no reference nav in the footer"
        for path in ("/methodology/", "/disclosure/", "/api/", "/cli/", "/about/"):
            assert f'href="{path}"' in nav.group(1), f"{page}: footer lacks {path}"


# ── the badge ──────────────────────────────────────────────────────────────


def _measured(weight: str) -> int:
    return int((Decimal(weight) * 100).to_integral_value(rounding=ROUND_FLOOR))


def _expected(m: dict, report: dict) -> tuple[str, str]:
    """(right-hand text, colour) for one report, by `lib/badge.ts`'s rule."""
    if report["registry_state"] == "delisted":
        return "delisted", "grey"
    scored = [a for a in m["axes"] if report["axes"][a["key"]]["score"] is not None]
    if not scored:
        return "not scored", "grey"
    # min() keeps the first of equal scores, which is AXES order — the badge's.
    lowest = min(scored, key=lambda a: report["axes"][a["key"]]["score"])
    axis = report["axes"][lowest["key"]]
    pct = _measured(axis["assessed_weight"])
    text = f"{lowest['label'].lower()} {axis['score']}"
    text += f" ({pct}% measured)" if pct < 100 else ""
    return text, _band(m, axis["score"])


def _contrast(a: str, b: str) -> float:
    def lum(h: str) -> float:
        c = [int(h.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]

    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_the_lowest_axis_rule_on_constructed_reports(m) -> None:
    """The selection rule on cases the live data may not hold today: a tie,
    a partial axis, nothing scored, a delisted server."""

    def report(scores: dict[str, tuple[int | None, str]], state: str = "listed") -> dict:
        axes = {a["key"]: {"score": None, "assessed_weight": "0"} for a in m["axes"]}
        for key, (score, weight) in scores.items():
            axes[key] = {"score": score, "assessed_weight": weight}
        return {"registry_state": state, "axes": axes}

    assert _expected(m, report({"transparency": (33, "1"), "code_safety": (90, "1")})) == (
        "transparency 33", "red")
    assert _expected(m, report({"maintenance": (60, "1"), "auth_posture": (60, "1")})) == (
        "auth posture 60", "yellow")  # tie: the first in axis order
    assert _expected(m, report({"auth_posture": (80, "0.25")})) == (
        "auth posture 80 (25% measured)", "green")
    assert _expected(m, report({"code_safety": (40, "0.999")})) == (
        "code safety 40 (99% measured)", "orange")  # coverage rounds DOWN
    assert _expected(m, report({})) == ("not scored", "grey")
    assert _expected(m, report({"code_safety": (100, "1")}, "delisted")) == ("delisted", "grey")


@needs_dist
def test_every_server_has_a_badge_naming_its_lowest_axis(m, reports) -> None:
    assert reports, "no published data — the gate would pass vacuously"
    for report in reports:
        path = DIST / "badge" / f"{report['slug']}.svg"
        assert path.is_file(), f"no badge for {report['name']}"
        root = ElementTree.fromstring(path.read_text())  # noqa: S314 - our own build output
        texts = [t.text for t in root.iter(f"{SVG}text")]
        assert texts[0] == "mcpwatchman", path.name
        want_text, want_colour = _expected(m, report)
        assert texts[1] == want_text, f"{path.name}: {texts[1]!r} != {want_text!r}"
        coloured = [r for r in root.iter(f"{SVG}rect") if r.get("data-colour")]
        assert len(coloured) == 1 and coloured[0].get("data-colour") == want_colour, path.name


@needs_dist
def test_no_badge_publishes_the_composite(m, reports) -> None:
    """The only numbers a badge may print are one axis's score and its measured
    share; and the title says the composite is not published."""
    for report in reports:
        svg = (DIST / "badge" / f"{report['slug']}.svg").read_text()
        root = ElementTree.fromstring(svg)  # noqa: S314 - our own build output
        value = [t.text for t in root.iter(f"{SVG}text")][1]
        allowed = set()
        scored = {k: a for k, a in report["axes"].items() if a["score"] is not None}
        for a in scored.values():
            allowed |= {str(a["score"]), str(_measured(a["assessed_weight"]))}
        assert set(re.findall(r"\d+", value)) <= allowed, f"{report['slug']}: {value!r}"
        if len(scored) == len(m["axes"]):
            total = composite.composite_score({k: a["score"] for k, a in scored.items()})
            lowest = min(a["score"] for a in scored.values())
            if total != lowest:
                assert str(total) not in re.findall(r"\d+", value), report["slug"]
        title = root.find(f"{SVG}title").text
        assert "No composite score is published" in title
        for axis in m["axes"]:
            assert axis["label"] in title, f"{report['slug']}: title omits {axis['label']}"


@needs_dist
def test_badges_are_self_contained_and_legible(reports) -> None:
    """No script, no style, no external reference — the CSP on `/*` is
    `default-src 'none'` — and every text run meets AA against its fill."""
    for report in reports:
        svg = (DIST / "badge" / f"{report['slug']}.svg").read_text()
        root = ElementTree.fromstring(svg)  # noqa: S314 - our own build output
        tags = {el.tag.removeprefix(SVG) for el in root.iter()}
        allowed_tags = {"svg", "title", "clipPath", "rect", "g", "text"}
        assert tags <= allowed_tags, f"{report['slug']}: {tags}"
        attrs = {name for el in root.iter() for name in el.attrib}
        # An attribute check, not a substring one: a server's NAME is in the
        # title, and one published server is called `com.hreflangly/site`.
        assert not {a for a in attrs if a.endswith("href") or a == "style"}, report["slug"]
        fills = [r.get("fill") for r in root.iter(f"{SVG}rect")][1:]  # skip the clip rect
        inks = [t.get("fill") for t in root.iter(f"{SVG}text")]
        assert len(fills) == len(inks) == 2
        for fill, ink in zip(fills, inks, strict=True):
            assert _contrast(fill, ink) >= 4.5, f"{report['slug']}: {ink} on {fill}"


def test_the_badge_is_served_as_an_svg_cached_for_an_hour() -> None:
    headers = (SITE / "public" / "_headers").read_text()
    block = re.search(r"^/badge/\*\n((?:[ \t]+.*\n)+)", headers, re.M)
    assert block, "no /badge/* rule in _headers"
    rules = block.group(1)
    assert re.search(r"Content-Type: image/svg\+xml", rules)
    assert re.search(r"Cache-Control: public, max-age=3600\b", rules)


@needs_dist
def test_every_server_page_offers_its_badge(reports) -> None:
    for report in reports:
        slug = report["slug"]
        html = (DIST / "servers" / slug / "index.html").read_text()
        embed = (
            f"[![mcpwatchman](https://mcpwatchman.com/badge/{slug}.svg)]"
            f"(https://mcpwatchman.com/servers/{slug}/)"
        )
        assert embed in html, f"{slug}: no badge embed"
