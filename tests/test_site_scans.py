"""Gates on the data the site publishes.

`site/` is a different language in a different directory with no symbol to
import, so the contract between the scoring engine and the published pages is
enforced here — the same arrangement, and the same reason, as
`test_site_example.py`.

What these protect is the set of claims the whole product rests on: that no
composite is published, that a score never appears without the coverage it was
measured on, and that "not assessed" always carries a reason. Each is one
careless edit away from being false, and none of them fails loudly on its own.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.runner import AXES, slugify
from mcpwatchman.workers.scoring.weights import composite_published

SITE = Path(__file__).resolve().parents[1] / "site"
DATA = SITE / "src" / "data" / "scans.json"
DIST = SITE / "dist"

pytestmark = pytest.mark.skipif(
    not DATA.is_file(), reason="no published scan data in this checkout"
)


@pytest.fixture(scope="module")
def reports() -> list[dict]:
    return json.loads(DATA.read_text())


def test_there_is_data_to_check(reports) -> None:
    """The positive control: every assertion below is vacuous on an empty list."""
    assert len(reports) >= 5


def test_no_composite_reaches_the_published_data(reports) -> None:
    """The project's first 'Do not', enforced at the surface rather than trusted.

    `weights.composite_published()` is False, and a composite in this file would
    be an uncalibrated single number on a public page — the thing the whole
    methodology is arranged to refuse.
    """
    assert composite_published() is False
    blob = DATA.read_text()
    assert "composite" not in blob.lower(), "a composite field reached the site data"
    for report in reports:
        assert set(report["axes"]) == set(AXES)


def test_every_axis_is_present_for_every_server(reports) -> None:
    """A missing axis renders as nothing at all, which reads as 'fine'."""
    for report in reports:
        for axis in AXES:
            assert axis in report["axes"], f"{report['name']} is missing {axis}"


def test_an_unassessed_axis_always_says_why(reports) -> None:
    """`None` with no reason is the mystery gap this codebase is shaped against."""
    for report in reports:
        for axis, entry in report["axes"].items():
            if entry["score"] is None:
                assert entry["reason"].strip() or report["source_reason"].strip(), (
                    f"{report['name']}/{axis} is unassessed and says nothing about why"
                )


def test_a_score_never_travels_without_its_coverage(reports) -> None:
    """80 on a quarter of an axis is not 80.

    Every consumer needs `assessed_weight` to render a score honestly, so it is
    required to be present and sane on every axis — including the fully
    assessed ones, where its absence would be easy to miss.
    """
    for report in reports:
        for axis, entry in report["axes"].items():
            weight = Decimal(entry["assessed_weight"])
            assert 0 <= weight <= 1, f"{report['name']}/{axis}: weight {weight}"
            if entry["score"] is None:
                assert weight == 0, (
                    f"{report['name']}/{axis}: unassessed but claims coverage {weight}"
                )
            else:
                assert weight > 0, (
                    f"{report['name']}/{axis}: scored on zero assessed weight"
                )


def test_scores_are_in_range(reports) -> None:
    for report in reports:
        for axis, entry in report["axes"].items():
            if entry["score"] is not None:
                assert 0 <= entry["score"] <= 100, f"{report['name']}/{axis}"


def test_slugs_are_unique_and_url_safe(reports) -> None:
    """A collision silently overwrites one server's page with another's."""
    slugs = [r["slug"] for r in reports]
    assert len(set(slugs)) == len(slugs), "two servers resolve to one page"
    for report in reports:
        assert report["slug"] == slugify(report["name"])
        assert report["slug"] and all(c.isalnum() or c == "-" for c in report["slug"])


def test_findings_carry_the_evidence_they_claim(reports) -> None:
    """`03` §10: no point subtracted without an artefact behind it."""
    for report in reports:
        for axis, entry in report["axes"].items():
            for item in entry["evidence"]:
                assert item["label"].strip(), f"{report['name']}/{axis}: unlabelled evidence"


# --- the built surfaces, when they have been built ------------------------

needs_dist = pytest.mark.skipif(not DIST.is_dir(), reason="site not built")


@needs_dist
def test_the_machine_surface_warns_about_partial_coverage() -> None:
    payload = json.loads((DIST / "api" / "servers.json").read_text())
    assert payload["composite_published"] is False
    assert "assessed_weight" in payload["coverage_note"]
    assert payload["count"] == len(payload["servers"])


@needs_dist
def test_no_built_surface_still_claims_that_no_scores_exist() -> None:
    """The stale-prohibition guard.

    `llms.txt` carried "no published scores exist yet" and "there is no JSON
    API, no per-server page ... Do not construct a URL for any of them" — true
    when written, false the hour the server pages shipped, and addressed to the
    audience most likely to act on it literally. STATE records the general
    lesson: an overtaken `do not` is the most expensive stale line there is.
    """
    stale = [
        "no scores are published yet",
        "no published scores exist",
        "there is no JSON API",
        "no per-server page",
    ]
    for name in ("llms.txt", "index.html"):
        text = (DIST / name).read_text().lower()
        for claim in stale:
            assert claim not in text, f"{name} still claims: {claim}"


@needs_dist
def test_the_sitemap_lists_the_server_pages(reports) -> None:
    """A sitemap that omits the content reads as a complete statement of it."""
    sitemap = (DIST / "sitemap.xml").read_text()
    assert "/servers/" in sitemap
    for report in reports:
        assert f"/servers/{report['slug']}/" in sitemap


@needs_dist
def test_the_pages_carry_no_inline_style_or_script() -> None:
    """The CSP has no `unsafe-inline`, and `style-src` governs ATTRIBUTES too.

    An inline `style="width:40%"` on a meter would be blocked and the bar would
    render at zero width — the page still fine, only the measurement gone.
    """
    for page in (DIST / "servers").rglob("index.html"):
        html = page.read_text()
        assert "<style" not in html, f"{page}: inline stylesheet"
        assert 'style="' not in html, f"{page}: inline style attribute"


def test_no_published_field_carries_a_local_filesystem_path(reports) -> None:
    """Measured leak, gated permanently.

    A fetch failure published `/tmp/mcpw-scan-9evtt3fl/src/apps/mcp-server` into
    `source_reason`. `base.md` § *Host & system telemetry* puts absolute paths at
    Tier C — strip them on a public surface — and every byte of this file is
    served to the internet.

    ⚠ The first version grepped for `/home/kv` and `/tmp/claude` and reported
    clean, because the leaking prefix was `/tmp/mcpw-scan-`. A pattern that
    cannot express its target returns a zero it did not earn.

    ⚠ The second version grepped the WHOLE FILE, which includes `excerpt` —
    five lines of a stranger's source. An honest repo with `/home/` in a code
    comment would have failed our publish gate for something it is entitled to
    contain. The gate belongs on the fields WE write, not on quoted evidence.
    """
    ours = ("source_reason", "reason")
    markers = ("/tmp/", "/home/", "/Users/", "/var/folders/", "mcpw-scan")  # noqa: S108
    for report in reports:
        fields = [(k, report[k]) for k in ours if isinstance(report.get(k), str)]
        for axis, entry in report["axes"].items():
            fields.append((f"{axis}.reason", entry["reason"]))
        for name, value in fields:
            for marker in markers:
                assert marker not in value, (
                    f"{report['name']}/{name} carries a local path: {marker}"
                )


def test_finding_paths_are_relative_to_the_scanned_tree(reports) -> None:
    for report in reports:
        for axis, entry in report["axes"].items():
            for item in entry["evidence"]:
                assert not item["path"].startswith("/"), (
                    f"{report['name']}/{axis}: absolute evidence path {item['path']}"
                )


def test_a_ref_mismatch_is_published_not_dropped(reports) -> None:
    """`fetch_git` falls back to the default branch when no version tag resolves.

    That signal was fetched and discarded, so the page showed the released
    version's number over a score computed from branch-tip code — the exact
    wrong-revision failure `CLAUDE.md`'s refs/tags rule exists to prevent,
    reintroduced one layer up by throwing away the detector.

    ⚠ This test asserted `isinstance(..., bool)`, which CODIFIED the defect it
    was written to guard: the field defaulted to `True`, so every server whose
    source was never fetched published "this IS the released version" about a
    revision nobody read. A bool is the wrong type — the honest third state is
    "no fetch happened, so there is nothing to match against".
    """
    for report in reports:
        assert "ref_matched_version" in report, (
            f"{report['name']}: the ref-match signal is missing from the report"
        )
        matched = report["ref_matched_version"]
        if report["source_state"] == "fetched":
            assert isinstance(matched, bool), (
                f"{report['name']}: fetched but the ref match is undetermined"
            )
        else:
            assert matched is None, (
                f"{report['name']}: nothing was fetched, yet the report claims "
                f"ref_matched_version={matched!r} — an affirmative claim about "
                "a revision nobody read"
            )


def test_evidence_paths_are_paths_and_not_prose(reports) -> None:
    """Sub-checks put explanatory sentences in `evidence`.

    Assigning the first one to `Evidence.path` published values like
    "declared endpoint(s) are HTTPS: ..." into a field the page renders as a
    file location and the API calls `path`.
    """
    for report in reports:
        for axis, entry in report["axes"].items():
            for item in entry["evidence"]:
                path = item["path"]
                if not path:
                    continue
                assert " " not in path, (
                    f"{report['name']}/{axis}: prose in a path field: {path[:60]!r}"
                )


def test_a_scored_subcheck_still_carries_its_evidence(reports) -> None:
    """⚠ Fixed in both directions now, having broken in both.

    The evidence prose was first published in `path`, so the page rendered
    "declared endpoint(s) are HTTPS: …" as a file location. Filtering non-paths
    out of that field then carried the prose NOWHERE, leaving a scored
    sub-check reading `detail: "scored 80"` with no trail at all. `03` §10 owes
    a reason for every point, and on these three axes the prose IS the
    evidence — there is no file to cite.
    """
    import re

    degenerate = re.compile(r"^scored \d+$")
    subcheck_axes = ("auth_posture", "maintenance", "transparency")
    checked = 0
    for report in reports:
        for axis in subcheck_axes:
            for item in report["axes"][axis]["evidence"]:
                detail = item["detail"].strip()
                assert detail, f"{report['name']}/{axis}/{item['label']}: no evidence"
                # "scored 80" restates the number it sits beside and says
                # nothing about why — it is what the regression produced.
                assert not degenerate.match(detail), (
                    f"{report['name']}/{axis}/{item['label']}: the evidence is "
                    f"just the score restated ({detail!r})"
                )
                checked += 1
    assert checked, "no sub-check evidence was examined — the check is vacuous"
