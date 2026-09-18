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

import ast
import json
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.runner import AXES, slugify
from mcpwatchman.workers.scoring.weights import composite_published

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
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


def test_a_coverage_claim_is_quantized_and_never_rounds_up(reports) -> None:
    """A coverage figure is the one value this project rounds DOWN.

    ⚠ **THIS WAS LIVE ON THE SITE.** Two servers published an
    `assessed_weight` of 28 significant digits — `0.8636363636363636363636363636`
    — because one coverage claim was computed by an ad-hoc division instead of
    through the convention `semgrep_check` states at length. It surfaced only
    when a wider cohort produced a server with 4,155 dependency findings, the
    first non-terminating division; at 40 servers that axis was scored once and
    divided evenly.

    Two decimal places, and `03`'s direction is down: 4110 of 4155 rounds UP to
    0.99 and, two findings later, to 1.00 — which publishes a partly-measured
    axis as fully measured, and the site keys its partly-measured banner on
    `Number(w) < 1`, so the over-claim erases its own disclosure.
    """
    for report in reports:
        for axis, entry in report["axes"].items():
            weight = entry["assessed_weight"]
            _, _, places = weight.partition(".")
            assert len(places) <= 2, (
                f"{report['name']}/{axis}: coverage {weight} is unquantized — "
                "a published claim, not an intermediate value"
            )
            # And it must be a real fraction, not a rounded-up 1.
            assert Decimal("0") <= Decimal(weight) <= Decimal("1")


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


def test_a_deduction_is_never_published_without_its_evidence(reports) -> None:
    """`03` §10: no point subtracted without an artefact — asserted, not trusted.

    ⚠ **WRITTEN BECAUSE THE SUITE PASSED THROUGH A DEFECT THAT EMPTIED THIS
    FIELD ON EVERY SCORED AXIS.** `AxisScore` gained a fifth field and two
    construction sites passed `evidence` positionally, so the evidence tuple
    landed in `fault` and the evidence went empty — on Code Safety and
    Dependency Health, the only two axes that carry findings. 830 tests were
    green: `test_findings_carry_the_evidence_they_claim` iterates the evidence
    list, and iterating an empty list asserts nothing. mypy caught it and
    nothing else did.

    The invariant that is not vacuous: an axis opens at 100, so a score BELOW
    100 means a deduction was taken, and a deduction comes from a finding that
    carries a file and a line. No findings means no deduction means 100 — the
    two are the same statement, which is why the absence of evidence at 100 is
    correct and its absence below 100 is the product's central claim failing.
    """
    findings_axes = ("code_safety", "dependency_health")
    checked = 0
    for report in reports:
        for axis in findings_axes:
            entry = report["axes"][axis]
            if entry["score"] is None or entry["score"] >= 100:
                continue
            checked += 1
            assert entry["evidence"], (
                f"{report['name']}/{axis} scored {entry['score']} — a deduction "
                "was taken — and publishes no evidence for it"
            )
    assert checked, (
        "no deducted axis was examined; this check cannot report a failure on "
        "this corpus and proves nothing about it"
    )


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

    ⚠ EVERY BUILT PAGE, not just `dist/servers/`. `public/_headers` sets the
    policy on `/*`, so the homepage is governed identically — and it was the
    one built page this gate did not glob. Found 2026-09-18 by controlling the
    gate rather than trusting it: an injected `style="margin:0"` in
    `dist/index.html` left it GREEN. A gate named for "the pages" that reads
    492 of 494 is the shape this suite keeps paying for, and the miss is
    invisible because the assertion it does run passes honestly.
    """
    pages = sorted(DIST.rglob("*.html"))
    assert pages, "no built pages to check — the gate would pass vacuously"
    for page in pages:
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
        assert matched in (True, False, None)
        if report["source_state"] != "fetched":
            assert matched is None, (
                f"{report['name']}: nothing was fetched, yet the report claims "
                f"ref_matched_version={matched!r} — an affirmative claim about "
                "a revision nobody read"
            )
        # ⚠ A SUCCESSFUL FETCH DOES NOT IMPLY A BOOL, and asserting that was
        # this test's second wrong contract. Only a GIT fetch resolves a ref;
        # an npm or PyPI fetch succeeds having established nothing about one,
        # so `None` is the honest answer there too. The earlier version
        # required a bool whenever `source_state == "fetched"`, which is the
        # same fail-open the field itself had — 18 of 40 servers reported
        # `true` purely because a dict lookup missed.


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


def test_a_package_failure_is_never_published_as_a_repository_failure(reports) -> None:
    """A false public statement about a named third party, measured live.

    An npm 404 sets `source_state = "unreachable"`, and four surfaces re-expressed
    that as "declares a repository nobody can read" — including for a server
    whose GitHub repository resolves perfectly well. Its own page said "package"
    correctly while the roster, the homepage tally and `llms.txt` said
    "repository": mcpwatchman.com contradicted itself about someone else's
    project. `08-disclosure-policy.md` requires factual, never defamatory.

    One judgement, five sites, four unpropagated — `base.md` → *Canonical homes*
    → *Judgment-call clause*. The report now carries WHAT was unreachable and
    every surface keys on that.
    """
    for report in reports:
        subject = report["source_subject"]
        assert subject in ("", "repository", "package")
        if report["source_state"] != "unreachable":
            assert subject == "", (
                f"{report['name']}: not unreachable, yet names a subject"
            )
            continue
        assert subject, f"{report['name']}: unreachable about WHAT?"
        reason = report["source_reason"]
        if subject == "package":
            assert "repository" not in reason, (
                f"{report['name']}: a package failure phrased as a repository "
                f"claim — {reason[:80]!r}"
            )
        else:
            assert "repository" in reason


@needs_dist
def test_no_built_surface_calls_a_package_failure_a_repository_failure(reports) -> None:
    """The four surfaces, checked where they are actually rendered."""
    packages = [r for r in reports if r["source_subject"] == "package"]
    if not packages:
        pytest.skip("no package-registry failures in this corpus")
    for report in packages:
        page = (DIST / "servers" / report["slug"] / "index.html").read_text()
        assert "could not be fetched from its registry" in page
        assert "the repository this server declares" not in page
    roster = (DIST / "servers" / "index.html").read_text()
    assert "publish a package we could not fetch" in roster


def test_the_published_data_matches_the_current_scoring_contract(reports) -> None:
    """What invalidates a published score is a METHODOLOGY or RULESET change.

    ⚠ THIS GATE FIRST ASSERTED `scanner_version == __version__`, AND THAT WAS A
    BAD GATE IN THE PRECISE WAY THIS REPO KEEPS RE-LEARNING. `scanner_version`
    defaults to `__version__` at serialization, so the assertion fired on ANY
    bump from ANY cause — roughly 15 of the preceding 25 commits would have gone
    red, none of which touched the scanner. CI cannot self-heal it either:
    regenerating needs live registry access, 40 third-party clones, semgrep and
    osv-scanner. So the standing remedy at every bump was a 40-server re-scan
    or editing the stamp — and the stamp is 40 plain JSON strings, so `sed`
    greens it over arbitrarily old data. **A gate whose cheapest satisfaction
    is falsifying it is worse than no gate, because it gets obeyed.**

    What actually governs whether a score means what it says is the methodology
    version (the weights and bands) and the ruleset version (what the rules
    match). Those change deliberately, and when they do the published numbers
    genuinely are from a different contract. A patch bump to the CLI is not.

    `scanner_version` is still required to be PRESENT — provenance a consumer
    can chase — but it is recorded, not asserted equal.

    ⚠ **One half of the ordering hazard stays open and no gate closes it.** The
    prescribed workflow is bump → regenerate → commit, which this catches when
    the version moves after generation. It does NOT catch the tail: bump,
    regenerate, then keep editing the scanner in the same commit. Stamp and
    version still agree, this passes, and the data was produced by code that no
    longer exists. Regenerate LAST, after the code is final.
    """
    from mcpwatchman.workers.scanner.semgrep_check import rules_root, ruleset_version
    from mcpwatchman.workers.scoring.weights import CURRENT_METHODOLOGY_VERSION

    expected_rules = ruleset_version(rules_root())
    for report in reports:
        if report.get("registry_state") == "delisted":
            # ⚠ THE ONE EXEMPTION, and it is not a softening. A delisted
            # server has no current registry entry, so "regenerate it" is not
            # an available remedy — the alternatives are to publish the last
            # scan taken while it was listed, labelled as exactly that, or to
            # delete a live page. The label is the field this branch reads, and
            # `test_cohort.py` gates the label's own honesty.
            assert report["registry_note"].strip(), (
                f"{report['name']}: delisted and exempted from the contract "
                "gate, yet says nothing about why its numbers are older"
            )
            continue
        assert report["methodology_version"] == CURRENT_METHODOLOGY_VERSION, (
            f"{report['name']}: scored under methodology "
            f"{report['methodology_version']}, but the engine is now "
            f"{CURRENT_METHODOLOGY_VERSION} — the weights or bands moved, so "
            "these numbers are from a different contract and must be regenerated"
        )
        # Only servers that actually reached semgrep carry a ruleset version.
        if report["ruleset_version"]:
            assert report["ruleset_version"] == expected_rules, (
                f"{report['name']}: scored against ruleset "
                f"{report['ruleset_version']}, current is {expected_rules}"
            )
        assert report["scanner_version"], f"{report['name']}: no provenance recorded"


def test_no_published_gap_is_attributed_to_our_own_tooling(reports) -> None:
    """The published-artifact half of the chokepoint gate.

    `cohort.publication_errors` stops the driver writing this; this stops the
    file being edited into that state afterwards, and it is the assertion that
    would have caught the 2026-09-18 run — 40 servers, 15 seconds, exit 0,
    Code Safety unassessed on every one because neither scanner binary was on
    PATH, and *"semgrep is not on PATH; it ships in the `workers` extra"*
    about to become the published reason a third party went unscored.

    Note what this does NOT assert: that an axis was SCORED. Abstention is
    legitimate and common — `03` renormalises around it, 45.3% of declared
    repositories are not publicly reachable — so requiring a number would
    fire for an expected condition. What it requires is that the gap belong
    to somebody nameable: the publisher, or this project's own disclosed
    limits. Never this run's accidents.
    """
    from mcpwatchman.workers.scanner.reachability import Fault

    checked = 0
    for report in reports:
        for axis, entry in report["axes"].items():
            if entry["score"] is not None:
                continue
            checked += 1
            raw = entry.get("fault")
            assert raw, f"{report['name']}/{axis}: unassessed with no attribution"
            assert Fault(raw).publishable, (
                f"{report['name']}/{axis} is unassessed and the gap is {raw} — "
                f"ours, not the server's: {entry['reason'][:80]!r}"
            )
    assert checked, "no unassessed axis was examined — the check is vacuous"


def test_every_report_says_what_the_registry_said_about_it(reports) -> None:
    """`registry_state` is present on every record, never inferred from absence.

    A page can outlive its registry entry — the published set is pinned, so a
    server that leaves the registry keeps its URL (`mcpwatchman.cohort`). The
    field that distinguishes "scanned last night" from "last scanned while it
    was still listed" therefore has to be on every record, because a consumer
    reading it as optional would read a missing value as `listed` and publish
    an old scan as a current one.

    The state space is deliberately open past `listed`/`delisted`: a server
    the registry carries with a non-active status gets the registry's OWN word
    (`deprecated`), because that is the publisher's label and inventing a
    vocabulary for it would put a term on the page that appears nowhere in the
    registry. 1 of the 40 pinned servers is in that state today.

    So the invariant is not an enumeration — it is that anything other than
    `listed` EXPLAINS ITSELF, and that `listed` carries no note. The same
    discipline `source_subject` is held to: a field that only means something
    in one state must be empty in the other, or it becomes a place for a
    sentence nobody can account for.
    """
    for report in reports:
        state = report.get("registry_state")
        assert isinstance(state, str) and state, (
            f"{report['name']}: registry_state is {state!r}"
        )
        if state == "listed":
            assert not report["registry_note"], (
                f"{report['name']}: listed, yet carries a registry note: "
                f"{report['registry_note'][:80]!r}"
            )
        else:
            assert report["registry_note"].strip(), (
                f"{report['name']}: registry_state is {state!r} and the report "
                "says nothing about what that means"
            )


def test_no_report_claims_to_have_been_scanned_in_the_future(reports) -> None:
    """A clock or serialization defect, and the only staleness check that earns
    its place in a suite.

    Deliberately NOT a freshness bound. A test that reds by the calendar fires
    for an expected condition — data ages — and `base.md` § *Signal design* is
    explicit that such a signal trains the reader to route around it. The page
    prints the scan date instead, which is the honest mechanism: a reader can
    see the age and judge it.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    for report in reports:
        scanned = datetime.fromisoformat(report["scanned_at"])
        assert scanned <= now, (
            f"{report['name']}: scanned_at {report['scanned_at']} is in the future"
        )


def test_the_driver_refuses_to_scan_without_its_scanner_binaries(monkeypatch) -> None:
    """A missing binary publishes a clean non-assessment, so it must not run.

    Measured 2026-09-18 by doing it: with neither `semgrep` nor `osv-scanner`
    on PATH, a run scanned 40 servers in 15 seconds, exited **0**, and reported
    Code Safety unassessed on every one — including the 16 that carry real
    scores. No gate in this file would have caught the regenerated data,
    because none of them requires an axis to be SCORED, and adding such a
    requirement is the wrong fix: an unscored axis is legitimately the common
    case (`03` renormalises around it).

    The fix belongs before the scan, and this is its positive control — the
    check has to be capable of passing, or it is a permanent refusal nobody
    would notice either.
    """
    from ops.scan_cohort import REQUIRED_TOOLS, preflight

    assert REQUIRED_TOOLS, "the positive control: an empty tool list never fails"

    monkeypatch.setattr("shutil.which", lambda _tool: "/usr/bin/stub")
    assert preflight() == []

    monkeypatch.setattr("shutil.which", lambda _tool: None)
    missing = preflight()
    assert len(missing) == len(REQUIRED_TOOLS)
    # Each line must name the tool AND the axis that silently goes dark: the
    # tool alone reads as a setup nit rather than as published-data damage.
    for (tool, axis, _where), line in zip(REQUIRED_TOOLS, missing, strict=True):
        assert tool in line and axis in line

    # And one tool missing is still a refusal — Dependency Health alone going
    # dark is 20% of the composite.
    monkeypatch.setattr(
        "shutil.which", lambda tool: None if tool == "osv-scanner" else "/usr/bin/stub"
    )
    assert len(preflight()) == 1


def test_the_growth_key_depends_only_on_a_server_name() -> None:
    """⚠ THIS TEST PASSED THROUGHOUT THE ROTATION IT WAS WRITTEN TO PREVENT.

    It replaced a seeded shuffle — reproducible for a FIXED list and nothing
    more — with `sha256(name)` ordering, and then asserted that the surviving
    members of a grown pool keep their relative order. That assertion is true,
    and it is not the property the published set needed. It filters the grown
    pool down to today's members before taking the first 10, which is precisely
    the step production could not take: a new server whose hash sorts low
    DISPLACES the tenth, and the candidate pool was itself an alphabetical
    prefix of the registry that every new registration shifted. Measured
    2026-09-18 — two regenerations two days apart shared **4 of 40**, and 100
    published pages have been lost this way.

    So the docstring's conclusion ("growth inserts without displacing") was a
    claim about the ORDERING stated as a claim about the SAMPLE, and the test
    read as covering the second. What actually keeps the set stable is
    `ops/cohort.json`; `tests/test_cohort.py` gates it.

    What survives here is the narrow property this key is still used for —
    choosing which unpinned servers to ADD is reproducible and depends on
    nothing but their identity, so two people growing the cohort by ten pick
    the same ten.
    """
    from ops.scan_cohort import sample_key

    assert sample_key("a") == sample_key("a")
    assert sample_key("a") != sample_key("b")

    pool = [f"srv-{i}" for i in range(50)]
    grown = [*pool, *(f"new-{i}" for i in range(500))]
    order = sorted(pool, key=sample_key)
    survivors = [n for n in sorted(grown, key=sample_key) if n in set(pool)]
    assert order == survivors, "a server's position moved when the pool grew"

    # And the displacement the old test was shaped around not noticing: the
    # first ten of the grown pool are NOT the first ten of the old one, which
    # is why a top-N draw could never have been stable.
    assert sorted(grown, key=sample_key)[:10] != order[:10]


def _git() -> str:
    """The git binary, resolved. A bare name is whatever PATH happens to hold."""
    found = shutil.which("git")
    assert found is not None, "git is unavailable, so provenance cannot be checked"
    return found


def _commit_declaring(version: str) -> str | None:
    """The first commit whose `pyproject.toml` declares `version`, or None."""
    revs = subprocess.run(  # noqa: S603 - argument list, never a shell string
        [_git(), "log", "--format=%H", "--", "pyproject.toml"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    for rev in revs.stdout.split():
        blob = subprocess.run(  # noqa: S603 - argument list, never a shell string
            [_git(), "show", f"{rev}:pyproject.toml"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if blob.returncode == 0 and f'version = "{version}"' in blob.stdout:
            return rev
    return None


def test_the_stamped_scanner_version_could_have_produced_this_record(reports) -> None:
    """`scanner_version` is a reproducibility claim, and it was not checkable.

    ⚠ EVERY PUBLISHED RECORD STAMPED `0.22.0` WHILE CARRYING `fault`, A FIELD
    `0.22.0` DID NOT HAVE. `ServerReport.scanner_version` defaults to
    `__version__`, captured when the scan runs — and the scan ran before
    `/bump` ticked the version, so the data and the stamp came from different
    versions. A consumer following that provenance reaches code incapable of
    producing the record it is trying to reproduce, which on a site whose whole
    premise is checkable claims is the worst kind of wrong: confidently
    specific, and addressed to the audience least able to notice.

    Derived from git rather than from a hand-kept map of field-to-version,
    because such a map is the per-site discipline that goes stale silently: the
    stamped version's own `AxisScore` is read out of that commit and must
    declare every key the data actually uses. Found by the Codex leg of a
    `/qaa`; positive-controlled against the live defect, where it went red.
    """
    shallow = subprocess.run(  # noqa: S603 - argument list, never a shell string
        [_git(), "rev-parse", "--is-shallow-repository"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert shallow.stdout.strip() != "true", (
        "shallow clone: this gate cannot read the history it needs and would "
        "pass without checking — set `fetch-depth: 0` on the checkout"
    )

    published: set[str] = set()
    for report in reports:
        for axis in report["axes"].values():
            published |= set(axis)

    for version in sorted({r["scanner_version"] for r in reports}):
        rev = _commit_declaring(version)
        assert rev is not None, (
            f"the data is stamped scanner_version {version!r}, which no commit "
            "in this repository ever declared — the provenance names a version "
            "that does not exist"
        )
        src = subprocess.run(  # noqa: S603 - argument list, never a shell string
            [_git(), "show", f"{rev}:src/mcpwatchman/workers/scanner/runner.py"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        fields = {
            node.target.id
            for cls in ast.walk(ast.parse(src.stdout))
            if isinstance(cls, ast.ClassDef) and cls.name == "AxisScore"
            for node in cls.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        assert fields, f"could not read AxisScore out of {version} ({rev[:8]})"
        impossible = published - fields
        assert not impossible, (
            f"the data is stamped scanner_version {version!r} ({rev[:8]}) but "
            f"publishes axis field(s) {sorted(impossible)} that version could "
            "not produce — the scan ran against newer code than the stamp "
            "names, so the record is not reproducible from it"
        )
