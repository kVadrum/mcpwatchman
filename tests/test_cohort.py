"""Gates on the pinned cohort — the promise that a published URL keeps working.

Every assertion here guards a failure that is **silent in production**: a
regeneration that drops a server writes a clean file, builds a valid site,
passes every other gate in this suite, and 404s a page that is in the sitemap
and in agents' hands. There is no error to notice, which is why the checks are
here rather than left to review.

The history is in `mcpwatchman.cohort`: nine committed generations, 140 distinct
servers published, 100 of them now gone from the live site.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mcpwatchman.cohort import (
    Cohort,
    CohortError,
    PinnedServer,
    carry_forward,
    load,
    mark_status,
    parse,
    publication_errors,
    save,
)
from mcpwatchman.workers.scanner.runner import slugify

ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "ops" / "cohort.json"
DATA = ROOT / "site" / "src" / "data" / "scans.json"


def _pin(name: str, published: str = "2026-09-18") -> PinnedServer:
    return PinnedServer(name=name, slug=slugify(name), first_published=published)


# --- the module's own invariants -----------------------------------------


def test_a_malformed_file_is_never_read_as_an_empty_cohort() -> None:
    """The failure that would unpublish everything at once.

    An empty cohort is not a harmless default: it means "nothing is promised",
    so the driver would publish whatever it drew and every existing URL would
    be free to disappear. Same shape as `parse_page` refusing a 200 with no
    `servers` array, and for the same reason.
    """
    with pytest.raises(CohortError, match="no 'servers' array"):
        parse({"note": "looks fine"})
    with pytest.raises(CohortError, match="JSON object"):
        parse([])


def test_a_pinned_slug_that_no_longer_derives_from_its_name_is_a_hard_error() -> None:
    """The stored slug is the live URL; `slugify` is what the generator will emit.

    When they disagree the published page moves and nothing says so, so the
    disagreement has to be the loud event rather than the quiet one.
    """
    with pytest.raises(CohortError, match="no longer what slugify"):
        parse(
            {
                "servers": [
                    {
                        "name": "ai.example/server",
                        "slug": "some-other-page",
                        "first_published": "2026-09-18",
                    }
                ]
            }
        )


def test_two_entries_may_not_resolve_to_one_page() -> None:
    duplicate = {
        "name": "ai.example/server",
        "slug": "ai-example-server",
        "first_published": "2026-09-18",
    }
    with pytest.raises(CohortError, match="duplicate"):
        parse({"servers": [duplicate, dict(duplicate)]})


def test_first_published_must_be_a_date() -> None:
    with pytest.raises(CohortError, match="YYYY-MM-DD"):
        parse(
            {
                "servers": [
                    {
                        "name": "ai.example/server",
                        "slug": "ai-example-server",
                        "first_published": "last Tuesday",
                    }
                ]
            }
        )


def test_growth_only_ever_adds() -> None:
    """`extended_with` is the only mutation, and it cannot lose a server."""
    start = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two")))
    grown = start.extended_with(["io.github.c/three"], on="2026-10-01")
    assert start.names < grown.names
    assert len(grown) == 3
    # Idempotent: re-growing with an already-pinned name changes nothing, and
    # in particular does not re-date it.
    again = grown.extended_with(["ai.a/one"], on="2026-12-25")
    assert again.names == grown.names
    assert {s.first_published for s in again.servers if s.name == "ai.a/one"} == {
        "2026-09-18"
    }


def test_the_cohort_is_name_ordered_so_an_append_reads_as_added_lines() -> None:
    grown = Cohort(servers=(_pin("ai.z/last"),)).extended_with(
        ["ai.a/first"], on="2026-10-01"
    )
    assert [s.name for s in grown.servers] == ["ai.a/first", "ai.z/last"]


def test_an_absent_cohort_file_is_not_an_empty_one(tmp_path: Path) -> None:
    with pytest.raises(CohortError, match="an absent pin is not an empty one"):
        load(tmp_path / "cohort.json")


def test_save_then_load_round_trips(tmp_path: Path) -> None:
    original = Cohort(servers=(_pin("ai.a/one"), _pin("io.github.b/two")))
    path = tmp_path / "cohort.json"
    save(path, original)
    assert load(path).servers == original.servers
    # ⚠ THIS TEST ASSERTED THE WEAKER CONTRACT AND SO PROTECTED THE DEFECT:
    # it required `load` to IGNORE a disagreeing `count`, which is what left
    # `"servers": []` parseable. An empty array unpublishes every page and
    # exits 0 — the one outcome `parse`'s own docstring says it refuses. The
    # count is now the cross-check that makes a half-written file loud.
    payload = json.loads(path.read_text())
    assert payload["count"] == 2
    payload["count"] = 99
    path.write_text(json.dumps(payload))
    with pytest.raises(CohortError, match="declares 99"):
        load(path)


def test_a_truncated_cohort_file_is_refused_rather_than_read_as_empty(
    tmp_path: Path,
) -> None:
    """The failure the count cross-check exists for.

    A half-written or half-edited file leaving `"servers": []` parsed to an
    empty cohort, published nothing, and exited 0 — unpublishing all 140 pages
    while reporting success. The bootstrap case (both zero) stays legal,
    because a cohort has to start somewhere.
    """
    path = tmp_path / "cohort.json"
    path.write_text(json.dumps({"count": 140, "servers": []}))
    with pytest.raises(CohortError, match="refusing a half-written file"):
        load(path)

    path.write_text(json.dumps({"count": 0, "servers": []}))
    assert len(load(path)) == 0


def test_a_deprecated_server_is_scanned_and_labelled_not_carried_forward() -> None:
    """The distinction the first real run turned up.

    `ai.haymon/database` is `deprecated` in the registry today, and 349 of
    33,081 entries are not active-and-latest — so this is an ordinary state,
    not an edge case. Its entry is still in the manifest, so its source
    resolves and the scan can be current; carrying a stale report forward
    instead would publish an old measurement while a readable repository sat
    right there.

    What the label must NOT do is read as a finding: the status is the
    publisher's word, and `03` defines no band for it.
    """
    marked = mark_status(
        {"name": "ai.example/server", "scanned_at": "2026-09-18T04:18:16+00:00"},
        status="deprecated",
        observed_on="2026-09-18",
    )
    assert marked["registry_state"] == "deprecated"
    assert "publisher's own label" in marked["registry_note"]
    assert "no axis scores it" in marked["registry_note"]
    assert "current" in marked["registry_note"]


def test_a_carried_forward_report_keeps_its_scan_date_and_says_it_did() -> None:
    """The dormant path, tested here because production cannot exercise it yet.

    A pinned server that leaves the registry cannot be re-scanned, so its page
    keeps the last scan taken while it was listed. Carrying it forward SILENTLY
    would leave an old measurement reading as a current one — so the marker and
    both dates are the point of the operation, not decoration on it.
    """
    previous = {
        "name": "ai.example/server",
        "scanned_at": "2026-09-18T04:18:16+00:00",
        "registry_state": "listed",
        "registry_note": "",
        "axes": {"code_safety": {"score": 70}},
    }
    carried = carry_forward(
        previous,
        checked_on="2026-11-02",
        observation="The registry no longer lists this server",
    )
    assert carried["registry_state"] == "delisted"
    assert carried["scanned_at"] == previous["scanned_at"], (
        "the scan happened when it happened; re-dating it would publish a "
        "measurement we did not take"
    )
    assert carried["axes"] == previous["axes"]
    assert "2026-11-02" in carried["registry_note"]
    assert "2026-09-18" in carried["registry_note"]
    # The input is not mutated: the caller may still hold the previous report.
    assert previous["registry_state"] == "listed"


def test_publishing_is_refused_when_a_pinned_server_produced_no_report() -> None:
    """The driver's refusal, tested where it can be: a dropped server 404s.

    This is the case the whole mechanism exists to stop, and it is the one that
    leaves no trace — the write succeeds, the site builds, and the gap is only
    visible to whoever follows the link.
    """
    cohort = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two")))
    problems = publication_errors(cohort, [{"name": "ai.a/one", "slug": "ai-a-one"}])
    assert len(problems) == 1
    assert "ai.b/two" in problems[0]
    assert "stop existing" in problems[0]


def test_publishing_is_refused_for_a_report_with_no_pin() -> None:
    """The other direction: a URL served without the promise to keep it.

    Not symmetry for its own sake — this is precisely how 100 pages came to
    exist and then not.
    """
    cohort = Cohort(servers=(_pin("ai.a/one"),))
    problems = publication_errors(
        cohort,
        [
            {"name": "ai.a/one", "slug": "ai-a-one"},
            {"name": "ai.surprise/extra", "slug": "ai-surprise-extra"},
        ],
    )
    assert len(problems) == 1
    assert "ai.surprise/extra" in problems[0]
    assert "without being pinned" in problems[0]


def test_publishing_is_refused_when_a_report_lands_on_the_wrong_url() -> None:
    """The right servers at the wrong addresses — a mass move nobody announced."""
    cohort = Cohort(servers=(_pin("ai.a/one"),))
    problems = publication_errors(
        cohort, [{"name": "ai.a/one", "slug": "ai-a-one-v2"}]
    )
    assert len(problems) == 1
    assert "/servers/ai-a-one/" in problems[0]
    assert "/servers/ai-a-one-v2/" in problems[0]


def test_an_our_side_gap_is_refused_at_publication() -> None:
    """The recurring failure shape, caught at the chokepoint rather than at N sites.

    A missing scanner binary produces a clean non-assessment, exit 0, and no
    gate objects — so the run publishes 500 pages whose reason for not scoring
    a third party is *our* broken environment. Measured 2026-09-18: 40 servers
    scanned in 15 seconds with `code=—` on every one.

    `environment` and `unattributed` are both refused, and the second is the
    load-bearing one: it is the DEFAULT, so an axis or a tool added later
    inherits the refusal without anyone remembering to wire it. The site
    nobody remembers to guard is the site that generates no symbol to grep
    and no failure to observe.
    """
    cohort = Cohort(servers=(_pin("ai.a/one"),))

    def report(fault: str) -> dict:
        return {
            "name": "ai.a/one",
            "slug": "ai-a-one",
            "axes": {
                "code_safety": {
                    "score": None,
                    "reason": "semgrep is not on PATH; it ships in the `workers` extra",
                    "fault": fault,
                }
            },
        }

    for refused in ("environment", "unattributed", "", "typo-nobody-noticed"):
        problems = publication_errors(cohort, [report(refused)])
        assert problems, f"{refused!r} reached publication"
        assert "code_safety" in problems[0]

    for allowed in ("publisher", "project"):
        assert publication_errors(cohort, [report(allowed)]) == [], allowed

    # A MISSING key is the same as unattributed: data written before the field
    # existed must not read as publishable.
    bare = report("publisher")
    del bare["axes"]["code_safety"]["fault"]
    assert publication_errors(cohort, [bare])


def test_a_scored_axis_needs_no_attribution() -> None:
    """The narrowing half, and skipping it would make the gate fire on everything.

    `fault` answers "whose gap is this", which is a question only an
    unassessed axis has. A scored axis has a number and the field is
    meaningless there — so it is read only when `score is None`.
    """
    cohort = Cohort(servers=(_pin("ai.a/one"),))
    assert publication_errors(
        cohort,
        [{
            "name": "ai.a/one",
            "slug": "ai-a-one",
            "axes": {"code_safety": {"score": 78, "reason": "", "fault": "unattributed"}},
        }],
    ) == []


def test_a_correct_publication_produces_no_problems() -> None:
    """The negative control: the checks above must be capable of passing."""
    cohort = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two")))
    assert (
        publication_errors(
            cohort,
            [
                {"name": "ai.a/one", "slug": "ai-a-one"},
                {"name": "ai.b/two", "slug": "ai-b-two"},
            ],
        )
        == []
    )


# --- the real files ------------------------------------------------------


@pytest.fixture(scope="module")
def cohort() -> Cohort:
    return load(COHORT)


@pytest.fixture(scope="module")
def published() -> list[dict]:
    if not DATA.is_file():
        pytest.skip("no published scan data in this checkout")
    return json.loads(DATA.read_text())


def test_the_committed_cohort_is_valid(cohort: Cohort) -> None:
    assert len(cohort) >= 1, "the positive control: every check below needs entries"
    cohort.validate()


def test_every_pinned_server_is_published(cohort: Cohort, published: list[dict]) -> None:
    """The gate this whole mechanism exists for.

    A pinned server missing from the published data is a live URL that 404s on
    the next deploy. The driver refuses to write in that case; this catches a
    file edited by hand afterwards, which the driver never sees.
    """
    have = {r["name"] for r in published}
    missing = sorted(cohort.names - have)
    assert not missing, (
        f"pinned but not published, so /servers/<slug>/ would 404: {missing}"
    )


def test_nothing_is_published_without_being_pinned(
    cohort: Cohort, published: list[dict]
) -> None:
    """The other direction, and it is not symmetric decoration.

    An unpinned published server is a URL we started serving without recording
    the promise to keep serving it — which is exactly how 100 pages were
    published and lost.
    """
    orphans = sorted({r["name"] for r in published} - cohort.names)
    assert not orphans, f"published without a pin: {orphans}"


def test_the_published_slug_is_the_pinned_slug(
    cohort: Cohort, published: list[dict]
) -> None:
    pinned = {s.name: s.slug for s in cohort.servers}
    for report in published:
        if report["name"] not in pinned:
            continue  # the orphan case, and the test above names it properly
        assert report["slug"] == pinned[report["name"]], (
            f"{report['name']} is published at /servers/{report['slug']}/ but "
            f"pinned at /servers/{pinned[report['name']]}/"
        )


def test_the_cohort_has_not_shrunk_since_the_last_commit(cohort: Cohort) -> None:
    """Append-only, enforced against this file's own committed predecessor.

    Nothing else can catch a removal: delete a line, regenerate, and every
    other gate here passes over a consistent, smaller set of promises.

    Skips when `ops/cohort.json` is not in HEAD — which is true of the commit
    that introduces it and of nothing else. The parse of HEAD's version is
    asserted non-empty first, so a garbled read cannot pass this vacuously.
    """
    git = shutil.which("git")
    if git is None:  # pragma: no cover - git is present everywhere this runs
        pytest.skip("git unavailable, so HEAD's cohort cannot be read")
    blob = subprocess.run(  # noqa: S603 - argument list, never a shell string
        [git, "show", "HEAD:ops/cohort.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if blob.returncode != 0:
        pytest.skip("ops/cohort.json is not in HEAD yet (the commit adding it)")
    was = parse(json.loads(blob.stdout))
    assert len(was) > 0, "the positive control: HEAD's cohort parsed to nothing"
    dropped = sorted(was.names - cohort.names)
    assert not dropped, (
        "these servers were pinned in the last commit and are not pinned now, "
        f"so their published pages would stop existing: {dropped}"
    )


# --- the driver's main flow ----------------------------------------------


def test_the_driver_publishes_the_pin_and_appends_growth(tmp_path, monkeypatch) -> None:
    """End-to-end over `main()` with a stubbed registry and scanner.

    **The driver had no test of its main flow, which is where every decision
    this module exists to enforce actually happens** — and an hour-long run is
    a bad place to discover a slip in it. Stubbing the two expensive calls
    leaves the part that is ours: the pinned/flagged/carried split, the
    growth append, the refusal, and the write.
    """
    import ops.scan_cohort as driver

    cohort_path = tmp_path / "cohort.json"
    out = tmp_path / "scans.json"
    save(cohort_path, Cohort(servers=(_pin("ai.pinned/one"),)))

    class FakeEntry:
        def __init__(self, name, status="active", is_latest=True):
            self.name = name
            self.version = "1.0.0"
            self.status = status
            self.is_latest = is_latest
            self.repository = None
            self.packages = ()
            self.remotes = ()

    entries = [
        FakeEntry("ai.pinned/one"),
        FakeEntry("ai.candidate/two"),
        FakeEntry("ai.candidate/three"),
    ]
    monkeypatch.setattr(driver, "fetch_all", lambda: entries)
    monkeypatch.setattr(driver, "current_entries", lambda es: es)
    monkeypatch.setattr(driver, "preflight", lambda: [])

    class FakeResolution:
        scannable = True
        primary = "github.com/x/y"

    monkeypatch.setattr(driver, "resolve_source", lambda _e: FakeResolution())

    def fake_scan(entry, *_a, **_kw):
        from mcpwatchman.workers.scanner.runner import AxisScore, ServerReport

        return ServerReport(
            name=entry.name,
            version=entry.version,
            slug=slugify(entry.name),
            scanned_at="2026-09-18T00:00:00+00:00",
            axes={
                a: AxisScore(a, 100, "", "1", fault="publisher") for a in ("code_safety",)
            },
        )

    monkeypatch.setattr(driver, "scan_entry", fake_scan)
    monkeypatch.setattr(
        "sys.argv",
        ["scan_cohort.py", "--out", str(out), "--cohort", str(cohort_path), "--grow", "1"],
    )

    assert driver.main() == 0

    published = json.loads(out.read_text())
    grown = load(cohort_path)
    # The pin is published, exactly one candidate was added, and the cohort
    # grew in the same run that first published its page — the two must never
    # come apart, which is what makes the URL a promise.
    assert len(published) == 2
    assert len(grown) == 2
    assert "ai.pinned/one" in grown.names
    assert grown.names == {r["name"] for r in published}
    assert publication_errors(grown, published) == []
    # Name order, so a regeneration diffs as changed values rather than a
    # reshuffled file.
    assert [r["name"] for r in published] == sorted(r["name"] for r in published)


def test_adopting_a_name_pins_it_only_when_it_publishes(tmp_path, monkeypatch) -> None:
    """Recovery of a lost URL follows growth's rule, and shares its code path.

    100 pages were published before the pin existed and are 404 now. Bringing
    them back by PRE-PINNING them was the wrong shape and cost a 500-server
    run: one of them failed to measure on its first publication, had no
    previous report to fall back to, and the run correctly refused to write.
    Nothing had promised that page — so the failure must cost that one name,
    not the other 499.
    """
    import ops.scan_cohort as driver

    cohort_path = tmp_path / "cohort.json"
    out = tmp_path / "scans.json"
    adopt = tmp_path / "adopt.txt"
    save(cohort_path, Cohort(servers=()))
    adopt.write_text("ai.good/one\nai.broken/two\n")

    class FakeEntry:
        def __init__(self, name):
            self.name = name
            self.version = "1.0.0"
            self.status = "active"
            self.is_latest = True
            self.repository = None

    entries = [FakeEntry("ai.good/one"), FakeEntry("ai.broken/two")]
    monkeypatch.setattr(driver, "fetch_all", lambda: entries)
    monkeypatch.setattr(driver, "current_entries", lambda es: es)
    monkeypatch.setattr(driver, "preflight", lambda: [])
    monkeypatch.setattr(
        driver,
        "resolve_source",
        lambda _e: type("R", (), {"scannable": True, "primary": "g"})(),
    )

    def scan(entry, *_a, **_kw):
        from mcpwatchman.workers.scanner.runner import AxisScore, ServerReport

        broken = entry.name == "ai.broken/two"
        return ServerReport(
            name=entry.name,
            version=entry.version,
            slug=slugify(entry.name),
            scanned_at="2026-09-18T00:00:00+00:00",
            axes={
                "code_safety": AxisScore(
                    "code_safety",
                    None if broken else 80,
                    "semgrep failed" if broken else "",
                    "0" if broken else "1",
                    fault="environment" if broken else "publisher",
                )
            },
        )

    monkeypatch.setattr(driver, "scan_entry", scan)
    monkeypatch.setattr(
        "sys.argv",
        [
            "scan_cohort.py", "--out", str(out),
            "--cohort", str(cohort_path), "--adopt-file", str(adopt),
        ],
    )

    assert driver.main() == 0
    published = {r["name"] for r in json.loads(out.read_text())}
    pinned = load(cohort_path).names
    assert published == {"ai.good/one"}
    assert pinned == {"ai.good/one"}, (
        "the unmeasurable name must not be pinned — a pin records a published "
        "page, and pinning an unpublished one promises a 404"
    )


def test_the_driver_refuses_rather_than_dropping_an_unmeasurable_new_pin(
    tmp_path, monkeypatch
) -> None:
    """An our-side gap on a GROWTH candidate must not be pinned.

    Publishing it would mint a URL whose very first version states our broken
    run as the reason nobody scored that server — and then the pin would
    promise to keep it. Skipped instead, so nothing is promised and the next
    run may pick it up.
    """
    import ops.scan_cohort as driver

    cohort_path = tmp_path / "cohort.json"
    out = tmp_path / "scans.json"
    save(cohort_path, Cohort(servers=()))

    class FakeEntry:
        name = "ai.candidate/only"
        version = "1.0.0"
        status = "active"
        is_latest = True
        repository = None

    monkeypatch.setattr(driver, "fetch_all", lambda: [FakeEntry()])
    monkeypatch.setattr(driver, "current_entries", lambda es: es)
    monkeypatch.setattr(driver, "preflight", lambda: [])
    monkeypatch.setattr(
        driver, "resolve_source", lambda _e: type("R", (), {"scannable": True, "primary": "g"})()
    )

    def broken_scan(entry, *_a, **_kw):
        from mcpwatchman.workers.scanner.runner import AxisScore, ServerReport

        return ServerReport(
            name=entry.name,
            version=entry.version,
            slug=slugify(entry.name),
            scanned_at="2026-09-18T00:00:00+00:00",
            # What a missing semgrep produces.
            axes={
                "code_safety": AxisScore(
                    "code_safety", None, "not on PATH", "0", fault="environment"
                )
            },
        )

    monkeypatch.setattr(driver, "scan_entry", broken_scan)
    monkeypatch.setattr(
        "sys.argv",
        ["scan_cohort.py", "--out", str(out), "--cohort", str(cohort_path), "--grow", "1"],
    )

    assert driver.main() == 0
    assert json.loads(out.read_text()) == []
    assert len(load(cohort_path)) == 0, "an unmeasurable candidate must not be pinned"
