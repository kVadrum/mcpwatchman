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
    # The count in the file is a convenience for a human reading it; it must
    # not be the thing anyone trusts, so loading ignores it.
    payload = json.loads(path.read_text())
    assert payload["count"] == 2
    payload["count"] = 99
    path.write_text(json.dumps(payload))
    assert len(load(path)) == 2


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
