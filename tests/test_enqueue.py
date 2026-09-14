"""Poll-planning invariants (`02` §2.1).

The planner decides what a night's work is. Tests aim at the decisions that
would be expensive to get wrong — what becomes a job, what becomes a documented
skip, what a quiet night looks like, and whether a failing enqueue can silently
eat the queue.
"""

from __future__ import annotations

import pytest
from tests.test_registry import make_raw

from mcpwatchman.workers.crawler.enqueue import (
    Lane,
    PollPlan,
    ScanJob,
    enqueue_plan,
    plan_from_diff,
    plan_rescan,
)
from mcpwatchman.workers.crawler.registry import ManifestDiff, parse_entry


def entry(name="a/x", version="1.0.0", **fields):
    return parse_entry(make_raw(name=name, version=version, **fields))


NPM = [{"registryType": "npm", "identifier": "pkg", "version": "1.0.0"}]
REMOTE = [{"type": "streamable-http", "url": "https://x.example"}]


def test_changed_entries_become_jobs_and_unchanged_ones_do_not():
    """Hash-based cache hits are why a nightly full-registry crawl is cheap."""
    diff = ManifestDiff(
        added=(entry(name="a/x", packages=NPM),),
        updated=(entry(name="b/y", packages=NPM),),
        unchanged=(entry(name="c/z", packages=NPM),),
    )
    plan = plan_from_diff(diff)
    assert {j.name for j in plan.jobs} == {"a/x", "b/y"}
    assert plan.unchanged == 1


def test_unscannable_entry_becomes_a_documented_skip_not_a_dropped_job():
    """An absent score must be explainable; silence renders as a bad score."""
    diff = ManifestDiff(added=(entry(name="r/emote", remotes=REMOTE),))
    plan = plan_from_diff(diff)
    assert plan.jobs == ()
    assert len(plan.skipped) == 1
    assert "remote-only" in plan.skipped[0].reason
    assert plan.skipped[0].key == "r/emote@1.0.0"


def test_job_carries_the_hash_it_was_planned_against():
    """The queue can be hours deep; the worker must be able to detect that the
    registry moved underneath it before attaching a score to a stale artifact."""
    e = entry(packages=NPM)
    plan = plan_from_diff(ManifestDiff(added=(e,)))
    assert plan.jobs[0].content_hash == e.content_hash


def test_job_carries_the_repo_supplement_alongside_the_package():
    e = entry(
        packages=NPM, repository={"url": "https://github.com/acme/server"}
    )
    job = plan_from_diff(ManifestDiff(added=(e,))).jobs[0]
    assert job.source_spec == "npm:pkg@1.0.0"
    assert job.supplement_spec == "github:acme/server@1.0.0"


def test_monorepo_subfolder_reaches_the_job_via_the_spec_string():
    """The path reaches the worker in `source_spec`, which is the only place it
    lives. `ScanJob` carries no `subfolder` field: as a second copy it meant the
    PRIMARY's subfolder for a git source and the SUPPLEMENT's for an npm one, so
    a worker joining it onto the fetched tree was right only half the time."""
    e = entry(
        repository={
            "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"
        }
    )
    job = plan_from_diff(ManifestDiff(added=(e,))).jobs[0]
    assert job.source_spec.endswith("#src/fetch")
    assert not hasattr(job, "subfolder")


def test_a_package_primary_does_not_smuggle_the_repos_subfolder():
    """The case that made the removed field ambiguous: the tarball has no
    `src/fetch` in it, so a subfolder taken from the repository and applied to
    the package root names a path that does not exist."""
    e = entry(
        packages=NPM,
        repository={"url": "https://github.com/m/s/tree/main/src/fetch"},
    )
    job = plan_from_diff(ManifestDiff(added=(e,))).jobs[0]
    assert "#" not in job.source_spec          # the npm primary carries none
    assert job.supplement_spec.endswith("#src/fetch")  # the repo carries its own


def test_removals_are_reported_not_applied():
    """Marking a server removed is a write; a planner that writes cannot be run
    to find out what a poll would do."""
    plan = plan_from_diff(ManifestDiff(removed=("gone/x@1.0.0",)))
    assert plan.removed == ("gone/x@1.0.0",)
    assert plan.jobs == ()
    assert not plan.is_empty  # a removal is still work


def test_a_quiet_night_is_empty_and_is_not_a_fault():
    """Signal design: the registry not changing is the expected case."""
    plan = plan_from_diff(ManifestDiff(unchanged=(entry(packages=NPM),)))
    assert plan.is_empty and plan.unchanged == 1


def test_default_lane_is_the_overnight_drip():
    plan = plan_from_diff(ManifestDiff(added=(entry(packages=NPM),)))
    assert plan.jobs[0].lane is Lane.DEFAULT


def test_cli_requested_scan_can_claim_the_priority_lane():
    plan = plan_from_diff(
        ManifestDiff(added=(entry(packages=NPM),)), lane=Lane.PRIORITY
    )
    assert plan.jobs[0].lane is Lane.PRIORITY


def test_rescan_ignores_hashes_and_uses_the_recalibration_lane():
    """A methodology change re-scores servers that did not change (`03` §11),
    and must not starve the interactive lane while doing it."""
    plan = plan_rescan([entry(name="a/x", packages=NPM), entry(name="b/y", packages=NPM)])
    assert len(plan.jobs) == 2
    assert {j.lane for j in plan.jobs} == {Lane.RECALIBRATION}


def test_plan_reports_coverage_over_everything_current():
    """Coverage counts the whole registry, not just tonight's changes —
    otherwise a quiet night reads as 100% coverage."""
    diff = ManifestDiff(
        added=(entry(name="a/x", packages=NPM),),
        unchanged=(entry(name="c/z", remotes=REMOTE),),
    )
    plan = plan_from_diff(diff)
    assert plan.coverage is not None
    assert plan.coverage.total == 2 and plan.coverage.scannable == 1


# --- enqueue isolation ----------------------------------------------------


def test_enqueue_reports_counts():
    plan = plan_from_diff(
        ManifestDiff(added=(entry(name="a/x", packages=NPM), entry(name="b/y", packages=NPM)))
    )
    seen: list[ScanJob] = []
    assert enqueue_plan(plan, seen.append) == (2, 0)
    assert len(seen) == 2


def test_one_failing_enqueue_does_not_cost_the_rest_of_the_night():
    plan = plan_from_diff(
        ManifestDiff(
            added=tuple(entry(name=f"n/{i}", packages=NPM) for i in range(4))
        )
    )
    errors = []

    def flaky(job: ScanJob):
        if job.name == "n/1":
            raise RuntimeError("queue hiccup")

    enqueued, failed = enqueue_plan(plan, flaky, on_error=lambda j, e: errors.append(j.name))
    assert (enqueued, failed) == (3, 1)
    assert errors == ["n/1"]


def test_a_partial_enqueue_is_reported_rather_than_swallowed():
    """A silent partial enqueue is indistinguishable from a quiet registry."""
    plan = plan_from_diff(ManifestDiff(added=(entry(packages=NPM),)))

    def always_fails(job: ScanJob):
        raise RuntimeError("down")

    assert enqueue_plan(plan, always_fails) == (0, 1)


def test_empty_plan_enqueues_nothing():
    assert enqueue_plan(PollPlan(), lambda job: pytest.fail("should not enqueue")) == (0, 0)


# --- Codex review, 2026-09-14 ---------------------------------------------


def test_a_poll_that_only_found_unscannable_servers_is_not_quiet():
    """Five new remote-only servers is work, not silence: each is owed a page
    saying why it was not analysed. A caller short-circuiting on `is_empty`
    would otherwise drop the reasons, and the server renders as an absent score
    instead of an explained one."""
    plan = plan_from_diff(ManifestDiff(added=(entry(name="r/emote", remotes=REMOTE),)))
    assert plan.jobs == () and plan.removed == ()
    assert plan.skipped and not plan.is_empty


def test_incremental_plan_reports_registry_metrics_as_ABSENT_not_zero():
    """An incremental response carries only what moved, so coverage and the
    manifest hash are NOT derivable from it. Computing them anyway describes the
    delta while reading as a claim about the registry — a quiet poll would
    report 0% coverage. Coverage is bound for a public page."""
    from tests.test_registry import make_raw

    from mcpwatchman.workers.crawler.registry import diff_incremental, parse_entry

    e = parse_entry(make_raw(name="a/x", packages=NPM))
    plan = plan_from_diff(diff_incremental({e.key: e.content_hash}, [e]))
    assert plan.coverage is None
    assert plan.manifest_hash is None


def test_full_manifest_plan_still_reports_both():
    """The contrast that makes the absence meaningful."""
    plan = plan_from_diff(ManifestDiff(added=(entry(packages=NPM),)))
    assert plan.coverage is not None and plan.manifest_hash
