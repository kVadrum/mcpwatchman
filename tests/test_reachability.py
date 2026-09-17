"""A declared repository the public cannot read is a fact about the server.

Measured 2026-09-15 over 200 registry entries: 43 of the 95 that declare a
repository return 404 unauthenticated. Until now that reached a `FetchError`
and stopped.
"""

from __future__ import annotations

import pytest

from mcpwatchman.workers.crawler.registry import CoverageReport
from mcpwatchman.workers.scanner.reachability import (
    SourceAvailability,
    SourceState,
    from_exception,
)
from mcpwatchman.workers.scanner.source import FetchError, SourceUnreachableError
from mcpwatchman.workers.scanner.transparency_check import assess_transparency


def test_an_unreachable_repository_is_a_finding_about_the_publisher() -> None:
    a = SourceAvailability(SourceState.UNREACHABLE, "https://github.com/x/y")
    assert a.is_transparency_finding
    assert not a.readable


def test_our_own_failure_is_never_a_finding_about_the_server() -> None:
    """The `SourceUnreachableError` / `FetchError` split, carried through.

    A timeout or a full scratch disk says nothing about anyone's repository,
    and publishing it as though it did would be a false accusation sourced
    entirely from our own infrastructure.
    """
    a = SourceAvailability(SourceState.FETCH_FAILED, detail="read-only scratch mount")
    assert not a.is_transparency_finding
    assert "our side" in a.reason
    assert "not a finding about the server" in a.reason


def test_the_reason_never_claims_the_repository_is_absent() -> None:
    """GitHub 404s private repositories deliberately, so we cannot tell.

    The honest claim is "not publicly reachable". "Does not exist" would be an
    over-claim we have no way to support, and it is the phrasing that comes
    naturally.
    """
    reason = SourceAvailability(SourceState.UNREACHABLE, "https://github.com/x/y").reason
    assert "not publicly reachable" in reason
    assert "does not exist" not in reason
    assert "private" in reason
    assert "https://github.com/x/y" in reason


def test_a_declared_url_is_optional_in_the_reason() -> None:
    reason = SourceAvailability(SourceState.UNREACHABLE).reason
    assert "not publicly reachable" in reason
    assert "()" not in reason


def test_no_declaration_is_distinct_from_an_unreachable_one() -> None:
    a = SourceAvailability(SourceState.NOT_DECLARED)
    assert a.is_transparency_finding
    assert "declares no source" in a.reason


def test_not_attempted_is_about_our_queue_not_the_server() -> None:
    a = SourceAvailability(SourceState.NOT_ATTEMPTED)
    assert not a.is_transparency_finding
    assert not a.readable


def test_a_fetched_source_has_no_reason_to_give() -> None:
    a = SourceAvailability(SourceState.FETCHED)
    assert a.readable
    assert a.reason == ""
    assert not a.is_transparency_finding


@pytest.mark.parametrize(("exc", "expected"), [
    (SourceUnreachableError("repository not found"), SourceState.UNREACHABLE),
    (FetchError("connection timed out"), SourceState.FETCH_FAILED),
    (OSError("no space left on device"), SourceState.FETCH_FAILED),
])
def test_exceptions_classify_by_whose_fault_they_are(exc, expected) -> None:
    assert from_exception(exc, "https://github.com/x/y").state is expected


# --- what the reader actually gets ----------------------------------------


def test_transparency_reports_the_real_cause_not_a_generic_one() -> None:
    """The point of the whole module: two different facts, two sentences.

    Without this, a repository that 404s for the world and a server our queue
    simply has not reached both render as "no source was fetched". One is about
    the publisher and one is about us.
    """
    unreachable = assess_transparency(
        availability=SourceAvailability(SourceState.UNREACHABLE, "https://github.com/x/y")
    )
    queued = assess_transparency()

    assert unreachable.score is None and queued.score is None
    assert unreachable.assessed_weight == 0

    theirs = {s.reason for s in unreachable.unassessed}
    ours = {s.reason for s in queued.unassessed}
    assert theirs != ours
    assert all("not publicly reachable" in r for r in theirs)
    assert all("no source was fetched" in r for r in ours)


def test_an_unreachable_repository_still_scores_nothing_rather_than_zero() -> None:
    """`03` §7 defines no band for this, so it is reported and not scored."""
    axis = assess_transparency(
        availability=SourceAvailability(SourceState.UNREACHABLE, "https://github.com/x/y")
    )
    assert axis.score is None, "a 0 here would accuse the server of documenting nothing"
    assert len(axis.unassessed) == 5


# --- coverage accounting --------------------------------------------------


def test_coverage_reads_none_until_outcomes_exist() -> None:
    """Not checked and checked-and-none-reachable are opposite claims."""
    report = CoverageReport(total=10, declared_scannable=8)
    assert report.declared_coverage == 0.8
    assert report.verified_coverage is None
    assert report.verified_unreachable is None
    assert report.declared_but_unreachable is None


def test_outcomes_fill_the_verified_half_and_expose_the_overstatement() -> None:
    report = CoverageReport(total=10, declared_scannable=8).with_outcomes([
        *[SourceAvailability(SourceState.FETCHED)] * 4,
        *[SourceAvailability(SourceState.UNREACHABLE, "https://github.com/x/y")] * 3,
        SourceAvailability(SourceState.FETCH_FAILED, detail="timeout"),
    ])
    assert report.declared_coverage == 0.8          # the publisher's claim
    assert report.verified_coverage == 0.4          # what we could actually read
    assert report.verified_unreachable == 3
    # Our own failure is not counted against anyone's repository.
    assert report.verified_scannable == 4


def test_with_outcomes_leaves_the_declared_half_untouched() -> None:
    original = CoverageReport(total=10, declared_scannable=8, by_kind={"git": 8})
    updated = original.with_outcomes([SourceAvailability(SourceState.FETCHED)])
    assert updated.total == original.total
    assert updated.declared_scannable == original.declared_scannable
    assert updated.by_kind == original.by_kind
    assert original.verified_scannable is None, "with_outcomes must not mutate"


def test_a_published_reason_never_carries_our_scratch_path() -> None:
    """Measured, not hypothetical: this reached the published data.

    A fetch failure published `/tmp/mcpw-scan-9evtt3fl/src/apps/mcp-server` — a
    path that tells a reader nothing and tells everyone else where we unpack
    strangers' code. `base.md` § *Host & system telemetry* puts absolute paths
    at Tier C: strip them on a public surface, and this is as public as it gets.
    """
    a = SourceAvailability(
        SourceState.FETCH_FAILED,
        "https://github.com/x/y",
        detail="fetch produced no tree at /tmp/mcpw-scan-9evtt3fl/src/apps/mcp-server",
    )
    assert "/tmp/" not in a.reason  # noqa: S108 - the literal is the needle, not a path we open
    assert "mcpw-scan" not in a.reason
    assert "<path>" in a.reason
    # The useful half survives: whose fault it is, and that it is retryable.
    assert "our side" in a.reason and "retryable" in a.reason


def test_redaction_leaves_ordinary_prose_alone() -> None:
    from mcpwatchman.workers.scanner.reachability import redact_paths

    assert redact_paths("connection timed out after 30s") == "connection timed out after 30s"
    assert redact_paths("could not read a/b") == "could not read a/b"


def test_redaction_leaves_a_url_intact() -> None:
    """A redaction that eats an address is worse than the leak it prevents.

    The first pattern matched from the SECOND slash of `https://…` and published
    `https:/<path>` — a destroyed address that still looks like redaction worked.
    """
    from mcpwatchman.workers.scanner.reachability import redact_paths

    assert redact_paths("could not reach https://github.com/owner/repo") == (
        "could not reach https://github.com/owner/repo"
    )
    assert redact_paths("spec github:Pack/pack@1.0.0#apps/mcp-server") == (
        "spec github:Pack/pack@1.0.0#apps/mcp-server"
    )
    # …while still catching the thing it is for.
    assert "<path>" in redact_paths("no tree at /tmp/mcpw-scan-9ev/src/apps")  # noqa: S108
