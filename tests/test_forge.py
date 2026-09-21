"""Forge retrieval for the Maintenance axis (`03` §5, `04` §7).

Aimed at the pure half, which is where the decisions are: what a payload MEANS,
whose fault an absence is, and which of the two claims a sentence is making.
The network half gets a stub client rather than a mock library — the thing worth
pinning is the mapping from an HTTP outcome to a `Fault`, and that is four
branches, not a protocol.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.forge import (
    CACHE_TTL_SECONDS,
    ForgeError,
    ForgeUnreachableError,
    RepoRef,
    _bus_factor,
    _cache_path,
    _classify_errors,
    classify_repo_url,
    fetch_signals,
    parse_repo_url,
    signals_from_payload,
    token_from_env,
)
from mcpwatchman.workers.scanner.maintenance_check import (
    MaintenanceSignals,
    assess_maintenance,
)
from mcpwatchman.workers.scanner.reachability import Fault

AS_OF = date(2026, 9, 20)


def _iso(days_ago: float) -> str:
    return (
        datetime.combine(AS_OF, datetime.min.time(), tzinfo=UTC)
        - timedelta(days=days_ago)
    ).isoformat()


def _payload(**over) -> dict:
    """A minimal well-formed repository payload, overridable per test."""
    base: dict = {
        "defaultBranchRef": {
            "target": {
                "committedDate": _iso(5),
                "history": {"totalCount": 1, "nodes": [
                    {"committedDate": _iso(5), "author": {"user": {"login": "amy"}}},
                ]},
            }
        },
        "releases": {"nodes": []},
        "refs": {"nodes": []},
        "issues": {"totalCount": 0, "nodes": []},
    }
    base.update(over)
    return base


def _signals(payload: dict, *, fetched: int = 1, total: int = 1) -> MaintenanceSignals:
    return signals_from_payload(payload, AS_OF, fetched=fetched, total=total)


# ── URL classification ──────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.com/acme/srv",
    "https://github.com/acme/srv.git",
    "https://github.com/acme/srv/tree/main/packages/x",
    "https://www.github.com/acme/srv/",
])
def test_github_urls_resolve_to_the_repository(url: str) -> None:
    assert parse_repo_url(url) == RepoRef("github.com", "acme", "srv")


@pytest.mark.parametrize("url", ["https://gitlab.com/a/b", "", "not a url", "https://github.com/acme"])
def test_non_github_urls_do_not_resolve(url: str) -> None:
    assert parse_repo_url(url) is None


def test_the_three_reasons_there_is_no_repository_are_three_different_faults() -> None:
    """⚠ The whole point of `classify_repo_url`, and they are not interchangeable.

    Collapsing them is how our unbuilt GitLab support would get published as a
    finding about a GitLab-hosted server, or how a server that declares nothing
    would be excused as our gap.
    """
    nothing = classify_repo_url("")
    elsewhere = classify_repo_url("https://gitlab.com/acme/srv")
    malformed = classify_repo_url("https://github.com/acme")

    assert nothing[0] is Fault.PUBLISHER
    assert elsewhere[0] is Fault.PROJECT
    assert malformed[0] is Fault.PUBLISHER
    # The PROJECT sentence must say the limit is ours, in our own voice.
    assert "not built" in elsewhere[1] and "limit of ours" in elsewhere[1]
    assert "gitlab.com" in elsewhere[1]


def test_a_repo_name_cannot_escape_the_cache_directory(tmp_path: Path) -> None:
    """Registry-supplied text reaching a filesystem path, bounded at the boundary."""
    ok = _cache_path(tmp_path, RepoRef("github.com", "acme", "srv"))
    assert tmp_path in ok.parents
    with pytest.raises(ForgeError):
        _cache_path(tmp_path, RepoRef("github.com", "..", "..%2Fetc"))


def test_the_token_is_read_from_the_project_name_first() -> None:
    assert token_from_env({"GITHUB_TOKEN": "b", "MCPWATCHMAN_GITHUB_TOKEN": "a"}) == "a"
    assert token_from_env({"GITHUB_TOKEN": "b"}) == "b"
    # Whitespace is not a token. Reading it as one produces the silent
    # whole-cohort carry-forward `preflight` exists to prevent.
    assert token_from_env({"MCPWATCHMAN_GITHUB_TOKEN": "  ", "GITHUB_TOKEN": ""}) is None


# ── the branch-head trap ────────────────────────────────────────────────────

def test_an_abandoned_repository_scores_zero_rather_than_abstaining() -> None:
    """⚠ THE INVERSION THIS AXIS EXISTS TO CATCH.

    `history(since:)` is filtered to 12 months, so a repository with no commit
    in two years returns an EMPTY history — identical in shape to one we failed
    to read. Deriving `last_commit` from the history nodes would make `03` §5's
    only 0 band unreachable and publish "not assessed" about the single case
    the axis is most confident in.
    """
    stale = _payload(defaultBranchRef={"target": {
        "committedDate": _iso(800),
        "history": {"totalCount": 0, "nodes": []},
    }})
    signals = _signals(stale, fetched=0, total=0)
    assert signals.last_commit == date(2024, 7, 12)

    axis = assess_maintenance(signals, as_of=AS_OF)
    recency = next(s for s in axis.subchecks if s.name == "recency")
    assert recency.score == 0, "an 800-day-old repository is `03` §5's 0 band, not a gap"


def test_an_empty_repository_abstains_and_blames_nobody_for_it() -> None:
    empty = _payload(defaultBranchRef={})
    signals = _signals(empty, fetched=0, total=0)
    assert signals.last_commit is None
    assert signals.retrieved is True
    recency = next(
        s for s in assess_maintenance(signals, as_of=AS_OF).subchecks if s.name == "recency"
    )
    assert recency.score is None
    # Read, not unread — the forge answered and the repository has no commit.
    assert "no commit on its default branch" in recency.reason
    assert recency.fault == Fault.PUBLISHER.value


# ── bus factor ──────────────────────────────────────────────────────────────

def test_a_bounded_walk_answers_exactly_when_it_exhausted_the_history() -> None:
    assert _bus_factor({"a": 9, "b": 6, "c": 1}, fetched=16, total=16) == (2, 3)


def test_three_qualifying_authors_need_no_further_pages() -> None:
    """More commits can only ADD authors, and `03` §5's top band is "3 or more"."""
    authors, contributors = _bus_factor({"a": 5, "b": 5, "c": 5}, fetched=100, total=9000)
    assert authors == 3
    assert contributors is None, "a lower bound must not be reported as a count"
    assert assess_maintenance(
        MaintenanceSignals(authors_12mo=authors, last_commit=AS_OF, retrieved=True),
        as_of=AS_OF,
    ).subchecks[3].score == 100


def test_an_ambiguous_tail_abstains_rather_than_accusing() -> None:
    """⚠ A lower bound of 1 is not "sole maintainer" — it is "we stopped reading".

    The difference between §5's 50 and its 100 band, published about someone
    else's project on the strength of a page limit of ours.
    """
    assert _bus_factor({"a": 90, "b": 2}, fetched=100, total=9000) == (None, None)
    # ...and that gap is OURS, not the publisher's.
    signals = MaintenanceSignals(
        authors_12mo=None, last_commit=AS_OF, retrieved=True, fault=Fault.PUBLISHER.value
    )
    bus = next(
        s for s in assess_maintenance(signals, as_of=AS_OF).subchecks if s.name == "bus_factor"
    )
    assert bus.score is None
    assert bus.fault == Fault.PROJECT.value, "our page bound is not their neglect"
    assert "limit of ours" in bus.reason


def test_a_short_tail_cannot_change_the_band() -> None:
    # Four unread commits cannot produce a further 5-commit author.
    assert _bus_factor({"a": 90}, fetched=96, total=100)[0] == 1


def test_release_bots_are_not_maintainers() -> None:
    """A dependabot with forty commits would turn a sole maintainer into two.

    Favourable direction, which is the one this project is least willing to
    get wrong.
    """
    busy = _payload(defaultBranchRef={"target": {
        "committedDate": _iso(2),
        "history": {"totalCount": 12, "nodes": (
            [{"committedDate": _iso(1), "author": {"user": {"login": "amy"}}}] * 6
            + [{"committedDate": _iso(1), "author": {"user": {"login": "dependabot[bot]"}}}] * 6
        )},
    }})
    assert _signals(busy, fetched=12, total=12).authors_12mo == 1


# ── releases ────────────────────────────────────────────────────────────────

def test_version_tags_stand_in_when_a_project_publishes_no_releases() -> None:
    """`03` §5 measures shipping, and tagging plus a registry publish is shipping."""
    tagged = _payload(refs={"nodes": [
        {"target": {"committedDate": _iso(10)}},
        {"target": {"target": {"committedDate": _iso(50)}}},  # annotated tag
        {"target": {"committedDate": _iso(95)}},
    ]})
    signals = _signals(tagged)
    assert signals.release_basis == "tags"
    assert signals.last_release == date(2026, 9, 10)
    assert signals.median_release_gap_days == pytest.approx(42.5)

    # The basis reaches the page. A reader comparing two servers is owed which
    # artefact each number came from.
    cadence = next(
        s for s in assess_maintenance(signals, as_of=AS_OF).subchecks
        if s.name == "release_cadence"
    )
    assert "by tags" in cadence.evidence[0]


def test_real_releases_win_over_tags() -> None:
    both = _payload(
        releases={"nodes": [{"publishedAt": _iso(3), "isDraft": False}]},
        refs={"nodes": [{"target": {"committedDate": _iso(400)}}]},
    )
    signals = _signals(both)
    assert signals.release_basis == "releases"
    assert signals.last_release == date(2026, 9, 17)


def test_a_draft_is_not_a_release() -> None:
    drafts = _payload(releases={"nodes": [
        {"publishedAt": _iso(1), "isDraft": True},
        {"publishedAt": _iso(40), "isDraft": False},
    ]})
    assert _signals(drafts).last_release == date(2026, 8, 11)


def test_one_release_in_the_window_yields_no_median() -> None:
    """`03` §5 defines its remaining bands on a median; a sample of one has none."""
    single = _payload(releases={"nodes": [{"publishedAt": _iso(200), "isDraft": False}]})
    signals = _signals(single)
    assert signals.last_release is not None
    assert signals.median_release_gap_days is None
    cadence = next(
        s for s in assess_maintenance(signals, as_of=AS_OF).subchecks
        if s.name == "release_cadence"
    )
    assert cadence.score is None
    # A methodology limit, not the publisher's — and not our environment either.
    assert cadence.fault == Fault.PROJECT.value


# ── issues ──────────────────────────────────────────────────────────────────

def _issue(created_days: float, comments: list[dict]) -> dict:
    return {"createdAt": _iso(created_days), "author": {"login": "asker"},
            "comments": {"nodes": comments}}


def _comment(days_ago: float, *, who: str = "amy", assoc: str = "OWNER") -> dict:
    return {"createdAt": _iso(days_ago), "authorAssociation": assoc,
            "author": {"login": who}}


def test_the_median_is_days_to_the_first_maintainer_comment() -> None:
    payload = _payload(issues={"totalCount": 2, "nodes": [
        _issue(30, [_comment(28)]),   # 2 days
        _issue(20, [_comment(16)]),   # 4 days
    ]})
    signals = _signals(payload)
    assert signals.median_first_response_days == pytest.approx(3.0)
    assert signals.issues_sampled == 2


def test_a_drive_by_commenter_is_not_a_maintainer_response() -> None:
    payload = _payload(issues={"totalCount": 1, "nodes": [
        _issue(40, [_comment(39, who="stranger", assoc="NONE"), _comment(20)]),
    ]})
    # 20 days to the OWNER's comment, not 1 day to the passer-by's.
    assert _signals(payload).median_first_response_days == pytest.approx(20.0)


def test_answering_your_own_issue_is_not_answering_anyone() -> None:
    """Maintainer-filed tracking issues would otherwise report minutes."""
    payload = _payload(issues={"totalCount": 1, "nodes": [
        {"createdAt": _iso(40), "author": {"login": "amy"},
         "comments": {"nodes": [_comment(39.9, who="amy")]}},
    ]})
    # Censored at 40 days waited, not scored at 0.1.
    assert _signals(payload).median_first_response_days == pytest.approx(40.0)


def test_an_unanswered_issue_is_censored_not_dropped() -> None:
    """⚠ `03` §5's bottom band IS the unanswered case.

    Excluding silent issues from the median deletes exactly the observations
    the band exists to catch, and would score a tracker nobody reads at 100 on
    the strength of its one answered issue.
    """
    payload = _payload(issues={"totalCount": 2, "nodes": [
        _issue(120, []),
        _issue(100, []),
    ]})
    signals = _signals(payload)
    assert signals.median_first_response_days == pytest.approx(110.0)
    responsiveness = next(
        s for s in assess_maintenance(signals, as_of=AS_OF).subchecks
        if s.name == "issue_responsiveness"
    )
    assert responsiveness.score == 0


def test_a_lifetime_median_is_withheld_unless_the_sample_really_is_the_lifetime() -> None:
    """⚠ `score_issue_responsiveness` renders the words "lifetime median" verbatim.

    On a busy tracker the newest 50 issues are a recent sample, and the small
    fetch bound must not be laundered into a claim about the project's history.
    """
    complete = _payload(issues={"totalCount": 1, "nodes": [_issue(400, [_comment(399)])]})
    assert _signals(complete).lifetime_first_response_days == pytest.approx(1.0)

    truncated = _payload(issues={"totalCount": 900, "nodes": [_issue(400, [_comment(399)])]})
    assert _signals(truncated).lifetime_first_response_days is None


# ── error classification ────────────────────────────────────────────────────

def test_errors_are_classified_on_type_and_never_on_prose() -> None:
    """⚠ GitHub interpolates the repository NAME into `message`.

    So a repository can write our error text. Reading it would let one named
    `rate limit exceeded` talk us out of reporting a fault that is ours — or
    one named to look like a 404 manufacture an accusation against itself.
    """
    steering = [{"type": "INTERNAL", "message": "Could not resolve to a Repository"}]
    assert isinstance(_classify_errors(steering), ForgeError)
    assert not isinstance(_classify_errors(steering), ForgeUnreachableError)

    assert isinstance(
        _classify_errors([{"type": "NOT_FOUND", "message": "rate limit exceeded"}]),
        ForgeUnreachableError,
    )
    # An unrecognised type is OURS: a retry costs seconds, the other direction
    # publishes a claim we could not identify.
    assert type(_classify_errors([{"type": "WHAT"}])) is ForgeError


class _Response:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _Client:
    """Enough of `httpx.Client` for the four branches that matter."""

    def __init__(self, response: _Response) -> None:
        self._response = response
        self.calls = 0

    def post(self, *_a, **_kw) -> _Response:
        self.calls += 1
        return self._response

    def close(self) -> None:
        pass


def test_an_unreadable_repository_is_theirs_and_a_rate_limit_is_ours(tmp_path: Path) -> None:
    """The one distinction the whole module is arranged around."""
    theirs = fetch_signals(
        "https://github.com/acme/srv", token="t", cache_dir=tmp_path, as_of=AS_OF,
        client=_Client(_Response(200, {"errors": [{"type": "NOT_FOUND"}]})),
    )
    assert theirs.fault is Fault.PUBLISHER
    # ⚠ Asserts the sentence names its OWN stage. The fetch stage's wording
    # ("the repository this server declares…") is forbidden on the page of a
    # server whose PACKAGE failed, and reusing it here put it there — caught
    # by `test_no_built_surface_calls_a_package_failure_a_repository_failure`
    # on a real 492-server regeneration, not by this file.
    assert "GitHub API" in theirs.reason
    assert "the repository this server declares" not in theirs.reason

    ours = fetch_signals(
        "https://github.com/acme/srv", token="t", cache_dir=tmp_path, as_of=AS_OF,
        client=_Client(_Response(403, {})),
    )
    assert ours.fault is Fault.ENVIRONMENT
    assert "retryable" in ours.reason
    assert not ours.fault.publishable, "our outage must never reach a page"


def test_a_missing_token_is_our_environment_not_their_repository(tmp_path: Path) -> None:
    outcome = fetch_signals(
        "https://github.com/acme/srv", token="", cache_dir=tmp_path, as_of=AS_OF,
        client=_Client(_Response(200, {})),
    )
    assert outcome.fault is Fault.ENVIRONMENT
    assert not outcome.retrieved


def test_a_successful_fetch_attributes_every_remaining_gap_to_the_publisher(
    tmp_path: Path,
) -> None:
    outcome = fetch_signals(
        "https://github.com/acme/srv", token="t", cache_dir=tmp_path, as_of=AS_OF,
        client=_Client(_Response(200, {"data": {"repository": _payload()}})),
    )
    assert outcome.fault is Fault.PUBLISHER
    assert outcome.signals.retrieved is True
    assert outcome.signals.last_commit == date(2026, 9, 15)


def test_the_cache_is_used_and_expires(tmp_path: Path) -> None:
    client = _Client(_Response(200, {"data": {"repository": _payload()}}))
    args = dict(token="t", cache_dir=tmp_path, as_of=AS_OF, client=client)

    first = fetch_signals("https://github.com/acme/srv", now=1000.0, **args)
    assert client.calls == 1
    second = fetch_signals("https://github.com/acme/srv", now=1000.0, **args)
    assert client.calls == 1, "a warm cache must not spend a request"
    assert second.signals == first.signals

    fetch_signals("https://github.com/acme/srv", now=1000.0 + CACHE_TTL_SECONDS + 1, **args)
    assert client.calls == 2, "`04` §7 caches for 24 hours, not forever"


def test_a_cache_hit_reproduces_the_walk_bounds(tmp_path: Path) -> None:
    """⚠ `_bus_factor` reads `fetched` against `total`, and neither is in the payload.

    A cache that stored only the repository would re-answer an exhausted walk
    as a bounded one, flipping an exact author count into an abstention on the
    second run and back again on the third.
    """
    payload = _payload(defaultBranchRef={"target": {
        "committedDate": _iso(3),
        "history": {"totalCount": 7, "nodes": [
            {"committedDate": _iso(3), "author": {"user": {"login": "amy"}}},
        ] * 7},
    }})
    client = _Client(_Response(200, {"data": {"repository": payload}}))
    args = dict(token="t", cache_dir=tmp_path, as_of=AS_OF, now=1000.0, client=client)
    cold = fetch_signals("https://github.com/acme/srv", **args)
    warm = fetch_signals("https://github.com/acme/srv", **args)
    assert client.calls == 1
    assert cold.signals == warm.signals
    assert cold.signals.authors_12mo == 1 and cold.signals.contributors_12mo == 1


def test_a_leap_day_scan_does_not_crash(tmp_path: Path) -> None:
    """⚠ A once-in-four-years total outage no ordinary test date can see.

    `.replace(year=as_of.year - 1)` raises on 29 February, and the `since`
    bound is computed on every server — so a run on that date fails on all of
    them, not on one.
    """
    client = _Client(_Response(200, {"data": {"repository": _payload()}}))
    outcome = fetch_signals(
        "https://github.com/acme/srv", token="t", cache_dir=tmp_path,
        as_of=date(2028, 2, 29), client=client,
    )
    assert outcome.fault is Fault.PUBLISHER
