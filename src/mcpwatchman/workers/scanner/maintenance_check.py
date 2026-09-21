"""Maintenance scoring (`03` §5) over forge signals (`04` §7).

`03` §5 measures one thing: **"if I file an issue tomorrow, will anyone read
it?"** It is the axis that says an unmaintained server with no findings today is
a riskier choice than a maintained one with a medium finding today, because the
unmaintained one cannot respond to the next finding.

**This module is the SCORING half.** All five of `03` §5's ladders are here and
pure — no network, no clock beyond the `as_of` the caller supplies, so the same
signals always score the same way and the gold-set calibration can run them a
few thousand times. The fetch half is `scanner.forge`.

⚠ **This docstring said "the FETCH half is not built" and listed two named
blockers. One of them is gone and the sentence outlived it.** `scanner.forge`
retrieves four of the five sub-checks' signals from the GitHub GraphQL API. The
surviving blocker is the second one and it is unchanged:

**`repository_signals` is not a per-server measurement at all.** `03` §5 scores
it by z-score *within the server's category*, falling back to the registry-wide
distribution for categories under ten servers. That needs a distribution across
every scanned server, so it cannot be computed while scanning one — it is a
post-pass over the whole crawl. It also needs a *category*, and a registry entry
carries none. Until both exist the sub-check reports unassessed and its 10%
renormalises away, which is the correct handling and not a gap to paper over.

Every sub-check abstains independently, so a partial fetch scores what it
brought back instead of failing the axis: a repository whose commits are
readable but whose issues are not still scores recency, cadence and bus factor.

⚠ **An absent field now has TWO meanings and `MaintenanceSignals.retrieved`
separates them.** While no fetch existed, `last_release=None` could only mean
"we never looked". It can now also mean "this project has never released" —
opposite claims about who is at fault, and `_absent` is what keeps the published
sentence matching the one that actually holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from mcpwatchman.workers.scanner.reachability import Fault
from mcpwatchman.workers.scoring.axes import AxisResult, SubCheck, ladder, score_axis

AXIS = "maintenance"

# `03` §5's ladders, as data. Each is (threshold_inclusive, score), ascending,
# for a smaller-is-better measurement in days.
RECENCY_DAYS = ((30, 100), (90, 80), (180, 60), (365, 30))
RELEASE_GAP_DAYS = ((60, 100), (120, 80), (240, 60))
ISSUE_RESPONSE_DAYS = ((3, 100), (7, 80), (21, 60), (60, 30))

# `03` §5: a release inside this window scores 100 regardless of median gap.
RECENT_RELEASE_DAYS = 30
# `03` §5's bus-factor definition: "distinct authors with >= 5 commits in the
# last 12 months".
BUS_FACTOR_MIN_COMMITS = 5
BUS_FACTOR_STALE_DAYS = 90
# `03` §5: fewer than this many issues in the last 6 months falls back to the
# repository's lifetime median.
ISSUE_SAMPLE_MIN = 3


@dataclass(frozen=True, slots=True)
class MaintenanceSignals:
    """What `04` §7 pulls from the forge, as the values `03` §5 scores.

    Every field is optional and `None` means *not retrieved*, never *zero*. The
    distinction decides whether a sub-check scores or abstains, and conflating
    them would turn an API failure into an accusation of neglect — a repository
    whose issues endpoint 404s is not a repository nobody answers.
    """

    last_commit: date | None = None
    last_release: date | None = None
    # Median days between releases over the last 12 months.
    median_release_gap_days: float | None = None
    # Median days to first maintainer comment, over the last 6 months.
    median_first_response_days: float | None = None
    # How many issues that median was taken over, so the small-sample fallback
    # in `03` §5 can be applied by the caller that fetched them.
    issues_sampled: int | None = None
    # Lifetime median, used when `issues_sampled` is under ISSUE_SAMPLE_MIN.
    lifetime_first_response_days: float | None = None
    # Distinct authors with >= BUS_FACTOR_MIN_COMMITS commits in 12 months.
    authors_12mo: int | None = None
    # Distinct authors with ANY commit in 12 months. Separates "one person
    # committing steadily" from "one person who pushed twice", which `03` §5's
    # ladder starts below.
    contributors_12mo: int | None = None
    # 1 (top) to 4 (bottom) within the server's category. Not computable while
    # scanning a single server — see the module docstring.
    category_quartile: int | None = None

    # ⚠ Whether `scanner.forge` actually READ the repository. It decides what an
    # absent field MEANS, and the two readings are opposite claims: before the
    # fetch existed, `last_release=None` meant "we never looked"; now it can
    # also mean "this project has never released". Publishing the first
    # sentence about the second case blames our own unbuilt capability for a
    # measurement we have taken.
    retrieved: bool = False
    # Whether `median_release_gap_days` was derived from GitHub Releases or from
    # version tags. `03` §5 says "releases" and a project that tags `v1.4.2` and
    # publishes to npm has released — but a reader is owed which artefact the
    # number came from, so it is rendered rather than assumed.
    release_basis: str = "releases"
    # WHOSE gap an absent field is, as a `reachability.Fault` value. ⚠ DEFAULTS
    # TO THE REFUSED VALUE for the reason `SubCheck.fault` does: a caller that
    # builds signals without saying where they came from must cost a failed run,
    # never a public page. `assess_maintenance()` with no arguments is exactly
    # that caller, and it was this module's only entry point for as long as the
    # fetch did not exist.
    fault: str = Fault.UNATTRIBUTED.value


def _days_since(when: date | None, as_of: date) -> int | None:
    return None if when is None else (as_of - when).days


def _absent(signals: MaintenanceSignals, *, read: str, unread: str) -> str:
    """Why a signal is missing — *the repository has none* vs *we did not look*.

    Two different claims that produced one sentence while only the second was
    possible. A page saying "no release history was retrieved" about a project
    that demonstrably publishes none is not merely imprecise: it attributes to
    our tooling a fact the publisher owns, on a surface whose premise is that
    every claim is checkable.
    """
    return read if signals.retrieved else unread


def score_recency(signals: MaintenanceSignals, as_of: date) -> SubCheck:
    """`03` §5's recency ladder.

    §5 is explicit that this does not penalise a stable server for being stable:
    a project at v1.0.0 for a year with a commit a month is not unmaintained.
    The signal wanted is whether anyone is still reading.
    """
    name = "recency"
    days = _days_since(signals.last_commit, as_of)
    if days is None:
        return SubCheck(
            name, None,
            reason=_absent(
                signals,
                read="this repository has no commit on its default branch",
                unread="no last-commit date was retrieved for this repository",
            ),
            fault=signals.fault,
        )
    if days < 0:
        # A future-dated commit is a forged or clock-skewed timestamp. Treat it
        # as today rather than trusting it: rewarding a server for a commit
        # dated next year would make the ladder trivially gameable.
        days = 0
    return SubCheck(
        name, ladder(days, RECENCY_DAYS),
        evidence=(f"last commit {days} day(s) before {as_of.isoformat()}",),
    )


def score_release_cadence(signals: MaintenanceSignals, as_of: date) -> SubCheck:
    """`03` §5's release-cadence ladder.

    Its top band is a disjunction — "released in the last 30 days OR median gap
    <= 60 days" — so a project that has just shipped scores 100 whatever its
    history, and the two lowest bands turn on whether anything shipped at all
    inside a year.
    """
    name = "release_cadence"
    since_release = _days_since(signals.last_release, as_of)
    gap = signals.median_release_gap_days

    if since_release is None and gap is None:
        return SubCheck(
            name, None,
            reason=_absent(
                signals,
                read="this repository publishes neither releases nor version tags",
                unread="no release history was retrieved for this repository",
            ),
            fault=signals.fault,
        )

    # Clamped for the same reason `score_recency` clamps, and this ladder was
    # the one that missed it — the one-fixed-one-missed shape `CLAUDE.md`
    # records for this repo. A future-dated release otherwise scores 100 and
    # renders "released -442 day(s) ago" on a public page.
    if since_release is not None and since_release < 0:
        since_release = 0
    if since_release is not None and since_release <= RECENT_RELEASE_DAYS:
        return SubCheck(
            name, 100,
            evidence=(f"released {since_release} day(s) ago (by "
                      f"{signals.release_basis}), inside `03` §5's "
                      f"{RECENT_RELEASE_DAYS}-day window",),
        )
    if since_release is not None and since_release > 365:
        return SubCheck(
            name, 0,
            evidence=(f"no release in {since_release} days (by "
                      f"{signals.release_basis}) — over a year",),
        )
    if gap is None:
        return SubCheck(
            name, None,
            reason="a release exists but fewer than two fall inside `03` §5's "
                   "12-month window, so no median gap can be taken — and §5's "
                   "remaining bands are all defined on that median. A limit of "
                   "the methodology, not of this repository.",
            fault=Fault.PROJECT.value,
        )
    # Released within the year but with a median gap past the last rung: `03` §5
    # names this case explicitly and scores it 30.
    return SubCheck(
        name, ladder(gap, RELEASE_GAP_DAYS, floor=30),
        # The basis is rendered, never assumed. `03` §5 says "releases"; a
        # project that ships by tagging and publishing to a package registry
        # has released, and a reader comparing two servers is owed which
        # artefact each number was taken from.
        evidence=(f"median release gap {gap:.0f} days (by {signals.release_basis})"
                  + (f", last release {since_release} day(s) ago"
                     if since_release is not None else ""),),
    )


def score_issue_responsiveness(signals: MaintenanceSignals) -> SubCheck:
    """`03` §5's issue-responsiveness ladder, with its small-sample fallback.

    ⚠ **"No response on any issue" and "no issues to respond to" are different
    facts and `03` §5 scores only the first.** A repository with zero issues
    filed has not failed to answer anything; scoring it 0 would penalise a
    server for being uncontroversial. It abstains instead.
    """
    name = "issue_responsiveness"
    sampled = signals.issues_sampled
    median = signals.median_first_response_days

    if sampled is not None and sampled < ISSUE_SAMPLE_MIN:
        median = signals.lifetime_first_response_days
        basis = (
            f"lifetime median ({sampled} issue(s) in the last 6 months, under "
            f"`03` §5's floor of {ISSUE_SAMPLE_MIN})"
        )
    else:
        basis = (
            f"median over {sampled} issue(s) in the last 6 months"
            if sampled
            else "median first response"
        )

    if median is None:
        return SubCheck(
            name, None,
            reason=_absent(
                signals,
                read="this repository has no issues `03` §5's window covers. An "
                     "unanswered issue scores 0 under §5, but a repository with "
                     "no issues filed has not failed to answer one.",
                unread="no issue-response median was retrieved. An unanswered "
                       "issue scores 0 under `03` §5, but an absent measurement "
                       "is not an unanswered issue.",
            ),
            fault=signals.fault,
        )
    return SubCheck(
        name, ladder(median, ISSUE_RESPONSE_DAYS),
        evidence=(f"{basis}: {median:.1f} day(s) to first maintainer comment",),
    )


def score_bus_factor(signals: MaintenanceSignals, as_of: date) -> SubCheck:
    """`03` §5's bus-factor ladder.

    §5 does not penalise sole maintainers harshly — most high-quality servers in
    the registry are sole-maintainer projects — but the penalty exists because a
    sole-maintained server is structurally fragile.

    ⚠ **§5's ladder starts at one author and this case is common below it.** A
    repository with four commits from one person has ZERO authors at §5's
    >=5-commit bar, which the ladder does not describe. Rather than invent a
    band, that is scored as the weakest band §5 DOES describe (a sole maintainer
    who has gone quiet), because a project below the sole-maintainer bar is at
    least as fragile as one at it. Stated here because applying an existing band
    to an undescribed case is a judgement, not a reading.
    """
    name = "bus_factor"
    authors = signals.authors_12mo
    if authors is None:
        return SubCheck(
            name, None,
            reason=_absent(
                signals,
                # ⚠ WHEN THE FORGE WAS READ, THIS GAP IS OURS AND NOT THEIRS.
                # `forge._bus_factor` returns None only when our own page bound
                # left the count spanning more than one of `03` §5's bands —
                # the repository answered in full and we stopped reading.
                # Attributing that to the publisher would be the precise
                # inversion `reachability.Fault` exists to prevent.
                read="this repository's 12-month history is longer than the "
                     "bounded walk `04` §7 performs, and the authors found so "
                     "far span more than one of `03` §5's bands. A limit of "
                     "ours, not a finding about the server.",
                unread="no contributor history was retrieved for this repository",
            ),
            fault=Fault.PROJECT.value if signals.retrieved else signals.fault,
        )

    # ⚠ `or 0` here read UNKNOWN as "committed today": `_days_since` returns
    # None for a missing date and `None or 0` is 0, so a sole maintainer whose
    # last commit was never retrieved scored 50 (healthy) instead of 30. It was
    # the one place in this module that turned a `None` signal into a
    # favourable value, against `MaintenanceSignals`' own rule that None means
    # not-retrieved and never zero.
    days_since_commit = _days_since(signals.last_commit, as_of)
    stale = days_since_commit is not None and days_since_commit > BUS_FACTOR_STALE_DAYS

    if authors >= 3:
        return SubCheck(
            name, 100,
            evidence=(f"{authors} authors with >= {BUS_FACTOR_MIN_COMMITS} "
                      "commits in 12 months",),
        )
    if authors == 2:
        return SubCheck(name, 80, evidence=("2 regular authors in the last 12 months",))
    if authors == 1:
        # ⚠ The sole-maintainer band FORKS on freshness — 50 if active, 30 if
        # quiet — so with no commit date we cannot choose between them, and the
        # two differ by 20 points. The old `(_days_since(...) or 0)` silently
        # picked the favourable one by turning None into 0, which is the single
        # place in this module that let a missing signal read as good news.
        # Abstaining costs the axis 15% of its weight and asserts nothing we did
        # not measure, which is the trade every other sub-check here makes.
        if days_since_commit is None:
            return SubCheck(
                name, None,
                reason="sole maintainer, but no last-commit date was retrieved — "
                       f"`03` §5 scores this 50 when active and 30 after "
                       f"{BUS_FACTOR_STALE_DAYS} quiet days, and nothing here "
                       "distinguishes the two",
                fault=signals.fault,
            )
        return SubCheck(
            name, 30 if stale else 50,
            evidence=("sole maintainer"
                      + (f", and no commit in over {BUS_FACTOR_STALE_DAYS} days"
                         if stale else ""),),
        )
    contributors = signals.contributors_12mo
    return SubCheck(
        name, 30,
        evidence=(f"no author reached `03` §5's {BUS_FACTOR_MIN_COMMITS}-commit bar "
                  f"in the last 12 months"
                  + (f" ({contributors} contributor(s) with fewer)"
                     if contributors is not None else "")
                  + " — scored at §5's weakest described band, which the section "
                    "defines for a quiet sole maintainer",),
    )


def score_repository_signals(signals: MaintenanceSignals) -> SubCheck:
    """`03` §5's relative popularity sub-check.

    §5 weights this only 10% and says why: popularity is not safety. The signal
    wanted is narrower — is this server used by anyone, or abandoned?
    """
    name = "repository_signals"
    quartile = signals.category_quartile
    if quartile is None:
        return SubCheck(
            name, None,
            reason="`03` §5 scores this by quartile WITHIN the server's category, "
                   "which needs a distribution across every scanned server and "
                   "so cannot be computed while scanning one. It is a post-pass "
                   "over the crawl and that pass does not exist yet.",
            fault=Fault.PROJECT.value,
        )
    if quartile not in (1, 2, 3, 4):
        raise ValueError(f"category_quartile must be 1-4, got {quartile!r}")
    return SubCheck(
        name, {1: 100, 2: 75, 3: 50, 4: 25}[quartile],
        evidence=(f"quartile {quartile} of 4 within its category on stars, forks "
                  "and dependents",),
    )


def assess_maintenance(
    signals: MaintenanceSignals | None = None, as_of: date | None = None
) -> AxisResult:
    """Score the Maintenance axis (`03` §5) from retrieved forge signals.

    `signals=None` means nothing was retrieved — no repository was declared, or
    the fetch failed — and every sub-check abstains. `as_of` defaults to today
    and exists so the ladders are testable and reproducible: a scan re-run
    against stored signals must produce the score it produced at the time.
    """
    as_of = as_of or date.today()
    signals = signals or MaintenanceSignals()
    return score_axis(AXIS, [
        score_recency(signals, as_of),
        score_issue_responsiveness(signals),
        score_release_cadence(signals, as_of),
        score_bus_factor(signals, as_of),
        score_repository_signals(signals),
    ])
