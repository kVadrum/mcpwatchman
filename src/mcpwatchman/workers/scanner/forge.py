"""Forge retrieval for the Maintenance axis (`03` §5, `04` §7).

`maintenance_check` has been the scoring half of a pair whose other half did not
exist: every one of its five ladders is written, tested and pure, and until now
it was handed a default `MaintenanceSignals` with every field `None`, so a
weight-15 axis reported unassessed on all 492 published servers. This module is
the fetch half.

**Two of `03` §5's five sub-checks were blocked on real work and one is blocked
on a different build.** Recency, release cadence, issue responsiveness and bus
factor are all per-repository reads and are implemented here.
`repository_signals` is NOT: `03` §5 scores it by quartile *within the server's
category*, and a registry entry carries no category — so it needs both a
post-pass over the whole crawl and a categorisation that does not exist. It
keeps abstaining, its 10% renormalises away, and that is the named blocker
rather than a shrug.

**GraphQL, not REST, and the reason is arithmetic.** `03` §5's issue
responsiveness is a median over *first maintainer comment*, which in REST is one
request per issue — 50 issues x 492 servers is 24,600 requests against a
5,000/hour limit. One GraphQL query returns the repository, its recent commit
history, its releases and its issues *with their first comments* together. The
whole cohort costs roughly one point per server per page.

**This deviates from `04` §7 on caching and says so rather than pretending.**
§7 specifies "etag caching and conditional requests", which is a REST mechanism;
GitHub's GraphQL endpoint does not honour `If-None-Match`. The intent of that
line is to stay inside the rate limit, and a 24-hour on-disk TTL per repository
serves it — a re-run the same day costs zero requests. Raised at review rather
than silently substituted.

**Whose fault a failure is, is the load-bearing decision in this file**, and it
is the same split `source.SourceUnreachableError` vs `source.FetchError` draws:

- The repository is not publicly readable -> `ForgeUnreachableError` ->
  `PUBLISHER`. It will not fix itself and it is a fact that server's page owes
  its reader.
- We have no token, we were rate-limited, the network failed -> `ForgeError` ->
  `ENVIRONMENT`. Ours, retryable, and `cohort.publication_errors` refuses to put
  it on a page.
- The forge is one we have not built for -> `PROJECT`. Ours, systematic, and
  disclosed in our own voice.

⚠ **Classification reads STRUCTURED fields only — never message text.** GitHub
echoes the owner and repository name into its error strings, so a repository
named to look like a rate-limit notice could otherwise steer our failure into
its own verdict. `CLAUDE.md` records that trap for `git`, where redaction is the
only defence available; here the payload has `errors[].type`, so there is no
excuse for matching on prose.
"""

from __future__ import annotations

import json
import os
import re
import statistics
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcpwatchman.workers.scanner.maintenance_check import MaintenanceSignals
from mcpwatchman.workers.scanner.reachability import Fault

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
USER_AGENT = "mcpwatchman (+https://mcpwatchman.com)"

# Read in this order. The project-specific name wins so a shell that already
# exports a `GITHUB_TOKEN` for something else does not silently decide which
# credential a 492-server crawl authenticates with.
TOKEN_ENV_VARS = ("MCPWATCHMAN_GITHUB_TOKEN", "GITHUB_TOKEN")

# `04` §7: cached 24 hours per repo. See the module docstring for why this is a
# TTL rather than the etag the spec names.
CACHE_TTL_SECONDS = 24 * 60 * 60

# Server-side page size for commit history. `03` §5's bus factor needs authors
# over 12 months, which on a busy repository is thousands of commits; this
# bounds one page and MAX_COMMIT_PAGES bounds the walk.
COMMIT_PAGE_SIZE = 100
MAX_COMMIT_PAGES = 3
# Most recent issues to consider. `03` §5 wants those filed in the last 6
# months; this bounds the fetch and the surplus serves the small-sample
# fallback — see `_issue_medians`.
ISSUE_SAMPLE_SIZE = 50
# First comments to inspect per issue. A maintainer who has not spoken in the
# first ten comments on their own issue has not "first-responded" in any sense
# `03` §5 would recognise.
COMMENTS_PER_ISSUE = 10
RELEASE_SAMPLE_SIZE = 100
TAG_SAMPLE_SIZE = 100

DAYS_PER_YEAR = 365
ISSUE_WINDOW_DAYS = 182  # `03` §5's "last 6 months"

# `03` §5's bus factor counts *people*. A release bot with forty commits is not
# a second maintainer, and counting it turns a sole-maintainer repository
# (score 50) into a two-author one (score 80) — a favourable error, which is
# the direction this project is least willing to make.
_BOT_LOGIN = re.compile(r"(\[bot\]$|^(dependabot|github-actions|renovate)(\[bot\])?$)", re.I)

# GitHub's `authorAssociation` values that mean "speaks for this project".
# CONTRIBUTOR is deliberately absent: it means only that someone once had a
# patch merged, which is not authority to answer an issue.
MAINTAINER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})


class ForgeError(RuntimeError):
    """The fetch failed for reasons on OUR side. Retryable; never published.

    Mirrors `source.FetchError`: a missing token, a rate limit, a timeout, a
    malformed response. `ENVIRONMENT` in `reachability.Fault` terms.
    """


class ForgeUnreachableError(ForgeError):
    """The repository is not publicly readable. THEIRS, and publishable.

    Mirrors `source.SourceUnreachableError`, including its caveat: GitHub
    answers `NOT_FOUND` for a private repository as well as an absent one, so
    this means *not publicly reachable* and never *does not exist*.
    """


@dataclass(frozen=True, slots=True)
class ForgeOutcome:
    """What the fetch produced, and who is responsible for anything missing.

    `signals` is always a `MaintenanceSignals` — an empty one when nothing was
    retrieved — so the caller never has to decide what `None` means. `fault`
    answers the question `signals` cannot: an all-`None` signals object from a
    repository that 404s and one from a run with no token look identical, and
    only one of them may reach a page.
    """

    signals: MaintenanceSignals
    fault: Fault
    reason: str = ""

    @property
    def retrieved(self) -> bool:
        """Whether the forge was actually read.

        ⚠ This compared the signals against a default-constructed
        `MaintenanceSignals`, which stopped being the same question the moment
        `fault` became a field: a no-token outcome differs from the default in
        exactly one attribute and so reported itself as retrieved. The signals
        carry the answer directly; deriving it was always the weaker form.
        """
        return self.signals.retrieved


@dataclass(frozen=True, slots=True)
class RepoRef:
    """A repository the GitHub API can be asked about."""

    host: str
    owner: str
    name: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


def token_from_env(environ: dict[str, str] | None = None) -> str | None:
    """The configured GitHub token, or None.

    ⚠ Returns the VALUE, so never log or format the result. `base.md` §
    *Never print secret VALUES* — the transcript is a channel, and so is a
    published evidence string.
    """
    env = os.environ if environ is None else environ
    for name in TOKEN_ENV_VARS:
        value = env.get(name, "").strip()
        if value:
            return value
    return None


def parse_repo_url(url: str) -> RepoRef | None:
    """Split a declared repository URL into the pieces the API needs.

    Returns None for anything that is not a GitHub repository URL, including a
    GitLab one — the caller turns that into a `PROJECT` abstention rather than
    an error, because "we have not built this forge" is our gap and not theirs.
    """
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if host not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    # A path segment that is not a plain repository name means this is a URL
    # into a repository rather than a repository URL, and guessing which is
    # which has no upside. Owners and names are restricted by GitHub to this
    # alphabet, so anything else is not addressable regardless.
    if not owner or not name or not _NAME_OK.match(owner) or not _NAME_OK.match(name):
        return None
    return RepoRef("github.com", owner, name)


_NAME_OK = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


_QUERY = """
query($owner:String!, $name:String!, $since:GitTimestamp!, $commits:Int!,
      $after:String, $issues:Int!, $comments:Int!, $releases:Int!, $tags:Int!) {
  repository(owner:$owner, name:$name) {
    defaultBranchRef {
      target {
        ... on Commit {
          committedDate
          history(since:$since, first:$commits, after:$after) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes {
              committedDate
              author { user { login } email name }
            }
          }
        }
      }
    }
    releases(first:$releases, orderBy:{field:CREATED_AT, direction:DESC}) {
      nodes { publishedAt isDraft }
    }
    refs(refPrefix:"refs/tags/", first:$tags,
         orderBy:{field:TAG_COMMIT_DATE, direction:DESC}) {
      nodes {
        target {
          ... on Commit { committedDate }
          ... on Tag { target { ... on Commit { committedDate } } }
        }
      }
    }
    issues(first:$issues, orderBy:{field:CREATED_AT, direction:DESC}) {
      totalCount
      nodes {
        createdAt
        author { login }
        comments(first:$comments) {
          nodes { createdAt authorAssociation author { login } }
        }
      }
    }
  }
}
"""

# Subsequent commit pages only. Re-requesting issues and releases each page
# would multiply the query cost for data we already hold.
_COMMITS_QUERY = """
query($owner:String!, $name:String!, $since:GitTimestamp!, $commits:Int!, $after:String) {
  repository(owner:$owner, name:$name) {
    defaultBranchRef {
      target {
        ... on Commit {
          history(since:$since, first:$commits, after:$after) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes { committedDate author { user { login } email name } }
          }
        }
      }
    }
  }
}
"""


# ---------------------------------------------------------------------------
# Pure parsing. Everything below this line is total over whatever GitHub
# returns: the payload describes a stranger's repository, so a missing key, a
# null author or a malformed date degrades one signal rather than failing the
# scan. `MaintenanceSignals`' rule holds throughout — None means NOT RETRIEVED
# and never zero, because the two score differently and only one of them is an
# accusation.
# ---------------------------------------------------------------------------


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _dict(container: Any, *path: str) -> dict:
    """Walk a GraphQL payload to a dict, returning an empty one at any break.

    Total by construction. Every node in these payloads is nullable — an empty
    repository has no `defaultBranchRef`, an unannotated tag has no inner
    `target` — so the alternative is a null check at each of a dozen hops, and
    the one that gets forgotten is a traceback on somebody else's repository.
    """
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return {}
        cursor = cursor.get(key)
    return cursor if isinstance(cursor, dict) else {}


def _nodes(container: Any, *path: str) -> list[dict]:
    """Walk a GraphQL payload to a `nodes` list, tolerating nulls at every step."""
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(key)
    if not isinstance(cursor, list):
        return []
    return [n for n in cursor if isinstance(n, dict)]


def _author_key(node: dict) -> str | None:
    """A stable identity for a commit's author, or None if it should not count.

    Bots are excluded rather than counted — see `_BOT_LOGIN`. An unattributable
    commit (no login, no email, no name) is dropped: it cannot be told from any
    other unattributable commit, so counting them as one person would invent a
    maintainer and counting them separately would invent several.
    """
    author = node.get("author")
    if not isinstance(author, dict):
        return None
    user = author.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    name = author.get("name")
    for candidate in (login, name):
        if isinstance(candidate, str) and _BOT_LOGIN.search(candidate.strip()):
            return None
    if isinstance(login, str) and login.strip():
        return f"login:{login.strip().lower()}"
    email = author.get("email")
    if isinstance(email, str) and email.strip():
        return f"email:{email.strip().lower()}"
    if isinstance(name, str) and name.strip():
        return f"name:{name.strip().lower()}"
    return None


def _bus_factor(
    counts: dict[str, int], *, fetched: int, total: int
) -> tuple[int | None, int | None]:
    """`03` §5's author counts, or `(None, None)` when the walk could not settle them.

    ⚠ **A BOUNDED WALK CAN STILL ANSWER EXACTLY, AND WHERE IT CANNOT IT MUST
    SAY SO.** `MAX_COMMIT_PAGES` caps the history at a few hundred commits, so
    on a busy repository the counts here are LOWER BOUNDS. Three cases, and
    only the third abstains:

    1. The walk exhausted the history (`fetched >= total`) — the counts are
       exact.
    2. Three authors already clear `03` §5's 5-commit bar. More commits can
       only add authors, and §5's top band is "3 or more", so the unread tail
       cannot change the score.
    3. Otherwise the tail could hold up to `(total - fetched) // 5` further
       qualifying authors. When that range spans more than one §5 band the
       honest answer is that we did not measure it — the alternative is
       publishing "sole maintainer" about a project with four of them.
    """
    qualifying = sum(1 for n in counts.values() if n >= 5)
    exact = fetched >= total
    if exact:
        return qualifying, len(counts)
    if qualifying >= 3:
        # Deliberately not `qualifying`: the true count is at least this, and
        # reporting the lower bound as if it were measured would be the same
        # over-claim in the favourable direction.
        return 3, None
    if (total - fetched) // 5 == 0:
        return qualifying, None
    return None, None


def _release_dates(payload: dict) -> tuple[list[datetime], str]:
    """Release timestamps, newest first, and the basis they were read from.

    **Falls back to version tags when a repository publishes no GitHub
    Releases, and that is not a liberty — it is what `03` §5 is measuring.**
    §5 asks for "median days between releases"; a project that tags `v1.4.2`
    and publishes to npm has released, whatever GitHub's Releases tab says.
    Treating only Releases as releases would score a steadily-shipping project
    as having never shipped, which is a false accusation rather than a
    conservative reading.
    """
    releases = [
        dt
        for node in _nodes(payload, "releases", "nodes")
        if not node.get("isDraft") and (dt := _parse_dt(node.get("publishedAt")))
    ]
    if releases:
        return sorted(releases, reverse=True), "releases"
    tags: list[datetime] = []
    for node in _nodes(payload, "refs", "nodes"):
        target = node.get("target")
        if not isinstance(target, dict):
            continue
        # A lightweight tag points straight at the commit; an annotated tag
        # points at a Tag object that points at the commit. Both shapes are
        # requested, and only one of them is present per node.
        inner = target.get("target")
        when = _parse_dt(target.get("committedDate")) or (
            _parse_dt(inner.get("committedDate")) if isinstance(inner, dict) else None
        )
        if when:
            tags.append(when)
    # ⚠ NOT `"tags"` UNCONDITIONALLY. A project with neither releases nor tags
    # has no basis at all, and labelling the absence after the place we looked
    # last is a statement about our search order rather than about the
    # repository — which `score_release_cadence` would then render verbatim.
    return (sorted(tags, reverse=True), "tags") if tags else ([], "releases")


def _median_release_gap(dates: list[datetime], as_of: date) -> float | None:
    """Median days between consecutive releases inside `03` §5's 12-month window.

    Gaps are taken between pairs that are BOTH inside the window, so a single
    release in the last year yields no median and the sub-check abstains —
    which is correct: §5's remaining bands are all defined on a median, and
    inventing one from a sample of one is the mystery number this project
    refuses.
    """
    cutoff = datetime.combine(as_of, datetime.min.time(), tzinfo=UTC)
    in_window = [d for d in dates if (cutoff - d).days <= DAYS_PER_YEAR]
    if len(in_window) < 2:
        return None
    ordered = sorted(in_window)
    gaps = [
        (later - earlier).total_seconds() / 86400
        for earlier, later in zip(ordered, ordered[1:], strict=False)
    ]
    return statistics.median(gaps) if gaps else None


def _first_response_days(issue: dict, as_of_dt: datetime) -> float | None:
    """Days to the first maintainer comment, or the days it has waited so far.

    ⚠ **An unanswered issue is CENSORED, not excluded.** `03` §5's bottom band
    is explicitly "> 60 days OR no response on any issue", so dropping silent
    issues from the median would delete exactly the observations the band
    exists to catch. Counting the days it has waited so far is the
    conventional lower bound on its eventual response time: it can only
    understate how bad the wait is, which keeps the error in the direction
    that flatters the publisher rather than accuses them.

    A comment by the issue's own author is not a response to it. Self-answered
    issues are common in maintainer-filed tracking issues, and counting one
    would report a project as answering within minutes when nobody outside it
    has been answered at all.
    """
    created = _parse_dt(issue.get("createdAt"))
    if created is None:
        return None
    author = issue.get("author")
    asker = author.get("login") if isinstance(author, dict) else None
    asker = asker.lower() if isinstance(asker, str) else None
    for comment in _nodes(issue, "comments", "nodes"):
        if comment.get("authorAssociation") not in MAINTAINER_ASSOCIATIONS:
            continue
        who = comment.get("author")
        login = who.get("login") if isinstance(who, dict) else None
        if isinstance(login, str) and asker and login.lower() == asker:
            continue
        when = _parse_dt(comment.get("createdAt"))
        if when and when >= created:
            return max((when - created).total_seconds() / 86400, 0.0)
    waited = (as_of_dt - created).total_seconds() / 86400
    return max(waited, 0.0)


def _issue_medians(
    payload: dict, as_of_dt: datetime
) -> tuple[float | None, int | None, float | None]:
    """`03` §5's response medians: (last 6 months, sample size, lifetime).

    ⚠ **The lifetime median is returned ONLY when the sample really is the
    repository's whole issue history.** `ISSUE_SAMPLE_SIZE` bounds the fetch,
    so on a busy tracker the newest 50 issues are a recent sample and calling
    their median a lifetime figure would be an over-claim — and
    `score_issue_responsiveness` renders the words "lifetime median" verbatim
    onto a public page. Withholding it costs nothing in practice: the fallback
    exists for repositories with fewer than three issues in six months, and
    those have few issues in total, so the sample is complete exactly where
    the fallback fires.
    """
    issues = _nodes(payload, "issues", "nodes")
    total = _dict(payload, "issues").get("totalCount")
    cutoff = as_of_dt.timestamp() - ISSUE_WINDOW_DAYS * 86400

    recent: list[float] = []
    every: list[float] = []
    for issue in issues:
        days = _first_response_days(issue, as_of_dt)
        if days is None:
            continue
        every.append(days)
        created = _parse_dt(issue.get("createdAt"))
        if created and created.timestamp() >= cutoff:
            recent.append(days)

    sampled = len(recent) if issues or isinstance(total, int) else None
    median_recent = statistics.median(recent) if recent else None
    complete = isinstance(total, int) and total <= len(issues)
    lifetime = statistics.median(every) if (complete and every) else None
    return median_recent, sampled, lifetime


def signals_from_payload(
    payload: dict, as_of: date, *, fetched: int, total: int
) -> MaintenanceSignals:
    """Build `MaintenanceSignals` from a merged GraphQL repository payload.

    Pure and total, so the gold-set calibration and the tests can drive it from
    fixtures without a network. `fetched`/`total` describe the commit walk and
    come from the caller because they accumulate across pages.
    """
    as_of_dt = datetime.combine(as_of, datetime.min.time(), tzinfo=UTC)

    target = _dict(payload, "defaultBranchRef", "target")
    # ⚠ READ THE BRANCH HEAD, NEVER THE HISTORY NODES. `history(since:)` is
    # filtered to 12 months, so an abandoned repository returns an EMPTY list —
    # and deriving the last commit from it would make the one case `03` §5
    # scores 0 ("no commit in over 365 days") indistinguishable from a repo we
    # failed to read, which abstains. The exact inversion the axis exists to
    # catch.
    last_commit_dt = _parse_dt(target.get("committedDate"))

    counts: dict[str, int] = {}
    for node in _nodes(target, "history", "nodes"):
        key = _author_key(node)
        if key:
            counts[key] = counts.get(key, 0) + 1
    authors, contributors = _bus_factor(counts, fetched=fetched, total=total)

    releases, basis = _release_dates(payload)
    median_recent, sampled, lifetime = _issue_medians(payload, as_of_dt)

    return MaintenanceSignals(
        last_commit=last_commit_dt.date() if last_commit_dt else None,
        last_release=releases[0].date() if releases else None,
        median_release_gap_days=_median_release_gap(releases, as_of),
        median_first_response_days=median_recent,
        issues_sampled=sampled,
        lifetime_first_response_days=lifetime,
        authors_12mo=authors,
        contributors_12mo=contributors,
        # Not computable per server — see the module docstring.
        category_quartile=None,
        # The forge answered, so every field still `None` below is a fact about
        # the repository rather than a gap in our reading.
        retrieved=True,
        release_basis=basis,
        fault=Fault.PUBLISHER.value,
    )


# ---------------------------------------------------------------------------
# Network and cache.
# ---------------------------------------------------------------------------


def classify_repo_url(url: str) -> RepoRef | tuple[Fault, str]:
    """A fetchable repository, or whose gap it is that there isn't one.

    Three outcomes and they are not interchangeable:

    - **Nothing declared** -> `PUBLISHER`. A server that names no repository
      has not been failed by us, and `03` §7 already treats the absence as a
      fact about the publisher.
    - **A forge we have not built for** -> `PROJECT`. Ours, systematic, and
      disclosed in our own voice; a GitLab-hosted server is not less
      maintained, it is less *read*.
    - **A GitHub URL that does not name a repository** -> `PUBLISHER`. The
      declaration is theirs and it does not resolve.
    """
    if not url or not url.strip():
        return (
            Fault.PUBLISHER,
            "this server declares no repository, so `03` §5's forge signals "
            "have nothing to read",
        )
    ref = parse_repo_url(url)
    if ref is not None:
        return ref
    host = ""
    try:
        host = (urlparse(url.strip()).hostname or "").lower()
    except ValueError:
        host = ""
    if host and host not in ("github.com", "www.github.com"):
        return (
            Fault.PROJECT,
            f"`03` §5's maintenance signals are retrieved from the GitHub API "
            f"and this server's repository is hosted on {host}; forge "
            "retrieval for it is not built. This is a limit of ours, not a "
            "finding about the server.",
        )
    return (
        Fault.PUBLISHER,
        "the repository URL this server declares does not name a repository "
        "we can query for maintenance signals",
    )


def _cache_path(cache_dir: Path, ref: RepoRef) -> Path:
    # The forge slug is used verbatim as two path segments after validation by
    # `_NAME_OK`, which admits neither `/` nor `..` — so a registry-supplied
    # name cannot escape the cache directory. Checked here rather than trusted
    # because this is attacker-controlled input reaching a filesystem path.
    if not (_NAME_OK.match(ref.owner) and _NAME_OK.match(ref.name)):
        raise ForgeError("refusing to build a cache path from an unvalidated repo name")
    return cache_dir / ref.host / ref.owner / f"{ref.name}.json"


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base else Path.home() / ".cache"
    return root / "mcpwatchman" / "forge"


def _read_cache(cache_dir: Path, ref: RepoRef, now: float) -> dict | None:
    path = _cache_path(cache_dir, ref)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    stamped = raw.get("fetched_at")
    if not isinstance(stamped, int | float) or now - stamped > CACHE_TTL_SECONDS:
        return None
    payload = raw.get("payload")
    return payload if isinstance(payload, dict) else None


def _write_cache(cache_dir: Path, ref: RepoRef, payload: dict, now: float) -> None:
    path = _cache_path(cache_dir, ref)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"fetched_at": now, "payload": payload}), encoding="utf-8"
        )
        tmp.replace(path)
    except OSError:
        # A cache that cannot be written is a performance problem, never a
        # correctness one. Failing the scan over it would turn a full disk into
        # a published non-assessment about a third party.
        return


def _classify_errors(errors: list) -> Exception:
    """Turn a GraphQL `errors` array into the right exception.

    ⚠ **STRUCTURED `type` ONLY.** GitHub interpolates the owner and repository
    name into `message`, so a repository called `rate limit exceeded` could
    otherwise talk us out of reporting a fault that is ours — or, in the other
    direction, a repository named to look like a 404 could manufacture a
    published accusation against itself. `CLAUDE.md` records the same trap on
    `git`'s stderr, where redaction is the only tool available; here the
    payload carries the machine-readable field, so matching on prose would be a
    choice.

    **An unrecognised type is OURS.** Failing toward `ForgeError` costs a
    retry; failing the other way publishes a claim about somebody's repository
    on the strength of an error we could not identify.
    """
    types = {e.get("type") for e in errors if isinstance(e, dict)}
    if "NOT_FOUND" in types:
        return ForgeUnreachableError(
            # ⚠ DELIBERATELY NOT the fetch stage's wording. `reachability`
            # says "the repository this server declares is not publicly
            # reachable" when the SOURCE fetch fails, and
            # `test_no_built_surface_calls_a_package_failure_a_repository_
            # failure` forbids that sentence on the page of a server whose
            # PACKAGE is what failed — because an npm 404 once published it
            # about a repository nobody had contacted.
            #
            # This is a different stage making a different claim: we really
            # did contact the GitHub API about the declared repository. The
            # claim is true, and phrased in the fetch stage's words it is
            # indistinguishable from the false one, so it names its own stage
            # instead. Caught by that gate on a real regeneration.
            "this server's declared repository could not be read through the "
            "GitHub API, so `03` §5's maintenance signals were not retrieved "
            "— note that a private repository and an absent one are "
            "indistinguishable from outside"
        )
    if "RATE_LIMITED" in types:
        return ForgeError("the GitHub API rate limit was exhausted for this run")
    return ForgeError(f"the GitHub API returned {len(errors)} error(s) we do not classify")


def _post(client: Any, query: str, variables: dict, token: str) -> dict:
    """One GraphQL request. Raises `ForgeError`/`ForgeUnreachableError`."""
    import httpx

    try:
        response = client.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query, "variables": variables},
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        # `exc` may embed the request URL but never the header, so the token
        # cannot reach this string. The repository slug can, and it is the
        # publisher's own text — kept out of the message for the same reason
        # `_classify_errors` will not read one.
        raise ForgeError(f"the GitHub API could not be reached ({type(exc).__name__})") from exc

    if response.status_code == 401:
        raise ForgeError("the configured GitHub token was rejected")
    if response.status_code in (403, 429):
        raise ForgeError("the GitHub API refused the request (rate limit or abuse guard)")
    if response.status_code >= 500:
        raise ForgeError(f"the GitHub API returned {response.status_code}")
    if response.status_code != 200:
        raise ForgeError(f"the GitHub API returned {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise ForgeError("the GitHub API returned a response that is not JSON") from exc
    if not isinstance(payload, dict):
        raise ForgeError("the GitHub API returned a non-object response")

    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        raise _classify_errors(errors)
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ForgeError("the GitHub API response carried no data")
    repository = data.get("repository")
    if repository is None:
        # No `errors` array and a null repository. GitHub does emit NOT_FOUND
        # for this, but a null with no explanation is still THEIR repository
        # being unreadable rather than our request failing.
        raise ForgeUnreachableError(
            "this server's declared repository could not be read through the "
            "GitHub API, so `03` §5's maintenance signals were not retrieved"
        )
    if not isinstance(repository, dict):
        raise ForgeError("the GitHub API returned a repository of an unexpected shape")
    return repository


def _fetch_repository(client: Any, ref: RepoRef, token: str, as_of: date) -> dict:
    """Every page this scan will read of one repository, merged.

    Returns the cacheable wrapper: the repository payload plus how much of its
    commit history was actually walked, which `_bus_factor` needs and which
    cannot be recovered from the payload afterwards.
    """
    # ⚠ `timedelta`, NOT `.replace(year=as_of.year - 1)`. The replace form
    # raises `ValueError` on 29 February, so a scan run on a leap day would
    # crash on every server — a once-in-four-years total outage that no test
    # written on an ordinary date can see.
    since = (
        datetime.combine(as_of, datetime.min.time(), tzinfo=UTC)
        - timedelta(days=DAYS_PER_YEAR)
    ).isoformat()
    variables = {
        "owner": ref.owner,
        "name": ref.name,
        "since": since,
        "commits": COMMIT_PAGE_SIZE,
        "after": None,
        "issues": ISSUE_SAMPLE_SIZE,
        "comments": COMMENTS_PER_ISSUE,
        "releases": RELEASE_SAMPLE_SIZE,
        "tags": TAG_SAMPLE_SIZE,
    }
    repository = _post(client, _QUERY, variables, token)

    history = _nodes(repository, "defaultBranchRef", "target", "history", "nodes")
    hist_obj = _dict(repository, "defaultBranchRef", "target", "history")
    raw_total = hist_obj.get("totalCount")
    total = raw_total if isinstance(raw_total, int) else len(history)

    page_info = _dict(hist_obj, "pageInfo")
    cursor = page_info.get("endCursor")
    pages = 1
    while (
        page_info.get("hasNextPage")
        and isinstance(cursor, str)
        and pages < MAX_COMMIT_PAGES
    ):
        variables["after"] = cursor
        more = _post(client, _COMMITS_QUERY, variables, token)
        page = _nodes(more, "defaultBranchRef", "target", "history", "nodes")
        if not page:
            break
        history.extend(page)
        page_info = _dict(more, "defaultBranchRef", "target", "history", "pageInfo")
        cursor = page_info.get("endCursor")
        pages += 1

    # Write the merged history back so the cached payload is self-contained: a
    # cache hit must produce the same signals as the fetch that filled it, and
    # `_bus_factor` reads `fetched` against `total` to decide whether its counts
    # are exact. A cache holding only page one would silently re-answer an
    # exhausted walk as a bounded one.
    if hist_obj:
        hist_obj["nodes"] = history
    return {"repository": repository, "fetched": len(history), "total": total}


def fetch_signals(
    repo_url: str,
    *,
    token: str | None = None,
    client: Any = None,
    as_of: date | None = None,
    cache_dir: Path | None = None,
    now: float | None = None,
) -> ForgeOutcome:
    """Retrieve `03` §5's forge signals for one server's declared repository.

    Never raises for a repository's own defects — an unreadable repository is
    an OUTCOME carrying `PUBLISHER`, exactly as `scan_entry` treats an
    unfetchable source. It does not raise for ours either: a rate limit comes
    back as an `ENVIRONMENT` outcome, which `cohort.publication_errors` then
    refuses to publish and `ops/scan_cohort.py` retries.

    `client`, `as_of`, `cache_dir` and `now` are injectable so the whole path
    is testable without a network or a clock.
    """
    as_of = as_of or datetime.now(UTC).date()
    now = time.time() if now is None else now
    cache_dir = default_cache_dir() if cache_dir is None else cache_dir

    classified = classify_repo_url(repo_url)
    if isinstance(classified, tuple):
        fault, reason = classified
        return ForgeOutcome(MaintenanceSignals(fault=fault.value), fault, reason)
    ref = classified

    token = token or token_from_env()
    if not token:
        return ForgeOutcome(
            MaintenanceSignals(fault=Fault.ENVIRONMENT.value),
            Fault.ENVIRONMENT,
            "no GitHub token was configured for this run, so `03` §5's forge "
            f"signals were not retrieved (set {TOKEN_ENV_VARS[0]})",
        )

    wrapper = _read_cache(cache_dir, ref, now)
    if wrapper is None:
        owns_client = client is None
        if owns_client:
            import httpx

            client = httpx.Client(timeout=httpx.Timeout(30.0), follow_redirects=True)
        try:
            wrapper = _fetch_repository(client, ref, token, as_of)
        except ForgeUnreachableError as exc:
            return ForgeOutcome(
                MaintenanceSignals(fault=Fault.PUBLISHER.value),
                Fault.PUBLISHER,
                str(exc),
            )
        except ForgeError as exc:
            return ForgeOutcome(
                MaintenanceSignals(fault=Fault.ENVIRONMENT.value),
                Fault.ENVIRONMENT,
                f"{exc}; this is retryable and is not a finding about the server",
            )
        finally:
            if owns_client and client is not None:
                client.close()
        _write_cache(cache_dir, ref, wrapper, now)

    repository = wrapper.get("repository")
    if not isinstance(repository, dict):
        return ForgeOutcome(
            MaintenanceSignals(fault=Fault.ENVIRONMENT.value),
            Fault.ENVIRONMENT,
            "the cached forge payload for this repository is unusable",
        )
    fetched = wrapper.get("fetched")
    total = wrapper.get("total")
    signals = signals_from_payload(
        repository,
        as_of,
        fetched=fetched if isinstance(fetched, int) else 0,
        total=total if isinstance(total, int) else 0,
    )
    # ⚠ THE FETCH SUCCEEDED, SO EVERY REMAINING GAP IS THE REPOSITORY'S. A
    # project with no releases and no issues is not one we failed to read — and
    # leaving these sub-checks attributed `PROJECT`, as they were while the
    # fetch did not exist, would keep blaming our own unbuilt capability for a
    # measurement we have now taken.
    return ForgeOutcome(signals, Fault.PUBLISHER)


__all__ = [
    "ForgeError",
    "ForgeOutcome",
    "ForgeUnreachableError",
    "RepoRef",
    "classify_repo_url",
    "default_cache_dir",
    "fetch_signals",
    "parse_repo_url",
    "signals_from_payload",
    "token_from_env",
]
