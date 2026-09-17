"""Whether a server's DECLARED source actually exists to be read (`03` §7).

Measured 2026-09-15 over 200 registry entries: of the 95 that declare a
repository, **43 — 45.3% — return 404 unauthenticated.** Stated precisely,
because the obvious phrasing over-claims: GitHub answers 404 rather than 403 for
a *private* repository, deliberately, so as not to leak its existence. So this
measures *"not publicly reachable"* — absent **or** private — and never *"does
not exist"*. The operative fact is the same either way: nobody outside can read
it, us included.

**Until now that fact reached a `FetchError` and stopped there**, which threw
away the more interesting half. "The repository this server declares cannot be
read by the public" is not merely an obstacle to scanning it — it is a
Transparency fact about the server, and one of the few this project can state
with certainty. A consumer being asked to install something cannot audit what
they are installing.

**It is REPORTED and not SCORED, and that is deliberate.** `03` §7 gives
Transparency five sub-checks and defines bands for each; none of them is "the
declared repository is unreachable". Inventing a band would produce a published
number that appears nowhere in the methodology — the mystery number this project
exists to refuse. `CLAUDE.md` is explicit: where `03` specifies no band, abstain.

What it does instead is supply the **reason** the five real sub-checks are
unassessed. Before this, a server whose repository 404s and a server the crawler
simply had not reached both produced *"no source was fetched, so no
documentation could be read"* — true of both, useful about neither. One of those
two is a fact about the publisher and the other is a fact about our queue, and a
reader is owed the difference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class SourceState(StrEnum):
    """What happened when we tried to read a server's declared source."""

    # Never attempted — our queue, not their repository.
    NOT_ATTEMPTED = "not_attempted"
    # The entry declares nothing we know how to fetch.
    NOT_DECLARED = "not_declared"
    # Declared, attempted, and the world cannot read it. Theirs.
    UNREACHABLE = "unreachable"
    # Declared, attempted, and OUR side failed — timeout, disk, scratch mount.
    FETCH_FAILED = "fetch_failed"
    FETCHED = "fetched"

    @property
    def publisher_fault(self) -> bool:
        """Whether this state says something about the SERVER rather than us.

        The same split `source.SourceUnreachableError` vs `source.FetchError`
        draws: a declared repository the world cannot read will not fix itself
        and is a fact that server's page owes its reader; a timeout or a full
        disk is ours and is retryable.
        """
        return self in (SourceState.UNREACHABLE, SourceState.NOT_DECLARED)


# An absolute filesystem path in a PUBLISHED reason is our scratch directory
# leaking onto a public page. It happened: a fetch failure published
# `/tmp/mcpw-scan-9evtt3fl/src/apps/mcp-server`, which tells a reader nothing
# and tells everyone else where we unpack strangers' code. `base.md` §
# *Host & system telemetry* puts absolute paths at Tier C — publishable to a
# private remote, stripped on a public one, and this is as public as it gets.
#
# Same discipline `source._is_unreachable` already applies to URLs: sanitise
# the text before it can steer or decorate a verdict.
# The lookbehind keeps a URL intact: without it `https://github.com/x/y`
# matches from the SECOND slash and publishes `https:/<path>`, which is
# worse than the leak — it destroys a legitimate address while looking
# like a redaction did its job.
_ABSOLUTE_PATH = re.compile(r"(?<![:/\w])(?:/[\w.@+-]+){2,}/?")


def redact_paths(text: str) -> str:
    """Replace absolute filesystem paths with a placeholder."""
    return _ABSOLUTE_PATH.sub("<path>", text)


@dataclass(frozen=True, slots=True)
class SourceAvailability:
    """One server's source-reachability outcome, with the evidence for it."""

    state: SourceState
    declared_url: str | None = None
    detail: str = ""

    @property
    def readable(self) -> bool:
        return self.state is SourceState.FETCHED

    @property
    def reason(self) -> str:
        """Why the documentation sub-checks could not be assessed.

        Phrased for a reader of the server's page, not for a log. Never claims
        a repository is absent — only that it is not publicly reachable.
        """
        if self.state is SourceState.FETCHED:
            return ""
        if self.state is SourceState.UNREACHABLE:
            where = f" ({self.declared_url})" if self.declared_url else ""
            return (
                f"the repository this server declares{where} is not publicly "
                "reachable, so its documentation could not be read — note that "
                "a private repository and an absent one are indistinguishable "
                "from outside"
            )
        if self.state is SourceState.NOT_DECLARED:
            return "this server declares no source we know how to fetch"
        if self.state is SourceState.FETCH_FAILED:
            detail = redact_paths(self.detail) if self.detail else ""
            return (
                "the declared source could not be fetched for reasons on our "
                f"side{f': {detail}' if detail else ''}; this is "
                "retryable and is not a finding about the server"
            )
        return "no source was fetched, so no documentation could be read"

    @property
    def is_transparency_finding(self) -> bool:
        """Whether a reader is owed this on the server's page.

        True exactly when the cause lies with the publisher. **Reported, never
        scored** — see the module docstring.
        """
        return self.state.publisher_fault


def from_exception(exc: BaseException, declared_url: str | None = None) -> SourceAvailability:
    """Classify a fetch failure into whose problem it is.

    Imported lazily inside the function to keep this module free of a hard edge
    to `scanner.source`, which imports `crawler.registry`; the reachability
    vocabulary is wanted by surfaces that have no business pulling in a fetcher.
    """
    from mcpwatchman.workers.scanner.source import SourceUnreachableError

    state = (
        SourceState.UNREACHABLE
        if isinstance(exc, SourceUnreachableError)
        else SourceState.FETCH_FAILED
    )
    return SourceAvailability(state=state, declared_url=declared_url, detail=str(exc))


__all__ = ["SourceAvailability", "SourceState", "from_exception"]
