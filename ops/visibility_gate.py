"""Refuse to publish Maintenance data read from a repository the public cannot read.

The forge lookup behind Maintenance runs with whatever GitHub token the nightly
holds, and until a dedicated public-read token is configured that is the
operator's own login — so a pinned publisher naming a private repository the
operator can read would have its commit recency, issue and release cadence and
contributor band scored and published. Since v0.38.4 the forge lookup refuses
any repository GitHub does not report as public. This gate is the SECOND,
independent enforcer, and stays one after that check reaches `main`: it asks
from outside, anonymously, so it also holds for a scanner older than that check
(the nightly runs `main`'s) and for any future path that reads a repository
without asking.

This gate runs in the nightly between the scan and anything leaving the box.
For every row scanned THIS run whose Maintenance was assessed, the repository
must answer an anonymous `git ls-remote`. Which repository that is comes from
`forge.parse_repo_url`, the parser that decided what the lookup read — a row
the parser cannot name was read from SOME repository this gate cannot ask
about. Rows carried forward from an earlier run are not re-asked — they are
already public, and a repository deleted since would be withheld every night
over a page nobody can change.

A row that fails is WITHHELD, not the run: that server keeps its previous page,
labelled as kept and why (`cohort.carry_forward`, state `stale`), and the rest
of the night publishes. One publisher making a repository private between the
scan and this check used to stop every page's refresh (operator ruling
2026-10-21: one record is noted, skipped, and the run moves on). The gate still
states nothing new about a third party — every number it publishes was
published by an earlier run — which is why it may run from the working tree
while the scanner runs from `main`. Withheld rows count toward
`cohort.systemic_staleness`, so a dead network or a broken token, which fails
every question at once, still refuses the run instead of carrying every page.

A repository that fails anonymously is then asked about with the run's own
token, because "the public cannot read it" has two causes and only one is the
leak. PRIVATE, and visible to our token: withheld. Visible to nobody, our token
included — deleted, like the 16 `mcp-dir` repositories on 2026-10-19 — is not a
leak: any data for it can only have come from when it was public (the forge
cache keeps a payload 24 hours), and withholding it would freeze a page nobody
can change. Measured that day: 356 repositories asked, 16 anonymous
failures, all that one deleted account.

Exit 0: publishable, with any withheld rows named and `--after` rewritten.
Exit 1: refused — too many rows withheld, or one with no previous page to keep.
Any question that could not get an answer withholds its row: an unanswered
question about visibility is not a yes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path

from mcpwatchman.cohort import atomic_write, carry_forward, systemic_staleness
from mcpwatchman.workers.bounded import run_bounded
from mcpwatchman.workers.scanner.forge import (
    GITHUB_GRAPHQL_URL,
    USER_AGENT,
    parse_repo_url,
    token_from_env,
)


def probe_anonymous(url: str, *, attempts: int = 2, timeout: float = 30) -> bool:
    """Whether `url` answers `git ls-remote` with no credentials at all.

    Anonymous by construction: `run_bounded`'s environment is the scanner's
    allowlist, which carries no token; git reads no global or system config
    and, with HOME emptied, no `.netrc`; and it runs from `/`, because
    `ls-remote` inside a repository reads THAT repository's config, where a
    credential helper or url rewrite would answer for a private repository
    (measured 2026-10-21). No prompt, so a private repository fails instead of
    waiting. On a timeout it kills the whole group, `git-remote-https` included.
    """
    for _ in range(attempts):
        done = run_bounded(["git", "ls-remote", "-q", "--", url, "HEAD"],
                           timeout=timeout, cwd=os.sep)
        if done.returncode == 0 and not done.timed_out:
            return True
    return False


def _maintenance_assessed(row: dict) -> bool:
    weight = ((row.get("axes") or {}).get("maintenance") or {}).get("assessed_weight")
    try:
        return Decimal(str(weight)) > 0
    except (InvalidOperation, ValueError):
        # Unreadable is not "nothing measured": ask rather than assume.
        return True


def to_check(
    before: Iterable[dict], after: Iterable[dict],
) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    """(repository URL -> names of the rows scanned this run that need asking,
    (name, why) for each row this gate cannot ask about — withheld)."""
    previous = {(r.get("name"), r.get("scanned_at")) for r in before}
    urls: dict[str, list[str]] = {}
    unaskable: list[tuple[str, str]] = []
    for row in after:
        name = str(row.get("name"))
        # A row without what this gate keys on is not a row with nothing to
        # ask. The data is written by main's scanner and this gate runs from
        # dev, so a renamed field would otherwise read every row as carried
        # forward or unmeasured, and the gate would pass having asked nothing.
        maintenance = (row.get("axes") or {}).get("maintenance")
        if not (row.get("name") and row.get("scanned_at") and isinstance(maintenance, dict)
                and "assessed_weight" in maintenance):
            unaskable.append((name, "lacks the name, scanned_at or Maintenance "
                                    "assessed_weight this gate reads"))
            continue
        if (row.get("name"), row.get("scanned_at")) in previous:
            continue  # carried forward, not scanned this run
        if not _maintenance_assessed(row):
            continue  # no forge data was read
        ref = parse_repo_url(row.get("repository_url") or "")
        if ref is None:
            unaskable.append((name, "Maintenance scored from a repository URL "
                                    "the forge parser cannot read"))
            continue
        urls.setdefault(f"https://github.com/{ref.slug}", []).append(name)
    return urls, unaskable


# What the run's token says about a repository the public could not read.
PRIVATE, PUBLIC, INVISIBLE, UNKNOWN = "private", "public", "invisible", "unknown"
_BATCH = 50


def parse_answers(urls: list[str], payload: dict) -> dict[str, str]:
    """One GraphQL batch's answers. NOT_FOUND is the one error that is an
    answer (INVISIBLE); any other error leaves its repository UNKNOWN."""
    data = payload.get("data") or {}
    errors = payload.get("errors") or []
    not_found = {e["path"][0] for e in errors
                 if e.get("type") == "NOT_FOUND" and e.get("path")}
    other = any(e.get("type") != "NOT_FOUND" for e in errors)
    answers = {}
    for i, url in enumerate(urls):
        repo = data.get(f"r{i}")
        if isinstance(repo, dict) and isinstance(repo.get("isPrivate"), bool):
            answers[url] = PRIVATE if repo["isPrivate"] else PUBLIC
        elif repo is None and f"r{i}" in not_found and not other:
            answers[url] = INVISIBLE
        else:
            answers[url] = UNKNOWN
    return answers


def ask_with_token(urls: list[str], token: str | None) -> dict[str, str]:
    """`isPrivate` per repository, from GitHub's API with the run's token."""
    import urllib.request

    if not token:
        return dict.fromkeys(urls, UNKNOWN)
    answers: dict[str, str] = {}
    for start in range(0, len(urls), _BATCH):
        batch = urls[start:start + _BATCH]
        # `parse_repo_url` admits only GitHub's name alphabet, so neither part
        # can carry a quote or a backslash into the query string. A URL it does
        # not parse gets no field, so it reads back UNKNOWN: refused.
        refs = list(map(parse_repo_url, batch))
        fields = " ".join(
            f'r{i}: repository(owner: "{ref.owner}", name: "{ref.name}") {{ isPrivate }}'
            for i, ref in enumerate(refs) if ref is not None
        )
        request = urllib.request.Request(  # noqa: S310 - fixed https URL
            GITHUB_GRAPHQL_URL,
            data=json.dumps({"query": f"query {{ {fields} }}"}).encode(),
            headers={"Authorization": f"bearer {token}", "Content-Type": "application/json",
                     "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                answers.update(parse_answers(batch, json.load(response)))
        except (OSError, ValueError):
            answers.update(dict.fromkeys(batch, UNKNOWN))
    return answers


def refused(
    urls: dict[str, list[str]],
    probe: Callable[[str], bool] | None = None,
    ask: Callable[[list[str]], dict[str, str]] | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """(refused url -> row names, the urls allowed because nobody can read them)."""
    probe = probe or probe_anonymous
    if ask is None:
        # The token the forge lookup read with: same variables, same order.
        token = token_from_env()
        ask = lambda batch: ask_with_token(batch, token)  # noqa: E731
    with ThreadPoolExecutor(max_workers=8) as pool:
        failed = [url for url, ok in zip(urls, pool.map(probe, urls), strict=True) if not ok]
    answers = ask(failed) if failed else {}
    # PUBLIC after a failed probe is GitHub saying it is not private (a
    # transient probe failure, or a repository disabled for everyone).
    allowed = {PUBLIC, INVISIBLE}
    bad = {url: urls[url] for url in failed if answers.get(url) not in allowed}
    invisible = [url for url in failed if answers.get(url) == INVISIBLE]
    return bad, invisible


# What a withheld row's page says. It states what was observed — the
# repository could not be CONFIRMED public — never why: "private" and "did not
# answer" fail the same way, and only one of them is the publisher's doing.
WITHHELD_OBSERVATION = (
    "This server is listed in the registry, and its newest scan was withheld: "
    "the repository its maintenance record was read from could not be confirmed "
    "as publicly readable when that scan was checked before publishing"
)
WITHHELD_BECAUSE = (
    ", because nothing read from a repository that cannot be confirmed public "
    "is published."
)


def withhold(
    before: Iterable[dict], after: list[dict], names: Iterable[str], today: str,
) -> tuple[list[dict], list[str]]:
    """`after` with each named row replaced by its previous page, labelled,
    and the names that have no previous page to keep."""
    previous = {r.get("name"): r for r in before if r.get("name")}
    names = set(names)
    out: list[dict] = []
    orphans: list[str] = []
    for row in after:
        name = row.get("name")
        if str(name) not in names:
            out.append(row)
        elif name in previous:
            out.append(carry_forward(
                previous[name], checked_on=today, state="stale",
                observation=WITHHELD_OBSERVATION,
                not_recomputed_because=WITHHELD_BECAUSE,
            ))
        else:
            orphans.append(str(name))
            out.append(row)
    return out, orphans


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--before", type=Path, required=True,
                    help="the published scans.json this run started from")
    ap.add_argument("--after", type=Path, required=True,
                    help="the scans.json this run wrote; rewritten when a row is withheld")
    a = ap.parse_args(argv)
    before = json.loads(a.before.read_text())
    after = json.loads(a.after.read_text())
    urls, unaskable = to_check(before, after)
    bad, invisible = refused(urls)
    why = dict(unaskable)
    for url, names in bad.items():
        for name in names:
            why[name] = f"{url} is private or did not answer"
    print(f"visibility gate: {len(urls)} repositories asked anonymously, "
          f"{len(invisible)} readable by nobody (allowed), {len(bad)} not confirmed "
          f"public, {len(unaskable)} rows this gate cannot ask about; "
          f"{len(why)} rows withheld, each keeping its previous page")
    for name, reason in sorted(why.items()):
        print(f"  withheld {name}: {reason}")
    if not why:
        return 0
    published, orphans = withhold(before, after, why, time.strftime("%Y-%m-%d", time.gmtime()))
    if orphans:
        # A pinned server always has a published page, so this is our record
        # being inconsistent, not a publisher's doing — and withholding the
        # row would 404 the page instead.
        print(f"REFUSED: no previous page to keep for {', '.join(sorted(orphans))}; "
              "nothing written")
        return 1
    systemic = systemic_staleness(published)
    if systemic:
        print(f"REFUSED: {systemic}")
        return 1
    atomic_write(a.after, json.dumps(published, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
