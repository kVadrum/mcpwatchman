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

This gate runs in the nightly between the scan and anything leaving the box. It
REFUSES; it never edits a row. That is why it may run from the working tree
while the scanner runs from `main`: it cannot state anything about a third
party, only stop a run from stating it. For every row scanned THIS run whose
Maintenance was assessed, the repository must answer an anonymous
`git ls-remote`. Which repository that is comes from `forge.parse_repo_url`,
the parser that decided what the lookup read — a row the parser cannot name
was read from SOME repository this gate cannot ask about, and is refused.
Rows carried forward from an earlier run
are not re-asked — they are already public, and a repository deleted since
would refuse every run over a page nobody can change.

A repository that fails anonymously is then asked about with the run's own
token, because "the public cannot read it" has two causes and only one is the
leak. PRIVATE, and visible to our token: refused. Visible to nobody, our token
included — deleted, like the 16 `mcp-dir` repositories on 2026-10-19 — is not a
leak: any data for it can only have come from when it was public (the forge
cache keeps a payload 24 hours), and refusing it would stop the run over a page
nobody can change. Measured that day: 356 repositories asked, 16 anonymous
failures, all that one deleted account.

Exit 0: nothing to refuse. Exit 1: refused, with the rows named. Any question
that could not get an answer counts as refused: an unanswered question about
visibility is not a yes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path

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
    """(repository URL -> slugs of the rows scanned this run that need asking,
    (slug, why) for each row this gate cannot ask about — refused)."""
    previous = {(r.get("slug"), r.get("scanned_at")) for r in before}
    urls: dict[str, list[str]] = {}
    unaskable: list[tuple[str, str]] = []
    for row in after:
        slug = str(row.get("slug"))
        # A row without what this gate keys on is not a row with nothing to
        # ask. The data is written by main's scanner and this gate runs from
        # dev, so a renamed field would otherwise read every row as carried
        # forward or unmeasured, and the gate would pass having asked nothing.
        maintenance = (row.get("axes") or {}).get("maintenance")
        if not (row.get("slug") and row.get("scanned_at") and isinstance(maintenance, dict)
                and "assessed_weight" in maintenance):
            unaskable.append((slug, "lacks the slug, scanned_at or Maintenance "
                                    "assessed_weight this gate reads"))
            continue
        if (row.get("slug"), row.get("scanned_at")) in previous:
            continue  # carried forward, not scanned this run
        if not _maintenance_assessed(row):
            continue  # no forge data was read
        ref = parse_repo_url(row.get("repository_url") or "")
        if ref is None:
            unaskable.append((slug, "Maintenance scored from a repository URL "
                                    "the forge parser cannot read"))
            continue
        urls.setdefault(f"https://github.com/{ref.slug}", []).append(slug)
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
    """(refused url -> slugs, the urls allowed because nobody can read them)."""
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--before", type=Path, required=True,
                    help="the published scans.json this run started from")
    ap.add_argument("--after", type=Path, required=True, help="the scans.json this run wrote")
    a = ap.parse_args(argv)
    before = json.loads(a.before.read_text())
    after = json.loads(a.after.read_text())
    urls, unaskable = to_check(before, after)
    bad, invisible = refused(urls)
    print(f"visibility gate: {len(urls)} repositories asked anonymously, "
          f"{len(invisible)} readable by nobody (allowed), {len(bad)} refused, "
          f"{len(unaskable)} rows this gate cannot ask about")
    for url, slugs in sorted(bad.items()):
        print(f"  private or unanswered: {url} (Maintenance scored for {', '.join(slugs)})")
    for slug, why in sorted(unaskable):
        print(f"  {slug}: {why}")
    return 1 if bad or unaskable else 0


if __name__ == "__main__":
    sys.exit(main())
