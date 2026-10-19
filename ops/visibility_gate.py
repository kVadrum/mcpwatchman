"""Refuse to publish Maintenance data read from a repository the public cannot read.

The forge lookup behind Maintenance runs with whatever GitHub token the nightly
holds, and until a dedicated public-read token is configured that is the
operator's own login. `main`'s scanner does not ask whether a repository is
public (the `isPrivate` check is v0.38.4, unsynced), so a pinned publisher
naming a private repository the operator can read would have its commit
recency, issue and release cadence and contributor band scored and published.

This gate runs in the nightly between the scan and anything leaving the box. It
REFUSES; it never edits a row. That is why it may run from the working tree
while the scanner runs from `main`: it cannot state anything about a third
party, only stop a run from stating it. For every row scanned THIS run whose
Maintenance was assessed from a github.com repository, the repository must
answer an anonymous `git ls-remote`. Rows carried forward from an earlier run
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
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path

_GITHUB = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")

# Anonymous by construction: no config file, so no credential helper and no
# url rewrite; no prompt, so a private repository fails instead of waiting.
_ANONYMOUS = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
              "GIT_TERMINAL_PROMPT": "0"}
_PASSED_THROUGH = ("PATH", "HOME", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR",
                   "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")


def probe_anonymous(url: str, *, attempts: int = 2, timeout: float = 30) -> bool:
    """Whether `url` answers `git ls-remote` with no credentials at all."""
    env = {k: os.environ[k] for k in _PASSED_THROUGH if k in os.environ}
    env.update(_ANONYMOUS)
    for _ in range(attempts):
        try:
            done = subprocess.run(  # noqa: S603 - argv form; url matched _GITHUB or a test path
                ["git", "ls-remote", "-q", "--", url, "HEAD"],  # noqa: S607
                env=env, capture_output=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if done.returncode == 0:
            return True
    return False


def _maintenance_assessed(row: dict) -> bool:
    weight = ((row.get("axes") or {}).get("maintenance") or {}).get("assessed_weight")
    try:
        return Decimal(str(weight)) > 0
    except (InvalidOperation, ValueError):
        # Unreadable is not "nothing measured": ask rather than assume.
        return weight is not None


def to_check(before: Iterable[dict], after: Iterable[dict]) -> dict[str, list[str]]:
    """repository URL -> slugs of the rows scanned this run that need asking."""
    previous = {(r.get("slug"), r.get("scanned_at")) for r in before}
    urls: dict[str, list[str]] = {}
    for row in after:
        if (row.get("slug"), row.get("scanned_at")) in previous:
            continue  # carried forward, not scanned this run
        url = (row.get("repository_url") or "").strip()
        if not _GITHUB.match(url) or not _maintenance_assessed(row):
            continue
        urls.setdefault(url.rstrip("/"), []).append(str(row.get("slug")))
    return urls


# What the run's token says about a repository the public could not read.
PRIVATE, PUBLIC, INVISIBLE, UNKNOWN = "private", "public", "invisible", "unknown"
_BATCH = 50


def _owner_name(url: str) -> tuple[str, str]:
    owner, name = url.rstrip("/").split("/")[-2:]
    return owner, name.removesuffix(".git")


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
        # Owner and name matched _GITHUB's character class, so neither can
        # carry a quote or a backslash into the query string.
        fields = " ".join(
            f'r{i}: repository(owner: "{o}", name: "{n}") {{ isPrivate }}'
            for i, (o, n) in enumerate(map(_owner_name, batch))
        )
        request = urllib.request.Request(  # noqa: S310 - fixed https URL
            "https://api.github.com/graphql",
            data=json.dumps({"query": f"query {{ {fields} }}"}).encode(),
            headers={"Authorization": f"bearer {token}", "Content-Type": "application/json"},
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
        token = os.environ.get("MCPWATCHMAN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        ask = lambda batch: ask_with_token(batch, token)  # noqa: E731
    with ThreadPoolExecutor(max_workers=8) as pool:
        public = dict(zip(urls, pool.map(probe, urls), strict=True))
    failed = [url for url in urls if not public[url]]
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
    urls = to_check(before, after)
    bad, invisible = refused(urls)
    print(f"visibility gate: {len(urls)} repositories asked anonymously, "
          f"{len(invisible)} readable by nobody (allowed), {len(bad)} refused")
    for url, slugs in sorted(bad.items()):
        print(f"  private or unanswered: {url} (Maintenance scored for {', '.join(slugs)})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
