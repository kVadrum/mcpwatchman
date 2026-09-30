"""`ops/pin_gold_commits.py`: recovering the tree a pre-pin audit read.

Every answer here becomes a PROPOSED pin a human confirms, so the failure worth
testing is a confident wrong commit: the wrong repository, the tag's object
instead of its commit, a commit after the scan rather than before it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import ops.pin_gold_commits as pgc
import pytest

from mcpwatchman import goldset as gs
from mcpwatchman.workers.crawler.registry import SourceKind
from mcpwatchman.workers.scanner.source import SourceSpec

GIT = shutil.which("git") or "git"
C1, C2, TAGOBJ = "1" * 40, "2" * 40, "3" * 40


def _row(ref_matched=None, reason=""):
    return {"ref_matched_version": ref_matched, "axes": {"code_safety": {"reason": reason}}}


@pytest.mark.parametrize("row,primary,supplement,want", [
    (_row(True), "github:a/r@1.0.0", None, ("github:a/r@1.0.0", True)),
    (_row(False), "github:a/r@1.0.0", None, ("github:a/r@1.0.0", False)),
    (_row(None, "scored on the declared repository at version 1.0.0, because x"),
     "npm:pkg@1.0.0", "github:a/r@1.0.0", ("github:a/r@1.0.0", True)),
    (_row(None, "scored on the declared repository, because x; no tag matched this "
                "version, so the repository's default branch was read"),
     "npm:pkg@1.0.0", "github:a/r@1.0.0", ("github:a/r@1.0.0", False)),
    # A package scored on its own tree: the declared repository was never read.
    (_row(None, ""), "npm:pkg@1.0.0", "github:a/r@1.0.0", None),
])
def test_the_repository_read_comes_from_the_published_row(row, primary, supplement, want):
    got = pgc.repository_read(row, primary, supplement)
    assert (got and (str(got.spec), got.tag_matched)) == want


@pytest.mark.parametrize("listing,want", [
    (f"{C1}\trefs/tags/1.0.0\n", C1),                                   # lightweight
    (f"{TAGOBJ}\trefs/tags/1.0.0\n{C1}\trefs/tags/1.0.0^{{}}\n", C1),    # annotated: peel
    (f"{C2}\trefs/tags/v1.0.0\n", C2),                                  # v-prefixed only
    (f"{C1}\trefs/tags/1.0.0\n{C2}\trefs/tags/v1.0.0\n", C1),           # the fetcher's order
    (f"{C1}\trefs/tags/1.0.1\n", None),
])
def test_a_tag_resolves_to_its_commit_not_its_tag_object(listing, want):
    assert pgc.tag_commit(listing, "1.0.0") == want


def test_a_recovered_pin_lands_in_the_front_matter_and_still_parses():
    from tests.test_gold_set import entry

    written = pgc.insert_commit(entry(), C1, "tag 1.2.0 as the forge holds it today")
    parsed = gs.parse(written)
    assert parsed.commit == C1
    assert "confirm at ratification" in written.split("+++")[1]
    with pytest.raises(ValueError):
        pgc.insert_commit("+++\nname = 'x'\n+++\n", C1, "how")


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    if date:
        env |= {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    return subprocess.run(  # noqa: S603 - argument list, never a shell string
        [GIT, *args], cwd=repo, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def origin(tmp_path: Path, monkeypatch) -> tuple[Path, str, str]:
    """Two commits a day apart, the first tagged (annotated) `1.0.0`."""
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "f").write_text("1")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "one", date="2026-09-28T12:00:00+00:00")
    _git(repo, "tag", "-a", "1.0.0", "-m", "release", date="2026-09-28T12:00:00+00:00")
    first = _git(repo, "rev-parse", "HEAD")
    (repo / "f").write_text("2")
    _git(repo, "commit", "-qam", "two", date="2026-09-30T12:00:00+00:00")
    second = _git(repo, "rev-parse", "HEAD")
    monkeypatch.setattr(pgc, "_git_url", lambda _spec: f"file://{repo}")
    return repo, first, second


def test_a_branch_tip_scan_recovers_the_commit_before_it(origin):
    """The scan at 09-29 read `one`; `two` came after. Real git."""
    _, first, _ = origin
    read = pgc.RepositoryRead(SourceSpec(SourceKind.GITHUB, "a/r", "9.9.9"), tag_matched=False)
    sha, how = pgc.recover(read, "2026-09-29T00:00:00+00:00")
    assert sha == first and "before the scan" in how


def test_a_tag_matched_scan_recovers_the_tags_commit(origin):
    _, first, _ = origin
    read = pgc.RepositoryRead(SourceSpec(SourceKind.GITHUB, "a/r", "1.0.0"), tag_matched=True)
    assert pgc.recover(read, "2026-09-30T23:00:00+00:00")[0] == first


def test_a_tag_that_is_gone_is_not_recovered(origin):
    read = pgc.RepositoryRead(SourceSpec(SourceKind.GITHUB, "a/r", "2.0.0"), tag_matched=True)
    with pytest.raises(RuntimeError, match="no longer holds"):
        pgc.recover(read, "2026-09-30T23:00:00+00:00")


@pytest.mark.parametrize("row,primary,supplement", [
    # A repository source whose row does not say whether a tag matched.
    (_row(None), "github:a/r@1.0.0", None),
    # The declared repository WAS read (and held no covered source), but the
    # row does not say at which ref — calibration would refuse the entry as
    # unpinned, so "no pin needed" here would send the operator in a loop.
    (_row(None, "the package ships only build output; the declared repository holds no "
                "source in a covered language either"), "npm:pkg@1.0.0", "github:a/r@1.0.0"),
])
def test_a_read_at_an_unknown_ref_is_refused_not_guessed(row, primary, supplement):
    """A guessed tree is worse than no pin: calibration would measure the rules
    against code nobody audited."""
    with pytest.raises(RuntimeError, match="pin by hand"):
        pgc.repository_read(row, primary, supplement)
