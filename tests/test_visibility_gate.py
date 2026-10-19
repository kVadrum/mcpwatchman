"""`ops/visibility_gate.py`: no Maintenance data from a repository the public cannot read."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import ops.visibility_gate as gate
import pytest

GIT = shutil.which("git") or "git"


def _row(slug: str, url: str, weight: str = "0.45", scanned_at: str = "2026-10-20") -> dict:
    return {
        "slug": slug, "scanned_at": scanned_at, "repository_url": url,
        "axes": {"maintenance": {"assessed_weight": weight}},
    }


def test_a_row_scored_this_run_from_an_unreadable_repository_is_refused() -> None:
    after = [_row("a", "https://github.com/acme/public"),
             _row("b", "https://github.com/acme/private")]
    urls = gate.to_check([], after)
    bad, _ = gate.refused(urls, probe=lambda url: url.endswith("/public"),
                          ask=lambda batch: dict.fromkeys(batch, gate.PRIVATE))
    assert bad == {"https://github.com/acme/private": ["b"]}


@pytest.mark.parametrize("answer,refuse", [
    (gate.PRIVATE, True),     # the leak: private, and our token read it
    (gate.UNKNOWN, True),     # no answer is not a yes
    (gate.INVISIBLE, False),  # deleted: nobody, our token included, can read it
    (gate.PUBLIC, False),     # GitHub says public; the probe failed transiently
])
def test_a_repository_the_public_cannot_read_is_judged_by_what_our_token_sees(
    answer: str, refuse: bool,
) -> None:
    urls = {"https://github.com/acme/r": ["s"]}
    bad, invisible = gate.refused(urls, probe=lambda url: False,
                                  ask=lambda batch: dict.fromkeys(batch, answer))
    assert bool(bad) is refuse
    assert invisible == (["https://github.com/acme/r"] if answer == gate.INVISIBLE else [])


def test_without_a_token_every_anonymous_failure_is_refused() -> None:
    assert gate.ask_with_token(["https://github.com/acme/r"], None) == {
        "https://github.com/acme/r": gate.UNKNOWN}


def test_graphql_answers_are_read_per_repository() -> None:
    urls = ["https://github.com/a/private", "https://github.com/a/public",
            "https://github.com/a/gone"]
    payload = {"data": {"r0": {"isPrivate": True}, "r1": {"isPrivate": False}, "r2": None},
               "errors": [{"type": "NOT_FOUND", "path": ["r2"]}]}
    assert gate.parse_answers(urls, payload) == {
        urls[0]: gate.PRIVATE, urls[1]: gate.PUBLIC, urls[2]: gate.INVISIBLE}


def test_an_error_that_is_not_NOT_FOUND_leaves_a_missing_repository_unknown() -> None:
    """A rate limit or an auth failure also nulls the field; reading that as
    "deleted" would wave a private repository through."""
    payload = {"data": {"r0": None}, "errors": [
        {"type": "NOT_FOUND", "path": ["r0"]}, {"type": "RATE_LIMITED"}]}
    assert gate.parse_answers(["https://github.com/a/r"], payload) == {
        "https://github.com/a/r": gate.UNKNOWN}
    assert gate.parse_answers(["https://github.com/a/r"], {"data": None}) == {
        "https://github.com/a/r": gate.UNKNOWN}


def test_only_what_needs_asking_is_asked() -> None:
    """Carried-forward rows are already public, an unassessed axis read no
    forge data, and a URL that is not a plain github.com repository was never
    sent to the forge lookup."""
    carried = _row("carried", "https://github.com/acme/gone", scanned_at="2026-10-19")
    after = [
        carried,
        _row("unassessed", "https://github.com/acme/x", weight="0"),
        _row("gitlab", "https://gitlab.com/acme/x"),
        _row("deep", "https://github.com/acme/x/tree/main"),
        _row("none", ""),
        _row("asked", "https://github.com/acme/asked/"),
    ]
    assert gate.to_check([carried], after) == {"https://github.com/acme/asked": ["asked"]}


def test_an_unreadable_weight_is_asked_about_rather_than_assumed_zero() -> None:
    assert gate.to_check([], [_row("odd", "https://github.com/acme/odd", weight="n/a")])


def test_one_repository_behind_several_servers_is_asked_once() -> None:
    after = [_row("a", "https://github.com/acme/mono"), _row("b", "https://github.com/acme/mono")]
    assert gate.to_check([], after) == {"https://github.com/acme/mono": ["a", "b"]}


def _bare(tmp_path: Path) -> Path:
    seed = tmp_path / "seed"
    seed.mkdir()
    for args in (["init", "-q", "-b", "main"], ["commit", "-q", "--allow-empty", "-m", "x"]):
        subprocess.run(  # noqa: S603
            [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
            cwd=seed, check=True, capture_output=True,
        )
    bare = tmp_path / "bare.git"
    subprocess.run([GIT, "clone", "-q", "--bare", str(seed), str(bare)],  # noqa: S603
                   check=True, capture_output=True)
    return bare


def test_the_probe_answers_both_ways(tmp_path: Path) -> None:
    """Positive control: a probe that always said no would refuse every run;
    one that always said yes would pass every leak."""
    bare = _bare(tmp_path)
    assert gate.probe_anonymous(f"file://{bare}") is True
    assert gate.probe_anonymous(f"file://{tmp_path}/missing.git", attempts=1) is False


def test_the_probe_never_reads_the_operators_git_config(tmp_path: Path, monkeypatch) -> None:
    """The question is whether the PUBLIC can read it. A url rewrite (or a
    credential helper) in the operator's config would answer for the operator
    instead — here the rewrite points a missing repository at a readable one."""
    bare = _bare(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        f'[url "file://{bare}"]\n\tinsteadOf = file://{tmp_path}/missing.git\n'
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    missing = f"file://{tmp_path}/missing.git"
    # Negative control: plain git, reading that config, says it is readable.
    plain = subprocess.run([GIT, "ls-remote", "-q", missing],  # noqa: S603
                           capture_output=True, check=False)
    assert plain.returncode == 0, "the fixture's rewrite did not take; the test proves nothing"
    assert gate.probe_anonymous(missing, attempts=1) is False


@pytest.mark.parametrize("refusal,code", [(False, 0), (True, 1)])
def test_main_exits_by_the_answer(tmp_path: Path, monkeypatch, refusal: bool, code: int) -> None:
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text("[]")
    after.write_text('[{"slug": "s", "scanned_at": "t", '
                     '"repository_url": "https://github.com/acme/r", '
                     '"axes": {"maintenance": {"assessed_weight": "0.5"}}}]')
    monkeypatch.setattr(gate, "probe_anonymous", lambda url: not refusal)
    assert gate.main(["--before", str(before), "--after", str(after)]) == code
