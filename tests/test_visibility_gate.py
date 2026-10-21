"""`ops/visibility_gate.py`: no Maintenance data from a repository the public cannot read."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import ops.visibility_gate as gate
import pytest

GIT = shutil.which("git") or "git"


def _row(slug: str, url: str, weight: str = "0.45", scanned_at: str = "2026-10-20") -> dict:
    return {
        "name": slug, "slug": slug, "scanned_at": scanned_at, "repository_url": url,
        "registry_state": "listed", "registry_note": "",
        "axes": {"maintenance": {"assessed_weight": weight}},
    }


def _main(tmp_path: Path, monkeypatch, before: list[dict], after: list[dict],
          probe=lambda url: True) -> tuple[int, str]:
    """Run the gate as the nightly does; (exit code, the --after file afterwards)."""
    # No token: an anonymous failure would otherwise put a live question to GitHub.
    for name in ("MCPWATCHMAN_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(gate, "probe_anonymous", probe)
    b, a = tmp_path / "before.json", tmp_path / "after.json"
    b.write_text(json.dumps(before))
    a.write_text(json.dumps(after))
    code = gate.main(["--before", str(b), "--after", str(a)])
    return code, a.read_text()


def test_a_row_scored_this_run_from_an_unreadable_repository_is_refused() -> None:
    after = [_row("a", "https://github.com/acme/public"),
             _row("b", "https://github.com/acme/private")]
    urls, _ = gate.to_check([], after)
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
    """Carried-forward rows are already public and an unassessed axis read no
    forge data; every other row is asked about the repository the forge lookup
    actually read — which for a URL into a repository is the repository."""
    carried = _row("carried", "https://github.com/acme/gone", scanned_at="2026-10-19")
    after = [
        carried,
        _row("unassessed", "https://github.com/acme/x", weight="0"),
        _row("asked", "https://github.com/acme/asked/"),
    ]
    assert gate.to_check([carried], after) == ({"https://github.com/acme/asked": ["asked"]}, [])


@pytest.mark.parametrize("url", [
    "https://github.com/acme/x/tree/main",
    "http://github.com/acme/x",
    "https://www.github.com/acme/x",
    "https://GitHub.com/acme/x",
    "https://github.com/acme/x.git",
])
def test_every_url_the_forge_lookup_reads_is_asked_about(url: str) -> None:
    """The gate once matched its own regex, which the forge's parser outgrew:
    each of these URLs had its Maintenance read from `acme/x` and was never
    asked about."""
    assert gate.to_check([], [_row("s", url)]) == ({"https://github.com/acme/x": ["s"]}, [])


@pytest.mark.parametrize("url", ["https://gitlab.com/acme/x", "", "git@github.com:acme/x.git"])
def test_maintenance_from_a_url_the_gate_cannot_name_is_withheld(
    tmp_path: Path, monkeypatch, url: str,
) -> None:
    """Assessed Maintenance came from SOME repository; a gate that skipped what
    it could not name would pass it unasked. No question asked, no yes."""
    urls, unaskable = gate.to_check([], [_row("s", url)])
    assert (urls, [name for name, _ in unaskable]) == ({}, ["s"])
    previous = _row("s", url, scanned_at="2026-10-19")
    code, written = _main(tmp_path, monkeypatch, [previous], [_row("s", url)])
    assert code == 0
    [kept] = json.loads(written)
    assert (kept["scanned_at"], kept["registry_state"]) == ("2026-10-19", "stale")


def test_an_unreadable_weight_is_asked_about_rather_than_assumed_zero() -> None:
    for weight in ("n/a", None):
        urls, _ = gate.to_check([], [_row("odd", "https://github.com/acme/odd", weight=weight)])
        assert urls, weight


@pytest.mark.parametrize("drop", ["name", "scanned_at", "axes", "maintenance", "assessed_weight"])
def test_a_row_without_what_the_gate_reads_is_withheld_not_skipped(
    tmp_path: Path, monkeypatch, drop: str,
) -> None:
    """main's scanner writes the data and this gate runs from dev, so a field
    renamed on one side reads, on the other, as "carried forward" or "nothing
    measured" — and a gate that skipped those rows passed having asked nothing."""
    previous = _row("s", "https://github.com/acme/r", scanned_at="2026-10-19")
    row = _row("s", "https://github.com/acme/r")
    if drop == "maintenance":
        del row["axes"]["maintenance"]
    elif drop == "assessed_weight":
        del row["axes"]["maintenance"]["assessed_weight"]
    else:
        del row[drop]
    urls, unaskable = gate.to_check([row], [row])
    assert urls == {} and len(unaskable) == 1
    code, written = _main(tmp_path, monkeypatch, [previous], [row])
    if drop == "name":
        # Nothing names the page to keep, so the run is refused, not the row.
        assert (code, json.loads(written)) == (1, [row])
    else:
        assert code == 0
        assert json.loads(written)[0]["scanned_at"] == "2026-10-19"


def test_the_published_data_carries_every_field_the_gate_reads() -> None:
    """The positive control for the test above, against the real records: every
    row is readable, and the gate finds repositories to ask about in them."""
    data = Path(__file__).resolve().parents[1] / "site" / "src" / "data" / "scans.json"
    urls, unaskable = gate.to_check([], json.loads(data.read_text()))
    assert unaskable == []
    assert len(urls) > 100


def test_one_repository_behind_several_servers_is_asked_once() -> None:
    after = [_row("a", "https://github.com/acme/mono"), _row("b", "https://github.com/acme/mono")]
    assert gate.to_check([], after) == ({"https://github.com/acme/mono": ["a", "b"]}, [])


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


def test_the_probe_never_reads_the_config_of_the_repository_it_runs_in(
    tmp_path: Path, monkeypatch,
) -> None:
    """`ls-remote` inside a repository reads that repository's config, and the
    nightly runs this gate from inside ours: a rewrite or credential helper
    there would answer for the public. The probe runs from `/`."""
    bare = _bare(tmp_path)
    here = tmp_path / "here"
    subprocess.run([GIT, "init", "-q", str(here)], check=True, capture_output=True)  # noqa: S603
    missing = f"file://{tmp_path}/missing.git"
    subprocess.run(  # noqa: S603
        [GIT, "config", f"url.file://{bare}.insteadOf", missing],
        cwd=here, check=True, capture_output=True,
    )
    monkeypatch.chdir(here)
    plain = subprocess.run([GIT, "ls-remote", "-q", missing],  # noqa: S603
                           capture_output=True, check=False)
    assert plain.returncode == 0, "the fixture's rewrite did not take; the test proves nothing"
    assert gate.probe_anonymous(missing, attempts=1) is False


def test_one_unconfirmed_repository_costs_its_own_page_its_refresh_not_the_run(
    tmp_path: Path, monkeypatch,
) -> None:
    """Operator ruling 2026-10-21: one publisher making a repository private
    stopped every page's refresh. Now that row keeps its previous page —
    labelled, its numbers untouched — and every other row publishes."""
    before = [_row("a", "https://github.com/acme/a", scanned_at="2026-10-19"),
              _row("b", "https://github.com/acme/private", scanned_at="2026-10-19"),
              _row("c", "https://github.com/acme/c", scanned_at="2026-10-19")]
    before[1]["v"] = "old"
    after = [_row("a", "https://github.com/acme/a"),
             _row("b", "https://github.com/acme/private"),
             _row("c", "https://github.com/acme/c")]
    after[1]["v"] = "new, read with our token"
    code, written = _main(tmp_path, monkeypatch, before, after,
                          probe=lambda url: not url.endswith("/private"))
    assert code == 0
    rows = json.loads(written)
    assert [r["name"] for r in rows] == ["a", "b", "c"], "order is the published order"
    assert rows[0] == after[0] and rows[2] == after[2]
    kept = rows[1]
    assert kept == {**before[1], "registry_state": "stale",
                    "registry_note": kept["registry_note"]}, "only the label changes"
    note = kept["registry_note"]
    assert "could not be confirmed as publicly readable" in note, note
    assert "2026-10-19" in note, "the page says how old its numbers are"
    # It says what was observed, never why: "private" and "did not answer"
    # fail the same probe, and only one of them is the publisher's doing.
    assert "private" not in note.lower(), note
    assert "did not complete" not in note, "the scan completed; it was withheld"


def test_a_withheld_row_with_no_previous_page_refuses_the_run(
    tmp_path: Path, monkeypatch,
) -> None:
    """Withholding a row that was never published would 404 a pinned page."""
    after = [_row("a", "https://github.com/acme/a"), _row("b", "https://github.com/acme/b")]
    code, written = _main(tmp_path, monkeypatch, [], after,
                          probe=lambda url: not url.endswith("/b"))
    assert code == 1
    assert json.loads(written) == after, "nothing written"


def test_withholding_past_the_staleness_bound_refuses_the_run(
    tmp_path: Path, monkeypatch,
) -> None:
    """A dead network fails every question at once; carrying every page then
    would be a run that changed nothing, reported as one that published."""
    from mcpwatchman.cohort import STALE_FLOOR

    n = STALE_FLOOR + 1
    before = [_row(f"s{i}", f"https://github.com/acme/s{i}", scanned_at="2026-10-19")
              for i in range(n)]
    after = [_row(f"s{i}", f"https://github.com/acme/s{i}") for i in range(n)]
    code, written = _main(tmp_path, monkeypatch, before, after, probe=lambda url: False)
    assert code == 1
    assert json.loads(written) == after, "nothing written"
    # The positive control: one fewer is an ordinary night.
    code, _ = _main(tmp_path, monkeypatch, before[:-1], after[:-1], probe=lambda url: False)
    assert code == 0


def test_a_clean_run_leaves_the_file_byte_for_byte(tmp_path: Path, monkeypatch) -> None:
    after = [_row("s", "https://github.com/acme/r")]
    b, a = tmp_path / "before.json", tmp_path / "after.json"
    b.write_text("[]")
    a.write_text(json.dumps(after, indent=4))
    for name in ("MCPWATCHMAN_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(gate, "probe_anonymous", lambda url: True)
    assert gate.main(["--before", str(b), "--after", str(a)]) == 0
    assert a.read_text() == json.dumps(after, indent=4)
