"""Score history: what a point is, when two scores may be compared, and the
git walk that keeps the derived file rebuildable."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from mcpwatchman import history as h

ROOT = Path(__file__).resolve().parents[1]


def _report(slug: str = "s", scanned: str = "2026-10-01T02:00:00Z", *, scanner: str = "0.38.0",
            ruleset: str = "0.1.2", code: int | None = 90, code_w: str = "1",
            maint: int | None = 80, **extra: Any) -> dict[str, Any]:
    axes = {k: {"score": None, "assessed_weight": "0", "fault": "publisher"} for k in h.AXES}
    axes["code_safety"] = {"score": code, "assessed_weight": code_w, "fault": None}
    axes["maintenance"] = {"score": maint, "assessed_weight": "0.7", "fault": None}
    return {"slug": slug, "name": f"io.x/{slug}", "scanned_at": scanned, "scanner_version": scanner,
            "ruleset_version": ruleset, "methodology_version": "0.2.0", "axes": axes, **extra}


def test_a_kept_page_adds_no_point() -> None:
    hist = h.empty()
    assert h.merge(hist, [_report()]) == 1
    assert h.merge(hist, [_report()]) == 0
    assert len(hist["servers"]["s"]) == 1


def test_the_latest_scan_of_a_day_wins_and_an_earlier_one_never_replaces_it() -> None:
    hist = h.empty()
    h.merge(hist, [_report(scanned="2026-10-01T02:00:00Z", code=50)])
    h.merge(hist, [_report(scanned="2026-10-01T09:00:00Z", code=60)])
    h.merge(hist, [_report(scanned="2026-10-01T05:00:00Z", code=70)])
    (only,) = hist["servers"]["s"]
    assert only[0] == "2026-10-01T09:00:00Z" and only[4][0] == 60


def test_points_stay_in_scan_order_whatever_order_they_arrive_in() -> None:
    hist = h.empty()
    late, early = _report(scanned="2026-10-03T02:00:00Z"), _report(scanned="2026-10-01T02:00:00Z")
    h.merge(hist, [late, early])
    assert [p[0][:10] for p in hist["servers"]["s"]] == ["2026-10-01", "2026-10-03"]


def test_a_record_written_before_fault_existed_reads_it_as_none() -> None:
    old = _report()
    for axis in old["axes"].values():
        axis.pop("fault")
    hist = h.empty()
    h.merge(hist, [old])
    assert all(cell[2] is None for cell in hist["servers"]["s"][0][4:])


def test_every_published_score_travels_with_its_assessed_weight() -> None:
    hist = h.empty()
    h.merge(hist, [_report(code=None, code_w="0")])
    out = h.expand("s", "io.x/s", hist["servers"]["s"])
    (pt,) = out["points"]
    assert pt["date"] == "2026-10-01"
    assert set(pt["axes"]) == set(h.AXES)
    for axis in pt["axes"].values():
        assert set(axis) == {"score", "assessed_weight", "fault"}
    assert pt["axes"]["code_safety"] == {"score": None, "assessed_weight": "0", "fault": None}


def test_an_unknown_schema_is_refused_not_merged_into() -> None:
    with pytest.raises(ValueError, match="schema"):
        h.merge({**h.empty(), "schema": 99}, [_report()])
    with pytest.raises(ValueError, match="axes"):
        h.merge({**h.empty(), "axes": ["code_safety"]}, [_report()])


def _series(*reports: dict[str, Any]) -> dict[str, Any]:
    hist = h.empty()
    h.merge(hist, reports)
    return hist


def _drops(hist: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
    return h.drops(hist, {"s": "io.x/s"}, "2026-10-10", **kw)


def test_a_fall_at_the_threshold_is_a_drop_and_one_below_is_not() -> None:
    at = _series(_report(code=90), _report(scanned="2026-10-02T02:00:00Z", code=80))
    below = _series(_report(code=90), _report(scanned="2026-10-02T02:00:00Z", code=81))
    (d,) = _drops(at)
    assert (d["axis"], d["before"], d["after"], d["date"]) == ("code_safety", 90, 80, "2026-10-02")
    assert _drops(below) == []


@pytest.mark.parametrize("change", [
    {"scanner": "0.39.0"}, {"ruleset": "0.1.3"}, {"code_w": "0.5"}, {"code": None},
])
def test_scores_under_different_measurements_are_never_compared(change: dict[str, Any]) -> None:
    after = {"code": 10, **change}
    hist = _series(_report(code=90), _report(scanned="2026-10-02T02:00:00Z", **after))
    assert _drops(hist) == []


def test_maintenance_decay_is_not_a_feed_event() -> None:
    hist = _series(_report(maint=80), _report(scanned="2026-10-02T02:00:00Z", maint=40))
    assert _drops(hist) == []
    assert [d["axis"] for d in _drops(hist, axes=h.AXES)] == ["maintenance"]


def test_drops_outside_the_window_or_the_cohort_are_left_out() -> None:
    hist = _series(_report(code=90), _report(scanned="2026-10-02T02:00:00Z", code=10))
    assert h.drops(hist, {"s": "io.x/s"}, "2027-03-01") == []
    assert h.drops(hist, {"other": "io.x/other"}, "2026-10-10") == []


# --- ops/score_history.py over a real git history -------------------------

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="needs git")


def _repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "site/src/data").mkdir(parents=True)
    env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    git = GIT or "git"
    subprocess.run([git, "init", "-q", str(repo)], check=True)  # noqa: S603
    for i, code in enumerate((90, 70, 70)):
        rows = [_report(scanned=f"2026-10-0{i + 1}T02:00:00Z", code=code)]
        (repo / "site/src/data/scans.json").write_text(json.dumps(rows))
        subprocess.run([git, "-C", str(repo), "add", "-A"], check=True)  # noqa: S603
        subprocess.run(  # noqa: S603
            [git, "-C", str(repo), *env, "commit", "-qm", f"data {i}"], check=True)
    return repo


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "ops/score_history.py"), *args],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
    )


@needs_git
def test_a_rebuild_reads_every_data_commit(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "history.json"
    done = _run("--repo", str(repo), "--ref", "HEAD", "--out", str(out), "--rebuild")
    assert done.returncode == 0, done.stderr
    hist = json.loads(out.read_text())
    assert [p[4][0] for p in hist["servers"]["s"]] == [90, 70, 70]
    assert [d["before"] for d in hist["drops"]] == [90]


@needs_git
def test_an_update_fills_nights_it_missed_from_git_then_adds_tonight(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = subprocess.run(  # noqa: S603
        [GIT or "git", "-C", str(repo), "rev-list", "--max-parents=0", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    stale = {**h.empty(), "through": first}
    h.merge(stale, [_report(scanned="2026-10-01T02:00:00Z", code=90)])
    before = tmp_path / "before.json"
    before.write_text(json.dumps(stale))
    tonight = tmp_path / "tonight.json"
    tonight.write_text(json.dumps([_report(scanned="2026-10-04T02:00:00Z", code=40)]))
    out = tmp_path / "history.json"
    done = _run("--repo", str(repo), "--ref", "HEAD", "--history", str(before),
                "--scans", str(tonight), "--out", str(out))
    assert done.returncode == 0, done.stderr
    assert "2 data commit(s) read" in done.stdout
    hist = json.loads(out.read_text())
    assert [p[0][:10] for p in hist["servers"]["s"]] == [
        "2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04"]


@needs_git
def test_a_through_that_is_no_longer_an_ancestor_rereads_everything(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = tmp_path / "before.json"
    before.write_text(json.dumps({**h.empty(), "through": "0" * 40}))
    out = tmp_path / "history.json"
    done = _run("--repo", str(repo), "--ref", "HEAD", "--history", str(before), "--out", str(out))
    assert done.returncode == 0, done.stderr
    assert "3 data commit(s) read" in done.stdout


@needs_git
def test_unreadable_input_is_refused_and_writes_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = tmp_path / "before.json"
    before.write_text(json.dumps({**h.empty(), "schema": 99}))
    out = tmp_path / "history.json"
    done = _run("--repo", str(repo), "--ref", "HEAD", "--history", str(before), "--out", str(out))
    assert done.returncode == 2 and "refused" in done.stderr
    assert not out.exists()


def test_the_committed_history_never_claims_a_scan_the_data_does_not_have() -> None:
    """The history may LAG the data — until `main` carries the derivation the
    nightly commits scans without it, an ordinary between-syncs state, and the
    site adds each page's current scan at build time — but it must never run
    ahead of it: a newest point later than the page's own scan is a point
    nobody published."""
    data = ROOT / "site/src/data"
    hist = json.loads((data / "history.json").read_text())
    rows = json.loads((data / "scans.json").read_text())
    assert hist["schema"] == h.SCHEMA and hist["axes"] == list(h.AXES)
    for row in rows:
        series = hist["servers"].get(row["slug"], [])
        if series:
            assert series[-1][0] <= row["scanned_at"], row["slug"]
