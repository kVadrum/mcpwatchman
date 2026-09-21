"""`ops/scan_cohort.py`'s per-server failure handling, driven through `main()`.

⚠ **THE COMPOSITION IS THE SUBJECT, not the helpers.** Every piece below was
already tested in isolation and the defect lived between them: `mark_status`
refuses a colliding registry status correctly, `_keep_previous` absorbs an
our-side gap correctly, and the call site joined them with nothing in between —
so one entry aborted a 492-page run with a traceback. A unit test on either
side passes while that is true.

`main()` reaches the network and the registry through module-level names, which
is what makes this stubbable: `fetch_all`, `current_entries`, `scan_entry`,
`preflight` and `load` are all patchable on `ops.scan_cohort`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpwatchman.cohort import Cohort, PinnedServer
from mcpwatchman.workers.crawler.registry import RegistryEntry, Repository


def _pin(name: str) -> PinnedServer:
    from mcpwatchman.workers.scanner.runner import slugify

    return PinnedServer(name=name, slug=slugify(name), first_published="2026-09-18")


def _report(name: str, *, fault: str = "publisher") -> dict:
    from mcpwatchman.workers.scanner.runner import slugify

    return {
        "name": name,
        "slug": slugify(name),
        "scanned_at": "2026-09-20T00:00:00+00:00",
        "axes": {
            "code_safety": {"score": 70, "assessed_weight": "1"},
            "maintenance": {
                "score": None, "fault": fault,
                "reason": "a reason, because an unassessed axis owes one",
            },
        },
    }


@pytest.fixture
def driver(monkeypatch, tmp_path: Path):
    """A `main()` wired to fixtures, returning (run, state) for each test to shape."""
    import ops.scan_cohort as sc

    state: dict = {"entries": {}, "reports": {}, "cohort": Cohort(servers=())}

    def run(*argv: str) -> tuple[int, str]:
        out = tmp_path / "scans.json"
        monkeypatch.setattr(sc, "preflight", lambda: [])
        monkeypatch.setattr(sc, "load", lambda _p: state["cohort"])
        monkeypatch.setattr(sc, "fetch_all", lambda: list(state["entries"].values()))
        # ⚠ NOT `lambda m: m`. `current_entries` is what separates a pinned
        # server the driver rescans from one it flags, and a pass-through stub
        # puts every entry in `live` — so the `to_flag` branch this file exists
        # to exercise is never reached and the test passes vacuously.
        monkeypatch.setattr(
            sc, "current_entries",
            lambda m: [e for e in m if e.status == "active" and e.is_latest],
        )
        monkeypatch.setattr(sc, "scan_entry", lambda e: _ScanStub(state["reports"][e.name]))
        monkeypatch.setattr(
            "sys.argv",
            ["scan_cohort", "--out", str(out), "--cohort", str(tmp_path / "cohort.json"), *argv],
        )
        code = sc.main()
        return code, out.read_text() if out.exists() else ""

    return run, state


class _ScanStub:
    def __init__(self, report: dict) -> None:
        self._report = report

    def to_dict(self) -> dict:
        return dict(self._report)

    # `_scan` prints a per-axis line from these before returning the dict.
    @property
    def axes(self):
        from types import SimpleNamespace

        return {k: SimpleNamespace(score=v.get("score"))
                for k, v in self._report["axes"].items()}

    @property
    def name(self) -> str:
        return self._report["name"]

    @property
    def source_state(self) -> str:
        return "fetched"


def test_a_colliding_registry_status_costs_one_page_its_refresh_not_the_run(
    driver, capsys, tmp_path: Path
) -> None:
    """⚠ The refusal is right; its blast radius was not.

    `mark_status` refuses a registry status that collides with one of ours,
    because relaying the word would disable that server's publication gate.
    Uncaught at the call site, it took down a 492-page run over one entry —
    wider than every other refusal in this driver, and against the project's
    own stance that a refused gap costs that page its refresh, not the run.
    """
    run, state = driver
    state["cohort"] = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two")))
    state["entries"] = {
        "ai.a/one": RegistryEntry(name="ai.a/one", version="1", is_latest=True),
        # `delisted` is a state of OURS. A registry that picked the same word —
        # a natural choice, and `06` says new statuses are relayed verbatim —
        # is what `mark_status` refuses.
        "ai.b/two": RegistryEntry(
            name="ai.b/two", version="1", is_latest=True, status="delisted"
        ),
    }
    state["reports"] = {n: _report(n) for n in state["entries"]}

    # A previous publication exists, so the refused page has something to keep.
    previous = [_report("ai.a/one"), _report("ai.b/two")]
    (tmp_path / "scans.json").write_text(json.dumps(previous))

    code, written = run()
    assert code == 0, "one entry must not abort the run"

    published = {r["name"] for r in json.loads(written)}
    assert published == {"ai.a/one", "ai.b/two"}, "the refused page must not vanish"

    printed = capsys.readouterr().out
    assert "collides" in printed, "the reason has to reach a human"
    assert "ai.b/two" in printed


def test_a_colliding_status_with_no_previous_page_still_refuses_the_write(
    driver, capsys
) -> None:
    """The positive control for the test above, and the case that must NOT pass.

    Absorbing the refusal is only correct when there is a published page to
    protect. A pin with no history and no report is a URL that would 404, which
    is the one failure the whole cohort mechanism exists to prevent — so here
    the run must still refuse to write anything at all.
    """
    run, state = driver
    state["cohort"] = Cohort(servers=(_pin("ai.b/two"),))
    state["entries"] = {
        "ai.b/two": RegistryEntry(
            name="ai.b/two", version="1", is_latest=True, status="stale"
        )
    }
    state["reports"] = {"ai.b/two": _report("ai.b/two")}

    code, _ = run()
    assert code == 2
    assert "REFUSING TO WRITE" in capsys.readouterr().err


def test_the_summary_names_what_it_did_not_publish(driver, capsys, tmp_path: Path) -> None:
    """⚠ The counts describe what PUBLISHED, so the two outcomes worth reading
    appeared either as a bare number or not at all.

    A kept page and a skipped growth candidate are both printed per server as
    the run goes — hundreds of lines earlier — so answering "which ones?" meant
    grepping a log that may not have been kept. A run that keeps ten servers is
    either a broken toolchain or a transient fault, and those want opposite
    responses.
    """
    run, state = driver
    state["cohort"] = Cohort(servers=(_pin("ai.a/one"),))
    state["entries"] = {
        "ai.a/one": RegistryEntry(
            name="ai.a/one", version="1", is_latest=True, status="delisted"
        ),
        # A growth candidate has to be SCANNABLE or `_growth_candidates`
        # never offers it, and `--grow 1` then silently grows by nothing.
        "ai.c/three": RegistryEntry(
            name="ai.c/three", version="1", is_latest=True,
            repository=Repository(url="https://github.com/c/three", source="github"),
        ),
    }
    state["reports"] = {
        "ai.a/one": _report("ai.a/one"),
        # An our-side gap on a name nothing has promised yet: do not pin it.
        "ai.c/three": _report("ai.c/three", fault="environment"),
    }
    (tmp_path / "scans.json").write_text(json.dumps([_report("ai.a/one")]))

    code, written = run("--grow", "1")
    assert code == 0
    assert {r["name"] for r in json.loads(written)} == {"ai.a/one"}

    printed = capsys.readouterr().out
    assert "kept previous scan (1): ai.a/one" in printed
    assert "not pinned, our side failed (1): ai.c/three" in printed
