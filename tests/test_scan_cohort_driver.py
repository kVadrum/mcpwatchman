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

    state: dict = {"entries": {}, "reports": {}, "cohort": Cohort(servers=()),
                   "raises": set(), "calls": []}

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
        def scan_entry(entry):
            state["calls"].append(entry.name)
            if entry.name in state["raises"]:
                raise ValueError(f"a check met a shape it never expected in {entry.name}")
            return _ScanStub(state["reports"][entry.name])

        monkeypatch.setattr(sc, "scan_entry", scan_entry)
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

    # ⚠ AND THE CARRIED PAGE MUST NOT SAY THE SCAN FAILED. This path reaches
    # the carry-forward with a COMPLETE, publishable scan in hand — only the
    # registry's status word was unrepresentable — but it reused the
    # scan-failure helper unchanged, so the page read "the most recent scan
    # could not measure it for reasons on our side" about a server measured in
    # full moments earlier. Same borrowed-sentence defect `v0.28.2` fixed at
    # the fetch stage, arriving through a shared helper instead of a copied
    # string, which is why the fix is an override at the call site.
    # ⚠ ASSERT THE CLAIM, NOT THE PHRASE. The first version of this check
    # looked for the exact wording the fix removed ("could not measure it") and
    # passed while `carry_forward` appended a DIFFERENT scan-failure sentence
    # to the same note — so the record said "shown instead" and "the scan that
    # would have refreshed them did not complete" at once. Found by the review
    # leg on the commit that added this test.
    carried = next(r for r in json.loads(written) if r["name"] == "ai.b/two")
    note = carried.get("registry_note", "")
    assert "cannot represent" in note, note
    for failed_scan_claim in (
        "could not measure it",
        "did not complete",
        "no current entry to scan",
    ):
        assert failed_scan_claim not in note, f"{failed_scan_claim!r} in {note!r}"


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


def test_a_systemic_our_side_failure_refuses_to_write_and_exits_3(
    driver, capsys, tmp_path: Path
) -> None:
    """An exhausted token gives EVERY server the same our-side gap. Absorbed
    per page, that wrote "could not measure it" on the whole set and exited 0 —
    a scheduled run that changed nothing, reported as success."""
    run, state = driver
    names = [f"ai.s/n{i}" for i in range(8)]
    state["cohort"] = Cohort(servers=tuple(_pin(n) for n in names))
    state["entries"] = {n: RegistryEntry(name=n, version="1", is_latest=True) for n in names}
    # Six of eight fail on our side — past max(5, 10%).
    state["reports"] = {
        n: _report(n, fault="environment" if i < 6 else "publisher")
        for i, n in enumerate(names)
    }
    previous = [_report(n) for n in names]
    (tmp_path / "scans.json").write_text(json.dumps(previous))

    code, written = run()

    assert code == 3
    assert json.loads(written) == previous, "the published set must be left untouched"
    err = capsys.readouterr().err
    assert "systemic" in err and "6 of 8" in err


def test_an_ordinary_handful_of_our_side_gaps_is_still_absorbed(
    driver, tmp_path: Path
) -> None:
    """The negative control: five is the floor an ordinary run absorbs."""
    run, state = driver
    names = [f"ai.s/n{i}" for i in range(8)]
    state["cohort"] = Cohort(servers=tuple(_pin(n) for n in names))
    state["entries"] = {n: RegistryEntry(name=n, version="1", is_latest=True) for n in names}
    state["reports"] = {
        n: _report(n, fault="environment" if i < 5 else "publisher")
        for i, n in enumerate(names)
    }
    (tmp_path / "scans.json").write_text(json.dumps([_report(n) for n in names]))

    code, written = run()

    assert code == 0
    states = [r.get("registry_state") for r in json.loads(written)]
    assert states.count("stale") == 5


def test_a_scan_that_raises_costs_that_page_its_refresh_not_the_run(
    driver, capsys, tmp_path: Path
) -> None:
    """Operator ruling 2026-10-21: one record is noted, skipped, and the run
    moves on. A check module raising on one repository's contents ended the
    whole run with a traceback; now the pinned page keeps its last scan, a
    growth candidate is not pinned, and the traceback is still printed."""
    run, state = driver
    state["cohort"] = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two")))
    state["entries"] = {
        "ai.a/one": RegistryEntry(name="ai.a/one", version="1", is_latest=True),
        "ai.b/two": RegistryEntry(name="ai.b/two", version="1", is_latest=True),
        "ai.c/three": RegistryEntry(
            name="ai.c/three", version="1", is_latest=True,
            repository=Repository(url="https://github.com/c/three", source="github"),
        ),
    }
    state["reports"] = {n: _report(n) for n in state["entries"]}
    state["raises"] = {"ai.b/two", "ai.c/three"}
    previous = [{**_report(n), "scanned_at": "2026-09-19T00:00:00+00:00"}
                for n in ("ai.a/one", "ai.b/two")]
    (tmp_path / "scans.json").write_text(json.dumps(previous))

    code, written = run("--grow", "1")

    assert code == 0, "one record must not end the run"
    rows = {r["name"]: r for r in json.loads(written)}
    assert set(rows) == {"ai.a/one", "ai.b/two"}, "the candidate that raised is not pinned"
    assert rows["ai.a/one"]["scanned_at"] == "2026-09-20T00:00:00+00:00", "the rest rescanned"
    assert rows["ai.b/two"]["scanned_at"] == "2026-09-19T00:00:00+00:00"
    assert rows["ai.b/two"]["registry_state"] == "stale"
    assert state["calls"].count("ai.b/two") == 2, "retried once, like any our-side gap"
    captured = capsys.readouterr()
    assert "ValueError" in captured.err and "Traceback" in captured.err, "a defect to fix"
    assert "kept previous scan (1): ai.b/two" in captured.out
    assert "not pinned, our side failed (1): ai.c/three" in captured.out


def _api_changes(tmp_path: Path, page_size: int, status: str, not_before: str) -> None:
    (tmp_path / "api-changes.json").write_text(json.dumps({
        "page_size": page_size,
        "changes": [{"id": "servers-json-pages", "status": status, "not_before": not_before}],
    }))


def _one_pin_and_a_candidate(state: dict, tmp_path: Path) -> None:
    state["cohort"] = Cohort(servers=(_pin("ai.a/one"),))
    state["entries"] = {
        "ai.a/one": RegistryEntry(name="ai.a/one", version="1", is_latest=True),
        "ai.c/three": RegistryEntry(
            name="ai.c/three", version="1", is_latest=True,
            repository=Repository(url="https://github.com/c/three", source="github"),
        ),
    }
    state["reports"] = {n: _report(n) for n in state["entries"]}
    (tmp_path / "scans.json").write_text(json.dumps([_report("ai.a/one")]))


def test_growth_past_the_announced_page_is_refused_before_anything_is_pinned(
    driver, capsys, tmp_path: Path
) -> None:
    """`ops/cohort.json` is append-only, so a pin past the page the paging
    notice promises could not be taken back; the publication gate would then
    fail every night until the notice ran out. The refusal comes first."""
    run, state = driver
    _one_pin_and_a_candidate(state, tmp_path)
    _api_changes(tmp_path, page_size=1, status="announced", not_before="2999-01-01")

    code, written = run("--grow", "1")

    assert code == 2
    assert "REFUSING TO GROW" in capsys.readouterr().err
    assert state["calls"] == [], "nothing is scanned"
    assert [r["name"] for r in json.loads(written)] == ["ai.a/one"], "the store is untouched"
    assert not (tmp_path / "cohort.json").exists(), "nothing is pinned"


@pytest.mark.parametrize(("page_size", "status", "not_before"), [
    (2, "announced", "2999-01-01"),  # still fits one page
    (1, "landed", "2000-01-01"),     # the notice has run and the change landed
])
def test_growth_the_page_allows_is_pinned(
    driver, tmp_path: Path, page_size: int, status: str, not_before: str
) -> None:
    run, state = driver
    _one_pin_and_a_candidate(state, tmp_path)
    _api_changes(tmp_path, page_size=page_size, status=status, not_before=not_before)

    code, written = run("--grow", "1")

    assert code == 0
    assert {r["name"] for r in json.loads(written)} == {"ai.a/one", "ai.c/three"}
    assert (tmp_path / "cohort.json").exists(), "the new name is pinned"


def test_a_name_adopted_twice_counts_once_against_the_page(
    driver, tmp_path: Path
) -> None:
    """Pinning keeps one of a repeated name, so the limit and the scan must too:
    one pin plus the same name listed twice is two servers, inside a page of 2."""
    run, state = driver
    _one_pin_and_a_candidate(state, tmp_path)
    _api_changes(tmp_path, page_size=2, status="announced", not_before="2999-01-01")
    adopt = tmp_path / "adopt.txt"
    adopt.write_text("ai.c/three\nai.c/three\n")

    code, written = run("--adopt-file", str(adopt))

    assert code == 0
    assert [r["name"] for r in json.loads(written)] == ["ai.a/one", "ai.c/three"]
    assert state["calls"].count("ai.c/three") == 1


# --- the rolling nightly (D1a, ruled 2026-11-09) ------------------------------


def _three_pins_one_moved(state: dict, tmp_path: Path) -> None:
    """Three pinned pages: `ai.c/three` has a new registry version, `ai.a/one`
    the oldest scan, `ai.b/two` the newest."""
    state["cohort"] = Cohort(servers=(_pin("ai.a/one"), _pin("ai.b/two"), _pin("ai.c/three")))
    state["entries"] = {
        "ai.a/one": RegistryEntry(name="ai.a/one", version="1", is_latest=True),
        "ai.b/two": RegistryEntry(name="ai.b/two", version="1", is_latest=True),
        "ai.c/three": RegistryEntry(name="ai.c/three", version="2", is_latest=True),
    }
    state["reports"] = {n: _report(n) for n in state["entries"]}
    from mcpwatchman.workers.scanner.semgrep_check import rules_root, ruleset_version
    from mcpwatchman.workers.scoring.weights import CURRENT_METHODOLOGY_VERSION

    # As every published page has: `feed.stamp_first_seen` adds the field to
    # a page without it, which would read here as a pass-through edited.
    contract = {"methodology_version": CURRENT_METHODOLOGY_VERSION,
                "ruleset_version": ruleset_version(rules_root()),
                "findings_tracked_since": "2026-09-10"}
    previous = [
        {**_report("ai.a/one"), **contract, "version": "1",
         "registry_state": "listed", "scanned_at": "2026-09-10T00:00:00+00:00"},
        {**_report("ai.b/two"), **contract, "version": "1",
         "registry_state": "listed", "scanned_at": "2026-09-19T00:00:00+00:00"},
        {**_report("ai.c/three"), **contract, "version": "1",
         "registry_state": "listed", "scanned_at": "2026-09-19T00:00:00+00:00"},
    ]
    (tmp_path / "scans.json").write_text(json.dumps(previous))


def test_a_moved_registry_entry_is_scanned_first_then_the_oldest_page(
    driver, tmp_path: Path
) -> None:
    """The deadline cuts the END of the queue, so the order is what decides
    which pages wait: a new version first (its page shows code nobody installs
    now), then the oldest scan, so a page the last run could not measure keeps
    its old date and is tried again first."""
    run, state = driver
    _three_pins_one_moved(state, tmp_path)

    code, _ = run()

    assert code == 0
    assert state["calls"] == ["ai.c/three", "ai.a/one", "ai.b/two"]


def test_past_the_deadline_a_publishable_page_waits_and_a_moved_one_does_not(
    driver, monkeypatch, capsys, tmp_path: Path
) -> None:
    """A page the night did not reach keeps its page as published — own date,
    no `stale` label — carries no stamp of this run, and is not among the rows
    the night is judged on. But the deadline passes by only a page that is
    publishable as it stands: `ai.c/three`'s registry version moved, so its
    page would state the old one unlabelled, and it is scanned past the
    deadline, as is a growth candidate with no page to fall back on."""
    import ops.scan_cohort as sc

    from mcpwatchman.cohort import checked_this_run

    run, state = driver
    _three_pins_one_moved(state, tmp_path)
    before = {r["name"]: r for r in json.loads((tmp_path / "scans.json").read_text())}
    state["entries"]["ai.d/four"] = RegistryEntry(
        name="ai.d/four", version="1", is_latest=True,
        repository=Repository(url="https://github.com/d/four", source="github"),
    )
    state["reports"]["ai.d/four"] = _report("ai.d/four")
    monkeypatch.setattr(sc, "SCAN_DEADLINE_SECONDS", -1)

    code, written = run("--adopt-file", str(_adopt(tmp_path, "ai.d/four")))

    assert code == 0, "a night that stops at its deadline publishes what it reached"
    assert state["calls"] == ["ai.d/four", "ai.c/three"]
    rows = {r["name"]: r for r in json.loads(written)}
    for name in ("ai.a/one", "ai.b/two"):
        assert rows[name] == before[name], f"{name} must pass through exactly as published"
    judged = {r["name"] for r in checked_this_run(rows.values())}
    assert judged == {"ai.c/three", "ai.d/four"}
    out = capsys.readouterr().out
    assert "deadline: 2 pins not reached" in out
    assert "2 not reached" in out


@pytest.mark.parametrize(
    "page_change",
    [
        {"methodology_version": "0.1.0"},  # another scoring contract
        {"axes": {"code_safety": {"score": None, "fault": "environment",
                                  "reason": "our tool did not run"}}},  # refused tonight
        {"registry_state": "deprecated", "registry_note": "the registry calls it deprecated"},
    ],
    ids=["off-contract", "unpublishable", "status-moved"],
)
def test_the_deadline_never_passes_by_a_page_that_cannot_be_published_as_it_stands(
    driver, monkeypatch, tmp_path: Path, page_change: dict
) -> None:
    """Passed through, each of these would be refused by a publication gate
    (every night, since a refused night commits nothing and the next one starts
    from the same pages) or would state something the registry no longer says."""
    import ops.scan_cohort as sc

    run, state = driver
    _three_pins_one_moved(state, tmp_path)
    pages = json.loads((tmp_path / "scans.json").read_text())
    pages[0] = {**pages[0], **page_change}  # ai.a/one
    (tmp_path / "scans.json").write_text(json.dumps(pages))
    monkeypatch.setattr(sc, "SCAN_DEADLINE_SECONDS", -1)

    code, _ = run()

    assert code == 0
    assert "ai.a/one" in state["calls"]
    assert "ai.b/two" not in state["calls"]


def test_a_night_that_reaches_almost_none_of_its_pins_is_refused(
    driver, monkeypatch, capsys, tmp_path: Path
) -> None:
    """The file such a night writes is last night's and as publishable as it
    was, so no gate on the file can see it; before the deadline existed the
    unit's timeout failed it. Exit 3, the systemic code, and nothing written."""
    import ops.scan_cohort as sc

    run, state = driver
    _three_pins_one_moved(state, tmp_path)
    state["entries"]["ai.c/three"] = RegistryEntry(name="ai.c/three", version="1", is_latest=True)
    before = (tmp_path / "scans.json").read_text()
    monkeypatch.setattr(sc, "SCAN_DEADLINE_SECONDS", -1)

    code, written = run()

    assert code == 3
    assert state["calls"] == []
    assert written == before, "nothing written"
    assert "reached 0 of 3 pins" in capsys.readouterr().err


def _adopt(tmp_path: Path, *names: str) -> Path:
    path = tmp_path / "adopt.txt"
    path.write_text("\n".join(names) + "\n")
    return path


def test_every_row_the_run_looked_at_carries_its_stamp_kept_ones_included(
    driver, tmp_path: Path
) -> None:
    """`cohort.checked_this_run` judges the night on the rows stamped with its
    start, so a page this run tried and could not measure must carry the stamp
    too — else a broken night would drop its own failures from the count."""
    run, state = driver
    _three_pins_one_moved(state, tmp_path)
    state["raises"] = {"ai.b/two"}

    code, written = run()

    assert code == 0
    rows = {r["name"]: r for r in json.loads(written)}
    stamps = {r.get("checked_at") for r in rows.values()}
    assert len(stamps) == 1 and None not in stamps, stamps
    assert rows["ai.b/two"]["registry_state"] == "stale"
    from mcpwatchman.cohort import checked_this_run

    assert len(checked_this_run(rows.values())) == 3


def test_the_deadline_leaves_the_unit_time_to_publish() -> None:
    """The unit kills the night at `TimeoutStartSec`, and a killed night
    publishes nothing. The deadline only stops scans STARTING: the last one
    started can run every tool to its budget — fetch, secrets, semgrep, then a
    supplementary repository's fetch and semgrep, osv-scanner — and an our-side
    timeout is retried once. Then the gates, build, commit and deploy."""
    import re

    import ops.scan_cohort as sc

    from mcpwatchman.workers.scanner.auth_check import SECRET_SCAN_TIMEOUT
    from mcpwatchman.workers.scanner.osv_check import OSV_TIMEOUT_S
    from mcpwatchman.workers.scanner.semgrep_check import SEMGREP_TIMEOUT_S
    from mcpwatchman.workers.scanner.source import FETCH_TIMEOUT_S

    unit = (Path(__file__).resolve().parents[1] / "ops" / "systemd"
            / "mcpwatchman-nightly.service").read_text()
    hours = int(re.search(r"^TimeoutStartSec=(\d+)h$", unit, re.M).group(1))  # type: ignore[union-attr]
    one_attempt = (2 * FETCH_TIMEOUT_S + SECRET_SCAN_TIMEOUT + 2 * SEMGREP_TIMEOUT_S
                   + OSV_TIMEOUT_S)
    before_and_after_the_scan = 15 * 60
    assert (sc.SCAN_DEADLINE_SECONDS + 2 * one_attempt + before_and_after_the_scan
            <= hours * 3600)
