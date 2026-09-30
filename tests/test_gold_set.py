"""The gold set's format, and the gate that stops calibration being declared early.

`03` §3 defines the confidence tiers as false-positive rates MEASURED on the
gold set, and `03` §8 withholds the composite until it is calibrated. So the
flags that unlock both are claims about this directory, and this file is what
keeps them honest: neither may be set while fewer than `MIN_RATIFIED_ENTRIES`
entries are ratified — and a draft, however complete, is never ratified.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpwatchman import goldset as gs
from mcpwatchman.workers.scoring import weights

REPO = Path(__file__).resolve().parents[1]

ENTRY = """+++
name = "io.example/tool"
version = "1.2.0"
category = "filesystem"
status = "{status}"
audited_by = "a subagent — draft"
audited_on = "2026-09-29"
ratified_by = "{ratified_by}"
ratified_on = "{ratified_on}"

[expected]
composite = [60, 75]

[expected.axes]
code_safety = [85, 100]
auth_posture = [40, 60]
dependency_health = [50, 80]
maintenance = [60, 80]
transparency = [40, 60]

[[findings]]
rule = "mcp-js-ssrf-nonliteral-url"
path = "src/fetch.ts"
line = 33
label = "fp"
why = "the URL is validated against an allowlist on line 30"
+++
## Notes
"""


def entry(status="draft", ratified_by="", ratified_on="") -> str:
    return ENTRY.format(status=status, ratified_by=ratified_by, ratified_on=ratified_on)


def in_range() -> dict:
    """A report scoring every axis inside the fixture's expected range."""
    scores = {"code_safety": 90, "auth_posture": 50, "dependency_health": 60,
              "maintenance": 70, "transparency": 50}
    return {a: {"score": v} for a, v in scores.items()}


def test_a_draft_parses_and_is_not_ratified() -> None:
    e = gs.parse(entry())
    assert e.expected_axes["code_safety"] == (85, 100)
    assert e.findings[0].label == "fp"
    assert not e.ratified


def test_ratified_requires_a_name_and_a_date() -> None:
    with pytest.raises(gs.GoldSetError, match="names who ratified"):
        gs.parse(entry(status="ratified"))
    assert gs.parse(entry("ratified", "kVadrum", "2026-10-01")).ratified


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('transparency = [40, 60]\n', "", "exactly the five axes"),
        ('label = "fp"', 'label = "maybe"', "'tp' or 'fp'"),
        ('why = "the URL is validated against an allowlist on line 30"', 'why = ""', "unexplained"),
        ("code_safety = [85, 100]", 'code_safety = "unassessed"', "needs all five"),
        ("code_safety = [85, 100]", "code_safety = [100, 85]", "within 0..100"),
    ],
)
def test_an_entry_that_is_not_an_audit_is_refused(old, new, message) -> None:
    text = entry()
    assert old in text
    with pytest.raises(gs.GoldSetError, match=message):
        gs.parse(text.replace(old, new))


def test_drift_is_judged_at_the_tolerance_boundary() -> None:
    """`09` §5: ±8 per axis, ±5 composite — asserted at the edge, not the middle."""
    e = gs.parse(entry())
    axes = in_range()
    assert gs.compare(e, {"axes": axes}, composite=70) == []
    axes["code_safety"] = {"score": 77}           # 85 - 8: inside
    axes["auth_posture"] = {"score": 69}          # 60 + 8 = 68: outside by one
    drift = gs.compare(e, {"axes": axes}, composite=80)   # 75 + 5: inside
    assert drift == ["auth_posture: expected 40–60 (±8), scored 69"]
    assert "composite" in gs.compare(e, {"axes": axes}, composite=81)[-1]


def test_an_expected_unassessed_axis_must_stay_unassessed() -> None:
    e = gs.parse(
        entry()
        .replace("dependency_health = [50, 80]", 'dependency_health = "unassessed"')
        .replace("composite = [60, 75]", 'composite = "unassessed"')
    )
    assert gs.compare(e, {"axes": in_range()}, None) == [
        "dependency_health: expected unassessed, scored 60"
    ]


@pytest.mark.parametrize(
    ("fp", "total", "tier"),
    [(0, 9, "unmeasured"), (0, 10, "high"), (1, 20, "medium"), (1, 21, "high"),
     (3, 20, "medium"), (4, 20, "low")],
)
def test_measured_tier_boundaries(fp, total, tier) -> None:
    """5% and 20% are strict (`03` §3 says "<"), and too few labels is no rate."""
    assert gs.measured_tier(fp, total) == tier


def test_only_ratified_entries_live_in_the_tracked_directory() -> None:
    """A draft committed to `evals/gold-set/` would read as a hand audit to
    anyone browsing the repository, and could carry an unembargoed finding."""
    for path in gs.entry_files(gs.DEFAULT_ROOT):
        entry_ = gs.load(path)
        assert entry_.ratified, f"{path.name} is tracked but not ratified — keep it in drafts/"


def test_drafts_and_private_notes_can_never_be_committed() -> None:
    ignored = (REPO / ".gitignore").read_text().splitlines()
    assert "evals/gold-set/drafts/" in ignored
    assert "evals/gold-set/private/" in ignored


def test_calibration_cannot_be_declared_on_too_few_ratified_entries() -> None:
    """The gate. Flipping either flag asserts a measurement on the gold set;
    until the set exists, the flag is the mystery number `03` refuses."""
    declared = [
        name for name, table in (
            ("RULESET_CALIBRATED", weights.RULESET_CALIBRATED),
            ("COMPOSITE_PUBLISHED", weights.COMPOSITE_PUBLISHED),
        )
        if any(table.values())
    ]
    if declared:
        ratified = len(gs.ratified_entries())
        assert ratified >= gs.MIN_RATIFIED_ENTRIES, (
            f"{', '.join(declared)} set on {ratified} ratified gold-set entries; "
            f"calibration needs {gs.MIN_RATIFIED_ENTRIES}"
        )


def test_the_calibration_gate_fires(monkeypatch) -> None:
    """The positive control for the test above: flip the flag with an empty
    gold set and the gate must refuse."""
    monkeypatch.setitem(weights.RULESET_CALIBRATED, "0.2.0", True)
    with pytest.raises(AssertionError, match="calibration needs"):
        test_calibration_cannot_be_declared_on_too_few_ratified_entries()


def _report(*findings: tuple[str, str, int], omitted: int = 0) -> dict:
    return {"axes": {"code_safety": {
        "score": 80,
        "evidence": [{"label": f"{r} (critical/medium)", "path": p, "line": n}
                     for r, p, n in findings],
        "evidence_omitted": omitted,
    }}}


def test_labels_reconcile_against_what_the_scanner_reports_now() -> None:
    """A label is about ONE finding. If the scanner no longer reports it — the
    rule was fixed, the code moved — the label is stale and may not count
    toward a rule's measured rate (Codex leg of this file's /qaa)."""
    e = gs.parse(entry())  # labels mcp-js-ssrf-nonliteral-url src/fetch.ts:33 as fp
    same = gs.reconcile(e, _report(("mcp-js-ssrf-nonliteral-url", "src/fetch.ts", 33)))
    assert len(same.matched) == 1 and not same.stale and not same.unlabeled

    moved = gs.reconcile(e, _report(("mcp-js-ssrf-nonliteral-url", "src/fetch.ts", 40)))
    assert not moved.matched and len(moved.stale) == 1 and not moved.unverifiable
    assert moved.unlabeled == (("mcp-js-ssrf-nonliteral-url", "src/fetch.ts", 40),)


def test_a_label_missing_from_a_capped_list_is_unverifiable_not_stale() -> None:
    """The published evidence keeps the worst 50 findings. A labelled finding
    that fell past the cap is still reported by the scanner, so calling it
    stale would be a bounded look asserting an absence (CLAUDE.md)."""
    e = gs.parse(entry())
    rec = gs.reconcile(e, _report(("mcp-js-ssrf-nonliteral-url", "src/other.ts", 1), omitted=12))
    assert not rec.stale and not rec.matched
    assert [f.path for f in rec.unverifiable] == ["src/fetch.ts"]
    assert "capped" in rec.unverifiable_reason


def test_labels_on_an_unassessed_axis_are_unverifiable_not_stale() -> None:
    """Code Safety not assessed means nothing was looked for, so no label's
    finding can be said to be gone."""
    e = gs.parse(entry())
    report = {"axes": {"code_safety": {
        "score": None, "reason": "no source files", "evidence": [], "evidence_omitted": 0,
    }}}
    rec = gs.reconcile(e, report)
    assert not rec.stale and not rec.matched
    assert len(rec.unverifiable) == len(e.findings) == 1
    assert "not assessed" in rec.unverifiable_reason


def _with_commit(value: str) -> str:
    return entry().replace('version = "1.2.0"\n', f'version = "1.2.0"\ncommit = {value}\n', 1)


def test_an_entry_pins_the_commit_its_audit_read() -> None:
    """Labels and ranges describe ONE tree; a tag can move and a branch tip
    always does. Absent is allowed — a package-sourced server reads no
    repository — and calibration refuses a repository read without a pin."""
    assert gs.parse(entry()).commit is None
    full = "0123456789abcdef" * 2 + "01234567"
    assert gs.parse(_with_commit(f'"{full}"')).commit == full


@pytest.mark.parametrize("bad", ['"0123abc"', '"' + "A" * 40 + '"', '"-' + "0" * 39 + '"', "40"])
def test_a_commit_pin_is_a_full_lowercase_object_name(bad: str) -> None:
    """A prefix can resolve to a different commit tomorrow; the fetcher refuses
    what this refuses (one rule, `mcpwatchman.workers.commits`)."""
    with pytest.raises(gs.GoldSetError, match="full lowercase commit id"):
        gs.parse(_with_commit(bad))
