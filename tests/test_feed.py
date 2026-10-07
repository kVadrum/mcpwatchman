"""When a finding first appeared (`mcpwatchman.feed`) — what the Atom feed reads.

The two failures worth a test each: announcing a baseline as news (every finding
on every page, the day tracking starts or a server is grown), and losing a
finding's date when an unrelated edit moves its line.
"""

from __future__ import annotations

import copy

from mcpwatchman.feed import TRACKED_SINCE, feed_items, stamp_first_seen


def _finding(rule: str, path: str = "src/a.ts", line: int = 1, severity: str = "critical",
             first_seen: str | None = None) -> dict:
    return {"label": f"{rule} ({severity}/medium)", "detail": "", "path": path,
            "line": line, "excerpt": "", "url": "", "finding": rule,
            "severity": severity, "first_seen": first_seen}


def _prose(label: str = "transport_security") -> dict:
    return {"label": label, "detail": "scored 80", "path": "", "line": 0,
            "excerpt": "", "url": "", "finding": "", "severity": "", "first_seen": None}


def _report(*findings: dict, tracked: str | None = None, slug: str = "s",
            omitted: int = 0, score: int | None = 50, scanner: str = "0.38.1",
            ruleset: str = "0.1.1") -> dict:
    report = {"name": slug, "slug": slug, "scanner_version": scanner,
              "ruleset_version": ruleset, "axes": {
        "code_safety": {"evidence": list(findings), "score": score,
                        "evidence_omitted": omitted},
        "auth_posture": {"evidence": [_prose()], "score": 80, "evidence_omitted": 0},
    }}
    if tracked:
        report[TRACKED_SINCE] = tracked
    return report


def _items(report: dict) -> list[dict]:
    return report["axes"]["code_safety"]["evidence"]


def test_a_page_first_published_is_a_baseline_not_news() -> None:
    stamped = stamp_first_seen(None, _report(_finding("r1")), "2026-10-08")
    assert stamped[TRACKED_SINCE] == "2026-10-08"
    assert _items(stamped)[0]["first_seen"] is None


def test_tracking_starts_quietly_on_a_page_published_before_it_existed() -> None:
    """The day this ships, every previous report predates the stamp. Announcing
    their findings would put the whole cohort in the feed at once."""
    previous = _report(_finding("r1"))  # no TRACKED_SINCE
    stamped = stamp_first_seen(previous, _report(_finding("r1"), _finding("r2")),
                               "2026-10-08")
    assert [i["first_seen"] for i in _items(stamped)] == [None, None]
    assert stamped[TRACKED_SINCE] == "2026-10-08"


def test_a_finding_the_previous_tracked_report_lacked_is_dated_today() -> None:
    previous = _report(_finding("r1"), tracked="2026-10-08")
    stamped = stamp_first_seen(previous, _report(_finding("r1"), _finding("r2")),
                               "2026-10-09")
    assert [i["first_seen"] for i in _items(stamped)] == [None, "2026-10-09"]
    assert stamped[TRACKED_SINCE] == "2026-10-08"


def test_a_date_survives_every_later_run() -> None:
    previous = _report(_finding("r2", first_seen="2026-10-09"), tracked="2026-10-08")
    stamped = stamp_first_seen(previous, _report(_finding("r2")), "2026-10-20")
    assert _items(stamped)[0]["first_seen"] == "2026-10-09"


def test_a_moved_line_is_the_same_finding_but_a_new_file_is_not() -> None:
    previous = _report(_finding("r1", line=10, first_seen="2026-10-09"),
                       tracked="2026-10-08")
    current = _report(_finding("r1", line=42), _finding("r1", path="src/b.ts"))
    stamped = stamp_first_seen(previous, current, "2026-10-10")
    assert [i["first_seen"] for i in _items(stamped)] == ["2026-10-09", "2026-10-10"]


def test_sub_check_prose_is_never_stamped_and_inputs_are_not_modified() -> None:
    previous = _report(tracked="2026-10-08")
    current = _report(_finding("r1"))
    before = copy.deepcopy((previous, current))
    stamped = stamp_first_seen(previous, current, "2026-10-09")
    assert stamped["axes"]["auth_posture"]["evidence"][0]["first_seen"] is None
    assert (previous, current) == before


def test_the_feed_takes_dated_high_and_critical_findings_newest_first() -> None:
    reports = [
        _report(_finding("old", first_seen="2026-10-09"),
                _finding("medium", severity="medium", first_seen="2026-10-12"),
                _finding("baseline"), slug="a"),
        _report(_finding("new", severity="high", first_seen="2026-10-11"), slug="b"),
    ]
    assert [(r["slug"], i["finding"]) for r, _, i in feed_items(reports)] == [
        ("b", "new"), ("a", "old"),
    ]


def test_a_finding_the_cap_hid_last_night_is_not_news() -> None:
    """On a server showing 50 of 4,659, fixing a shown critical lets a hidden
    one surface — announced as new on the day the server got safer."""
    previous = _report(_finding("shown"), tracked="2026-10-08", omitted=4609)
    stamped = stamp_first_seen(previous, _report(_finding("shown"), _finding("was-hidden")),
                               "2026-10-09")
    assert [i["first_seen"] for i in _items(stamped)] == [None, None]


def test_an_unscored_axis_last_night_showed_nothing_to_compare() -> None:
    previous = _report(tracked="2026-10-08", score=None)
    stamped = stamp_first_seen(previous, _report(_finding("r1")), "2026-10-09")
    assert _items(stamped)[0]["first_seen"] is None


def test_a_scanner_or_ruleset_release_is_not_the_server_changing() -> None:
    previous = _report(_finding("old", first_seen="2026-10-05"), tracked="2026-10-01")
    for change in ({"scanner": "0.39.0"}, {"ruleset": "0.2.0"}):
        stamped = stamp_first_seen(previous, _report(_finding("old"), _finding("new-rule"),
                                                     **change), "2026-10-09")
        # The known date survives; the newly detected finding is baseline.
        assert [i["first_seen"] for i in _items(stamped)] == ["2026-10-05", None]


def test_two_hits_of_one_rule_in_one_file_are_one_feed_entry() -> None:
    report = _report(_finding("r", line=1, first_seen="2026-10-09"),
                     _finding("r", line=9, first_seen="2026-10-09"))
    assert len(feed_items([report])) == 1
