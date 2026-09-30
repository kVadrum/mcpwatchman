"""`ops/calibrate.py`: what it may say about an entry it could not measure.

Its exit codes are a contract — 1 is drift, 2 is ours — so an our-side failure
that reached the default exit 1 would read as evidence against the methodology.
"""

from __future__ import annotations

import io
import json
import urllib.error

import ops.calibrate as cal
import pytest


def _page(*servers: tuple[str, str], cursor: str | None = None) -> io.BytesIO:
    body = {
        "servers": [{"server": {"name": n, "version": v}} for n, v in servers],
        "metadata": {"nextCursor": cursor} if cursor else {},
    }
    return io.BytesIO(json.dumps(body).encode())


def _serve(monkeypatch, pages: list[io.BytesIO]) -> list[str]:
    urls: list[str] = []

    def urlopen(url, timeout):
        urls.append(url)
        return pages.pop(0)

    monkeypatch.setattr(cal.urllib.request, "urlopen", urlopen)
    return urls


def test_the_search_follows_its_cursor_to_the_entry(monkeypatch) -> None:
    urls = _serve(monkeypatch, [
        _page(("a/x", "1.0"), cursor="c1"),
        _page(("a/x", "2.0")),
    ])
    found, why = cal.registry_entry("a/x", "2.0")
    assert found is not None and found.version == "2.0" and why == ""
    assert "cursor=c1" in urls[1]


def test_an_exhausted_search_may_say_absent(monkeypatch) -> None:
    _serve(monkeypatch, [_page(("a/x", "1.0"))])
    found, why = cal.registry_entry("a/x", "2.0")
    assert found is None and why == "is not in the registry"


def test_a_search_stopped_at_our_bound_does_not_say_absent(monkeypatch) -> None:
    monkeypatch.setattr(cal, "SEARCH_MAX_PAGES", 2)
    _serve(monkeypatch, [_page(("a/x", "1.0"), cursor="c1"), _page(("a/x", "1.1"), cursor="c2")])
    found, why = cal.registry_entry("a/x", "2.0")
    assert found is None
    assert "not in the registry" not in why and "first 2 pages" in why


@pytest.mark.parametrize("error", [
    urllib.error.URLError("dns"), TimeoutError("slow"), json.JSONDecodeError("x", "", 0),
])
def test_a_registry_outage_is_ours_not_drift(monkeypatch, tmp_path, capsys, error) -> None:
    entry = cal.GoldEntry(
        name="a/x", version="1.0", category="c", status="draft", audited_by="",
        audited_on="", ratified_by="", ratified_on="", expected_composite=None,
        expected_axes={},
    )
    monkeypatch.setattr(cal, "preflight", lambda: [])
    monkeypatch.setattr(cal, "entry_files", lambda *_a, **_k: [tmp_path / "e.md"])
    monkeypatch.setattr(cal, "load", lambda _p: entry)

    def down(_name, _version):
        raise error

    monkeypatch.setattr(cal, "registry_entry", down)
    monkeypatch.setattr("sys.argv", ["calibrate"])
    assert cal.main() == 2
    assert "the registry could not be read" in capsys.readouterr().out


def _entry(status: str, version: str = "1.0") -> cal.GoldEntry:
    return cal.GoldEntry(
        name="a/x", version=version, category="c", status=status, audited_by="a",
        audited_on="2026-09-29", ratified_by="op" if status == "ratified" else "",
        ratified_on="2026-09-30" if status == "ratified" else "",
        expected_composite=None, expected_axes={},
    )


def test_a_draft_cannot_block_a_ratified_verdict(monkeypatch, tmp_path, capsys) -> None:
    """Drafts are preview-only. A draft of a server that also has a ratified
    entry used to share its NAME with it, so the draft's drift entered the
    ratified blocking set (Codex leg of this file's /qaa)."""
    ratified, draft = _entry("ratified"), _entry("draft", "2.0")
    assert ratified.ratified and not draft.ratified
    files = {tmp_path / "r.md": ratified, tmp_path / "d.md": draft}

    class _Report:
        def to_dict(self):
            axes = {a: {"score": 50, "reason": "", "evidence": []} for a in cal.AXES}
            return {"axes": axes, "ref_matched_version": True}

    monkeypatch.setattr(cal, "MIN_RATIFIED_ENTRIES", 1)
    monkeypatch.setattr(cal, "preflight", lambda: [])
    monkeypatch.setattr(cal, "entry_files", lambda *_a, **_k: list(files))
    monkeypatch.setattr(cal, "load", files.__getitem__)
    monkeypatch.setattr(cal, "registry_entry", lambda n, v: (object(), ""))
    monkeypatch.setattr(cal, "scan_entry", lambda _e, **_k: _Report())
    monkeypatch.setattr(cal, "unpublishable_gaps", lambda _n, _r: [])
    monkeypatch.setattr(
        cal, "compare", lambda e, _r, _c: [] if e.ratified else ["the draft drifted"],
    )
    monkeypatch.setattr("sys.argv", ["calibrate", "--include-drafts"])

    assert cal.main() == 1  # the draft's drift is still listed
    assert "Calibration may be declared." in capsys.readouterr().out


def test_a_supplement_read_at_a_branch_tip_is_noticed() -> None:
    """The top-level flag describes the PACKAGE fetch; a build-output-only
    package scored on its repository's default branch says so only on the
    Code Safety axis."""
    from mcpwatchman.workers.scanner.runner import SUPPLEMENT_BRANCH_TIP

    def report(flag, reason):
        return {"ref_matched_version": flag, "axes": {"code_safety": {"reason": reason}}}

    assert cal.read_at_branch_tip(report(False, ""))
    assert cal.read_at_branch_tip(report(None, f"scored on the repo; {SUPPLEMENT_BRANCH_TIP}"))
    assert not cal.read_at_branch_tip(report(None, "scored on the declared repository at 1.0"))
    assert not cal.read_at_branch_tip(report(True, ""))
