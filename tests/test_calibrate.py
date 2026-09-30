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


def _serve(monkeypatch, answer) -> list[str]:
    """urlopen answering every request with `answer` (bytes, or an exception)."""
    urls: list[str] = []

    def urlopen(url, timeout):
        urls.append(url)
        if isinstance(answer, Exception):
            raise answer
        return io.BytesIO(answer)

    monkeypatch.setattr(cal.urllib.request, "urlopen", urlopen)
    return urls


def _http(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("u", code, "m", {}, None)  # type: ignore[arg-type]


def test_the_lookup_asks_for_exactly_this_name_and_version(monkeypatch) -> None:
    """The exact endpoint: the search it replaced took 31 s a page and timed
    out on 16 of 30 entries (2026-09-30)."""
    urls = _serve(monkeypatch, json.dumps({"server": {"name": "a/x", "version": "2.0"}}).encode())
    found, why = cal.registry_entry("a/x", "2.0")
    assert found is not None and found.version == "2.0" and why == ""
    assert urls == [f"{cal.REGISTRY_BASE_URL}/v0/servers/a%2Fx/versions/2.0"]


def test_an_exact_404_may_say_absent(monkeypatch) -> None:
    _serve(monkeypatch, _http(404))
    assert cal.registry_entry("a/x", "2.0") == (None, "is not in the registry")


@pytest.mark.parametrize("error", [_http(500), _http(429), TimeoutError("slow")])
def test_any_other_failure_is_ours_and_raises(monkeypatch, error) -> None:
    """Only a 404 is an absence; a 500, a rate limit or a timeout must reach
    the caller, which reports the entry unmeasured (ours), never absent."""
    _serve(monkeypatch, error)
    with pytest.raises(type(error)):
        cal.registry_entry("a/x", "2.0")


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


def _pinned(commit: str | None) -> cal.GoldEntry:
    return cal.GoldEntry(
        name="a/x", version="1.0", category="c", status="draft", audited_by="a",
        audited_on="2026-09-29", ratified_by="", ratified_on="",
        expected_composite=None, expected_axes={}, commit=commit,
    )


A, B = "a" * 40, "b" * 40


@pytest.mark.parametrize("pin,read,refused", [
    (None, None, False),   # a package source: pinned by its version
    (A, A, False),         # measured at the audited tree
    (None, B, True),       # a repository read with no pin: the audited tree is unknown
    (A, B, True),          # the pin did not take
    (A, None, True),       # pinned, but no repository was read at all
])
def test_only_the_audited_tree_is_a_measurement(pin, read, refused) -> None:
    """Labels and ranges describe one tree. A scan of another is the code's
    movement, not evidence about the rules — and that includes an unpinned
    TAGGED read, because tags can be moved too."""
    problem = cal.pin_problem(_pinned(pin), {"repository_commit": read})
    assert bool(problem) is refused, problem


def test_calibration_scans_at_the_pin_and_refuses_an_unpinned_repository(
    monkeypatch, tmp_path, capsys
) -> None:
    """Driven through main(): the pin reaches the scan, a pinned entry is
    measured, and an entry whose scan read a repository without a pin is
    unmeasured (exit 2) — never scored against a tree nobody audited."""
    pinned, unpinned = _pinned(A), cal.GoldEntry(**{
        **{f: getattr(_pinned(None), f) for f in ("name", "category", "status", "audited_by",
           "audited_on", "ratified_by", "ratified_on", "expected_composite")},
        "version": "2.0", "expected_axes": {},
    })
    files = {tmp_path / "p.md": pinned, tmp_path / "u.md": unpinned}
    asked: list[str | None] = []

    class _Report:
        def __init__(self, commit):
            self.commit = commit

        def to_dict(self):
            axes = {a: {"score": 50, "reason": "", "evidence": []} for a in cal.AXES}
            return {"axes": axes, "repository_commit": self.commit or B}

    def scan(_found, *, evidence_cap, commit):
        asked.append(commit)
        return _Report(commit)

    monkeypatch.setattr(cal, "preflight", lambda: [])
    monkeypatch.setattr(cal, "entry_files", lambda *_a, **_k: list(files))
    monkeypatch.setattr(cal, "load", files.__getitem__)
    monkeypatch.setattr(cal, "registry_entry", lambda n, v: (object(), ""))
    monkeypatch.setattr(cal, "scan_entry", scan)
    monkeypatch.setattr(cal, "unpublishable_gaps", lambda _n, _r: [])
    monkeypatch.setattr(cal, "compare", lambda *_a: [])
    monkeypatch.setattr("sys.argv", ["calibrate", "--include-drafts"])

    assert cal.main() == 2
    out = capsys.readouterr().out
    assert asked == [A, None]
    assert "[ok   ] a/x" in out
    assert "pins no commit" in out
