"""Which repository tree a report read, and where a pinned commit goes.

A report reads at most one repository — the source itself, or the declared
repository Code Safety falls back to for a build-output-only package — so one
`repository_commit` field is unambiguous, and a calibration pin has exactly
one place to go. These pin that routing, not git (`test_source.py` does git).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_registry import make_raw

from mcpwatchman.workers.crawler.registry import SourceKind, parse_entry
from mcpwatchman.workers.scanner import runner
from mcpwatchman.workers.scanner.inventory import Inventory
from mcpwatchman.workers.scanner.semgrep_check import (
    SemgrepResult,
    SemgrepStatus,
    assess_code_safety,
)
from mcpwatchman.workers.scanner.source import FetchResult, SourceSpec

PIN = "a" * 40
READ = "b" * 40
REPO = {"repository": {"url": "https://github.com/acme/server"}}
NPM = {"packages": [{"registryType": "npm", "identifier": "pkg", "version": "1.0.0"}]}


def _route(monkeypatch, tmp_path, raw) -> tuple[list[tuple[SourceKind, str | None]], dict]:
    fetches: list[tuple[SourceKind, str | None]] = []

    def fetch(spec: SourceSpec, workspace: Path, *, commit: str | None = None) -> FetchResult:
        fetches.append((spec.kind, commit))
        git = spec.kind in (SourceKind.GITHUB, SourceKind.GITLAB)
        return FetchResult(
            spec=spec, root=workspace, scan_root=workspace, bytes_on_disk=0,
            file_count=0, commit=(commit or READ) if git else None,
        )

    assembled: dict = {}

    def assemble(*args, **kwargs):
        assembled.update(kwargs)
        return None

    monkeypatch.setattr(runner, "fetch", fetch)
    monkeypatch.setattr(runner, "_assemble", assemble)
    runner.scan_entry(parse_entry(raw), tmp_path, commit=PIN)
    return fetches, assembled


def test_a_pin_on_a_repository_source_pins_that_fetch(monkeypatch, tmp_path) -> None:
    fetches, assembled = _route(monkeypatch, tmp_path, make_raw(**REPO))
    assert fetches == [(SourceKind.GITHUB, PIN)]
    assert assembled["repository_commit"] == PIN
    assert assembled["supplement_pin"] is None


def test_a_pin_on_a_package_source_waits_for_the_supplement(monkeypatch, tmp_path) -> None:
    """A package is pinned by its version; the pin names the declared
    repository, which only the Code Safety fallback reads."""
    fetches, assembled = _route(monkeypatch, tmp_path, make_raw(**NPM, **REPO))
    assert fetches == [(SourceKind.NPM, None)]
    assert assembled["repository_commit"] is None
    assert assembled["supplement_pin"] == PIN


@pytest.fixture
def build_output_only() -> SemgrepResult:
    return assess_code_safety(Path("/nonexistent"), Inventory(build_output={"javascript": 2}))


def _supplement(monkeypatch, *, ref_matched: bool | None) -> None:
    def fetch(spec, workspace, *, commit=None):
        root = workspace / "src"
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "src" / "index.ts").write_text("export {}")
        return FetchResult(
            spec=spec, root=root, scan_root=root, bytes_on_disk=0, file_count=1,
            ref_matched_version=None if commit else ref_matched, commit=commit or READ,
        )

    monkeypatch.setattr(runner, "fetch", fetch)
    monkeypatch.setattr(
        runner, "assess_code_safety",
        lambda root, inv, version: SemgrepResult(status=SemgrepStatus.OK, score=90),
    )


def test_the_supplement_reports_the_commit_it_read(monkeypatch, tmp_path, build_output_only):
    _supplement(monkeypatch, ref_matched=False)
    _, note, read = runner._code_from_supplement(
        build_output_only, "github:acme/server@1.0.0", tmp_path, "0.2.0",
    )
    assert read == READ
    assert "default branch was read" in note


def test_a_pinned_supplement_says_commit_not_version(monkeypatch, tmp_path, build_output_only):
    """The version was never resolved, so "at version 1.0.0" would be false —
    and so would the branch-tip warning: a pin is not a moving tip."""
    _supplement(monkeypatch, ref_matched=False)
    _, note, read = runner._code_from_supplement(
        build_output_only, "github:acme/server@1.0.0", tmp_path, "0.2.0", commit=PIN,
    )
    assert read == PIN
    assert note.startswith(f"scored on the declared repository at commit {PIN}")
    assert "at version" not in note and "default branch" not in note


def test_the_commit_is_published_with_the_report() -> None:
    report = runner.ServerReport(
        name="a/b", version="1", slug="a-b", scanned_at="2026-09-30T00:00:00+00:00",
        methodology_version="0.2.0", repository_commit=READ,
    )
    assert report.to_dict()["repository_commit"] == READ


def test_an_unrecorded_tag_answer_is_never_worded_as_a_match(
    monkeypatch, tmp_path, build_output_only
):
    """None is "nobody checked": the note must not say "at version", which
    claims a tag resolved. The default-branch wording claims nothing unearned."""
    _supplement(monkeypatch, ref_matched=None)
    _, note, _ = runner._code_from_supplement(
        build_output_only, "github:acme/server@1.0.0", tmp_path, "0.2.0",
    )
    assert "at version" not in note and "default branch was read" in note
