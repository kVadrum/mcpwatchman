"""Code Safety from the declared repository, when the package ships only build output.

`04` §2: the repository supplements the published package "for rules that
benefit from full file context not present in a published tarball". An npm
package holding nothing but `dist/` is that case — and before this path
existed, 90 of 492 published servers carried "no source files in a language
the ruleset covers" attributed to the PUBLISHER, about npm packages whose
compiled code is exactly what a user installs (measured 2026-09-29).

Each test pins one outcome and, above all, WHOSE gap it is: the package's own
result is already ours (`PROJECT`), so a failure of the fallback may keep it
ours or make it this run's accident (`ENVIRONMENT`) — never theirs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpwatchman.workers.scanner import runner
from mcpwatchman.workers.scanner.inventory import Inventory
from mcpwatchman.workers.scanner.reachability import Fault
from mcpwatchman.workers.scanner.semgrep_check import (
    SemgrepResult,
    SemgrepStatus,
    assess_code_safety,
)
from mcpwatchman.workers.scanner.source import (
    FetchError,
    FetchResult,
    SourceSpec,
    SourceUnreachableError,
)

SUPPLEMENT = "github:acme/tools@0.1.1#packages/server"


@pytest.fixture
def package_result() -> SemgrepResult:
    result = assess_code_safety(Path("/nonexistent"), Inventory(build_output={"javascript": 2}))
    assert result.build_output_only and result.fault is Fault.PROJECT
    return result


def _fake_fetch(monkeypatch, *, files: dict[str, str], ref_matched: bool | None = True):
    seen: list[Path] = []

    def fetch(spec: SourceSpec, workspace: Path, *, commit: str | None = None) -> FetchResult:
        seen.append(workspace)
        root = workspace / "src"
        for rel, body in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(body)
        root.mkdir(parents=True, exist_ok=True)
        return FetchResult(
            spec=spec, root=root, scan_root=root, bytes_on_disk=0,
            file_count=len(files), ref_matched_version=ref_matched,
            commit=commit or "c" * 40,
        )

    monkeypatch.setattr(runner, "fetch", fetch)
    return seen


def _raising_fetch(monkeypatch, exc: Exception) -> None:
    def fetch(spec, workspace, *, commit=None):
        raise exc

    monkeypatch.setattr(runner, "fetch", fetch)


def _scored(monkeypatch, score: int = 90) -> None:
    """semgrep is a workers-extra binary; stub the scan, not the attribution."""
    monkeypatch.setattr(
        runner, "assess_code_safety",
        lambda root, inv, version: SemgrepResult(
            status=SemgrepStatus.OK, score=score, files_scanned=3,
        ),
    )


def test_the_repository_scores_the_axis_and_the_page_says_so(
    tmp_path, monkeypatch, package_result
) -> None:
    seen = _fake_fetch(monkeypatch, files={"src/index.ts": "export {}"})
    _scored(monkeypatch)

    result, note, _ = runner._code_from_supplement(package_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert result.assessed and result.score == 90
    assert "declared repository at version 0.1.1" in note
    assert "build output" in note
    # Its own directory: the package's checkout under `src/` is not clobbered.
    assert seen == [tmp_path / "supplement"]


def test_a_default_branch_read_is_disclosed_on_the_axis(
    tmp_path, monkeypatch, package_result
) -> None:
    """The report's `ref_matched_version` describes the PACKAGE fetch, so a
    repository read at its default branch has to say so on the axis it scored,
    or the page publishes branch-tip findings under the release's number."""
    _fake_fetch(monkeypatch, files={"index.ts": "export {}"}, ref_matched=False)
    _scored(monkeypatch)

    _, note, _ = runner._code_from_supplement(package_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert "default branch" in note
    assert "not necessarily the release" in note
    assert "default branch was read" in note


def test_an_unreachable_repository_keeps_the_gap_ours(
    tmp_path, monkeypatch, package_result
) -> None:
    """The package's code existed and WE declined to read it; their repository
    being unreadable does not transfer that decision to them."""
    _raising_fetch(monkeypatch, SourceUnreachableError("404"))

    result, note, _ = runner._code_from_supplement(package_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert not result.assessed
    assert result.fault is Fault.PROJECT
    assert "could not be read" in result.reason
    assert note == ""


def test_our_own_fetch_failure_is_refused_not_published(
    tmp_path, monkeypatch, package_result
) -> None:
    """A timeout or a full disk is this run's accident: publication must refuse
    it, so a pinned page keeps its last good scan instead of this one."""
    _raising_fetch(monkeypatch, FetchError("timed out"))

    result, _, _ = runner._code_from_supplement(package_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert result.fault is Fault.ENVIRONMENT
    assert not result.fault.publishable


def test_a_repository_with_no_covered_source_either_stays_ours(
    tmp_path, monkeypatch, package_result
) -> None:
    """Real attribution, no stub: the repository holds only docs, so
    `assess_code_safety` returns before semgrep would run."""
    _fake_fetch(monkeypatch, files={"README.md": "# docs"})

    result, note, _ = runner._code_from_supplement(package_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert result.fault is Fault.PROJECT
    assert "no source in a covered language either" in result.reason
    assert note == ""


def test_the_source_note_leads_the_axis_reason() -> None:
    """Rendered on the page as the axis note, before the prune disclosure."""
    availability = runner.SourceAvailability(runner.SourceState.FETCHED, "")
    axis = runner._code_axis(
        SemgrepResult(status=SemgrepStatus.OK, score=80, pruned=2),
        availability,
        "scored on the declared repository at version 1.0.0",
    )
    assert axis.score == 80
    assert axis.reason.startswith("scored on the declared repository")
    assert "2 vendored or minified paths were excluded" in axis.reason


@pytest.fixture
def unfinished_result() -> SemgrepResult:
    result = assess_code_safety(
        Path("/nonexistent"), Inventory(build_output={}, build_output_truncated=True)
    )
    assert result.build_output_unfinished and not result.build_output_only
    assert result.fault is Fault.PROJECT
    return result


def test_the_repository_is_tried_for_an_unfinished_probe_too(
    package_result, unfinished_result
) -> None:
    """Build output our bounded look could not finish may hold the package's
    code, so the repository `04` §2 names as the supplement is tried for it as
    for build-output-only packages — and for nothing else."""
    assert runner._wants_supplement(package_result)
    assert runner._wants_supplement(unfinished_result)
    no_source = assess_code_safety(Path("/nonexistent"), Inventory())
    assert no_source.fault is Fault.PUBLISHER
    assert not runner._wants_supplement(no_source)


def test_an_unfinished_probe_scored_on_the_repository_says_why(
    tmp_path, monkeypatch, unfinished_result
) -> None:
    """The note must not say "only as build output": that asserts what the
    unread part of the build output holds."""
    _fake_fetch(monkeypatch, files={"src/index.ts": "export {}"})
    _scored(monkeypatch)

    result, note, _ = runner._code_from_supplement(unfinished_result, SUPPLEMENT, tmp_path, "0.2.0")

    assert result.assessed and result.score == 90
    assert note.startswith("scored on the declared repository at version 0.1.1")
    assert "stopped before it finished" in note
    assert "only as build output" not in note
