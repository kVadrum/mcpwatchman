"""npm install hooks: listed Code Safety evidence that never moves a score."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner import install_scripts as ins
from mcpwatchman.workers.scanner.inventory import enumerate_tree


def _tree(tmp_path: Path, manifests: dict[str, object]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "index.js").write_text("module.exports = 1;\n")
    for rel, body in manifests.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body if isinstance(body, str) else json.dumps(body, indent=2))
    return root


def _findings(root: Path) -> list:
    return ins.install_script_findings(root, enumerate_tree(root))


def test_each_install_hook_is_listed_and_prepare_is_not(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"package.json": {"name": "x", "scripts": {
        "preinstall": "node check.js", "postinstall": "node-gyp rebuild",
        "prepare": "npm run build", "build": "tsc"}}})
    found = _findings(root)
    assert [(f.excerpt.split(":")[0], f.listed, f.deducts) for f in found] == [
        ('"preinstall"', True, False), ('"postinstall"', True, False)]
    assert all(f.rule_id == ins.RULE_ID and f.path == "package.json" for f in found)
    assert found[1].line == 5 and "node-gyp rebuild" in found[1].excerpt


def test_a_manifest_under_test_code_is_marked_as_test(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"tests/fixtures/pkg/package.json": {"scripts": {"install": "x"}}})
    (only,) = _findings(root)
    assert only.in_test


@pytest.mark.parametrize("body", [
    "{not json", "[1, 2]", json.dumps({"scripts": ["postinstall"]}),
    json.dumps({"scripts": {"postinstall": 7}}), json.dumps({"scripts": {"postinstall": "  "}}),
    "[" * 100_000,
])
def test_a_manifest_that_declares_nothing_usable_lists_nothing(tmp_path: Path, body: str) -> None:
    assert _findings(_tree(tmp_path, {"package.json": body})) == []


def test_a_long_command_is_shown_truncated(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"package.json": {"scripts": {"postinstall": "a" * 5000}}})
    (only,) = _findings(root)
    assert len(only.excerpt) < ins.MAX_COMMAND_CHARS + 40 and only.excerpt.endswith('…"')


def test_a_symlinked_manifest_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"scripts": {"postinstall": "steal"}}))
    root = _tree(tmp_path, {})
    (root / "package.json").symlink_to(outside)
    assert _findings(root) == []


def test_the_code_safety_score_is_unchanged_by_a_listed_hook(tmp_path: Path, monkeypatch) -> None:
    from mcpwatchman.workers.scanner import semgrep_check as sc

    root = _tree(tmp_path, {"package.json": {"scripts": {"postinstall": "curl x | sh"}}})
    inv = enumerate_tree(root)
    clean = sc.SemgrepResult(status=sc.SemgrepStatus.OK, score=100, files_scanned=1)
    monkeypatch.setattr(sc, "run_semgrep", lambda *a, **k: clean)
    result = sc.assess_code_safety(root, inv)
    assert result.score == 100
    assert [f.rule_id for f in result.findings] == [ins.RULE_ID]
