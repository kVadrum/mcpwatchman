"""The semgrep runner's failure paths (`04` §4.4).

Every test here is about a way the scanner can report a CLEAN result having
established nothing — the failure shape this project exists to oppose, pointed
at ourselves. None of them need semgrep installed; they drive the parser
directly, which is the point: the dangerous cases are the ones where semgrep is
broken or absent.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner import semgrep_check as sc
from mcpwatchman.workers.scanner.inventory import (
    FileRecord,
    Inventory,
    Language,
    Role,
)
from mcpwatchman.workers.scoring.composite import Confidence, Severity

RULES = sc.rules_root()


def _inventory(*languages: Language) -> Inventory:
    return Inventory(
        files=tuple(
            FileRecord(
                path=f"s{i}.x", language=lang, role=Role.SOURCE,
                size_bytes=10, sha256="0" * 64,
            )
            for i, lang in enumerate(languages)
        )
    )


def _payload(results, scanned=("server.py",)):
    return json.dumps({"results": list(results), "errors": [],
                       "paths": {"scanned": list(scanned)}})


def _result(rule_id, path="server.py", line=1, severity="ERROR"):
    return {
        "check_id": f"rules.python.{rule_id}",
        "path": path,
        "start": {"line": line},
        "extra": {"message": "bad thing", "severity": severity,
                  "lines": "requires login",
                  "metadata": {"mcp_pattern": "value-to-shell", "cwe": "CWE-78"}},
    }


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "server.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n\n\nprint('tail')\n"
    )
    return tmp_path


def _fake_run(monkeypatch, stdout, returncode=0, raises=None):
    def fake(cmd, **kw):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout, "")
    monkeypatch.setattr(sc.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(sc.subprocess, "run", fake)


# --- the ways a broken scan must NOT read as clean ------------------------


def test_semgrep_absent_is_unavailable_not_a_perfect_score(tree, monkeypatch) -> None:
    monkeypatch.setattr(sc.shutil, "which", lambda _: None)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.UNAVAILABLE
    assert result.score is None
    assert "workers" in result.reason


def test_non_json_output_is_a_failure_not_an_empty_finding_set(tree, monkeypatch) -> None:
    """semgrep exits non-zero with no JSON on a config error."""
    _fake_run(monkeypatch, "Configuration is invalid\n", returncode=2)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.FAILED
    assert result.score is None
    assert "no JSON" in result.reason


def test_a_timeout_is_a_failure(tree, monkeypatch) -> None:
    _fake_run(monkeypatch, "", raises=subprocess.TimeoutExpired("semgrep", 300))
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.FAILED
    assert result.score is None
    assert "300s" in result.reason


def test_scanning_zero_files_with_source_present_is_a_failure(tree, monkeypatch) -> None:
    """The positive control, wired into the runner rather than left to a test.

    The inventory says there is Python here and semgrep opened nothing. Every
    mechanism that produces this — a repo-supplied ignore file, a bad target
    path, a default ignore list — produces the same confident zero.
    """
    _fake_run(monkeypatch, _payload([], scanned=()))
    result = sc.run_semgrep(tree, rules=RULES, inventory=_inventory(Language.PYTHON))
    assert result.status is sc.SemgrepStatus.FAILED
    assert result.score is None
    assert "scanned 0 files" in result.reason


def test_scanning_zero_files_with_no_covered_source_is_fine(tree, monkeypatch) -> None:
    """The negative control for the test above: an empty scan can be honest."""
    _fake_run(monkeypatch, _payload([], scanned=()))
    result = sc.run_semgrep(tree, rules=RULES, inventory=_inventory(Language.RUST))
    assert result.status is sc.SemgrepStatus.OK
    assert result.score == 100


def test_a_server_with_no_covered_language_is_unavailable_not_100() -> None:
    result = sc.assess_code_safety(Path("/nonexistent"), _inventory(Language.RUBY))
    assert result.status is sc.SemgrepStatus.UNAVAILABLE
    assert result.score is None
    assert "ruleset covers" in result.reason


def test_an_unmapped_rule_id_raises_rather_than_guessing(tree, monkeypatch) -> None:
    _fake_run(monkeypatch, _payload([_result("mcp-python-rule-that-does-not-exist")]))
    with pytest.raises(sc.RulesetError, match="no defined deduction"):
        sc.run_semgrep(tree, rules=RULES)


# --- scoring and evidence -------------------------------------------------


def test_findings_are_scored_through_the_code_safety_table(tree, monkeypatch) -> None:
    """Two critical findings, clamped to medium: 20 + 15 deducted."""
    _fake_run(monkeypatch, _payload([
        _result("mcp-python-pickle-loads", line=5),
        _result("mcp-python-tool-arg-to-shell", line=5),
    ]))
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK
    assert [f.severity for f in result.findings] == [Severity.CRITICAL] * 2
    assert [f.confidence for f in result.findings] == [Confidence.MEDIUM] * 2
    assert result.score == 65


def test_confidence_is_clamped_and_says_so(tree, monkeypatch) -> None:
    """A clamp that did not render would be indistinguishable from a low rule."""
    _fake_run(monkeypatch, _payload([_result("mcp-python-pickle-loads", line=5)]))
    monkeypatch.setattr(sc, "confidence_ceiling", lambda *_a, **_k: "low")
    result = sc.run_semgrep(tree, rules=RULES)
    finding = result.findings[0]
    assert finding.confidence is Confidence.LOW
    assert finding.declared_confidence is Confidence.MEDIUM
    assert finding.clamped


def test_an_unclamped_finding_records_no_declared_confidence(tree, monkeypatch) -> None:
    _fake_run(monkeypatch, _payload([_result("mcp-python-ssrf-nonliteral-url", line=5)]))
    finding = sc.run_semgrep(tree, rules=RULES).findings[0]
    assert finding.confidence is Confidence.LOW
    assert finding.declared_confidence is None
    assert not finding.clamped


def test_the_excerpt_is_read_from_our_copy_not_from_semgrep(tree, monkeypatch) -> None:
    _fake_run(monkeypatch, _payload([_result("mcp-python-pickle-loads", line=5)]))
    finding = sc.run_semgrep(tree, rules=RULES).findings[0]
    assert "subprocess.run(cmd, shell=True)" in finding.excerpt
    assert "requires login" not in finding.excerpt
    # Context either side, bounded — not the whole file.
    assert "def run(cmd):" in finding.excerpt
    assert "print('tail')" not in finding.excerpt


def test_an_absolute_path_from_semgrep_is_made_relative(tree, monkeypatch) -> None:
    """Paths are published; an absolute one leaks the scratch layout."""
    _fake_run(monkeypatch, _payload([
        _result("mcp-python-pickle-loads", path=str(tree / "server.py"), line=5)
    ]))
    finding = sc.run_semgrep(tree, rules=RULES).findings[0]
    assert finding.path == "server.py"


def test_repo_supplied_scanner_config_is_deleted_before_the_scan(tree, monkeypatch) -> None:
    (tree / ".semgrepignore").write_text("server.py\n")
    (tree / "nested").mkdir()
    (tree / "nested" / ".semgrepignore").write_text("*\n")
    _fake_run(monkeypatch, _payload([]))
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.neutralised == (".semgrepignore", "nested/.semgrepignore")
    assert not (tree / ".semgrepignore").exists()
    assert not (tree / "nested" / ".semgrepignore").exists()


# --- the ruleset loader ---------------------------------------------------


def test_rules_root_raises_when_there_is_no_ruleset(tmp_path: Path) -> None:
    with pytest.raises(sc.RulesetError, match="cannot run without its ruleset"):
        sc.rules_root(tmp_path / "deep" / "nested" / "file.py")


def test_a_malformed_mapping_entry_is_caught_at_load(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "python").mkdir(parents=True)
    (root / "python" / "r.yaml").write_text(
        "rules:\n  - id: x\n    languages: [python]\n    severity: ERROR\n"
        "    message: m\n    pattern: eval($X)\n"
    )
    (root / "_meta").mkdir()
    meta = root / "_meta" / "severity-mapping.yaml"
    meta.write_text("rules:\n  x: {severity: catastrophic, confidence: medium}\n")
    with pytest.raises(sc.RulesetError, match="unknown severity"):
        sc.load_severity_mapping(root)

    meta.write_text("rules:\n  x: {severity: critical, confidence: certain}\n")
    with pytest.raises(sc.RulesetError, match="unknown confidence"):
        sc.load_severity_mapping(root)


def test_a_rule_id_containing_a_dot_is_rejected(tmp_path: Path) -> None:
    """semgrep namespaces check_id by dots; we recover the bare id by splitting."""
    root = tmp_path / "rules"
    (root / "python").mkdir(parents=True)
    (root / "python" / "r.yaml").write_text(
        "rules:\n  - id: has.a.dot\n    languages: [python]\n    severity: ERROR\n"
        "    message: m\n    pattern: eval($X)\n"
    )
    with pytest.raises(sc.RulesetError, match="must not contain"):
        sc.declared_rule_ids(root)
