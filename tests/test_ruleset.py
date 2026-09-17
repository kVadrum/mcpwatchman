"""Gates on the semgrep ruleset itself (`04` §4).

Two kinds of check live here and they fail for different reasons.

The **structural** ones read YAML and need no semgrep: every rule is mapped,
every mapping entry exists, the semgrep severity is the projection of ours, no
rule claims a confidence the methodology has not measured. They are cheap and
always run.

The **control** ones run the real scanner. They exist because everything above
can pass while the ruleset matches nothing at all: a rule with a `pattern-not`
that swallows its own positive pattern is valid YAML, validates cleanly, and is
dead. One shipped exactly that way during this ruleset's first draft. So the bar
is: every rule must fire on a vulnerable fixture, and none may fire on the safe
one. A rule that cannot be made to fire does not ship.

⚠ **The fixtures are COPIED to a tmp dir before scanning, and that is not
incidental.** semgrep's default ignore list excludes `tests/`, so scanning them
where they live reports `scanned: 0, findings: 0` — a clean-looking result from
a scanner that opened nothing. Measured. The copy also mirrors production, where
the tree under scan is a scratch copy we own.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from mcpwatchman.workers.scanner import semgrep_check as sc
from mcpwatchman.workers.scoring.composite import Confidence, Severity
from mcpwatchman.workers.scoring.weights import (
    CURRENT_METHODOLOGY_VERSION,
    confidence_ceiling,
)

RULES = sc.rules_root()
FIXTURES = Path(__file__).parent / "fixtures" / "semgrep"

# `_meta/severity-mapping.yaml` states this projection; it is re-derived here
# rather than imported so a silent edit to one side fails the test.
PROJECTION = {
    Severity.CRITICAL: "ERROR",
    Severity.HIGH: "ERROR",
    Severity.MEDIUM: "WARNING",
    Severity.LOW: "INFO",
    Severity.INFORMATIONAL: "INFO",
}

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep lives in the `workers` extra; the workers-extra CI job runs these",
)


def _rule_files() -> list[Path]:
    return sorted(p for p in RULES.glob("*/*.yaml") if p.parent.name != "_meta")


def _rules() -> list[tuple[Path, dict]]:
    out = []
    for path in _rule_files():
        for rule in yaml.safe_load(path.read_text())["rules"]:
            out.append((path, rule))
    return out


# --- structural -----------------------------------------------------------


def test_the_ruleset_is_not_empty() -> None:
    """The positive control for every other test in this file.

    `rules/` held four empty `.gitkeep`s for three sessions while Code Safety
    reported nothing. Every assertion below is vacuously true against an empty
    ruleset, so this one runs first.
    """
    assert len(_rule_files()) >= 3
    assert len(_rules()) >= 20


def test_every_rule_is_mapped_and_every_mapping_entry_exists() -> None:
    declared = sc.declared_rule_ids(RULES)
    mapped = set(sc.load_severity_mapping(RULES))
    assert declared - mapped == set(), "rule(s) with no severity mapping"
    assert mapped - declared == set(), "mapping entr(ies) for rules that do not exist"


def test_semgrep_severity_is_the_projection_of_ours() -> None:
    """The one place the two vocabularies could drift into disagreeing."""
    mapping = sc.load_severity_mapping(RULES)
    for path, rule in _rules():
        ours = Severity(mapping[rule["id"]]["severity"])
        assert rule["severity"] == PROJECTION[ours], (
            f"{path.name}:{rule['id']} declares semgrep severity "
            f"{rule['severity']} but the mapping says {ours}"
        )


def test_no_rule_claims_a_confidence_the_gold_set_has_not_measured() -> None:
    """`03` §3 defines confidence by measurement; the gold set does not exist."""
    ceiling = Confidence(confidence_ceiling(CURRENT_METHODOLOGY_VERSION))
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    for rule_id, entry in sc.load_severity_mapping(RULES).items():
        got = Confidence(entry["confidence"])
        assert order.index(got) <= order.index(ceiling), (
            f"{rule_id} claims {got} confidence, above the {ceiling} ceiling "
            "for an uncalibrated ruleset"
        )


def test_every_rule_carries_a_message_and_an_mcp_pattern() -> None:
    """`03` §10: no finding reaches a reader without saying what it means."""
    for path, rule in _rules():
        assert rule.get("message", "").strip(), f"{path.name}:{rule['id']} has no message"
        assert rule.get("metadata", {}).get("mcp_pattern"), (
            f"{path.name}:{rule['id']} declares no mcp_pattern"
        )


def test_ruleset_version_comes_from_the_changelog() -> None:
    version = sc.ruleset_version(RULES)
    assert version[0].isdigit(), f"{version!r} is not a version"
    assert version in (RULES / "_meta" / "changelog.md").read_text()


def test_meta_is_not_offered_to_semgrep_as_a_config() -> None:
    """semgrep crashes on `severity-mapping.yaml` — it is a map, not a list."""
    assert all(c.name != "_meta" for c in sc._language_configs(RULES))
    assert (RULES / "_meta" / "severity-mapping.yaml").is_file()


# --- controls against the real scanner ------------------------------------


def _scan(target: Path) -> dict:
    cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore"]
    for config in sc._language_configs(RULES):
        cmd += ["--config", str(config)]
    cmd.append(str(target))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # noqa: S603
    return json.loads(proc.stdout)


@pytest.fixture
def scanned(tmp_path: Path):
    def _copy(name: str) -> Path:
        dest = tmp_path / name
        shutil.copytree(FIXTURES / name, dest)
        return dest
    return _copy


@needs_semgrep
def test_the_ruleset_compiles() -> None:
    cmd = ["semgrep", "--validate"]
    for config in sc._language_configs(RULES):
        cmd += ["--config", str(config)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # noqa: S603
    assert proc.returncode == 0, proc.stdout + proc.stderr


@needs_semgrep
def test_every_declared_rule_fires_on_the_vulnerable_fixtures(scanned) -> None:
    """No rule ships unexercised — the whole point of this file."""
    payload = _scan(scanned("vulnerable"))
    assert payload["paths"]["scanned"], "semgrep opened no files"
    fired = {r["check_id"].rsplit(".", 1)[-1] for r in payload["results"]}
    never = sorted(sc.declared_rule_ids(RULES) - fired)
    assert not never, f"rule(s) that never fire against their own fixtures: {never}"


@needs_semgrep
def test_the_safe_fixtures_produce_no_findings(scanned) -> None:
    """A false accusation is the expensive failure for this product."""
    payload = _scan(scanned("safe"))
    assert payload["paths"]["scanned"], "semgrep opened no files"
    assert payload["results"] == [], [
        (r["check_id"].rsplit(".", 1)[-1], r["path"], r["start"]["line"])
        for r in payload["results"]
    ]


@needs_semgrep
def test_a_repo_supplied_semgrepignore_cannot_switch_the_scan_off(scanned) -> None:
    """The evasion, and the control that proves the fixture could show it.

    A scanned repository is attacker-controlled input, and semgrep honours a
    `.semgrepignore` it finds there. Measured: one line naming the source file
    takes the scan to 0 files and 0 findings, exit 0 — indistinguishable from a
    clean repo. `run_semgrep` deletes it from the scratch copy first.
    """
    root = scanned("vulnerable")
    (root / ".semgrepignore").write_text("server.py\nserver.js\nserver.go\n")

    # Negative control: unneutralised, the evasion works.
    assert _scan(root)["results"] == []

    result = sc.run_semgrep(root, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK
    assert result.neutralised == (".semgrepignore",)
    assert result.findings, "neutralising the ignore file did not restore the scan"
    assert result.score is not None and result.score < 100


@needs_semgrep
def test_findings_carry_their_own_evidence(scanned) -> None:
    """semgrep returns `requires login` for excerpts; we read our own copy."""
    result = sc.run_semgrep(scanned("vulnerable"), rules=RULES)
    assert result.findings
    for finding in result.findings:
        assert finding.excerpt.strip(), f"{finding.rule_id} carries no excerpt"
        assert "requires login" not in finding.excerpt
        assert finding.line > 0
        assert not Path(finding.path).is_absolute()


@needs_semgrep
def test_confidence_is_clamped_and_the_clamp_is_recorded(scanned) -> None:
    result = sc.run_semgrep(scanned("vulnerable"), rules=RULES)
    ceiling = Confidence(confidence_ceiling())
    assert all(f.confidence is not Confidence.HIGH for f in result.findings)
    assert all(f.confidence in (Confidence.LOW, ceiling) for f in result.findings)
