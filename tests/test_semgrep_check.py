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
from mcpwatchman.workers.scanner.semgrep_check import _prune_unscannable
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


# --- what must not be scored ---------------------------------------------


def test_minified_bundles_are_not_scored(tmp_path: Path) -> None:
    """The live failure that forced this, reproduced.

    `ac.tandem/docs-mcp` scored **0** on Code Safety during the first real run
    because its built documentation site ships a minified highlight.js, and
    `guide/book/highlight-abc7f01d.js` matched the shell-exec rule four times on
    its single line 6. The server's own source was never the problem.
    """
    docs = tmp_path / "guide" / "book"
    docs.mkdir(parents=True)
    bundle = docs / "highlight-abc7f01d.js"
    bundle.write_text("!function(e){" + "var x=1;" * 200 + "require('child_process').exec(e)}\n")
    (docs / "app.min.js").write_text("const a=1;\n")
    (tmp_path / "server.js").write_text("const cp = require('child_process');\n")

    pruned, sample = sc._prune_unscannable(tmp_path)
    assert pruned == 2
    assert not bundle.exists()
    assert not (docs / "app.min.js").exists()
    assert (tmp_path / "server.js").exists(), "authored source must survive"
    assert any("highlight-abc7f01d.js" in s for s in sample)


def test_vendored_trees_are_not_scored(tmp_path: Path) -> None:
    """`excluded.py` calls itself a CONTRACT with two consumers.

    semgrep was a silent third consumer honouring none of it, so a repository
    that vendors its dependencies was scored on its dependencies' code.
    """
    (tmp_path / "node_modules" / "left-pad").mkdir(parents=True)
    (tmp_path / "node_modules" / "left-pad" / "index.js").write_text("eval(x)\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "dep.py").write_text("eval(x)\n")
    (tmp_path / "server.py").write_text("print('hi')\n")

    pruned, _ = sc._prune_unscannable(tmp_path)
    assert pruned == 2
    assert not (tmp_path / "node_modules").exists()
    assert not (tmp_path / "vendor").exists()
    assert (tmp_path / "server.py").exists()


@pytest.mark.parametrize(("name", "body", "minified"), [
    ("highlight-abc7f01d.js", "x\n", True),      # bundler content hash
    ("app.min.js", "x\n", True),
    ("vendor.bundle.js", "x\n", True),
    ("server.js", "x" * 900 + "\n", True),       # no human wrote this line
    ("server.js", "const x = 1;\n", False),
    ("README.md", "x" * 900 + "\n", False),      # prose wraps long; not code
    # ⚠ WAS `True`, with the comment "hashed artifact, any suffix". That
    # any-suffix behaviour is exactly the defect: it let a hex tail prune
    # `tools-deadbeef.py`. Minification is a property of web assets.
    ("data-abc7f01d.json", "{}\n", False),
])
def test_minification_detection(tmp_path: Path, name, body, minified) -> None:
    path = tmp_path / name
    path.write_text(body)
    assert sc._is_minified(path) is minified


def test_scanning_nothing_is_a_failure_even_when_paths_were_pruned(
    tmp_path, monkeypatch
) -> None:
    """⚠ REPLACES a test that asserted the control's own weakening as intended.

    The old version subtracted the prune count from the inventory's source
    count, and built an inventory claiming a Python file while the only file
    lived in `node_modules/` — a state `enumerate_tree` cannot produce, since it
    skips EXCLUDED_DIRS outright. So it locked in a comparison between two
    disjoint sets, and because every git clone prunes `.git`, the control
    silently stopped firing for any small server. Seven of forty published
    servers were in that state.

    The genuinely-all-vendored case needs no subtraction: `assess_code_safety`
    returns UNAVAILABLE before semgrep runs at all.
    """
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "a.py").write_text("eval(x)\n")
    (tmp_path / "server.py").write_text("print('hi')\n")
    _fake_run(monkeypatch, _payload([], scanned=()))
    result = sc.run_semgrep(tmp_path, rules=RULES, inventory=_inventory(Language.PYTHON))
    assert result.status is sc.SemgrepStatus.FAILED, (
        "semgrep opened nothing while the inventory held covered source"
    )
    assert result.score is None
    assert result.pruned == 1


def test_a_server_with_only_vendored_code_never_reaches_semgrep() -> None:
    """The other half: the all-vendored case is caught upstream, not by the control."""
    result = sc.assess_code_safety(Path("/nonexistent"), _inventory())
    assert result.status is sc.SemgrepStatus.UNAVAILABLE
    assert result.score is None


# --- what a scanned repository can do to the prune step -------------------


def test_a_symlinked_vendor_tree_cannot_evade_the_prune(tmp_path: Path) -> None:
    """A scanned repo could switch the exclusion off by linking instead of nesting.

    `shutil.rmtree` REFUSES to act on a symlink, and with `ignore_errors=True`
    it refuses silently — so a repository shipping `node_modules` as a symlink
    was counted as excluded while staying fully present and fully scannable.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "vendored.js").write_text("eval(danger)\n")
    root = tmp_path / "scan"
    root.mkdir()
    (root / "node_modules").symlink_to(outside)
    (root / "server.py").write_text("print('hi')\n")

    pruned, sample = _prune_unscannable(root)

    assert not (root / "node_modules").is_symlink(), "the link survived the prune"
    assert pruned == 1 and sample == ("node_modules/",)
    # We remove the LINK, never its target: deleting outside the scratch copy
    # on a stranger's instruction is the worse of the two bugs.
    assert (outside / "vendored.js").exists(), "the prune escaped the scan root"
    assert (root / "server.py").exists()


def test_the_prune_count_never_includes_something_it_failed_to_remove(
    tmp_path: Path, monkeypatch
) -> None:
    """The count is published verbatim on the server's page."""
    root = tmp_path / "scan"
    (root / "node_modules").mkdir(parents=True)
    (root / "node_modules" / "dep.js").write_text("eval(x)\n")

    monkeypatch.setattr(sc.shutil, "rmtree", lambda *a, **kw: None)  # a silent refusal
    pruned, sample = _prune_unscannable(root)

    assert pruned == 0, "counted a removal that did not happen"
    assert sample == ()
    assert (root / "node_modules").is_dir()


def test_a_symlinked_file_is_never_read_while_hunting_for_minified_files(
    tmp_path: Path,
) -> None:
    """`_is_minified` OPENS what it is handed, and `is_file()` follows symlinks.

    The motivating hazard is a FIFO reached through a symlink — `open()` blocks
    the worker forever. A FIFO asserts by hanging, so the control here is the
    same property made deterministic: a link to a genuinely minified file
    outside the root, named so no NAME heuristic can answer without reading.

    ⚠ The first version named it `link.min.js`, which `_is_minified` answers
    from the name without opening anything, so it passed with and without the
    fix — green for the wrong reason, which `/qa` §3b exists to catch.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.js").write_text("!function(e){" + "var x=1;" * 200 + "}\n")
    root = tmp_path / "scan"
    root.mkdir()
    (root / "payload.js").symlink_to(outside / "real.js")
    (root / "server.py").write_text("print('hi')\n")

    pruned, sample = _prune_unscannable(root)

    assert pruned == 0, "followed a symlink to decide whether to prune"
    assert sample == ()
    assert (root / "payload.js").is_symlink(), "acted on a symlink"
    assert (outside / "real.js").exists()


# --- evasions a scanned repository can attempt ----------------------------


@pytest.mark.skipif(
    __import__("shutil").which("semgrep") is None,
    reason="semgrep lives in the `workers` extra",
)
def test_an_inline_nosemgrep_comment_cannot_suppress_a_finding(tmp_path: Path) -> None:
    """The third door in the same room as `.semgrepignore`, and it was open.

    semgrep honours inline `nosem` / `# nosemgrep` comments BY DEFAULT, so a
    hostile server suppressed its own shell-injection finding with a comment,
    kept a non-empty `paths.scanned` so the positive control passed, and
    published Code Safety 100. A deleted config FILE cannot reach a comment
    inside a source line.

    Carries its own negative control: the identical code without the comment
    must be flagged, or this proves only that the rule is broken.
    """
    (tmp_path / "suppressed.py").write_text(
        "import subprocess\n"
        "def run(user_arg):\n"
        '    subprocess.run(f"cat {user_arg}", shell=True)  # nosemgrep\n'
    )
    (tmp_path / "honest.py").write_text(
        "import subprocess\n"
        "def run(user_arg):\n"
        '    subprocess.run(f"cat {user_arg}", shell=True)\n'
    )
    result = sc.run_semgrep(tmp_path, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK, result.reason
    flagged = {f.path for f in result.findings}
    assert "honest.py" in flagged, "the rule itself does not fire — control failed"
    assert "suppressed.py" in flagged, "a comment suppressed a finding"


@pytest.mark.parametrize("name", [
    "tools-deadbeef.py",      # a hex tail is a bundler hash only on a web asset
    "handler-abcdef12.go",
    "settings.minimal.py",    # `.min` as a SUBSTRING caught an ordinary word
    "config.minimal.json",
    "history.mine.ts",
])
def test_source_is_not_pruned_by_a_name_rule_meant_for_web_assets(
    tmp_path: Path, name
) -> None:
    """A stranger could choose which of their own files we read.

    Both name heuristics ran BEFORE the extension gate, so they applied to
    every file in the tree: a server naming its shell-injection module
    `tools-deadbeef.py` had it deleted before semgrep ran, and an honest repo's
    `settings.minimal.py` was dropped and reported as a generated bundle.
    """
    path = tmp_path / name
    path.write_text("x = 1\n")
    assert sc._is_minified(path) is False


@pytest.mark.parametrize("name", ["app.min.js", "vendor.bundle.js", "book-a0b12cfe.js"])
def test_real_web_bundles_are_still_pruned(tmp_path: Path, name) -> None:
    """The negative control for the test above — the narrowing must not gut it."""
    path = tmp_path / name
    path.write_text("x=1\n")
    assert sc._is_minified(path) is True


def test_unparsed_files_reduce_coverage_rather_than_voiding_the_axis(
    tree, monkeypatch
) -> None:
    """⚠ REPLACES a check that failed the whole scan on ANY error.

    That over-fired: 47 of 48 files parsing meant no Code Safety score at all,
    and three of thirty-two published servers lost a weight-30 axis to a single
    unparseable file. semgrep's errors carry a per-error `path`, so
    parsed-vs-unparsed is countable — and this repo already renders exactly
    this shape on the dependency axis.
    """
    # ⚠ THE FIXTURE PREVIOUSLY PUT `bad.ts` OUTSIDE `paths.scanned` and asserted
    # 0.75, which codified an assumption rather than testing one. Measured
    # against real semgrep: a file that fails to parse is listed in
    # `paths.scanned` AND named in `errors[]`. So the denominator is `scanned`
    # and the bad file belongs in it — 2 of 3, not 3 of 4.
    payload = json.dumps({
        "results": [],
        "errors": [{"type": ["PartialParsing", [{"path": "bad.ts"}]]}],
        "paths": {"scanned": ["a.py", "b.py", "bad.ts"]},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK
    assert result.files_unparsed == 1
    assert result.assessed_weight == "0.66", "2 of 3 files parsed, not 3 of 4"
    assert result.score == 100


def test_errors_with_nothing_parsed_are_still_a_failure(tree, monkeypatch) -> None:
    """The negative control: a void is right when NOTHING was read."""
    payload = json.dumps({
        "results": [],
        "errors": [{"type": "Timeout"}],
        "paths": {"scanned": []},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.FAILED
    assert result.score is None
    assert "parsed nothing" in result.reason


def test_a_finding_outside_the_scan_root_is_dropped_not_published(
    tree, monkeypatch
) -> None:
    """The `else path` fallback passed an ABSOLUTE path through.

    `root / "/etc/passwd"` is `/etc/passwd`, so the excerpt reader would have
    published five lines of it while the evidence path carried a local
    filesystem path onto the page.
    """
    _fake_run(monkeypatch, _payload([
        _result("mcp-python-pickle-loads", path="/etc/passwd", line=1)
    ]))
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK
    assert result.findings == (), "published a finding from outside the scan root"


def test_the_ruleset_is_packaged_for_an_installed_worker() -> None:
    """`rules/` lives at the repo root and the wheel packages only `src/`.

    Without an explicit force-include the ruleset shipped nowhere, so every
    installed wheel and the worker image — whose Dockerfile copies `src` alone —
    raised RulesetError before semgrep ran. It worked from a checkout, which was
    the only place it had ever been run. Verified for real by building a wheel
    and resolving `rules_root()` inside a venv with no checkout above it; this
    test guards the config line that makes that possible.
    """
    import tomllib

    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    include = config["tool"]["hatch"]["build"]["targets"]["wheel"].get("force-include", {})
    assert include.get("rules") == "mcpwatchman/rules", (
        "the ruleset is not packaged into the wheel"
    )


def test_a_structured_semgrep_error_does_not_leak_paths_into_the_reason(
    tree, monkeypatch
) -> None:
    """`errors[].type` is not always a string.

    For `PartialParsing` semgrep emits `["PartialParsing", [{"path": "/tmp/…"}]]`,
    so stringifying it published a Python repr of absolute scratch paths into a
    field rendered verbatim on the page. Caught by this repo's own leak gate on
    the regeneration immediately after the fix that introduced it.
    """
    payload = json.dumps({
        "results": [],
        "errors": [{"type": ["PartialParsing", [
            {"path": "/tmp/mcpw-scan-abc123/src/x.tsx",  # noqa: S108 - fixture data
             "start": {"line": 280}}
        ]]}],
        # `scanned: []` on purpose: the reason string is only BUILT on the
        # nothing-parsed branch. With files parsed the run is partial coverage
        # and carries no kinds string, so this fixture would exercise nothing.
        "paths": {"scanned": []},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.FAILED
    assert "PartialParsing" in result.reason, "the error kind was lost"
    assert "/tmp/" not in result.reason  # noqa: S108 - the literal is the needle
    assert "mcpw-scan" not in result.reason
    assert "{" not in result.reason, "a raw structure reached a published field"


def test_partial_coverage_never_rounds_up_to_fully_measured(tree, monkeypatch) -> None:
    """1276 of 1277 files parsed is not "all of them".

    Half-up quantization published `assessed_weight: "1.00"` for a scan that
    missed a file, and the site tests `Number(w) < 1` — so the server dropped
    out of the partly-measured tally and rendered as complete. Every other
    rounding decision here rounds the PUBLISHED value half-up; a coverage claim
    is the one that has to round down.
    """
    payload = json.dumps({
        "results": [],
        "errors": [{"type": ["PartialParsing", [{"path": "bad.ts"}]]}],
        "paths": {"scanned": [f"f{i}.py" for i in range(1276)]},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.files_unparsed == 1
    assert result.assessed_weight == "0.99", result.assessed_weight
    assert float(result.assessed_weight) < 1, "an incomplete scan read as complete"


@pytest.mark.parametrize(("scanned_n", "unparsed_n"), [(200, 199), (150, 149), (101, 100)])
def test_a_coverage_that_rounds_to_zero_is_a_failure(
    tree, monkeypatch, scanned_n, unparsed_n
) -> None:
    """⚠ The previous guard tested the RAW ratio against a half-up threshold.

    Coverage quantizes ROUND_DOWN, so anything under 0.01 floors to "0.00" —
    and 1 file parsed of 200, 150 or 101 all sailed past a `< 0.005` test and
    published a score on zero declared coverage. That is the defect the guard
    was added to prevent, off by the rounding mode. Judging the value actually
    published is also robust to the quantum ever changing.
    """
    bad = [{"path": f"bad{i}.ts"} for i in range(unparsed_n)]
    payload = json.dumps({
        "results": [],
        "errors": [{"type": ["PartialParsing", bad]}],
        "paths": {"scanned": [f"f{i}.py" for i in range(scanned_n)]},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.FAILED, (
        f"{scanned_n - unparsed_n} of {scanned_n} parsed was published as a score"
    )
    assert result.score is None
    assert "rounds to zero" in result.reason


def test_a_coverage_that_survives_rounding_still_scores(tree, monkeypatch) -> None:
    """The negative control — the guard must not swallow a real partial scan."""
    payload = json.dumps({
        "results": [],
        "errors": [{"type": ["PartialParsing", [{"path": "bad.ts"}]]}],
        "paths": {"scanned": ["a.py", "b.py", "bad.ts"]},
    })
    _fake_run(monkeypatch, payload)
    result = sc.run_semgrep(tree, rules=RULES)
    assert result.status is sc.SemgrepStatus.OK
    assert result.assessed_weight == "0.66"
