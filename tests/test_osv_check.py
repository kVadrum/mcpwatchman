"""Dependency Health scoring and the osv-scanner runner (`03` §6, `04` §5)."""

from __future__ import annotations

import json
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner import osv_check as oc
from mcpwatchman.workers.scanner.inventory import FileRecord, Inventory, Language, Role
from mcpwatchman.workers.scoring.composite import Severity, axis_score

needs_osv = pytest.mark.skipif(
    shutil.which("osv-scanner") is None,
    reason="osv-scanner is a Go binary installed in the worker image",
)


def _finding(severity, direct=True, osv_id="OSV-1", package="p") -> oc.DependencyFinding:
    return oc.DependencyFinding(
        package=package, ecosystem="PyPI", version="1.0", osv_id=osv_id,
        severity=severity, cvss=Decimal("9.5") if severity else None,
        direct=direct, lockfile="requirements.txt",
    )


def _inventory(*paths_roles) -> Inventory:
    return Inventory(files=tuple(
        FileRecord(path=p, language=Language.JSON, role=r, size_bytes=10, sha256="0" * 64)
        for p, r in paths_roles
    ))


# --- CVSS banding ---------------------------------------------------------


@pytest.mark.parametrize(("score", "expected"), [
    ("10.0", Severity.CRITICAL),
    ("9.0", Severity.CRITICAL),   # boundary: >= 9.0
    ("8.9", Severity.HIGH),
    ("7.0", Severity.HIGH),       # boundary: >= 7.0
    ("6.9", Severity.MEDIUM),
    ("4.0", Severity.MEDIUM),     # boundary: >= 4.0
    ("3.9", Severity.LOW),
    ("0", Severity.LOW),
])
def test_cvss_bands_match_the_methodology(score, expected) -> None:
    assert oc.severity_from_cvss(score) is expected


@pytest.mark.parametrize("score", [None, "", "not-a-number", "11.0", "-1"])
def test_an_unusable_cvss_abstains_rather_than_defaulting(score) -> None:
    """`03` §6 bands on a score. No score means no band, not a low one."""
    assert oc.severity_from_cvss(score) is None


def test_an_unscored_finding_refuses_to_produce_a_deduction() -> None:
    with pytest.raises(ValueError, match="no band"):
        _finding(None).deduction()


# --- the table, which is NOT Code Safety's -------------------------------


def test_the_deduction_table_is_03_section_6() -> None:
    assert oc.DEDUCTIONS == {
        Severity.CRITICAL: {"direct": 25, "transitive": 15},
        Severity.HIGH: {"direct": 15, "transitive": 8},
        Severity.MEDIUM: {"direct": 6, "transitive": 3},
        Severity.LOW: {"direct": 2, "transitive": 1},
    }


def test_dependency_scoring_is_not_code_safety_scoring() -> None:
    """The confusion this axis was most likely to ship with.

    One critical direct dependency deducts 25 here. Routed through
    `composite.axis_score` — which both axes structurally fit — the same finding
    would deduct 20 or 30 depending on a confidence field this axis does not
    have. That call compiles and returns a wrong number rather than an error.
    """
    findings = [_finding(Severity.CRITICAL, direct=True)]
    assert oc.dependency_axis_score(findings) == 75
    assert axis_score([]) == 100  # different function, different table


def test_direct_dependencies_are_penalised_harder_than_transitive() -> None:
    assert oc.dependency_axis_score([_finding(Severity.CRITICAL, direct=True)]) == 75
    assert oc.dependency_axis_score([_finding(Severity.CRITICAL, direct=False)]) == 85


def test_same_severity_findings_stack_with_diminishing_returns() -> None:
    """`03` §6 inherits §3's 75/50/25/10 ladder — one canonical implementation."""
    findings = [_finding(Severity.CRITICAL, osv_id=f"OSV-{i}") for i in range(3)]
    # 25 + 18.75 + 12.5 = 56.25 -> 100 - 56.25 = 43.75 -> 44
    assert oc.dependency_axis_score(findings) == 44


def test_stacking_takes_the_largest_deduction_first() -> None:
    """A direct and a transitive critical share one group; the direct leads."""
    findings = [
        _finding(Severity.CRITICAL, direct=False, osv_id="OSV-t"),
        _finding(Severity.CRITICAL, direct=True, osv_id="OSV-d"),
    ]
    # largest-first: 25 + 15*0.75 = 36.25 -> 63.75 -> 64 (smallest-first gives 66)
    assert oc.dependency_axis_score(findings) == 64


def test_the_axis_floors_at_zero() -> None:
    findings = [_finding(Severity.CRITICAL, osv_id=f"OSV-{i}") for i in range(40)]
    assert oc.dependency_axis_score(findings) == 0


def test_unscored_findings_are_excluded_from_the_arithmetic() -> None:
    scored = [_finding(Severity.HIGH, osv_id="a")]
    assert oc.dependency_axis_score([*scored, _finding(None, osv_id="b")]) == 85
    assert oc.dependency_axis_score(scored) == 85


# --- direct vs transitive from the manifests ------------------------------


def test_direct_dependencies_read_from_each_manifest_kind(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}}))
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\n'
        'dependencies = ["httpx>=0.27", "click"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8"]\n')
    (tmp_path / "requirements.txt").write_text(
        "# comment\nrequests==2.19.1\nurllib3 >= 1.24\n-r other.txt\n")
    (tmp_path / "go.mod").write_text(
        "module example.com/x\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/direct/pkg v1.0.0\n"
        "\tgithub.com/indirect/pkg v1.0.0 // indirect\n)\n")
    inv = _inventory(
        ("package.json", Role.PACKAGE_MANIFEST),
        ("pyproject.toml", Role.PACKAGE_MANIFEST),
        ("requirements.txt", Role.LOCKFILE),
        ("go.mod", Role.PACKAGE_MANIFEST),
    )
    names = oc.direct_dependencies(tmp_path, inv)
    assert {"express", "jest", "httpx", "click", "pytest",
            "requests", "urllib3", "github.com/direct/pkg"} <= names
    # go.mod says which are transitive; we must believe it.
    assert "github.com/indirect/pkg" not in names
    assert "other.txt" not in names


def test_a_malformed_manifest_does_not_abort_the_scan(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json")
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    inv = _inventory(("package.json", Role.PACKAGE_MANIFEST),
                     ("requirements.txt", Role.LOCKFILE))
    assert oc.direct_dependencies(tmp_path, inv) == {"requests"}


# --- the runner's failure paths -------------------------------------------


def _fake_run(monkeypatch, stdout, returncode=0, raises=None):
    def fake(cmd, **kw):
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout, "")
    monkeypatch.setattr(oc.shutil, "which", lambda _: "/usr/bin/osv-scanner")
    monkeypatch.setattr(oc.subprocess, "run", fake)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n")
    return tmp_path


LOCK_INV = None


@pytest.fixture
def inv() -> Inventory:
    return _inventory(("requirements.txt", Role.LOCKFILE))


def _payload(root: Path, groups, package="jinja2", vulns=None):
    return json.dumps({"results": [{
        "source": {"path": str(root / "requirements.txt"), "type": "lockfile"},
        "packages": [{
            "package": {"name": package, "version": "2.10", "ecosystem": "PyPI"},
            "vulnerabilities": vulns or [],
            "groups": groups,
        }],
    }]})


def test_osv_absent_is_unavailable_not_a_perfect_score(tree, inv, monkeypatch) -> None:
    monkeypatch.setattr(oc.shutil, "which", lambda _: None)
    result = oc.run_osv(tree, inv)
    assert result.status is oc.OsvStatus.UNAVAILABLE
    assert result.score is None


def test_exit_code_one_means_it_found_something_not_that_it_failed(
    tree, inv, monkeypatch
) -> None:
    """Measured on osv-scanner 2.6.0: rc 1 = vulnerabilities, rc 0 = clean."""
    _fake_run(monkeypatch, _payload(tree, [{"ids": ["PYSEC-1"], "aliases": ["CVE-1"],
                                            "max_severity": "9.8"}]), returncode=1)
    result = oc.run_osv(tree, inv)
    assert result.status is oc.OsvStatus.OK
    assert len(result.findings) == 1
    assert result.score == 75


@pytest.mark.parametrize("rc", [127, 128, 2])
def test_a_real_error_code_is_a_failure(tree, inv, monkeypatch, rc) -> None:
    _fake_run(monkeypatch, "", returncode=rc)
    result = oc.run_osv(tree, inv)
    assert result.status is oc.OsvStatus.FAILED
    assert result.score is None


def test_empty_stdout_is_a_failure_not_a_clean_bill(tree, inv, monkeypatch) -> None:
    _fake_run(monkeypatch, "", returncode=0)
    result = oc.run_osv(tree, inv)
    assert result.status is oc.OsvStatus.FAILED
    assert result.score is None
    assert "no JSON" in result.reason


def test_a_timeout_is_a_failure(tree, inv, monkeypatch) -> None:
    _fake_run(monkeypatch, "", raises=subprocess.TimeoutExpired("osv-scanner", 180))
    assert oc.run_osv(tree, inv).status is oc.OsvStatus.FAILED


def test_no_lockfile_is_unassessed_not_a_hundred(tmp_path: Path, monkeypatch) -> None:
    """`04` §5's generation fallback would run a package manager on hostile input."""
    monkeypatch.setattr(oc.shutil, "which", lambda _: "/usr/bin/osv-scanner")
    inv = _inventory(("package.json", Role.PACKAGE_MANIFEST))
    result = oc.run_osv(tmp_path, inv)
    assert result.status is oc.OsvStatus.UNAVAILABLE
    assert result.score is None
    assert result.transitive_coverage is False
    assert "no lockfile" in result.reason


def test_groups_are_counted_once_however_many_aliases_they_have(
    tree, inv, monkeypatch
) -> None:
    """The alias double-count: 12 vulnerabilities, 6 groups, measured on jinja2.

    Scoring the vulnerability list instead would roughly double the deduction,
    scaling the false accusation with how well catalogued a CVE is.
    """
    vulns = [{"id": i, "affected": []} for i in
             ("PYSEC-2019-217", "GHSA-462w-v97r-4m45", "CVE-2019-10906")]
    groups = [{"ids": ["PYSEC-2019-217", "GHSA-462w-v97r-4m45"],
               "aliases": ["CVE-2019-10906"], "max_severity": "8.6"}]
    _fake_run(monkeypatch, _payload(tree, groups, vulns=vulns), returncode=1)
    result = oc.run_osv(tree, inv)
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].cve_id == "CVE-2019-10906"


def test_a_group_without_a_cvss_is_reported_and_counted_but_not_scored(
    tree, inv, monkeypatch
) -> None:
    groups = [
        {"ids": ["OSV-scored"], "aliases": [], "max_severity": "9.8"},
        {"ids": ["OSV-unscored"], "aliases": [], "max_severity": ""},
    ]
    _fake_run(monkeypatch, _payload(tree, groups), returncode=1)
    result = oc.run_osv(tree, inv)
    assert len(result.findings) == 2
    assert result.unscored_findings == 1
    assert result.score == 75  # only the scored one deducts


def test_the_fixed_version_is_recovered_from_the_affected_ranges(
    tree, inv, monkeypatch
) -> None:
    vulns = [{"id": "PYSEC-1", "affected": [
        {"ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}]
    groups = [{"ids": ["PYSEC-1"], "aliases": [], "max_severity": "8.6"}]
    _fake_run(monkeypatch, _payload(tree, groups, vulns=vulns), returncode=1)
    assert oc.run_osv(tree, inv).findings[0].fixed_version == "2.10.1"


def test_lockfile_paths_are_made_relative(tree, inv, monkeypatch) -> None:
    groups = [{"ids": ["PYSEC-1"], "aliases": [], "max_severity": "8.6"}]
    _fake_run(monkeypatch, _payload(tree, groups), returncode=1)
    assert oc.run_osv(tree, inv).findings[0].lockfile == "requirements.txt"


# --- against the real binary ----------------------------------------------


@needs_osv
def test_the_real_scanner_finds_known_vulnerable_dependencies(tmp_path: Path) -> None:
    """The positive control for every zero this module reports.

    `04` §5 specified `osv-scanner --format json --recursive`, which on v2 emits
    a walk log and no JSON at all — the third specified invocation in this
    repository that would have scanned nothing while reporting cleanly.
    """
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\nrequests==2.19.1\n")
    inv = _inventory(("requirements.txt", Role.LOCKFILE))
    result = oc.run_osv(tmp_path, inv)
    assert result.status is oc.OsvStatus.OK, result.reason
    assert result.findings, "osv-scanner reported nothing for known-bad versions"

    packages = {f.package for f in result.findings}
    assert {"jinja2", "requests"} <= packages

    # osv-scanner 2.6.0 resolves the transitive closure itself, so `requests`
    # pulls in urllib3 and idna. That is what makes the direct-vs-transitive
    # split in `03` §6 testable against real data rather than only against a
    # fake: the two named in requirements.txt are direct and the rest are not.
    direct = {f.package for f in result.findings if f.direct}
    transitive = {f.package for f in result.findings if not f.direct}
    assert direct == {"jinja2", "requests"}
    assert transitive, "no transitive dependencies resolved; the split is untested"
    assert not (direct & transitive)

    assert any(f.severity is Severity.HIGH for f in result.findings)
    assert all(f.scored for f in result.findings)
    assert result.score is not None and result.score < 100
    assert result.transitive_coverage is True


@needs_osv
def test_the_real_scanner_reports_a_clean_project_as_clean(tmp_path: Path) -> None:
    """The negative control: the fixture above must be able to come back empty."""
    (tmp_path / "requirements.txt").write_text("click==8.4.2\n")
    inv = _inventory(("requirements.txt", Role.LOCKFILE))
    result = oc.run_osv(tmp_path, inv)
    assert result.status is oc.OsvStatus.OK, result.reason
    assert result.findings == ()
    assert result.score == 100


@needs_osv
def test_a_repo_supplied_osv_scanner_toml_cannot_suppress_its_own_cves(
    tmp_path: Path,
) -> None:
    """The `.semgrepignore` hole, one module over — and it was open.

    osv-scanner discovers an `osv-scanner.toml` in the tree it is scanning and
    honours its `[[IgnoredVulns]]`. The scanned tree is a stranger's
    repository, so that is a server editing our audit of itself. Measured:
    6 vulnerability groups became 5 with a single entry.

    `HOSTILE_CONFIG_FILES` lives in `workers.excluded` precisely so this
    defence is not one scanner's private business; it was semgrep's alone, and
    the identical hole stayed open here for exactly as long.
    """
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\n")
    inv = _inventory(("requirements.txt", Role.LOCKFILE))

    clean = oc.run_osv(tmp_path, inv)
    assert clean.status is oc.OsvStatus.OK, clean.reason
    baseline = {f.osv_id for f in clean.findings}
    assert baseline, "no findings to suppress — control failed"

    victim = next(iter(baseline))
    (tmp_path / "osv-scanner.toml").write_text(
        f'[[IgnoredVulns]]\nid = "{victim}"\nreason = "not applicable"\n'
    )
    guarded = oc.run_osv(tmp_path, inv)

    assert guarded.status is oc.OsvStatus.OK, guarded.reason
    assert guarded.neutralised == ("osv-scanner.toml",)
    assert {f.osv_id for f in guarded.findings} == baseline, (
        "a repo-supplied config suppressed its own vulnerability"
    )
    assert not (tmp_path / "osv-scanner.toml").exists()
