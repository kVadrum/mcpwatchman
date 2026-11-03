"""Every reader of a scanned repository's manifests survives a hostile one.

A `package.json` of 100,000 `[` raised RecursionError out of
`inventory._entry_points`, and a top-level JSON array raised AttributeError out
of `osv_check.direct_dependencies` — either one ends that server's scan, and a
server whose scan always fails keeps a stale page forever: a publisher could
freeze their own. CLAUDE.md: a bound added to one path over attacker input is
owed to all the others, so every manifest reader is driven over the same files
here, and a new reader belongs in this list.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.ci_workflows import workflow_findings
from mcpwatchman.workers.scanner.install_scripts import install_script_findings
from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.license_check import license_facts
from mcpwatchman.workers.scanner.osv_check import direct_dependencies

DEEP = "[" * 100_000
HOSTILE_PACKAGE_JSON = [
    DEEP, "[1, 2, 3]", '"just a string"', "null",
    '{"dependencies": ["a", "b"], "license": 7, "scripts": "postinstall", "bin": 3}',
    '{"dependencies": {"1": "x"}, "peerDependencies": null, "main": ["index.js"]}',
]
HOSTILE_PYPROJECT = [
    "a = " + "[" * 50_000,
    'project = "not a table"',
    '[project]\ndependencies = "requests"\noptional-dependencies = ["x"]\n',
    '[tool]\npoetry = 3\n',
    '[tool.poetry.group]\ndev = "x"\n',
    '[project]\nlicense = 5\nscripts = 7\n',
]


@pytest.mark.parametrize("body", HOSTILE_PACKAGE_JSON + [None])
@pytest.mark.parametrize("pyproject", HOSTILE_PYPROJECT[:3] + [None])
def test_no_manifest_reader_raises_on_a_hostile_manifest(
    tmp_path: Path, body: str | None, pyproject: str | None,
) -> None:
    root = tmp_path / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "index.js").write_text("module.exports = 1;\n")
    if body is not None:
        (root / "package.json").write_text(body)
    if pyproject is not None:
        (root / "pyproject.toml").write_text(pyproject)
    (root / ".github/workflows/ci.yml").write_text(body or "on: push\n")
    inventory = enumerate_tree(root)
    direct_dependencies(root, inventory)
    license_facts(root, inventory)
    install_script_findings(root, inventory)
    workflow_findings(root, inventory)


@pytest.mark.parametrize("pyproject", HOSTILE_PYPROJECT[3:])
def test_wrong_types_deep_in_pyproject_read_as_nothing_declared(
    tmp_path: Path, pyproject: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.py").write_text("print(1)\n")
    (root / "pyproject.toml").write_text(pyproject)
    inventory = enumerate_tree(root)
    assert direct_dependencies(root, inventory) == set()
    license_facts(root, inventory)
