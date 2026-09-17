"""Every third-party module we import must be a module we asked for.

⚠ **Written after every CI run from `v0.16.0` to `v0.19.0` failed for the same
reason, unnoticed for a day.** `semgrep_check` imports `yaml` at module level
and nothing declared PyYAML — it arrived transitively, because `semgrep`
happens to depend on it, and the `workers` extra is where semgrep lives. So the
local suite was green (that venv had the extra) while the `test` CI job died at
COLLECTION with `ModuleNotFoundError`.

This is the same shape as the `pgqueuer` driver already recorded in CLAUDE.md:
a package we import must be a package we ask for. An upstream dropping a
dependency then breaks us for a reason that looks unrelated to anything we did.

The check is deliberately structural rather than a list someone maintains: it
reads the imports out of the source and compares them against what the manifest
declares, so a new undeclared import fails here rather than in CI a day later.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "mcpwatchman"

# Distribution name -> the module name it actually installs, where they differ.
_DISTRIBUTION_MODULES = {
    "pyyaml": "yaml",
    "psycopg": "psycopg",
    "uvicorn": "uvicorn",
    "python-multipart": "multipart",
    "types-pyyaml": "yaml",
    "pydantic-settings": "pydantic_settings",
}


def _declared_modules() -> set[str]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = config["project"]
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)

    modules: set[str] = set()
    for spec in specs:
        # "pgqueuer[psycopg]>=1.4" -> "pgqueuer"
        name = spec.split(";")[0].split("[")[0]
        for sep in (">=", "<=", "==", "~=", "!=", ">", "<", " "):
            name = name.split(sep)[0]
        name = name.strip().lower()
        modules.add(_DISTRIBUTION_MODULES.get(name, name.replace("-", "_")))
    return modules


def _module_level_imports(path: Path) -> set[str]:
    """Top-level third-party roots imported by a file.

    Module level only: an import inside a function is a deliberate deferral
    (the CLI's lazy-import contract depends on exactly that) and cannot break
    collection.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def _third_party(modules: set[str]) -> set[str]:
    return {
        m for m in modules
        if m not in sys.stdlib_module_names and m != "mcpwatchman"
    }


SOURCES = sorted(SRC.rglob("*.py"))


def test_there_are_sources_to_check() -> None:
    """The positive control: every assertion below is vacuous on an empty list."""
    assert len(SOURCES) >= 10


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(SRC)))
def test_every_module_level_import_is_declared(path: Path) -> None:
    declared = _declared_modules()
    undeclared = sorted(_third_party(_module_level_imports(path)) - declared)
    assert not undeclared, (
        f"{path.relative_to(ROOT)} imports {', '.join(undeclared)} at module "
        "level, and pyproject.toml declares neither. It may work today through "
        "a transitive dependency; it will stop working the day that upstream "
        "drops it, and it already breaks any environment installing a narrower "
        "extra."
    )


def test_the_check_can_actually_fail() -> None:
    """A gate that cannot fire is worse than no gate — so fire it on purpose."""
    assert _third_party({"yaml", "os", "mcpwatchman"}) == {"yaml"}
    assert "yaml" in _declared_modules(), "PyYAML is imported and must be declared"
    assert _third_party({"definitely_not_a_real_package"}) - _declared_modules()
