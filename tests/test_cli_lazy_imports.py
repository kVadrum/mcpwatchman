"""The CLI startup path imports `click` and stdlib only (`CLAUDE.md`).

A tool people run *before* installing something gets run often, so startup cost
is a feature. `STATE.md`'s `/fp` baseline measured 103 modules and ~32 ms, and
predicted the contract "WILL regress the moment `check` is implemented, because
the obvious way to write it puts a network stack and a rendering library in the
startup path of `--help`". Nothing enforced it until now.

⚠ **This is a STATIC check, deliberately, and the reason is instrument parity.**
The natural test — import the CLI and inspect `sys.modules` — is only meaningful
where the heavy dependencies are actually installed. CI installs `.[dev]` alone,
so `httpx`, `sqlalchemy`, `fastapi` and friends are absent there and a
`sys.modules` assertion passes *because nothing could have been imported*: a
green that cannot predict the thing it guards. Reading the module's AST tests
the same contract identically whether or not anything is installed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

CLI_DIR = Path(__file__).resolve().parent.parent / "src" / "mcpwatchman" / "cli"

# `CLAUDE.md` names these explicitly; the rest are the transitive heavyweights
# that would arrive with them.
FORBIDDEN_AT_MODULE_LEVEL = frozenset({
    "httpx", "pydantic", "pydantic_settings", "rich", "sqlalchemy", "fastapi",
    "uvicorn", "alembic", "procrastinate", "psycopg", "semgrep", "detect_secrets",
})

# The scanner and worker packages pull the heavy stack by design; importing one
# from the CLI's module level imports the stack with it.
FORBIDDEN_INTERNAL_PREFIXES = ("mcpwatchman.workers", "mcpwatchman.db", "mcpwatchman.api")


def _module_level_imports(tree: ast.Module) -> list[tuple[str, int]]:
    """Every module name imported at MODULE level, with its line number.

    Imports nested inside a function or class body are the whole point of the
    contract, so only `tree.body` is walked — not `ast.walk`, which would
    descend into exactly the command functions where heavy imports belong.
    """
    found: list[tuple[str, int]] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module, node.lineno))
    return found


def _cli_modules() -> list[Path]:
    return sorted(CLI_DIR.rglob("*.py"))


def test_the_cli_package_exists() -> None:
    # A positive control: if the glob silently found nothing, every test below
    # would pass vacuously.
    assert _cli_modules(), f"no CLI modules found under {CLI_DIR}"


@pytest.mark.parametrize("path", _cli_modules(), ids=lambda p: p.name)
def test_no_heavy_third_party_import_at_module_level(path: Path) -> None:
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = [
        (name, line)
        for name, line in _module_level_imports(tree)
        if name.split(".")[0] in FORBIDDEN_AT_MODULE_LEVEL
    ]
    assert not offenders, (
        f"{path.name} imports {offenders} at module level. Heavy dependencies go "
        "INSIDE the command function — see CLAUDE.md and STATE.md's /fp baseline."
    )


@pytest.mark.parametrize("path", _cli_modules(), ids=lambda p: p.name)
def test_no_worker_or_db_import_at_module_level(path: Path) -> None:
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = [
        (name, line)
        for name, line in _module_level_imports(tree)
        if name.startswith(FORBIDDEN_INTERNAL_PREFIXES)
    ]
    assert not offenders, (
        f"{path.name} imports {offenders} at module level. `workers`, `db` and "
        "`api` pull the heavy stack transitively, so importing one from the CLI's "
        "module level defeats the lazy contract just as directly."
    )


def test_the_check_catches_a_module_level_heavy_import(tmp_path: Path) -> None:
    # Positive control for the instrument itself: prove it fires. Without this,
    # a bug in `_module_level_imports` reports every file clean forever.
    sample = tmp_path / "offender.py"
    sample.write_text("import click\nimport httpx\n\n\ndef cmd():\n    import rich\n")
    names = [n for n, _ in _module_level_imports(ast.parse(sample.read_text()))]
    assert "httpx" in names          # module level — caught
    assert "rich" not in names       # inside a function — allowed, and not flagged
