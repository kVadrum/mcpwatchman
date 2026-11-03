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
import os
import subprocess
import sys
from pathlib import Path

import pytest

CLI_DIR = Path(__file__).resolve().parent.parent / "src" / "mcpwatchman" / "cli"

# `CLAUDE.md` names these explicitly; the rest are the transitive heavyweights
# that would arrive with them.
FORBIDDEN_AT_MODULE_LEVEL = frozenset({
    "httpx", "pydantic", "pydantic_settings", "rich", "sqlalchemy", "fastapi",
    "uvicorn", "alembic", "pgqueuer", "psycopg", "semgrep", "detect_secrets",
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


# The command modules, and the stdlib modules only they need. `--help` and the
# startup of any OTHER command must load none of them: a command's module is
# imported inside its own function in `main`, never at `main`'s module level.
COMMAND_MODULES = (
    "mcpwatchman.cli.api", "mcpwatchman.cli.check", "mcpwatchman.cli.info",
    "mcpwatchman.cli.listing", "mcpwatchman.cli.trend", "mcpwatchman.cli.feeds",
    "mcpwatchman.cli.badge",
)
COMMAND_ONLY_STDLIB = ("urllib.request", "http.client", "ssl", "xml.etree.ElementTree", "json")
COMMANDS = ("check", "info", "list", "trend", "feed", "badge")


def test_main_imports_no_command_module_at_module_level() -> None:
    tree = ast.parse((CLI_DIR / "main.py").read_text())
    offenders = [n for n, _ in _module_level_imports(tree) if n in COMMAND_MODULES]
    assert not offenders, f"main.py imports {offenders} at module level"


def test_every_command_module_exists() -> None:
    # Positive control: a renamed module would make the checks below vacuous.
    for module in COMMAND_MODULES:
        assert (CLI_DIR / f"{module.rsplit('.', 1)[1]}.py").is_file(), module


def _loaded_after(code: str) -> set[str]:
    env = {**os.environ, "PYTHONPATH": str(CLI_DIR.parent.parent)}
    out = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", code + "\nimport sys; print('\\n'.join(sorted(sys.modules)))"],
        capture_output=True, text=True, env=env, check=True,
    ).stdout
    return set(out.splitlines())


@pytest.mark.parametrize("command", COMMANDS)
def test_help_for_each_command_loads_no_command_module(command: str) -> None:
    """Runtime twin of the AST checks, and sound where the module docstring's
    `sys.modules` caveat bites: every module looked for here is stdlib or our
    own, present wherever the suite runs, so absence means "not imported",
    never "not installed"."""
    loaded = _loaded_after(
        "from mcpwatchman.cli.main import cli\n"
        f"cli.main([{command!r}, '--help'], standalone_mode=False)"
    )
    assert "mcpwatchman.cli.main" in loaded  # the probe ran
    leaked = sorted(loaded & set(COMMAND_MODULES + COMMAND_ONLY_STDLIB))
    assert not leaked, f"`{command} --help` imported {leaked}"


def test_the_runtime_probe_sees_a_command_module_once_loaded() -> None:
    # Positive control for the probe: importing a command module DOES show.
    loaded = _loaded_after("import mcpwatchman.cli.feeds")
    assert {"mcpwatchman.cli.feeds", "xml.etree.ElementTree", "urllib.request"} <= loaded
