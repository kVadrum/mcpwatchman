"""npm lifecycle scripts that run when a package is installed — listed Code Safety evidence.

An MCP server is usually started with `npx <package>`, and npm runs a package's
`preinstall`, `install` and `postinstall` scripts automatically during that
install: code from the publisher executes before any client has started the
server, outside whatever the client sandboxes. It is how several npm
supply-chain compromises executed, and it is also how many honest packages
build a native module — a script's presence is not a finding against anyone,
so each one is LISTED, never deducted (`CodeFinding.listed`), with the command
in the excerpt for the reader to judge.

`prepare` is left out on purpose: npm does not run it on a registry install,
and it is routinely `npm run build` or a git-hook installer, so listing it would
bury the hooks that do run.

Reads `package.json` through `inventory.read_manifest` (bounded, confined, and
whole or not at all — this is attacker-controlled input), never directly.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_manifest
from mcpwatchman.workers.scoring.composite import Confidence, Severity

if TYPE_CHECKING:  # semgrep_check imports this module, so the class arrives lazily
    from mcpwatchman.workers.scanner.semgrep_check import CodeFinding

RULE_ID = "mcp-npm-install-script"
INSTALL_HOOKS = ("preinstall", "install", "postinstall")

# A monorepo can hold many manifests; past this many the check stops reading.
# The bound is on the work, not the result (CLAUDE.md, attacker-controlled input).
MAX_MANIFESTS = 200
MAX_COMMAND_CHARS = 300

MESSAGE = (
    "This package.json declares an npm `{hook}` script, which npm runs "
    "automatically when the package is installed — for an MCP server started "
    "with npx, before any client has run it. Install scripts are how several "
    "npm supply-chain compromises executed, and also how many packages build "
    "native code; the command is in the excerpt."
)


def _line_of(text: str, hook: str) -> int:
    needle = f'"{hook}"'
    for n, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return n
    return 0


def install_script_findings(root: Path, inventory: Inventory) -> list[CodeFinding]:
    """One listed finding per install hook declared in a manifest of the tree."""
    from mcpwatchman.workers.scanner.semgrep_check import CodeFinding  # noqa: F811 - runtime import

    manifests = [f for f in inventory.files if PurePosixPath(f.path).name == "package.json"]
    out: list[CodeFinding] = []
    for record in manifests[:MAX_MANIFESTS]:
        text = read_manifest(root, record.path)
        if not text:
            continue
        try:
            manifest = json.loads(text)
        except (ValueError, RecursionError):
            continue
        scripts = manifest.get("scripts") if isinstance(manifest, dict) else None
        if not isinstance(scripts, dict):
            continue
        for hook in INSTALL_HOOKS:
            command = scripts.get(hook)
            if not isinstance(command, str) or not command.strip():
                continue
            line = _line_of(text, hook)
            shown = command[:MAX_COMMAND_CHARS] + ("…" if len(command) > MAX_COMMAND_CHARS else "")
            out.append(CodeFinding(
                rule_id=RULE_ID,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                message=MESSAGE.format(hook=hook),
                path=record.path,
                line=line,
                excerpt=f'"{hook}": {json.dumps(shown, ensure_ascii=False)}',
                mcp_pattern="install-script",
                cwe="CWE-829",
                in_test=record.role is Role.TEST,
                listed=True,
            ))
    return out


__all__ = ["INSTALL_HOOKS", "RULE_ID", "install_script_findings"]
