"""Outsider-steerable GitHub Actions: listed Code Safety evidence."""

from __future__ import annotations

from pathlib import Path

from mcpwatchman.workers.scanner import ci_workflows as ci
from mcpwatchman.workers.scanner.inventory import enumerate_tree


def _tree(tmp_path: Path, workflows: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "index.js").write_text("module.exports = 1;\n")
    for name, body in workflows.items():
        (root / ".github/workflows" / name).write_text(body)
    return root


def _found(root: Path) -> list[tuple[str, int]]:
    return [(f.rule_id, f.line) for f in ci.workflow_findings(root, enumerate_tree(root))]


INJECTED = """\
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.comment.body }}")
      - run: echo "${{ github.event.issue.number }} ${{ github.sha }}"
      - if: contains(github.event.issue.title, 'bug')
        run: echo labelled
      - uses: some/action@v1
        with:
          text: ${{ github.event.issue.body }}
"""


def test_outsider_text_in_a_script_is_listed_and_safe_fields_are_not(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"triage.yml": INJECTED})
    assert _found(root) == [(ci.INJECTION_RULE, 6), (ci.INJECTION_RULE, 10)]
    finding = ci.workflow_findings(root, enumerate_tree(root))[0]
    assert finding.listed and not finding.deducts
    assert "github.event.issue.title" in finding.excerpt


PWN = """\
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""


def test_pull_request_target_checking_out_the_head_is_listed(tmp_path: Path) -> None:
    assert _found(_tree(tmp_path, {"pr.yaml": PWN})) == [(ci.PWN_REQUEST_RULE, 10)]


def test_the_same_checkout_under_pull_request_is_not(tmp_path: Path) -> None:
    safe = PWN.replace("pull_request_target", "pull_request")
    assert _found(_tree(tmp_path, {"pr.yaml": safe})) == []


def test_a_workflow_outside_github_workflows_is_not_read(tmp_path: Path) -> None:
    root = _tree(tmp_path, {})
    (root / "docs").mkdir()
    (root / "docs/triage.yml").write_text(INJECTED)
    assert _found(root) == []


def test_malformed_or_exploding_yaml_lists_nothing_and_does_not_hang(tmp_path: Path) -> None:
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [*{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, "
        f"*{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}]\n"
        for i in range(9)
    )
    root = _tree(tmp_path, {"bad.yml": "on: [push\n", "bomb.yml": bomb, "list.yml": "- 1\n"})
    assert _found(root) == []


def test_the_line_is_the_script_not_an_earlier_harmless_mention(tmp_path: Path) -> None:
    body = """\
on: workflow_run
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_branch }}
      - run: |
          git push origin "${{ github.event.workflow_run.head_branch }}"
"""
    assert _found(_tree(tmp_path, {"fix.yml": body})) == [(ci.INJECTION_RULE, 10)]


def test_a_workflow_directory_nested_below_the_root_is_not_ci(tmp_path: Path) -> None:
    root = _tree(tmp_path, {})
    nested = root / "docs/vendored/.github/workflows"
    nested.mkdir(parents=True)
    (nested / "triage.yml").write_text(INJECTED)
    assert _found(root) == []
