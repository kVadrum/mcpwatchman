"""Transparency detection and scoring (`04` §8, `03` §7)."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.transparency_check import (
    README_MIN_BYTES,
    assess_transparency,
    documentation_facts,
    score_declared_scopes,
    score_readme,
)

FULL_README = """# weatherbot

`weatherbot` is an MCP server that provides current weather for a named city.

## Installation

```bash
npm install weatherbot
```

Set the `WEATHER_API_KEY` environment variable.

## Tools

- `get_weather` — read-only; makes outbound requests to api.weather.example.
"""


def _tree(tmp_path: Path, **files: str) -> Path:
    for name, body in files.items():
        target = tmp_path / name.replace("__", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return tmp_path


def _facts(root: Path):
    return documentation_facts(root, enumerate_tree(root))


def _axis(root: Path):
    return assess_transparency(root, enumerate_tree(root))


def _sub(axis, name):
    return next(s for s in axis.subchecks if s.name == name)


# ── README quality ──────────────────────────────────────────────────────────

def test_short_readme_scores_zero_regardless_of_content(tmp_path: Path) -> None:
    # `03` §7's floor is unconditional: under 500 bytes is 0 even if every
    # other heuristic would have matched.
    root = _tree(tmp_path, **{"README.md": "## Installation\n```sh\nnpm i\n```\n"})
    result = score_readme(_facts(root))
    assert result.score == 0
    assert str(README_MIN_BYTES) in result.evidence[0]


def test_missing_readme_scores_zero(tmp_path: Path) -> None:
    assert score_readme(_facts(_tree(tmp_path, **{"x.py": "1"}))).score == 0


def test_complete_readme_earns_every_component(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": FULL_README + "x" * 400})
    result = score_readme(_facts(root))
    assert result.score == 100  # 25 + 25 + 30 + 20


def test_install_heading_without_a_code_fence_earns_nothing(tmp_path: Path) -> None:
    # `03` §7's heuristic is a fence NEAR an install heading, not the heading.
    body = "# x\n\nThis is an MCP server that does things.\n\n## Installation\n\nSomehow.\n"
    root = _tree(tmp_path, **{"README.md": body + "x" * 500})
    assert score_readme(_facts(root)).score == 20  # purpose only


def test_readme_score_caps_at_one_hundred(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": (FULL_README * 3) + "x" * 400})
    assert score_readme(_facts(root)).score == 100


def test_vendored_readme_does_not_stand_in_for_the_root_one(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "node_modules__dep__README.md": FULL_README + "x" * 400,
        "README.md": "# tiny\n",
    })
    assert score_readme(_facts(root)).score == 0


# ── declared scopes: the one-directional sub-check ──────────────────────────

def test_specific_scope_documentation_abstains_rather_than_claiming_complete(
    tmp_path: Path,
) -> None:
    # ⚠ `03` §7's 100 band is "all INFERRED scopes are documented" and nothing
    # infers scopes yet. Scoring 100 would be a vacuous truth over an empty
    # inference — a confident positive from a probe that tested nothing.
    root = _tree(tmp_path, **{"README.md": FULL_README + "x" * 400})
    result = score_declared_scopes(_facts(root))
    assert result.score is None
    assert "vacuous" in result.reason


def test_vague_capability_language_is_the_thirty_band(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": "# x\n\nIt manages your files.\n" + "y" * 500})
    assert score_declared_scopes(_facts(root)).score == 30


def test_no_scope_documentation_is_zero(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": "# x\n\nA server.\n" + "y" * 500})
    assert score_declared_scopes(_facts(root)).score == 0


def test_manifest_counts_as_scope_documentation(tmp_path: Path) -> None:
    # `03` §7 accepts README *or* server.json.
    root = _tree(tmp_path, **{
        "README.md": "# x\n" + "y" * 500,
        "server.json": '{"description": "read-only access to the filesystem"}',
    })
    assert score_declared_scopes(_facts(root)).score is None


# ── changelog and security contact ──────────────────────────────────────────

def test_changelog_presence(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"CHANGELOG.md": "## 1.0\n", "README.md": "x" * 600})
    assert _sub(_axis(root), "changelog").score == 100


def test_absent_changelog_names_the_credit_it_could_not_check(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": "x" * 600})
    result = _sub(_axis(root), "changelog")
    assert result.score == 0
    assert "forge API" in result.evidence[0]


def test_security_md_or_a_readme_contact_both_count(tmp_path: Path) -> None:
    with_file = _tree(tmp_path / "a", **{"SECURITY.md": "mail us\n", "README.md": "x" * 600})
    assert _sub(_axis(with_file), "security_contact").score == 100

    in_readme = _tree(tmp_path / "b",
                      **{"README.md": "Report issues to security@example.com\n" + "x" * 600})
    assert _sub(_axis(in_readme), "security_contact").score == 100


def test_no_disclosure_route_is_zero(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": "A nice server.\n" + "x" * 600})
    assert _sub(_axis(root), "security_contact").score == 0


# ── the axis ────────────────────────────────────────────────────────────────

def test_no_source_abstains_on_every_subcheck() -> None:
    # Zero would report "documents nothing" about a repository nobody opened.
    axis = assess_transparency()
    assert axis.score is None
    assert axis.assessed_weight == Decimal(0)
    assert len(axis.unassessed) == 5


def test_bare_repository_scores_zero_on_a_fully_assessed_axis(tmp_path: Path) -> None:
    # The contrast with the test above: here we DID look, and found nothing.
    root = _tree(tmp_path, **{"README.md": "# x\n", "server.py": "print(1)\n"})
    axis = _axis(root)
    assert axis.score == 0
    assert axis.fully_assessed


def test_well_documented_repository(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "README.md": FULL_README + "x" * 400,
        "LICENSE": "SPDX-License-Identifier: MIT\n\nPermission is hereby granted, "
                   "free of charge, to any person obtaining a copy\n",
        "package.json": '{"license": "MIT"}',
        "CHANGELOG.md": "## 1.0\n",
        "SECURITY.md": "security@example.com\n",
    })
    axis = _axis(root)
    assert axis.score == 100
    # declared_scopes abstained, so the axis is scored on 80% of its weight.
    assert axis.assessed_weight == Decimal("0.80")
