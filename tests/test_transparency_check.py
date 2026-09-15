"""Transparency detection and scoring (`04` §8, `03` §7)."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.transparency_check import (
    _SECURITY_CONTACT,
    README_MIN_BYTES,
    assess_transparency,
    documentation_facts,
    documents_disclosure_route,
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


# --- a disclosure ROUTE, not a mention of security -------------------------
#
# ⚠ Found by this repo's own /qa, 2026-09-15. `\bCVE\b`, `GPG` and `PGP` were
# alternatives in the contact pattern, so a CHANGELOG line reading "fixes
# CVE-2024-1234" and a README saying "we sign releases with GPG" each scored a
# full 100 on a sub-check worth 15% of Transparency — for a project offering no
# way to report anything. `03` §7 asks whether a finder can reach the maintainer
# privately, which neither fact answers.


@pytest.mark.parametrize(
    "readme_body",
    [
        "Fixes CVE-2024-1234 in the parser.",
        "We sign all releases with GPG.",
        "Signed with PGP keys available on request.",
        "This server had a security issue once.",
    ],
)
def test_mentioning_security_is_not_a_disclosure_route(
    tmp_path: Path, readme_body: str
) -> None:
    root = _tree(tmp_path, **{"README.md": readme_body + "\n" + "x" * 600})
    assert _sub(_axis(root), "security_contact").score == 0


@pytest.mark.parametrize(
    "readme_body",
    [
        "Report vulnerabilities to security@example.com",
        "Please report any security issue via our advisory page.",
        "See our responsible disclosure policy.",
        "File one at https://github.com/x/y/security/advisories/new",
        "Contact us about vulnerabilities at the address below.",
    ],
)
def test_a_real_disclosure_route_still_scores(tmp_path: Path, readme_body: str) -> None:
    root = _tree(tmp_path, **{"README.md": readme_body + "\n" + "x" * 600})
    assert _sub(_axis(root), "security_contact").score == 100


def test_a_generic_contact_address_is_not_a_disclosure_route(tmp_path: Path) -> None:
    # ⚠ Found by a negative control, 2026-09-15: the pattern accepted ANY email
    # address, so a support contact scored the full 15%. Worse, no positive test
    # exercised that arm — every one of them matched via a different
    # alternative — so the over-broad branch was both wrong and untested.
    root = _tree(tmp_path, **{
        "README.md": "Questions? Email me at hello@example.com\n" + "x" * 600})
    assert _sub(_axis(root), "security_contact").score == 0


def test_a_security_role_address_alone_is_a_disclosure_route(tmp_path: Path) -> None:
    # The arm the control found untested, now covered by a case that ONLY it
    # can match — no "report", no "disclosure", no advisory URL.
    root = _tree(tmp_path, **{"README.md": "security@example.com\n" + "x" * 600})
    assert _sub(_axis(root), "security_contact").score == 100


# --- regressions from the 2026-09-15 Deep review ---------------------------


def test_disclosure_pattern_stays_linear_on_a_hostile_readme() -> None:
    """⚠ A guard against reintroducing catastrophic backtracking.

    An intermediate form of `_SECURITY_CONTACT` accepted any address via
    `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}`, whose two `+` runs both
    contain `.` and are therefore mutually ambiguous. Measured by the reviewer at
    **84 seconds on a 200 KB README** — and `read_text` hands these patterns up
    to 512 KB of attacker-controlled text against `04` §9's 15-minute scan
    budget, so one hostile registry entry stalls the nightly batch.

    Narrowing to role addresses removed the ambiguity as a side effect of a
    correctness fix. This test is what stops a future widening from quietly
    bringing it back.
    """
    import time

    payload = "security@" + "a." * 40_000  # never terminates in [A-Za-z]{2,}
    started = time.monotonic()
    _SECURITY_CONTACT.search(payload)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"pattern took {elapsed:.1f}s on {len(payload)} chars"


@pytest.mark.parametrize(
    "readme_body",
    ["## Environment Variables\n\nSet things.", "## Config File", "Create a .env file"],
)
def test_configuration_headings_match_regardless_of_case(
    tmp_path: Path, readme_body: str
) -> None:
    # `_CONFIG_SIGNALS` was the only doc regex without IGNORECASE, so the two
    # commonest heading forms missed and cost a +25 band.
    root = _tree(tmp_path, **{"README.md": readme_body + "\n" + "x" * 600})
    assert "configuration documented" in score_readme(_facts(root)).evidence[0]


@pytest.mark.parametrize("name", ["CHANGES.rst", "HISTORY.rst", "NEWS.txt", "CHANGELOG.md"])
def test_changelog_is_found_whatever_its_extension(tmp_path: Path, name: str) -> None:
    # ⚠ `_find` searched for changes/history/news but `inventory._DOC_PREFIXES`
    # only routed those to Role.DOCS when the file was `.md`, so a Python project
    # shipping CHANGES.rst scored 0 with the evidence "no CHANGELOG in the
    # fetched source" — one rule, two enforcers, silently disagreeing.
    root = _tree(tmp_path, **{name: "## 1.0\n", "README.md": "x" * 600})
    assert _sub(_axis(root), "changelog").score == 100


# ── Codex leg 2: a negated mention is not a disclosure route ────────────────

@pytest.mark.parametrize("sentence", [
    "No security policy is currently provided.",
    "This project does not have a security policy.",
    "We have no responsible disclosure process yet.",
    "There is no security.txt for this server.",
])
def test_a_negated_security_mention_scores_zero(tmp_path: Path, sentence) -> None:
    """`security polic` matched the NEGATION of having one.

    Reproduction verbatim from the finding: the sub-check reported a private
    reporting channel — 15% of Transparency — for a README stating in the same
    sentence that none exists, which is the falsest direction available on this
    axis because a finder is told a route is there.
    """
    root = _tree(tmp_path, **{"README.md": FULL_README + "\n## Security\n\n" + sentence})
    facts = documentation_facts(root, enumerate_tree(root))
    from mcpwatchman.workers.scanner.transparency_check import score_security_contact
    assert score_security_contact(facts).score == 0


def test_a_negated_clause_does_not_suppress_a_real_route(tmp_path: Path) -> None:
    """The control, and the reason the check is per-MATCH rather than per-document.

    Both readings occur in one README, and this phrasing is the conventional
    one: a prohibition on public reporting followed by the private address. A
    document-wide negation test would score this 0 — a false accusation
    manufactured by the fix for the false reassurance.
    """
    readme = (FULL_README + "\n## Security\n\n"
              "Please do not report vulnerabilities in public issues; "
              "email security@example.com instead.\n")
    root = _tree(tmp_path, **{"README.md": readme})
    facts = documentation_facts(root, enumerate_tree(root))
    from mcpwatchman.workers.scanner.transparency_check import score_security_contact
    assert score_security_contact(facts).score == 100


def test_the_negation_check_stays_linear_on_a_hostile_readme() -> None:
    """The SECOND way this sub-check could be stalled by a README, found by
    timing it rather than by reading it.

    The clause-scoped negation test was written as a rescan from offset 0 per
    match — O(matches × text). Measured before the fix: 0.08s / 0.86s / 13.8s
    for 2k / 8k / 32k negated matches, 16× the time for 4× the input.

    It needs EVERY match negated to bite, because one clean match
    short-circuits the `any`. That makes the pathological input a README which
    mentions security policies and denies all of them — free to write, and
    indistinguishable from an honest "we have no security policy" page.

    Same consequence as the backtracking guard above (`04` §9's 15-minute
    budget, spent on one server) reached by a different mechanism, which is why
    it needs its own test: the regex here is fine.
    """
    import time

    text = "There is no security policy here " * 32_000  # ~1 MB, all negated
    started = time.monotonic()
    result = documents_disclosure_route(text)
    elapsed = time.monotonic() - started
    assert result is False, "every mention is negated; none is a route"
    assert elapsed < 1.0, f"negation check took {elapsed:.1f}s on {len(text)} chars"


def test_the_linear_negation_check_kept_the_original_semantics() -> None:
    """Indexing and bisecting must not change WHICH matches count as negated —
    the failure a pure-performance fix makes invisibly."""
    negated = [
        "No security policy is currently provided.",
        "We have no responsible disclosure process.",
    ]
    routes = [
        "Report a security issue to security@example.com.",
        "Do not open a public issue; email security@example.com instead.",
        "See our responsible disclosure policy.",
    ]
    for text in negated:
        assert documents_disclosure_route(text) is False, text
    for text in routes:
        assert documents_disclosure_route(text) is True, text
    # A negated clause followed by a real route in the same document.
    assert documents_disclosure_route(negated[0] + " " + routes[0]) is True


@pytest.mark.parametrize("text,expected", [
    # ⚠ THE REGRESSION: a route starting at the first character after a newline.
    # The break's stored end() EQUALS match.start(), and `bisect_left` excluded
    # that boundary — so the clause was taken to start on the PREVIOUS line and
    # its negation carried forward. A README saying "don't report publicly" and
    # then giving the address scored 0 for having no disclosure contact.
    ("Do not report publicly\nsecurity@example.com", True),
    ("Please do not open an issue\nEmail security@example.com", True),
    # The same shape with a space after the separator, which is what the
    # original semantics test used — and why it never reached the boundary.
    ("Do not report publicly. security@example.com", True),
    ("Do not open a public issue; email security@example.com instead.", True),
    # Genuine negations must still score 0.
    ("No security policy is currently provided.", False),
    ("There is no security.txt for this server.", False),
])
def test_a_clause_boundary_landing_ON_the_match_is_not_a_negation(text, expected) -> None:
    """The off-by-one the linearity rewrite introduced, in both directions.

    The per-match rescan it replaced handled this correctly, so the claim that
    the bisect version "preserved semantics" was false — and the test making
    that claim used a separator followed by a SPACE, which by construction never
    lands on the boundary case. Written from the reproduction this time.
    """
    assert documents_disclosure_route(text) is expected
