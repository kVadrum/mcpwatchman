"""The public worked example must agree with the shipped scoring engine.

`site/src/pages/index.astro` renders a Code Safety ledger as the site's central
argument: a score opens at 100 and every deduction is traceable. That example is
hand-written prose sitting in a different language in a different directory, with
nothing tying it to `workers.scoring.composite` — so it can drift, and on
2026-09-14 it had: the second finding was labelled critical/MEDIUM while carrying
a critical/HIGH deduction, so the page's own arithmetic contradicted the engine
(-20 × 0.75 = 15 → axis 55, against the 48 displayed). An external reviewer
caught it, not us.

`base.md` § *Canonical homes* → *Judgment-call clause* is the shape: the lockstep
answer is YES — change the deduction table and this page must change — but there
is no symbol to import across the language boundary. So the contract is enforced
by reading the published file and recomputing it.
"""

from __future__ import annotations

import pathlib
import re
from datetime import UTC

import pytest

from mcpwatchman.workers.scoring.composite import (
    Confidence,
    Finding,
    Severity,
    axis_score,
)

PAGE = pathlib.Path(__file__).resolve().parents[1] / "site/src/pages/index.astro"

pytestmark = pytest.mark.skipif(
    not PAGE.is_file(), reason="site/ not present in this checkout"
)


def _published_score() -> int:
    m = re.search(r'data-count-to="(\d+)"', PAGE.read_text())
    assert m, "no data-count-to on the page — the ledger's shape changed"
    return int(m.group(1))


def _ledger_findings() -> list[Finding]:
    """Rebuild the example's findings from the labels the page actually shows.

    Reads the rendered `detail` strings rather than the numbers, deliberately:
    the defect was a label disagreeing with its own arithmetic, so a test that
    trusted the numbers would have agreed with the bug.
    """
    rows = re.findall(r'detail:\s*"([^"]*)"', PAGE.read_text())
    findings = []
    for detail in rows:
        low = detail.lower()
        sev = next(
            (s for s in Severity if s.value in low and s is not Severity.INFORMATIONAL),
            None,
        )
        if sev is None:
            continue  # not a finding row (the opening/total rows carry no severity)
        conf = next((c for c in Confidence if c.value in low.split("·")[1]), None) \
            if "·" in low else None
        if conf is None:
            continue
        findings.append(Finding(sev, conf))
    return findings


def test_the_page_parses_into_findings_at_all():
    """Guards the two tests below from passing vacuously if the page's shape
    changes and the regex silently matches nothing."""
    assert len(_ledger_findings()) == 2


def test_published_example_matches_the_shipped_engine():
    """The number on the public page must be the number the engine computes
    from the labels printed beside it."""
    assert axis_score(_ledger_findings()) == _published_score()


def test_mislabelling_the_confidence_would_change_the_answer():
    """Proves the test above is not vacuous — the exact defect that shipped.

    Had the second finding really been critical/medium as it was labelled, the
    axis would be 55, not 48. So the assertion discriminates rather than holding
    for any labelling.
    """
    as_labelled_wrongly = [
        Finding(Severity.CRITICAL, Confidence.HIGH),
        Finding(Severity.CRITICAL, Confidence.MEDIUM),
    ]
    assert axis_score(as_labelled_wrongly) == 55
    assert axis_score(as_labelled_wrongly) != _published_score()


# --- agent-readable surfaces (operator ruling 2026-09-14) ----------------
#
# `CLAUDE.md`: every surface must be fully and effectively readable by humans
# AND by agents. These pin the machine half, which is the half with no visual
# feedback — a broken `llms.txt` looks exactly like a working one.

# `PAGE` already lives under site/, so parents[2] IS the site root — appending
# "site" again pointed every check at site/site/ and made them all FileNotFound.
SITE = PAGE.parents[2]


def _public(name: str) -> pathlib.Path:
    return SITE / "public" / name


def test_llms_txt_follows_the_llmstxt_spec():
    """llmstxt.org: H1 (the only required section), then a blockquote summary,
    then prose WITHOUT headings, then H2 sections containing link lists. An
    earlier version put prose under H2s, which is the one structural rule the
    spec states outright."""
    text = _public("llms.txt").read_text()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert lines[0].startswith("# "), "first non-blank line must be the H1"
    assert lines[1].startswith("> "), "the H1 must be followed by a blockquote summary"

    # Every H2 section must contain at least one markdown link and no prose
    # paragraphs — that is what "file lists" means in the spec.
    sections = re.split(r"^## ", text, flags=re.M)[1:]
    assert sections, "expected at least one H2 section"
    for section in sections:
        body = [ln for ln in section.splitlines()[1:] if ln.strip()]
        assert body, "an H2 section must not be empty"
        assert all(ln.lstrip().startswith("-") for ln in body), (
            "H2 sections carry link lists only; prose belongs above the first H2"
        )
        assert any("](" in ln for ln in body), "each section needs a markdown link"


def test_llms_txt_states_that_no_scores_are_published():
    """The single most important fact for a machine reading this today. An agent
    that concludes scores exist would act on an assessment we have not made."""
    text = _public("llms.txt").read_text().lower()
    assert "no scores are published" in text


def test_robots_txt_blocks_nobody():
    """Operator ruling: no crawler is blocked, agents included. A stray
    `Disallow: /` would be invisible on the rendered site and total for agents."""
    text = _public("robots.txt").read_text()
    disallows = [
        ln for ln in text.splitlines()
        if ln.strip().lower().startswith("disallow:") and ln.split(":", 1)[1].strip()
    ]
    assert disallows == []
    assert "Allow: /" in text
    assert "Sitemap:" in text


def test_security_txt_has_the_fields_rfc9116_requires():
    """RFC 9116: `Contact` is required, and `Expires` "MUST always be present".
    A project publishing security assessments of other people's software owes a
    documented way to report problems in its own."""
    text = _public(".well-known/security.txt").read_text()
    assert re.search(r"^Contact:\s*\S+", text, re.M)
    assert re.search(r"^Expires:\s*\d{4}-\d{2}-\d{2}T", text, re.M)
    assert re.search(r"^Canonical:\s*https://", text, re.M)


def test_security_txt_has_not_expired_and_is_not_about_to():
    """An expired `Expires` makes the file invalid rather than merely stale, and
    nothing else in the project would notice the date passing. Fails 30 days
    early so the renewal is a chore rather than an incident."""
    from datetime import datetime, timedelta

    text = _public(".well-known/security.txt").read_text()
    raw = re.search(r"^Expires:\s*(\S+)", text, re.M).group(1)
    expires = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
    assert expires > datetime.now(UTC) + timedelta(days=30), (
        f"security.txt expires {expires.date()} — renew it"
    )


def test_the_page_carries_parseable_structured_data():
    """An agent parsing the HTML should not have to infer identity, licence and
    status from prose. Inline `application/ld+json` is a DATA BLOCK, not
    executable script, so the strict `script-src 'self'` does not block it —
    verified in a browser against the production CSP."""
    import json

    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    html = built.read_text()
    block = re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
    assert block, "no JSON-LD in the built page"
    data = json.loads(block.group(1))
    assert data["@type"] == "SoftwareApplication"
    assert data["isAccessibleForFree"] is True
    # The pre-v0.1 position must be machine-readable, not only in prose.
    assert "no scores are published" in data["abstract"].lower()


def test_no_html_comments_reach_the_reader():
    """Source comments explain decisions to whoever edits the file; they are not
    part of the response. Astro emits `<!-- -->` verbatim and drops `{/* */}`,
    and a paragraph of CSP rationale shipped to every visitor before this."""
    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    assert "<!--" not in built.read_text()


def test_security_txt_policy_points_at_a_real_anchor():
    """`Policy:` is a URL a machine follows. It pointed at a README heading that
    did not exist — a dangling reference is worse in a machine-readable file than
    in prose, because nothing renders visibly wrong."""
    text = _public(".well-known/security.txt").read_text()
    policy = re.search(r"^Policy:\s*(\S+)", text, re.M)
    assert policy, "security.txt should declare a Policy"
    fragment = policy.group(1).partition("#")[2]
    if not fragment:
        return  # no anchor to verify
    readme = (PAGE.parents[3] / "README.md").read_text()
    # GitHub derives an anchor from a heading: lowercased, spaces to hyphens.
    headings = {
        "".join(c for c in h.lower().replace(" ", "-") if c.isalnum() or c == "-")
        for h in re.findall(r"^#+\s+(.*)$", readme, re.M)
    }
    assert fragment in headings, f"security.txt Policy anchor #{fragment} has no heading"


# ── theme: the failures here are all SILENT ─────────────────────────────────
#
# Every invariant below has the same shape as the CSP one this file already
# guards: the page keeps rendering and only the correctness goes missing. A
# deferred theme script still works — one paint late. A token defined on one
# theme and not the other inherits a value from the wrong palette. A control
# that is not `hidden` in the markup appears for visitors whose browser never
# ran the script that makes it do anything.

THEME_TOKENS = (
    "--ground", "--ground-lift", "--panel", "--rule",
    "--ink", "--ink-dim", "--ink-faint",
    "--signal", "--signal-ink", "--signal-hover", "--signal-on", "--deduct",
    "--paper", "--paper-ink", "--paper-dim", "--paper-rule",
)


def _theme_block(selector: str) -> str:
    """The declarations inside the first rule whose selector matches.

    Returns the body, and REFUSES to return an empty one: a helper that answers
    "" for a selector it could not find turns every comparison below into a
    vacuous pass. It did exactly that when first written — two empty strings
    compared equal and the test reported green having read nothing.
    """
    source = PAGE.read_text()
    at = source.index(selector)
    start = source.index("{", at) + 1
    depth, out = 1, []
    for ch in source[start:]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        out.append(ch)
    body = "".join(out)
    assert "--" in body, f"no custom properties found for {selector!r}"
    return body


def test_the_theme_script_runs_before_the_first_paint():
    """`defer`, `async` or `type="module"` all move this AFTER first paint.

    Each one leaves a working theme switcher that flashes the wrong theme on
    every load — the exact defect the file exists to prevent, reintroduced by a
    change that looks like a performance improvement and breaks no test.
    """
    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    head = built.read_text().split("</head>")[0]
    tag = re.search(r'<script[^>]*src="/theme\.js"[^>]*>', head)
    assert tag, "theme.js must be loaded from <head> — after it, the theme flashes"
    assert "defer" not in tag.group(0)
    assert "async" not in tag.group(0)
    assert 'type="module"' not in tag.group(0), "a module is deferred by spec"


def test_no_inline_executable_script_survives_the_build():
    """The whole CSP claim rests on this, and Astro inlines small scripts by
    default. `application/ld+json` is a DATA block and is exempt; anything else
    with a body is blocked by `script-src 'self'` — silently."""
    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", built.read_text(), re.S):
        if "ld+json" in attrs:
            continue
        assert not body.strip(), f"inline script would be CSP-blocked: {attrs}"


def test_both_themes_define_the_same_tokens():
    """A token defined on one theme and missing on the other does not fail —
    it inherits the other palette's value, so a light page renders one dark
    element and nothing reports it."""
    dark = _theme_block("\n      :root {")
    light = _theme_block(':root[data-theme="light"]')
    missing_light = [t for t in THEME_TOKENS if f"{t}:" not in light]
    missing_dark = [t for t in THEME_TOKENS if f"{t}:" not in dark]
    assert not missing_dark, f"absent from the default theme: {missing_dark}"
    assert not missing_light, f"absent from the light theme: {missing_light}"


def test_the_explicit_light_theme_matches_the_system_light_theme():
    """Two blocks carry the light palette — the media query for a system
    preference, and the attribute for an explicit choice. They must agree, or
    picking "Light" gives a different page from having light set system-wide."""
    explicit = _theme_block(':root[data-theme="light"]')
    system = _theme_block(':root:not([data-theme="dark"])')

    def declarations(block: str) -> dict[str, str]:
        found = {}
        for line in block.split(";"):
            name, sep, value = line.partition(":")
            if sep and name.strip().startswith("--"):
                found[name.strip()] = value.strip()
        return found

    assert declarations(explicit) == declarations(system)


def test_the_theme_control_is_hidden_until_script_reveals_it():
    """With JavaScript off the CSS still follows `prefers-color-scheme`, so the
    page is correct — but the control cannot do anything. Shipping it visible
    offers an override that silently does nothing."""
    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    control = re.search(r"<fieldset[^>]*class=\"theme\"[^>]*>", built.read_text())
    assert control, "no theme control in the built page"
    assert "hidden" in control.group(0)


def test_every_theme_text_token_clears_AA_on_its_own_ground():
    """Measured, not eyeballed — the light palette exists only because
    `#e9a63f` is 1.39:1 on lit slate. A future tweak that drops a token below
    4.5:1 is invisible to every other test here."""

    def channel(c: float) -> float:
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(hex_colour: str) -> float:
        h = hex_colour.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)

    def contrast(a: str, b: str) -> float:
        la, lb = luminance(a), luminance(b)
        hi, lo = max(la, lb), min(la, lb)
        return (hi + 0.05) / (lo + 0.05)

    for selector in ("\n      :root {", ':root[data-theme="light"]'):
        block = _theme_block(selector)
        token = dict(
            re.findall(r"(--[a-z-]+):\s*(#[0-9a-fA-F]{6})", block)
        )
        ground = token["--ground"]
        for name in ("--ink", "--ink-dim", "--ink-faint", "--signal-ink", "--deduct"):
            ratio = contrast(token[name], ground)
            assert ratio >= 4.5, f"{selector} {name} is {ratio:.2f}:1 on {ground}"
        # The evidence document carries its own ink on its own paper.
        for name in ("--paper-ink", "--paper-dim"):
            ratio = contrast(token[name], token["--paper"])
            assert ratio >= 4.5, f"{selector} {name} is {ratio:.2f}:1 on paper"
        # Text on the amber CTA chip.
        assert contrast(token["--signal-on"], token["--signal"]) >= 4.5


def test_the_footer_carries_the_copyright_in_house_style():
    """`<owner> © <year>` — the workspace's footer form, not the LICENSE-file
    form (`Copyright (c) …`), which is reserved for the licence text itself."""
    source = PAGE.read_text()
    assert "KeMeK Network &copy; {year}" in source, "footer copyright missing"
    built = SITE / "dist" / "index.html"
    if not built.is_file():
        pytest.skip("site not built")
    assert re.search(r"KeMeK Network &copy; 20\d\d", built.read_text())
