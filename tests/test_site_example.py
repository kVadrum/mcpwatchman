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
