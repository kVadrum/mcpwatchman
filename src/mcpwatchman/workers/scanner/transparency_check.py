"""Transparency detection and scoring (`04` §8, `03` §7).

Presence checks and content heuristics over the documentation a server ships,
assembled into the Transparency axis along with `license_check`'s sub-check.
`04` §8 is explicit that none of this involves an LLM or content
interpretation — they are cheap, deterministic regex passes, and their
cheapness is why the axis can run on every server every night.

⚠ **This module is not in `02` §208's file map, and neither is the phase it
implements.** The map names `license_check.py` — Transparency's license
sub-check — and nothing for §8's other four. Folding them into `license_check`
would make a license module that mostly does not concern licenses; folding them
into `runner.py` would make the orchestrator a grab-bag. `04` §8 describes a
distinct detector and this is it. Same deviation, and the same reasoning, as
`inventory.py` records for itself.

⚠ **Declared scopes is scored in one direction only, and it is worth knowing
why before reading a number from it.** `03` §7 puts its two upper bands (100:
"all inferred scopes are documented"; 60: "some documented, additional
capabilities exist in code") on a comparison against scopes inferred by static
analysis — and static analysis is not built yet. Its two lower bands (30:
"vague terms"; 0: "no scope documentation") are judgements about the
documentation alone, and those we can make today. So a server documenting
nothing scores 0 and a server documenting specifically is UNASSESSED, because
claiming its documentation is *complete* without having inferred anything to
compare against is a vacuous truth — "all ∅ inferred scopes are documented" —
and vacuous truths are how a probe returns a confident positive having tested
nothing. The sub-check therefore only ever subtracts until `semgrep_check`
lands. Recorded here rather than left as a surprise in the data.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_text
from mcpwatchman.workers.scanner.license_check import assess_license
from mcpwatchman.workers.scanner.reachability import SourceAvailability
from mcpwatchman.workers.scoring.axes import AxisResult, SubCheck, score_axis

AXIS = "transparency"

# `03` §7: "Does the README exist and exceed 500 bytes? (Otherwise 0.)"
README_MIN_BYTES = 500

# `03` §7: "Does it explain what the server does in the first 200 words?"
INTRO_WORDS = 200

_INSTALL_HEADING = re.compile(
    r"^#{1,6}\s*.*\b(install|installation|setup|getting started|quick ?start)\b",
    re.IGNORECASE | re.MULTILINE,
)
_CODE_FENCE = re.compile(r"^```", re.MULTILINE)
# ⚠ SPLIT BY CASE, and the split is the point — a blanket `IGNORECASE` would be
# wrong. This was the only doc regex in the file without the flag, so
# `## Environment Variables` and `## Config File` both missed and cost a +25
# band. But the env-var alternative below depends on case: lowercased, it would
# match any `word_key` identifier. So the prose arms get the flag and the
# SCREAMING_CASE arm does not.
#
# `\.env\b` also could not match after a space: `\b` before a literal `.`
# requires a preceding word character, so "Create a .env file" never matched.
_CONFIG_SIGNALS_PROSE = re.compile(
    r"\b(?:environment variables?|env vars?|configuration|config file|"
    r"claude_desktop_config|mcpServers)\b"
    r"|(?:^|[\s(`'\"])\.env\b",
    re.IGNORECASE | re.MULTILINE,
)
_CONFIG_SIGNALS_ENVVAR = re.compile(r"\b[A-Z][A-Z0-9]*_(?:KEY|TOKEN|SECRET|URL|PATH|ID)\b")
_TOOLS_HEADING = re.compile(
    r"^#{1,6}\s*.*\b(tools?|resources?|prompts?|capabilit(?:y|ies)|commands?)\b",
    re.IGNORECASE | re.MULTILINE,
)
# What the server DOES, stated up front — `03` §7's first-200-words check.
_PURPOSE_VERBS = re.compile(
    r"\b(is an? |provides?|lets? you|allows?|exposes?|gives?|enables?|"
    r"connects?|integrat\w+|server for|mcp server)\b",
    re.IGNORECASE,
)

# Scope vocabulary: the side effects and access a server declares (`03` §7).
_SPECIFIC_SCOPES = re.compile(
    r"\b(read-only|read only|write access|read/write|filesystem access|"
    r"network access|outbound request|api calls? to|sends? data to|"
    r"stores? (?:data|credentials)|requires? access to|scopes?:|permissions?:|"
    r"only accesses|does not (?:read|write|send|store)|sandbox)\b",
    re.IGNORECASE,
)
_VAGUE_SCOPES = re.compile(
    r"\b(manages? (?:your )?files|does file stuff|works with your data|"
    r"handles? (?:your )?data|interacts? with)\b",
    re.IGNORECASE,
)

# ⚠ **A disclosure ROUTE, not a mention of security.** `\bCVE\b`, `GPG` and
# `PGP` used to be alternatives here, and each produced a false 100 on a
# sub-check worth 15% of Transparency: a CHANGELOG line reading "fixes
# CVE-2024-1234" and a README saying "we sign releases with GPG" both scored as
# a documented disclosure contact for a project offering no way to report
# anything. `03` §7 asks whether a finder can reach the maintainer privately, so
# the pattern now needs an address or an actual instruction to report.
_SECURITY_CONTACT = re.compile(
    # ⚠ A ROLE address only — not any address. A generic `foo@example.com` for
    # support questions is a contact, not a DISCLOSURE contact, and matching it
    # awarded the full 15% to any README carrying an email. A README that does
    # say "report vulns to foo@bar.com" still scores, via the report arm below.
    r"(?:(?:security|secure|abuse|psirt|cve)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|responsible disclosure|coordinated disclosure|security polic"
    r"|security\.txt|/security/advisories|report (?:a |any )?"
    r"(?:security |vulnerabilit)"
    r"|(?:report|disclose|contact)[^.\n]{0,40}(?:vulnerabilit|security issue))",
    re.IGNORECASE,
)

# ⚠ **A NEGATED mention is not a route**, and the fix that narrowed the pattern
# to real disclosure vocabulary made this reachable rather than introducing it.
# "No security policy is currently provided" contains `security polic` and
# scored the full 100 — the sub-check reporting a private reporting channel for
# a project stating in the same sentence that it has none. Worth 15% of
# Transparency, and the falsest direction available on this axis: a finder is
# told a route exists.
#
# Checked per MATCH rather than over the document, because both readings occur
# in one README. "Do not report vulnerabilities in public issues; email
# security@example.com" negates its first clause and still documents a route —
# so a single un-negated match is enough, and only a document where EVERY match
# is negated scores 0.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|none|never|lacks?|lacking|missing|without|absent|neither|"
    r"don'?t|doesn'?t|isn'?t|aren'?t|hasn'?t|haven'?t|yet to)\b",
    re.IGNORECASE,
)
# Clause boundaries. A negation binds within its own clause: the `;` in the
# example above is what makes the second half an independent instruction.
_CLAUSE_BREAK = re.compile(r"[.;:!?\n]")


def documents_disclosure_route(text: str) -> bool:
    """Whether the text gives a finder a way to report privately (`03` §7).

    ⚠ **Indexed once and bisected, NOT rescanned per match — the obvious form is
    QUADRATIC on a README an attacker writes.** Scanning back from each match to
    find its clause start, and again for a negation inside it, is O(matches ×
    text): measured before the fix at 0.08s / 0.86s / 13.8s for 2k / 8k / 32k
    negated matches, i.e. 16× the time for 4× the input. It needs every match
    negated to bite, because a single clean match short-circuits — so the
    pathological input is a README that mentions security policies and denies
    all of them, which costs nothing to write.

    `read_text` caps a README at 512 KB, so this could not hang the worker
    outright; it could spend a large slice of `04` §9's 15-minute budget on one
    server. Same shape as the catastrophic-backtracking finding this module
    already carries a timing guard for, reached by a different route — a
    per-match rescan rather than a regex.

    Both positions lists are built in one pass and searched by bisection, which
    is exact: no lookback window, no change in which matches count as negated.
    """
    matches = _SECURITY_CONTACT.finditer(text)
    first = next(matches, None)
    if first is None:
        return False

    # Built only once a match exists — a README with no disclosure vocabulary at
    # all is the common case and pays for neither scan.
    clause_ends = [m.end() for m in _CLAUSE_BREAK.finditer(text)]
    negations = [m.start() for m in _NEGATION_RE.finditer(text)]

    for match in chain([first], matches):
        start = match.start()
        # The clause containing this match begins after the last break at or
        # before it. ⚠ `bisect_RIGHT`, and the difference is a real defect the
        # linearity rewrite introduced: a break's stored `end()` EQUALS
        # `match.start()` when the route begins at the first character after a
        # newline, and `bisect_left` excludes that boundary — so the clause was
        # taken to start on the PREVIOUS line and its negation carried forward.
        # `Do not report publicly\nsecurity@example.com` scored 0 for having no
        # disclosure contact. The per-match rescan this replaced got it right,
        # so "semantics preserved" was wrong; the test that claimed it used
        # `; ` — a separator followed by a SPACE, which never lands on the
        # boundary case.
        i = bisect_right(clause_ends, start)
        clause_start = clause_ends[i - 1] if i else 0
        # Negated iff some negation falls inside [clause_start, start).
        j = bisect_right(negations, clause_start - 1)
        if j >= len(negations) or negations[j] >= start:
            return True
    return False


@dataclass(frozen=True, slots=True)
class DocumentationFacts:
    """Which documentation the server ships, resolved once for all sub-checks."""

    readme_path: str | None = None
    readme: str = ""
    changelog_path: str | None = None
    security_path: str | None = None
    manifest_text: str = ""


def _find(inventory: Inventory, *prefixes: str) -> str | None:
    """Root-most documentation file whose name starts with any prefix.

    Root-most deliberately: a vendored dependency ships its own README and
    SECURITY.md, and grading the server on somebody else's documentation would
    reward it for a file it did not write.
    """
    matches = [
        f for f in inventory.by_role(Role.DOCS)
        if f.path.rsplit("/", 1)[-1].lower().startswith(prefixes)
    ]
    if not matches:
        return None
    return min(matches, key=lambda f: (f.path.count("/"), len(f.path))).path


def documentation_facts(root: Path, inventory: Inventory) -> DocumentationFacts:
    readme_path = _find(inventory, "readme")
    manifest = inventory.mcp_manifest
    return DocumentationFacts(
        readme_path=readme_path,
        readme=read_text(root, readme_path) if readme_path else "",
        changelog_path=_find(inventory, "changelog", "changes", "history", "news"),
        security_path=_find(inventory, "security"),
        manifest_text=read_text(root, manifest.path) if manifest else "",
    )


def score_readme(facts: DocumentationFacts) -> SubCheck:
    """`03` §7's README heuristic: 0 under 500 bytes, else additive to 100."""
    name = "readme_quality"
    text = facts.readme
    if not text:
        return SubCheck(name, 0, evidence=("no README in the fetched source",))
    if len(text.encode("utf-8")) < README_MIN_BYTES:
        return SubCheck(
            name, 0,
            evidence=(f"{facts.readme_path} is under `03` §7's {README_MIN_BYTES}-byte "
                      "floor, which scores 0 regardless of content",),
        )

    score = 0
    earned: list[str] = []
    # +25: installation instructions — a code fence somewhere after an install
    # heading, which is `03` §7's own heuristic.
    install = _INSTALL_HEADING.search(text)
    if install and _CODE_FENCE.search(text, install.end()):
        score += 25
        earned.append("installation instructions (+25)")
    if _CONFIG_SIGNALS_PROSE.search(text) or _CONFIG_SIGNALS_ENVVAR.search(text):
        score += 25
        earned.append("configuration documented (+25)")
    if _TOOLS_HEADING.search(text):
        score += 30
        earned.append("exposed tools or resources enumerated (+30)")
    intro = " ".join(text.split()[:INTRO_WORDS])
    if _PURPOSE_VERBS.search(intro):
        score += 20
        earned.append(f"states what the server does in the first {INTRO_WORDS} words (+20)")

    return SubCheck(
        name, min(100, score),
        evidence=(f"{facts.readme_path}: " + (", ".join(earned) if earned
                  else "over the size floor but none of `03` §7's content "
                       "heuristics matched"),),
    )


def score_declared_scopes(facts: DocumentationFacts) -> SubCheck:
    """`03` §7's declared-scopes sub-check, in the one direction it can run.

    See the module docstring: the upper two bands need a comparison against
    statically inferred scopes, and nothing infers scopes yet.
    """
    name = "declared_scopes"
    corpus = f"{facts.readme}\n{facts.manifest_text}"

    if _SPECIFIC_SCOPES.search(corpus):
        return SubCheck(
            name, None,
            reason="specific scope or access documentation is present, but `03` "
                   "§7's 100 and 60 bands both compare it against scopes "
                   "INFERRED from static analysis, which is not built yet. "
                   "Scoring 100 on an empty inference would be a vacuous truth "
                   "— 'all ∅ inferred scopes are documented'.",
        )
    if _VAGUE_SCOPES.search(corpus):
        return SubCheck(
            name, 30,
            evidence=("capabilities are described only in vague terms — `03` §7's "
                      "30 band, which needs no inference to establish",),
        )
    return SubCheck(
        name, 0,
        evidence=("neither the README nor the MCP manifest documents what the "
                  "server accesses or what side effects it has",),
    )


def score_changelog(facts: DocumentationFacts) -> SubCheck:
    """`03` §7's changelog presence check.

    §7 allows partial credit for "tagged releases on GitHub that include release
    notes (acts as a de facto changelog)". That requires the forge API, which is
    `maintenance_check`'s fetch — so an absent changelog is scored 0 on the file
    alone and the evidence names the credit it could not check for.
    """
    name = "changelog"
    if facts.changelog_path:
        return SubCheck(name, 100, evidence=(f"{facts.changelog_path} present",))
    return SubCheck(
        name, 0,
        evidence=("no CHANGELOG in the fetched source. `03` §7's partial credit "
                  "for tagged releases carrying release notes is not applied "
                  "here — that needs the forge API, which this check does not "
                  "call",),
    )


def score_security_contact(facts: DocumentationFacts) -> SubCheck:
    """`03` §7: SECURITY.md, or a disclosure contact documented in the README."""
    name = "security_contact"
    if facts.security_path:
        return SubCheck(name, 100, evidence=(f"{facts.security_path} present",))
    if documents_disclosure_route(facts.readme):
        return SubCheck(
            name, 100,
            evidence=(f"no SECURITY.md, but {facts.readme_path} documents a "
                      "disclosure route — `03` §7 accepts either",),
        )
    return SubCheck(
        name, 0,
        evidence=("no SECURITY.md and no disclosure contact in the README, so a "
                  "finder has no route to report a vulnerability privately",),
    )


def assess_transparency(
    root: Path | None = None,
    inventory: Inventory | None = None,
    availability: SourceAvailability | None = None,
) -> AxisResult:
    """Score the Transparency axis (`03` §7) for one server.

    Every sub-check on this axis reads shipped files, so a server with no
    fetchable source has no assessable Transparency at all — the axis comes back
    with a `None` score and 0 assessed weight rather than a zero, which would
    report "documents nothing" about a repository nobody opened.

    `availability` says WHY there was nothing to read, and passing it is worth
    the argument: a repository that 404s for the public and a server our queue
    has not reached yet are different facts about different parties, and without
    it both render as the same sentence. `reachability` owns that vocabulary and
    explains why the unreachable case is reported but never scored.
    """
    if root is None or inventory is None:
        no_source = (
            availability.reason if availability is not None
            else "no source was fetched, so no documentation could be read"
        )
        return score_axis(AXIS, [
            assess_license(None, None, no_source),
            SubCheck("readme_quality", None, reason=no_source),
            SubCheck("declared_scopes", None, reason=no_source),
            SubCheck("changelog", None, reason=no_source),
            SubCheck("security_contact", None, reason=no_source),
        ])

    facts = documentation_facts(root, inventory)
    return score_axis(AXIS, [
        assess_license(root, inventory),
        score_readme(facts),
        score_declared_scopes(facts),
        score_changelog(facts),
        score_security_contact(facts),
    ])
