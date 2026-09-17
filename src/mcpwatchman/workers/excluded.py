"""Directory names the scanner will not read, and the crawler will not emit.

**A shared home because this is a CONTRACT, not a preference.** The crawler
decides which `subfolder` values it puts into a `source_spec`, and the scanner
decides which it will parse back out — two sites, one rule, and if they
disagree the planner enqueues jobs the worker rejects on sight. Nothing fails
loudly in that state: the crawler is green, the scanner is green, and the work
simply never happens.

It could not live in either module. `scanner.source` already imports
`crawler.registry` for `SourceKind`, so pointing the crawler back at the scanner
would close an import cycle. `base.md` § *Canonical homes* → *Edge case: when
code IS a contract* is explicit that this is the case where duplication is
wrong: if the rule changes, every site must change in lockstep, so it gets one
home and the consumers reference it.
"""

from __future__ import annotations

EXCLUDED_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", "__pycache__"}
)


# Scanner configuration a SCANNED REPOSITORY may not supply.
#
# **Here rather than inside one scanner, because it is the same contract this
# module already exists for: one rule, more than one enforcer.** It lived in
# `semgrep_check` as that module's private defence, and the identical hole
# stayed open in `osv_check` for exactly as long — measured, 2026-09-17: a
# repo-supplied `osv-scanner.toml` with an `[[IgnoredVulns]]` entry took a scan
# from 6 vulnerability groups to 5, i.e. a server suppressing its own CVE from
# our audit. semgrep's `.semgrepignore` does the same thing and was closed a
# commit earlier; the lesson is that the defence generalises and its home
# should have too.
#
# Every future scanner that reads config from the tree it scans belongs here.
HOSTILE_CONFIG_FILES = (".semgrepignore", "osv-scanner.toml")
