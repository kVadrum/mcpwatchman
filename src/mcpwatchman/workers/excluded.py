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
