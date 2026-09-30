"""What a commit pin must look like — one rule, two enforcers.

A gold-set entry pins the repository tree its audit read (`goldset`), and the
fetcher checks that exact tree out (`scanner.source`). If the two disagreed, a
pin the gold file accepts would be refused at fetch, or one the fetcher would
take would never be accepted — and the first shows up only as an entry that is
never measured. So the rule has one home and both import it (the
`workers/excluded.py` precedent; `base.md` § *Canonical homes* → *when code IS
a contract*). Stdlib only: `goldset` is gated in the CI job without the
workers extra.
"""

from __future__ import annotations

import re

# A full object name and nothing else: it reaches git's argv, and anything
# shorter is a prefix git may resolve differently tomorrow. SHA-1 or SHA-256,
# lowercase, the form `git rev-parse` prints.
_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def valid_commit(commit: str) -> bool:
    """Whether `commit` is a full lowercase object name — what a pin must be."""
    return _COMMIT_RE.fullmatch(commit) is not None
