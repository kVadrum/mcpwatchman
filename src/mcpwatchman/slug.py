"""The published URL slug for a registry name — stdlib only, on purpose.

A contract, not a helper: `/servers/<slug>/` and `/api/servers/<slug>.json` are
URLs the site publishes and promises to keep (`cohort`), and the CLI computes
the same slug to find a server without downloading the index. It lives here
rather than in the scanner so the CLI's startup path can import it without
pulling the scanner in (`tests/test_cli_lazy_imports.py`).
"""

from __future__ import annotations


def slugify(name: str) -> str:
    """A URL-safe slug for a registry name like `io.github.owner/server`."""
    out = []
    for ch in name.lower():
        out.append(ch if ch.isalnum() else "-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


__all__ = ["slugify"]
