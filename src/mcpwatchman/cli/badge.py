"""`mcpwatchman badge` — the README badge snippet for a published server (`07` §9).

The server is resolved first, as `check` resolves it, so a package name or
repository URL yields its own slug and an unpublished server exits 1 instead of
printing a link to nothing. URLs are built on the API root exactly as `check`
builds page URLs, so `MCPWATCHMAN_API_URL` moves both.

stdout carries the snippet and nothing else (`07` §9: it gets piped). If the
badge image is not served — the endpoint was specified before it was built —
that is said on stderr: a snippet pasted into a README would otherwise render
as a broken image with nothing having warned anyone.
"""

from __future__ import annotations

import click

from mcpwatchman.cli.api import CliError, base_url, get_bytes, load

MAX_BADGE_BYTES = 256 * 1024


def snippet(base: str, slug: str) -> str:
    return f"[![mcpwatchman]({base}/badge/{slug}.svg)]({base}/servers/{slug}/)"


def run(server: str) -> None:
    base = base_url()
    slug = load(server, base)["slug"]
    click.echo(snippet(base, slug))
    image = f"{base}/badge/{slug}.svg"
    try:
        served = get_bytes(image, cap=MAX_BADGE_BYTES, accept="image/svg+xml") is not None
    except CliError as exc:
        click.echo(f"notice: could not confirm the badge image is served: {exc.message}", err=True)
        return
    if not served:
        click.echo(
            f"notice: {image} is not served yet, so this badge renders as a broken "
            "image until it is.",
            err=True,
        )
