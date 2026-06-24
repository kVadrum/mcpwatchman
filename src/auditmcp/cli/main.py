"""auditmcp command-line interface (scaffold)."""

from __future__ import annotations

import click

from auditmcp import __version__


@click.group()
@click.version_option(__version__, prog_name="auditmcp")
def cli() -> None:
    """Independent security and quality audit for MCP servers."""


@cli.command()
@click.argument("server")
def check(server: str) -> None:
    """Show the trust score for SERVER (not implemented yet)."""
    # Output formats (--format pretty/json/compact) return once scanning lands.
    raise click.ClickException(
        f"scanning {server!r} is not implemented yet — auditmcp is pre-v0.1. "
        "Follow https://github.com/kVadrum/auditmcp"
    )


if __name__ == "__main__":
    cli()
