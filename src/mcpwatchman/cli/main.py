"""mcpwatchman command-line interface."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any

import click

from mcpwatchman import __version__

# `07` §3.5 reserves exit 2 for "below --threshold" — the code a CI pipeline
# keys on — and Click exits 2 for a usage error. Left alone, a typo in a
# pipeline's flags would read as a failing server.
EXIT_USAGE = 5


class _Cli(click.Group):
    def main(  # type: ignore[override]
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        **extra: Any,
    ) -> Any:
        if not standalone_mode:
            return super().main(args, prog_name, complete_var, False, **extra)
        try:
            return super().main(args, prog_name, complete_var, False, **extra)
        except click.UsageError as exc:
            exc.show()
            sys.exit(EXIT_USAGE)
        except click.ClickException as exc:
            exc.show()
            sys.exit(exc.exit_code)
        except click.Abort:
            click.echo("Aborted!", err=True)
            sys.exit(1)


@click.group(cls=_Cli)
@click.version_option(__version__, prog_name="mcpwatchman")
def cli() -> None:
    """Independent security and quality audit for MCP servers."""


@cli.command()
@click.argument("server")
@click.option(
    "--format", "fmt", type=click.Choice(["pretty", "json", "compact"]), default="pretty",
    show_default=True, help="Output format; json and compact are for scripts.",
)
@click.option(
    "--threshold", type=click.IntRange(0, 100), default=None,
    help="Exit 2 below this composite. A no-op until the composite is published.",
)
@click.option("--version", "version", default=None, help="Require this server version.")
def check(server: str, fmt: str, threshold: int | None, version: str | None) -> None:
    """Show the published scan for SERVER.

    SERVER is a registry name or slug, an npm or PyPI package name, or a
    repository URL. Per-axis scores are shown with the share of each axis that
    could actually be measured; there is no single composite number yet.
    """
    from mcpwatchman.cli.check import run  # lazy: see the module docstring

    run(server, fmt, threshold, version)


if __name__ == "__main__":
    cli()
