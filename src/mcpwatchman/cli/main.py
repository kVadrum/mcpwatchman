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


# The values `--axis` accepts: an axis key or `check --format compact`'s short
# name. Spelled here rather than imported, because importing `cli.api` would
# put urllib on the startup path; `tests/test_cli_info.py` holds the two equal.
AXIS_NAMES = (
    "code_safety", "auth_posture", "dependency_health", "maintenance", "transparency",
    "code", "auth", "deps", "maint", "trans",
)
_AXIS_KEY = dict(zip(AXIS_NAMES[5:], AXIS_NAMES[:5], strict=True))


def _axis_key(value: str | None) -> str | None:
    return None if value is None else _AXIS_KEY.get(value, value)


def _axis_option(help_text: str) -> Any:
    return click.option(
        "--axis", type=click.Choice(AXIS_NAMES), default=None, help=help_text,
    )


@cli.command()
@click.argument("server")
@_axis_option("Show only this axis.")
@click.option(
    "--severity", type=click.Choice(["critical", "high", "medium", "low", "all"]),
    default="high", show_default=True,
    help="Show findings at this severity and above; `all` adds unrated ones.",
)
@click.option(
    "--format", "fmt", type=click.Choice(["pretty", "json"]), default="pretty",
    show_default=True, help="Output format.",
)
@click.option("--version", "version", default=None, help="Require this server version.")
def info(server: str, axis: str | None, severity: str, fmt: str, version: str | None) -> None:
    """Show SERVER's per-axis breakdown with the evidence behind it.

    Sub-check notes are always shown; findings are filtered by --severity.
    Findings the filter hides, and findings beyond the published evidence cap,
    are counted rather than silently dropped.
    """
    from mcpwatchman.cli.info import run

    run(server, _axis_key(axis), severity, fmt, version)


@cli.command("list")
@click.option("--min-score", type=click.IntRange(0, 100), default=None,
              help="Only servers scoring at least N on --axis.")
@click.option("--max-score", type=click.IntRange(0, 100), default=None,
              help="Only servers scoring at most N on --axis.")
@_axis_option("Sort by this axis, highest first; required by the score filters.")
@click.option("--limit", type=click.IntRange(min=0), default=25, show_default=True,
              help="Show at most N servers; 0 shows all.")
@click.option(
    "--format", "fmt", type=click.Choice(["pretty", "json"]), default="pretty",
    show_default=True, help="Output format.",
)
def list_(
    min_score: int | None, max_score: int | None, axis: str | None, limit: int, fmt: str
) -> None:
    """List published servers with their per-axis scores.

    Alphabetical by default. There is no composite to rank by, so sorting and
    score filters name an axis, and a filter matches only servers where that
    axis was scored: not assessed is never treated as zero.
    """
    from mcpwatchman.cli.listing import run

    run(min_score, max_score, _axis_key(axis), limit, fmt)


@cli.command()
@click.argument("server")
@click.option("--days", type=click.IntRange(min=1), default=90, show_default=True,
              help="How many days back to draw.")
@_axis_option("Draw only this axis.")
def trend(server: str, days: int, axis: str | None) -> None:
    """Draw SERVER's per-axis score history as sparklines.

    A gap glyph marks a scan where the axis was not assessed; a marker shows
    where the methodology or ruleset changed, across which scores do not compare.
    """
    from mcpwatchman.cli.trend import run

    run(server, days, _axis_key(axis))


@cli.command()
@click.option("--type", "feed_type", type=click.Choice(["high-severity", "score-drops"]),
              default=None, help="Read one feed; default both, newest first.")
@click.option("--days", type=click.IntRange(min=1), default=7, show_default=True,
              help="How many days back to show.")
def feed(feed_type: str | None, days: int) -> None:
    """Show recent entries from the site's Atom feeds."""
    from mcpwatchman.cli.feeds import run

    run(feed_type, days)


@cli.command()
@click.argument("server")
def badge(server: str) -> None:
    """Print the README badge markdown for SERVER."""
    from mcpwatchman.cli.badge import run

    run(server)


if __name__ == "__main__":
    cli()
