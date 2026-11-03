"""`mcpwatchman feed` — the site's Atom feeds, for a terminal (`07` §8).

Reads `/feed/high-severity.xml` and `/feed/score-drops.xml`; a feed that 404s
is reported as not published yet and the other is still read. Entries newer
than `--days` are interleaved, newest first.

The XML is untrusted remote input, so it is parsed defensively:
- the body is capped (`MAX_FEED_BYTES`) before parsing;
- it must decode as UTF-8 — Atom feeds here are UTF-8, and a declared foreign
  encoding is how a DOCTYPE could hide from the check below;
- any DOCTYPE or ENTITY declaration is refused BEFORE the parser sees it. An
  Atom feed needs neither, and a DTD is how entity expansion (a "billion
  laughs") or an external entity reaches an XML parser; expat limits some of
  that itself, but refusing costs nothing a feed needs;
- the decoded text — exactly what was screened — is what is parsed.
Titles and links come from scanned repositories, so they are printed through
`clean`, never raw.
"""

from __future__ import annotations

import datetime as dt
import xml.etree.ElementTree as ET  # noqa: S405 - DTDs refused before parsing; see above
from typing import NamedTuple

import click

from mcpwatchman.cli.api import EXIT_NETWORK, EXIT_NOT_FOUND, CliError, base_url, clean, get_bytes

FEEDS = {
    "high-severity": "/feed/high-severity.xml",
    "score-drops": "/feed/score-drops.xml",
}
MAX_FEED_BYTES = 4 * 1024 * 1024
ATOM = "{http://www.w3.org/2005/Atom}"


class Entry(NamedTuple):
    updated: dt.datetime
    title: str
    link: str


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def parse_atom(body: bytes, url: str) -> tuple[list[Entry], int]:
    """(entries, entries skipped for an unreadable date). Refuses any DTD."""
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CliError(f"{url} is not UTF-8; refusing to parse it", EXIT_NETWORK) from exc
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise CliError(
            f"{url} carries a DOCTYPE or ENTITY declaration; an Atom feed needs "
            "neither, so it is refused unparsed",
            EXIT_NETWORK,
        )
    try:
        root = ET.fromstring(text)  # noqa: S314 - DTDs refused above
    except ET.ParseError as exc:
        raise CliError(f"{url} is not well-formed XML: {exc}", EXIT_NETWORK) from exc
    if root.tag != f"{ATOM}feed":
        raise CliError(f"{url} is not an Atom feed", EXIT_NETWORK)
    entries: list[Entry] = []
    skipped = 0
    for entry in root.findall(f"{ATOM}entry"):
        try:
            updated = dt.datetime.fromisoformat((entry.findtext(f"{ATOM}updated") or "").strip())
        except ValueError:
            skipped += 1
            continue
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=dt.UTC)
        link = ""
        for candidate in entry.findall(f"{ATOM}link"):
            if candidate.get("rel", "alternate") == "alternate":
                link = candidate.get("href", "")
                break
        entries.append(Entry(updated, entry.findtext(f"{ATOM}title") or "", link))
    return entries, skipped


def run(feed_type: str | None, days: int) -> None:
    base = base_url()
    wanted = [feed_type] if feed_type else list(FEEDS)
    cutoff = _now() - dt.timedelta(days=days)
    rows: list[tuple[str, Entry]] = []
    missing = []
    for name in wanted:
        url = f"{base}{FEEDS[name]}"
        body = get_bytes(url, cap=MAX_FEED_BYTES, accept="application/atom+xml")
        if body is None:
            missing.append(name)
            click.echo(f"notice: the {name} feed is not published yet ({url}).", err=True)
            continue
        entries, skipped = parse_atom(body, url)
        if skipped:
            click.echo(
                f"notice: {skipped} {name} entr{'ies' if skipped != 1 else 'y'} had no "
                "readable date and could not be placed in the window; not shown.",
                err=True,
            )
        rows.extend((name, e) for e in entries if e.updated >= cutoff)
    if len(missing) == len(wanted):
        raise CliError("no requested feed is published yet.", EXIT_NOT_FOUND)
    rows.sort(key=lambda r: r[1].updated, reverse=True)
    if not rows:
        click.echo(f"No feed entries in the last {days} days.")
        return
    width = max(len(name) for name, _ in rows)
    for name, entry in rows:
        when = entry.updated.strftime("%Y-%m-%d")
        click.echo(f"{when}  {name:<{width}}  {clean(entry.title, one_line=True)}")
        if entry.link:
            click.echo(f"{'':<{12 + width}}{clean(entry.link, one_line=True)}")
