"""The published cohort — which servers have a page, and why the list is pinned.

A published URL is a promise. `mcpwatchman.com/servers/<slug>/` is listed in the
sitemap, counted in `llms.txt`, and constructed by agents that were told exactly
that shape; a server that quietly leaves the published set takes its page with
it and answers 404 to everyone still holding the link.

**The set was not stable, and the mechanism was the POOL, not the ordering.**
The scan driver drew its candidates from the first 800 registry entries and
ordered them by `sha256(name)`. That hash order is genuinely stable — a
server's position depends only on its own identity — but the registry paginates
**alphabetically by name** (measured 2026-09-18: 33,079 entries, name-ascending,
first cursor `ac.inference.sh/mcp:2.0.1`), so "the first 800" is an alphabetical
PREFIX that every new registration shifts. The 40 published servers sat at
registry positions 12–773 of 33,079 and every one of them was named `ai.*`;
two regenerations two days apart shared **4 of 40**. Across nine committed
generations, 140 distinct servers have held a page and 100 of them have lost
it — probed on the live site, they 404.

So the ordering fix that was applied was correct and insufficient, and the
remedy is not a better draw. It is to stop drawing: **this file is the authority
on what is published, and the registry decides only what a published page
says.** Growth is a deliberate append; a plain regeneration cannot change the
set, which is what makes the URLs durable.

**The invariant is APPEND-ONLY, and it reads better as a prohibition: deleting
a line from `ops/cohort.json` breaks a live URL.** There is deliberately no
removal API here. `tests/test_cohort.py` gates the file against its own
committed predecessor, because nothing else would notice — a smaller cohort
regenerates cleanly, passes every other gate, and 404s in production.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from mcpwatchman.workers.scanner.runner import slugify

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Carried in the file itself, because the file is the artefact someone edits at
# 2am and the consequence of a careless edit is invisible until a stranger's
# bookmark breaks.
FILE_NOTE = (
    "The published cohort. APPEND-ONLY: every entry here is a live URL at "
    "https://mcpwatchman.com/servers/<slug>/, so deleting a line breaks a page "
    "that is already in the sitemap and in agents' hands. Add servers with "
    "`ops/scan_cohort.py --grow N`; never remove one. See "
    "src/mcpwatchman/cohort.py for why this file exists."
)


class CohortError(ValueError):
    """The pinned cohort is unusable — malformed, or self-contradictory.

    Loud on purpose. Every failure this raises is one where continuing would
    publish a different set of URLs than the promised one, and that failure is
    silent by nature: the run succeeds, the site builds, and the pages that
    vanished are only missed by whoever follows a link.
    """


@dataclass(frozen=True, slots=True)
class PinnedServer:
    """One promise: this registry name has this page, since this date.

    `slug` is stored rather than derived at read time even though `slugify`
    derives it, because the two answers can disagree — and when they do it is
    the STORED one that a reader's link points at. A change to slug derivation
    is then a detectable event instead of a silent mass 404.
    """

    name: str
    slug: str
    first_published: str

    def validate(self) -> None:
        if not self.name.strip() or " " in self.name:
            raise CohortError(f"not a registry name: {self.name!r}")
        if not _DATE.match(self.first_published):
            raise CohortError(
                f"{self.name}: first_published must be YYYY-MM-DD, got "
                f"{self.first_published!r}"
            )
        derived = slugify(self.name)
        if self.slug != derived:
            raise CohortError(
                f"{self.name}: pinned slug {self.slug!r} is no longer what "
                f"slugify() produces ({derived!r}). The published URL and the "
                "generator disagree; changing slug derivation breaks every "
                "live page it touches."
            )


@dataclass(frozen=True, slots=True)
class Cohort:
    """The pinned set, in name order.

    Deliberately has no removal method. Retiring a URL is a product decision
    with a public consequence, not an operation a script reaches for.
    """

    servers: tuple[PinnedServer, ...]
    note: str = FILE_NOTE

    def __len__(self) -> int:
        return len(self.servers)

    def __contains__(self, name: object) -> bool:
        return name in self.names

    @property
    def names(self) -> frozenset[str]:
        return frozenset(s.name for s in self.servers)

    @property
    def slugs(self) -> frozenset[str]:
        return frozenset(s.slug for s in self.servers)

    def validate(self) -> None:
        for server in self.servers:
            server.validate()
        for label, seen in (("name", self.names), ("slug", self.slugs)):
            if len(seen) != len(self.servers):
                raise CohortError(
                    f"duplicate {label} in the cohort — two entries resolve to "
                    "one page, so one of them is already unreachable"
                )

    def extended_with(self, names: Iterable[str], *, on: str) -> Cohort:
        """This cohort plus `names`, first published `on`. Never smaller.

        Already-pinned names are skipped rather than rejected, so re-running a
        growth step is idempotent; the returned cohort always contains every
        server this one did.
        """
        additions = [
            PinnedServer(name=n, slug=slugify(n), first_published=on)
            for n in dict.fromkeys(names)
            if n not in self.names
        ]
        grown = Cohort(
            servers=tuple(sorted(self.servers + tuple(additions), key=lambda s: s.name)),
            note=self.note,
        )
        grown.validate()
        return grown


def parse(payload: object) -> Cohort:
    """Parse a loaded JSON document into a validated `Cohort`."""
    if not isinstance(payload, dict):
        raise CohortError("the cohort file must be a JSON object")
    raw = payload.get("servers")
    if not isinstance(raw, list):
        raise CohortError(
            "the cohort file has no 'servers' array — refusing to read a "
            "malformed file as an empty cohort, which would unpublish every page"
        )
    servers = []
    for item in raw:
        if not isinstance(item, dict):
            raise CohortError(f"not a cohort entry: {item!r}")
        try:
            servers.append(
                PinnedServer(
                    name=str(item["name"]),
                    slug=str(item["slug"]),
                    first_published=str(item["first_published"]),
                )
            )
        except KeyError as exc:
            raise CohortError(f"cohort entry missing {exc.args[0]}: {item!r}") from exc
    cohort = Cohort(
        servers=tuple(sorted(servers, key=lambda s: s.name)),
        note=str(payload.get("note") or FILE_NOTE),
    )
    cohort.validate()
    return cohort


def load(path: Path) -> Cohort:
    """Read and validate the cohort file.

    A missing file raises. It is the one failure mode where a helpful default —
    "no servers pinned yet" — would hand every caller the empty set and let a
    regeneration publish whatever it happened to draw, which is the behaviour
    this module exists to remove.
    """
    if not path.is_file():
        raise CohortError(
            f"no cohort file at {path.name}: the published set is pinned, and "
            "an absent pin is not an empty one"
        )
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise CohortError(f"{path.name} is not valid JSON: {exc}") from exc
    return parse(payload)


def save(path: Path, cohort: Cohort) -> None:
    """Write the cohort back, name-ordered, one server per line.

    The formatting is for the diff: this file's whole job is to be reviewable,
    and an append should read as added lines rather than a reflowed document.
    """
    cohort.validate()
    body = {
        "note": cohort.note,
        "count": len(cohort),
        "servers": [
            {"name": s.name, "slug": s.slug, "first_published": s.first_published}
            for s in cohort.servers
        ],
    }
    path.write_text(json.dumps(body, indent=1) + "\n")


def publication_errors(cohort: Cohort, reports: Iterable[dict]) -> list[str]:
    """Every reason this set of reports must not be published for this cohort.

    Returned rather than raised so a caller can print all of them at once: the
    interesting failure is "these six servers vanished", not the first one.

    **Both directions are load-bearing and they fail differently.** A pinned
    server with no report is a live URL that will 404 — the failure this whole
    mechanism exists to prevent. A report with no pin is a URL we would start
    serving without recording the promise to keep serving it, which is how 100
    pages were published and lost. The slug check catches the third case: the
    right servers published at the wrong addresses.

    Every one of these is invisible after the fact. The file regenerates
    cleanly, the site builds, the tests that read the published data pass over
    a consistent smaller set — and only a stranger's link breaks.
    """
    by_name = {r["name"]: r for r in reports}
    problems: list[str] = []
    for pin in cohort.servers:
        report = by_name.get(pin.name)
        if report is None:
            problems.append(
                f"{pin.name} is pinned at /servers/{pin.slug}/ but produced no "
                "report, so that page would stop existing"
            )
        elif report["slug"] != pin.slug:
            problems.append(
                f"{pin.name} is pinned at /servers/{pin.slug}/ but its report "
                f"publishes /servers/{report['slug']}/"
            )
    for name in sorted(set(by_name) - cohort.names):
        problems.append(
            f"{name} would be published without being pinned, so nothing "
            "promises to keep its page"
        )
    return problems


def mark_status(report: dict, *, status: str, observed_on: str) -> dict:
    """Label a freshly-scanned report whose registry entry is not `active`.

    **A deprecated server is SCANNED, not carried forward.** Its entry is still
    in the manifest, so its declared source resolves and the numbers can be
    current — and a stale scan published beside a perfectly readable repository
    would be a worse page than a fresh one. Measured on the first real run: 1
    of the 40 pinned servers is `deprecated` today, and 349 of 33,081 registry
    entries are not active-and-latest, so this is an ordinary condition rather
    than an exception.

    `registry_state` then carries the registry's OWN word rather than a
    vocabulary of ours. The publisher said "deprecated"; we are relaying that,
    and `03` has no band for it — so it is reported and not scored, the same
    treatment `reachability` gives an unreadable repository.
    """
    marked = dict(report)
    marked["registry_state"] = status
    marked["registry_note"] = (
        f"The registry lists this server with status {status} (observed "
        f"{observed_on}). That is the publisher's own label, not a finding of "
        "ours, and no axis scores it. The scan below is current."
    )
    return marked


def carry_forward(previous: dict, *, checked_on: str, observation: str) -> dict:
    """The report to publish for a pinned server the registry no longer lists.

    **The page stays, and the numbers are NOT recomputed** — there is no current
    entry to scan, so the honest publication is the last scan taken while the
    server was listed, labelled as exactly that. Both dates travel: `scanned_at`
    is left alone, because that is when the measurement happened, and
    `checked_on` records when we last looked for the entry.

    That labelling is the whole point. Carrying the report forward *silently*
    would leave an old scan reading as a current one — the same class of defect
    as a score without its coverage, arriving through the one door the scanner
    never opens, because the scanner only ever sees servers that are listed.

    `observation` states what was seen rather than why, the distinction
    `reachability` draws for a 404: absent from the listing and deliberately
    deleted are different facts, and only the first one was measured.
    """
    scanned_on = str(previous.get("scanned_at", ""))[:10]
    carried = dict(previous)
    carried["registry_state"] = "delisted"
    carried["registry_note"] = (
        f"{observation} (last checked {checked_on}). This page is kept because "
        "its URL is public; the scores below are from the last scan taken while "
        "the server was listed"
        + (f", on {scanned_on}" if scanned_on else "")
        + ", and have not been recomputed, because there is no current entry to "
        "scan."
    )
    return carried


__all__ = [
    "FILE_NOTE",
    "carry_forward",
    "mark_status",
    "publication_errors",
    "Cohort",
    "CohortError",
    "PinnedServer",
    "load",
    "parse",
    "save",
]
