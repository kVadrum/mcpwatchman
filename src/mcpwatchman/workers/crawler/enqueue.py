"""Turn a registry diff into scan jobs (`02-architecture.md` §2.1).

The poller's decision half: given what changed, work out what to scan, in which
lane, and what could not be scanned at all.

**The queue is injected, not imported.** RQ-vs-Procrastinate is still an open
evaluation (`11` §4, ADR-001) and `tasks.py` is where that choice lands. Nothing
here needs to know which won — planning is queue-agnostic, and keeping it that
way means the decision can be made on its merits instead of on how much code
already assumes an answer.

Equally, nothing here touches the database. `PollPlan` reports the removals it
found rather than applying them: marking a server `status = 'removed'`
(`02` §136) is a write, and a planner that writes cannot be run to find out what
a poll *would* do.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from mcpwatchman.workers.crawler.registry import (
    CoverageReport,
    ManifestDiff,
    RegistryEntry,
    coverage_report,
    manifest_hash,
    resolve_source,
)


class Lane(StrEnum):
    """Queue priority lanes (`02` §2.1).

    Workers consume in this order. `PRIORITY` carries a 30-second SLA because a
    human is waiting on a CLI pre-install check; `DEFAULT` is the overnight drip.
    """

    PRIORITY = "priority"
    DEFAULT = "default"
    RECALIBRATION = "recalibration"


@dataclass(frozen=True, slots=True)
class ScanJob:
    """One unit of scanner work: everything needed to fetch and scan a version.

    Carries `content_hash` so the worker can re-check, at the moment it runs,
    that the entry still matches what the poll saw. An overnight queue can be
    hours deep, and scanning a version the registry has since replaced attaches
    a score to the wrong artifact.
    """

    key: str
    name: str
    version: str
    source_spec: str
    content_hash: str
    lane: Lane = Lane.DEFAULT
    supplement_spec: str | None = None
    subfolder: str | None = None


@dataclass(frozen=True, slots=True)
class SkippedEntry:
    """A current server the v0.1 scanner cannot read, and why.

    Kept as data rather than logged. `03` §12 and the per-server page owe the
    reader an explicit "not analysed, because X" — an unscannable server
    rendered as an absent score reads as a bad one.
    """

    key: str
    name: str
    version: str
    reason: str


@dataclass(frozen=True, slots=True)
class PollPlan:
    """What one poll decided. Inert: no queue, no database, no side effects."""

    jobs: tuple[ScanJob, ...] = ()
    skipped: tuple[SkippedEntry, ...] = ()
    removed: tuple[str, ...] = ()
    unchanged: int = 0
    manifest_hash: str = ""
    coverage: CoverageReport | None = None

    @property
    def is_empty(self) -> bool:
        """True when the poll found nothing to do — a normal, quiet night.

        Deliberately not a fault: the registry not changing is the expected
        case, and a signal that fires for it trains the operator to ignore the
        one that matters (`base.md` § *Signal design*).
        """
        return not (self.jobs or self.removed)


def plan_from_diff(
    diff: ManifestDiff,
    *,
    lane: Lane = Lane.DEFAULT,
) -> PollPlan:
    """Plan the work implied by a diff.

    Only changed entries become jobs — unchanged ones are cache hits by content
    hash, which is what makes a daily crawl of the whole registry affordable
    (`02` §104).
    """
    jobs: list[ScanJob] = []
    skipped: list[SkippedEntry] = []

    for entry in diff.to_scan:
        resolution = resolve_source(entry)
        if not resolution.scannable or resolution.primary is None:
            skipped.append(
                SkippedEntry(
                    key=entry.key,
                    name=entry.name,
                    version=entry.version,
                    reason=resolution.skip_reason or "unresolved source",
                )
            )
            continue
        jobs.append(
            ScanJob(
                key=entry.key,
                name=entry.name,
                version=entry.version,
                source_spec=resolution.primary,
                content_hash=entry.content_hash,
                lane=lane,
                supplement_spec=resolution.supplement,
                subfolder=resolution.subfolder,
            )
        )

    seen = diff.added + diff.updated + diff.unchanged
    return PollPlan(
        jobs=tuple(jobs),
        skipped=tuple(skipped),
        removed=diff.removed,
        unchanged=len(diff.unchanged),
        manifest_hash=manifest_hash(seen),
        coverage=coverage_report(seen),
    )


def plan_rescan(
    entries: Iterable[RegistryEntry],
    *,
    lane: Lane = Lane.RECALIBRATION,
) -> PollPlan:
    """Plan a full re-scan of the given entries, ignoring content hashes.

    The methodology-change path (`03` §11): when weights or rules move, every
    server needs re-scoring even though nothing about it changed. Routed to the
    `recalibration` lane so a re-scan of the whole registry cannot starve the
    CLI's interactive lane.
    """
    materialised = list(entries)
    synthetic = ManifestDiff(added=tuple(materialised))
    plan = plan_from_diff(synthetic, lane=lane)
    return plan


def enqueue_plan(
    plan: PollPlan,
    enqueue: Callable[[ScanJob], object],
    *,
    on_error: Callable[[ScanJob, Exception], None] | None = None,
) -> tuple[int, int]:
    """Hand every job to `enqueue`. Returns `(enqueued, failed)`.

    One job's failure must not cost the rest of the night's work, so failures
    are counted and reported rather than raised. The caller decides what a
    partial enqueue means — but it is told, which is the part that matters: a
    silent partial enqueue looks exactly like a quiet registry.
    """
    enqueued = failed = 0
    for job in plan.jobs:
        try:
            enqueue(job)
        except Exception as exc:  # noqa: BLE001 - isolation is the whole point
            failed += 1
            if on_error is not None:
                on_error(job, exc)
        else:
            enqueued += 1
    return enqueued, failed
