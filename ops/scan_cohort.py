#!/usr/bin/env python3
"""Scan the PINNED cohort and emit the site's data file.

**In the repository rather than a scratch directory, because the published
numbers are not reproducible without it.** Every figure on mcpwatchman.com was
once produced by a script that existed only in one session's tmpdir — so
"40 servers sampled" could not be re-derived by anyone, including us.

⚠ **THE SET OF PUBLISHED SERVERS IS AN INPUT NOW, NOT AN OUTCOME.**
`ops/cohort.json` is the authority on which servers have a page; this script
decides only what those pages SAY. That inversion is the fix for a rotation
that shipped: the previous version drew candidates from the first 800 registry
entries and ordered them by `sha256(name)`, and while the hash order is stable,
the registry paginates alphabetically — so the pool was an alphabetical prefix
that every new registration shifted. Two runs two days apart shared 4 of 40,
and 100 servers have had a page and lost it. `mcpwatchman.cohort` carries the
measurements.

**A PIN RECORDS A PUBLISHED PAGE, NOT AN INTENTION — and getting that
backwards aborted a 500-server run at server 50.** The 100 URLs lost to the
rotation were pre-pinned by hand and then scanned; one of them (`ai.dynsoft/
sac`) came back with an our-side gap on its FIRST publication, so there was no
previous report to fall back to and the run correctly refused to write
anything at all. The refusal was right and the model was wrong: nothing had
promised that page yet — it was 404 at the time — so a failure to measure it
breaks no URL and must not cost the other 499.

So a name enters the cohort only in the run that successfully publishes it.
`--grow N` picks candidates by hash order; `--adopt-file` takes an explicit
list (recovering URLs that were published before the pin existed). Both follow
the same rule, which is the whole reason they share a code path: scan first,
pin only what published. A plain regeneration cannot change the set at all,
which is what makes the URLs durable.

**Growth draws from the WHOLE registry in hash order, which also fixes a
sampling bias nobody chose.** The pinned 40 sit at registry positions 12–773
of 33,079 and every one of them is named `ai.*` — an artefact of the
alphabetical pool, not a property of the registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

from mcpwatchman.cohort import (
    Cohort,
    CohortError,
    atomic_write,
    carry_forward,
    load,
    mark_status,
    publication_errors,
    save,
    unpublishable_gaps,
)
from mcpwatchman.workers.crawler.registry import (
    RegistryEntry,
    current_entries,
    fetch_all,
    resolve_source,
)
from mcpwatchman.workers.scanner.forge import TOKEN_ENV_VARS, token_from_env
from mcpwatchman.workers.scanner.runner import scan_entry, slugify

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COHORT = REPO_ROOT / "ops" / "cohort.json"


def sample_key(name: str) -> str:
    """Ordering key for GROWTH candidates, derived only from a server's identity.

    Reproducible and unbiased: it does not depend on what else the registry
    holds, so two people growing the cohort by 10 pick the same 10. It is no
    longer load-bearing for stability — the cohort file is — and that is the
    point: this decides what to ADD, never what to keep.
    """
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


# Every external binary an axis needs, and the axis that goes dark without it.
# `semgrep_check` and `osv_check` each resolve theirs with `shutil.which`, so
# PATH is what decides — not the interpreter, and not the installed extra.
REQUIRED_TOOLS = (
    ("semgrep", "Code Safety", "`workers` extra"),
    ("osv-scanner", "Dependency Health", "Go binary, see docker/Dockerfile"),
    # ⚠ THE THIRD BINARY, AND IT WAS MISSING FROM THIS LIST. `auth_check`
    # resolves it with `shutil.which` exactly as the other two do, and without
    # it the `secret_handling` sub-check abstains with *"`detect-secrets` was
    # not available to this worker"* — which `_from_axis_result` publishes as
    # evidence on an axis that stays SCORED, because `03` §4 renormalises the
    # abstention away. So our tooling reaches a third party's page through a
    # route the axis-level gate cannot see, on a page that looks fully
    # measured. It was masked locally because all three live in the same
    # `.venv-workers/bin`.
    ("detect-secrets", "Auth Posture (secret handling)", "`workers` extra"),
)


def preflight() -> list[str]:
    """Missing scanner binaries, named. Empty means the environment can publish.

    ⚠ **A MISSING BINARY IS NOT AN ERROR ANYWHERE DOWNSTREAM — IT IS A CLEAN
    NON-ASSESSMENT**, which is the one failure shape this repo keeps paying
    for. Measured 2026-09-18 by doing it: a run with neither tool on PATH
    scanned 40 servers in 15 seconds, exited 0, and reported `code=—` on every
    one, including the 16 that carry real Code Safety scores today. Nothing in
    the suite would have caught the regenerated file, because no gate requires
    an axis to be SCORED.

    Worse than the silence is what it would have published. The modules are
    honest about why — "semgrep is not on PATH; it ships in the `workers`
    extra" — and `_from_axis_result` carries that sentence into the axis
    reason, so 500 third-party pages would have stated OUR broken toolchain as
    the reason nobody scored them. `reachability` draws exactly this line for
    the fetch stage: a full disk is ours and retryable, an unreadable
    repository is theirs and is a fact their page owes its reader. A missing
    binary is ours, and it belongs in this script's exit status rather than on
    a public page.

    ⚠ **A CREDENTIAL IS THE SAME HAZARD AS A BINARY, and it fails WORSE.**
    Without a GitHub token `scanner.forge` attributes Maintenance
    `ENVIRONMENT` on every server, which `unpublishable_gaps` then refuses —
    so every pinned page falls back to its previous report and the run exits
    **0 having changed nothing**. That is quieter than the missing-binary case
    it is modelled on: a dark axis at least renders as a dash, whereas a
    whole-cohort carry-forward looks like a successful regeneration in the
    summary line. Named here rather than discovered at 03:00.
    """
    missing = [
        f"{tool} is not on PATH — {axis} would be unassessed on every server "
        f"({where})"
        for tool, axis, where in REQUIRED_TOOLS
        if shutil.which(tool) is None
    ]
    if token_from_env() is None:
        missing.append(
            "no GitHub token is configured — Maintenance (`03` §5) would be "
            "unassessed on every server, attributed to our environment, and "
            f"every pinned page would silently carry forward (set "
            f"{TOKEN_ENV_VARS[0]})"
        )
    return missing


def _scan(entry: RegistryEntry, label: str, index: int, total: int) -> dict:
    t0 = time.time()
    report = scan_entry(entry)
    axes = " ".join(
        f"{k.split('_')[0]}={'—' if v.score is None else v.score}"
        for k, v in report.axes.items()
    )
    print(
        f"[{index:3}/{total}] {label:9} {time.time() - t0:5.1f}s "
        f"{report.name[:40]:40} {report.source_state:13} {axes}",
        flush=True,
    )
    return report.to_dict()


def _scan_once_more_if_ours(
    entry: RegistryEntry, label: str, index: int, total: int
) -> tuple[dict, list[str]]:
    """Scan, and retry exactly once if the only gaps are ours.

    **Measured, not defensive.** Under load, `ai.adeu/adeu` came back with an
    our-side gap after 2.2 seconds — far too fast for either tool's budget, so
    a crash rather than a timeout — then scanned clean in isolation and again
    in a 40-server sequential pass. A transient failure of ours otherwise
    freezes that server's page at its last successful scan, which is a worse
    outcome than one more attempt costing a few seconds.

    One retry, not a loop: a deterministic failure — a repository that exceeds
    a documented budget — is attributed `project` and never reaches here, so
    anything failing twice is worth a human reading the reason rather than a
    machine trying harder.
    """
    report = _scan(entry, label, index, total)
    gaps = unpublishable_gaps(entry.name, report)
    if gaps:
        print(f"[retry]   {entry.name} — {gaps[0][:90]}", flush=True)
        report = _scan(entry, label, index, total)
        gaps = unpublishable_gaps(entry.name, report)
    return report, gaps


def _keep_previous(
    name: str, previous: dict[str, dict], today: str, gaps: list[str]
) -> dict | None:
    """The last publishable report for a pinned server this run could not measure.

    `None` means there is nothing to fall back to, and the caller must refuse
    rather than publish: a pinned page with no report and no history is a URL
    that would 404. Anything already published has a fallback by construction,
    so this only ever fires for a pin added without a successful publication —
    which the adopt/grow path exists to prevent.

    **`gaps` is printed, because "our side failed" alone is not actionable.**
    A run that keeps 10% of its servers is either a broken toolchain or a
    transient fault, and those want opposite responses — but the log said only
    that something went wrong, so telling them apart meant re-scanning the
    named servers by hand afterwards and finding they all passed.
    """
    if name not in previous:
        print(
            f"REFUSING TO WRITE: {name} could not be measured for reasons on "
            "our side and has no previous report to fall back to — fix the "
            f"run rather than publishing it\n  {'; '.join(gaps)}",
            file=sys.stderr,
        )
        return None
    print(f"[kept]    {name} — last scan retained; {'; '.join(gaps)}", flush=True)
    return carry_forward(
        previous[name],
        checked_on=today,
        # LISTED, and the scan is what is stale — the state must not say
        # `delisted` about a server the registry still carries.
        state="stale",
        observation=(
            "This server is listed in the registry, but the most recent scan "
            "could not measure it for reasons on our side"
        ),
    )


def _growth_candidates(
    live: dict[str, RegistryEntry], pinned: frozenset[str]
) -> list[RegistryEntry]:
    """Unpinned, scannable entries in hash order.

    The scannability filter is inherited deliberately rather than by accident,
    and it is the one place this script narrows what gets published: a
    remote-only server declares nothing to fetch, so it can only ever produce a
    non-assessment page. `CLAUDE.md`'s end state is that those servers get a
    page too — that is a product decision about what the published set MEANS,
    and it belongs to whoever grows the cohort, not to a default in here.
    """
    unpinned = [e for name, e in live.items() if name not in pinned]
    unpinned.sort(key=lambda e: sample_key(e.name))
    out = []
    for entry in unpinned:
        resolution = resolve_source(entry)
        if resolution.scannable and resolution.primary:
            out.append(entry)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True, help="site data file to write")
    ap.add_argument("--cohort", type=Path, default=DEFAULT_COHORT)
    ap.add_argument(
        "--grow",
        type=int,
        default=0,
        metavar="N",
        help="also publish N servers not yet in the cohort, and pin them",
    )
    ap.add_argument(
        "--adopt-file",
        type=Path,
        metavar="PATH",
        help="newline-separated registry names to publish and pin, in addition "
             "to the cohort — for URLs published before the pin existed",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan — what would be scanned, grown, carried forward",
    )
    args = ap.parse_args()

    missing = preflight()
    if missing:
        print(
            "REFUSING TO SCAN:\n  " + "\n  ".join(missing)
            + "\n\nA missing binary does not raise — it publishes a clean "
            "non-assessment naming our own tooling on someone else's page. "
            "Install the toolchain (`python -m venv .venv-workers && "
            '.venv-workers/bin/pip install -e ".[workers]"`, plus osv-scanner) '
            "and put its bin directory on PATH.",
            file=sys.stderr,
        )
        return 2

    cohort = load(args.cohort)
    print(f"cohort: {len(cohort)} servers pinned ({args.cohort})", flush=True)

    # `fetch_all` refuses to return a partial manifest, which is what licenses
    # the conclusion below that a pinned server is ABSENT rather than merely
    # unfetched. The old 800-entry pool could not tell those apart, and read
    # "outside my window" as "not in the registry".
    started = time.time()
    manifest = fetch_all()
    live = {e.name: e for e in current_entries(manifest)}
    # ⚠ `is_latest` WINS, rather than whichever row happens to come last. A
    # plain `{e.name: e for e in manifest}` keeps the LAST occurrence, so a
    # pinned server whose superseded version trails its current one in the
    # manifest resolved to the superseded row — `is_latest` False — and the
    # branch below then read "no current entry" and carried an old report
    # forward as DELISTED, about a server the registry still lists and whose
    # deprecated entry was scannable. A page frozen and mislabelled by manifest
    # ordering. 349 of 33,081 entries are not active-and-latest, so the
    # multi-version shape this depends on is ordinary.
    listed: dict[str, RegistryEntry] = {}
    # `row`, not `entry`: the name is reused below for a `RegistryEntry | None`,
    # and binding it here as a non-optional made the later assignment a type
    # error. mypy caught it — the gate over `ops` earning its place on the
    # commit that widened it.
    for row in manifest:
        held = listed.get(row.name)
        if held is None or (row.is_latest and not held.is_latest):
            listed[row.name] = row
    print(
        f"registry: {len(manifest)} entries, {len(live)} active-latest "
        f"({time.time() - started:.0f}s)",
        flush=True,
    )

    previous: dict[str, dict] = {}
    if args.out.is_file():
        previous = {r["name"]: r for r in json.loads(args.out.read_text())}

    today = time.strftime("%Y-%m-%d", time.gmtime())
    to_scan: list[RegistryEntry] = []
    # Scannable, but the registry's status is not `active` — the entry is real,
    # so the numbers can be current and the status is relayed beside them.
    to_flag: list[RegistryEntry] = []
    to_carry: list[tuple[str, str]] = []
    for pin in cohort.servers:
        if pin.name in live:
            to_scan.append(live[pin.name])
            continue
        entry = listed.get(pin.name)
        if entry is not None and entry.is_latest:
            # Present, latest, not active: deprecated (349 of 33,081 entries
            # on 2026-09-18). Its source still resolves, so scan it.
            to_flag.append(entry)
            continue
        # Absent, or present only as a SUPERSEDED version — `current_entries`
        # exists because scoring one publishes a grade against code nobody
        # installs. Either way there is no current entry to scan, so the page
        # keeps the last scan taken while the server was listed.
        observation = (
            f"The registry lists this server only at version {entry.version}, "
            "which is no longer the latest"
            if entry is not None
            else "The registry no longer lists this server"
        )
        to_carry.append((pin.name, observation))

    missing_history = [name for name, _ in to_carry if name not in previous]
    if missing_history:
        # Refusing here rather than dropping them: a pinned server with no
        # prior report and no registry entry cannot be published at all, and
        # writing the file anyway would 404 a live URL silently — the exact
        # failure the pin exists to prevent.
        print(
            "REFUSING TO WRITE: these pinned servers are not in the registry "
            "and have no previous report to carry forward, so their pages "
            "cannot be published:\n  " + "\n  ".join(missing_history),
            file=sys.stderr,
        )
        return 2

    growth: list[RegistryEntry] = []
    if args.adopt_file:
        wanted = [
            line.strip()
            for line in args.adopt_file.read_text().splitlines()
            if line.strip()
        ]
        missing_from_registry = [
            n for n in wanted if n not in live and n not in cohort.names
        ]
        if missing_from_registry:
            # Adoption needs a current entry to scan: there is no previous
            # report for a page that is not published. Named rather than
            # silently dropped — a name that cannot be adopted is a URL that
            # stays 404, which the operator asked to fix.
            print(
                f"{len(missing_from_registry)} name(s) to adopt are not in the "
                "registry's active listing and cannot be published:\n  "
                + "\n  ".join(missing_from_registry),
                file=sys.stderr,
            )
        growth.extend(live[n] for n in wanted if n in live and n not in cohort.names)
    if args.grow > 0:
        already = cohort.names | {e.name for e in growth}
        picked = _growth_candidates(live, already)[: args.grow]
        if len(picked) < args.grow:
            print(
                f"only {len(picked)} scannable unpinned servers available",
                file=sys.stderr,
            )
        growth.extend(picked)

    if args.dry_run:
        print(f"\nwould scan   {len(to_scan)} pinned")
        print(f"would scan   {len(to_flag)} pinned, flagged with a non-active status")
        for entry in to_flag:
            print(f"   {entry.name} — status {entry.status}")
        print(f"would carry  {len(to_carry)} pinned (no current registry entry)")
        for name, observation in to_carry:
            print(f"   {name} — {observation}")
        print(f"would publish {len(growth)} new/adopted (pinned only on success)")
        for entry in growth:
            print(f"   {entry.name} -> /servers/{slugify(entry.name)}/")
        return 0

    total = len(to_scan) + len(to_flag) + len(growth)
    reports: dict[str, dict] = {}
    index = 0
    unmeasured: list[str] = []
    for entry in to_scan:
        index += 1
        report, gaps = _scan_once_more_if_ours(entry, "pinned", index, total)
        # An ENVIRONMENT gap is ours and unpublishable, and at 500 servers it
        # is an ordinary event rather than an emergency: a clone that times
        # out, a scratch mount that fills. Refusing the whole run for one of
        # them would make the pin brittle in the one direction it exists to
        # prevent — a page disappearing — so the page keeps the last scan
        # taken when we could measure it, labelled, exactly as a delisted
        # server does. The next run retries for free.
        if gaps:
            kept = _keep_previous(entry.name, previous, today, gaps)
            if kept is None:
                return 2
            reports[entry.name] = kept
            unmeasured.append(entry.name)
            continue
        reports[entry.name] = report
    for entry in to_flag:
        index += 1
        # Same per-server handling as `to_scan` — a deprecated pin is still a
        # pinned page, and skipping this check meant a clone timeout on one of
        # them aborted the whole batch while the identical failure on a
        # non-deprecated pin was absorbed. 1 of the 40 original pins is
        # deprecated, so that asymmetry was load-bearing.
        report, gaps = _scan_once_more_if_ours(entry, "flagged", index, total)
        if gaps:
            kept = _keep_previous(entry.name, previous, today, gaps)
            if kept is None:
                return 2
            reports[entry.name] = kept
            unmeasured.append(entry.name)
            continue
        try:
            reports[entry.name] = mark_status(
                report, status=entry.status, observed_on=today
            )
        except CohortError as exc:
            # ⚠ FAIL CLOSED, BUT PER SERVER. `mark_status` refuses a registry
            # status that collides with a state of OURS, and it refuses it
            # correctly — relaying the word would disable this server's
            # publication gate. Uncaught, though, that refusal aborted a
            # 492-page run with a traceback over one entry, which is a wider
            # blast radius than every other refusal here takes: the project's
            # own stance is that a refused gap costs that page its refresh,
            # not the run.
            #
            # So it lands in the same machinery an our-side gap does. The
            # server keeps the last scan we could take, labelled, and the
            # reason is printed rather than raised — and it IS ours: the
            # collision is our schema sharing one field with a third party's
            # vocabulary, not a defect in what they published.
            kept = _keep_previous(entry.name, previous, today, [str(exc)])
            if kept is None:
                return 2
            reports[entry.name] = kept
            unmeasured.append(entry.name)
            continue
    published_growth: list[RegistryEntry] = []
    skipped: list[str] = []
    for entry in growth:
        index += 1
        report, gaps = _scan_once_more_if_ours(entry, "new", index, total)
        # Nothing promises this page yet, so an our-side gap means DON'T PIN
        # IT — publishing it would mint a URL whose first version states our
        # broken run as the reason nobody scored them.
        if gaps:
            print(f"[skipped] {entry.name} — our side failed; not pinned")
            skipped.append(entry.name)
            continue
        reports[entry.name] = report
        published_growth.append(entry)
    growth = published_growth
    for name, observation in to_carry:
        reports[name] = carry_forward(
            previous[name], checked_on=today, observation=observation
        )
        print(f"[carried] {name} — {observation}", flush=True)

    grown: Cohort = cohort
    if growth:
        grown = cohort.extended_with((e.name for e in growth), on=today)

    # The decision to refuse lives in `cohort.publication_errors`, which is
    # where it can be tested: every case it names is invisible once written.
    problems = publication_errors(grown, reports.values())
    if problems:
        print(
            "REFUSING TO WRITE:\n  " + "\n  ".join(problems),
            file=sys.stderr,
        )
        return 2

    # COHORT FIRST, and the order is the whole point. A crash between the two
    # writes leaves either a pin with no page — refused by the gate on the
    # next run, which then scans it — or a page with no pin, which is exactly
    # the mechanism that lost 100 URLs. Only the first is recoverable, so it
    # is the one a failure must produce.
    ordered = [reports[pin.name] for pin in grown.servers]
    if growth:
        save(args.cohort, grown)
        print(f"cohort grown to {len(grown)} — commit {args.cohort.name}")
    atomic_write(args.out, json.dumps(ordered, indent=1) + "\n")
    print(
        f"\n{len(ordered)} servers -> {args.out} "
        f"({len(to_scan) + len(to_flag)} scanned, {len(growth)} new, "
        f"{len(to_carry)} carried, {len(unmeasured)} kept) "
        f"in {time.time() - started:.0f}s"
    )
    # ⚠ NAMED, NOT TALLIED. The counts above describe what was PUBLISHED, so
    # the two outcomes that are worth a human's attention — a pinned page that
    # kept an older scan, and a growth candidate that did not get pinned —
    # appear either as a number with no names or not at all. Both were
    # printed per server as the run went, hundreds of lines earlier, so
    # answering "which ones?" meant grepping a log that may not have been
    # kept. A run that keeps ten servers is either a broken toolchain or a
    # transient fault and those want opposite responses.
    if unmeasured:
        print(f"kept previous scan ({len(unmeasured)}): {', '.join(sorted(unmeasured))}")
    if skipped:
        print(f"not pinned, our side failed ({len(skipped)}): {', '.join(sorted(skipped))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
