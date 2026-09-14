"""Registry polling: fetch the official MCP registry, diff it, resolve sources.

`02-architecture.md` §2.1 (registry poller) and `04-scanner-design.md` §2
(source resolution). The nightly job is: fetch every current entry, hash each
one, compare against the last snapshot, and hand the scanner a source spec for
everything that changed.

**Parsing, hashing, diffing and source resolution are pure stdlib. Only
`fetch_all` touches the network.** That split is deliberate: the pure half holds
every invariant worth pinning and runs over the whole registry each night, so it
has to be cheap to call and trivial to test without a fixture server.

**The registry returns one entry per (server, version), not per server.** A
server with six published versions is six entries, and exactly one of them
carries `isLatest`. Treating the raw page as a server list overcounts badly —
`current_entries` is the filter that makes it a server list.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from mcpwatchman import __version__

REGISTRY_BASE_URL = "https://registry.modelcontextprotocol.io"
SERVERS_PATH = "/v0/servers"

# The API caps `limit` at 100; asking for more is silently clamped, so the page
# count is a function of registry size and nothing we can tune away.
PAGE_LIMIT = 100

# Namespaced key the official registry stamps its own bookkeeping under. It is
# namespaced precisely because third parties may add their own `_meta` blocks,
# so read this key rather than assuming `_meta` has one child.
OFFICIAL_META_KEY = "io.modelcontextprotocol.registry/official"

# Derived from `__version__`, never written out. A hardcoded version here would
# drift silently at the next bump: nothing imports it, nothing tests it, and the
# only place it shows up is in someone else's access log.
USER_AGENT = f"mcpwatchman/{__version__} (+https://github.com/kVadrum/mcpwatchman)"

# Seconds between page requests. A measured FLOOR, not an established
# sustainable rate — the distinction is load-bearing, so read the whole note.
#
# Measured 2026-09-14 against the live registry:
#   - Four pages at ~0.1s apart return in 0.1-0.3s each; the fifth HANGS until
#     the client timeout. So sub-second pacing is definitely wrong.
#   - Eight consecutive pages at 1.0s apart returned clean, 1.9s worst case.
#   - **But a sustained crawl at that same 1.0s pacing, later the same session,
#     hit repeated slow pages (9.4s, 12.9s).** Eight pages was too short a probe
#     to see it: the limiter appears to have a longer window that a short burst
#     does not exhaust, and by then the session had spent it.
#
# So 1.0 fixes the obvious failure and is not known to be sustainable for a
# whole-registry crawl. **The sustainable rate, the limiter's window, and the
# registry's total page count are all UNMEASURED** — establishing them needs a
# clean window, not another probe appended to a session that has been hammering
# the API. Do not raise this number on the strength of a short green run; that
# is precisely the measurement that already misled once, here, in this comment.
#
# The failure mode is the dangerous part and the reason this is a constant
# rather than a caller's problem: the throttle does not answer 429, it stops
# answering. A retry loop reading that as a transient network fault retries
# straight back into the wall and turns a rate limit into an outage. `02` §146
# sizes the crawl's retry budget on the assumption that a failure means the
# registry is down; at pause=0 that assumption is wrong and self-inflicted.
DEFAULT_PAUSE = 1.0


class SourceKind(StrEnum):
    """Where a scannable artifact comes from.

    Mirrors `servers.source_type` in `05-data-model.md` §3.1, plus `OCI` which
    the schema folds into 'other' — kept distinct here because the scanner needs
    to know it is a container (deferred to v0.3, `04` §2) rather than merely
    unrecognised.
    """

    GITHUB = "github"
    GITLAB = "gitlab"
    NPM = "npm"
    PYPI = "pypi"
    OCI = "oci"
    OTHER = "other"


# registryType values the registry emits → our source kind. Anything absent
# resolves to OTHER rather than raising: a new package ecosystem is a coverage
# gap to report, never a crash in the nightly poll.
_REGISTRY_TYPE_TO_KIND: dict[str, SourceKind] = {
    "npm": SourceKind.NPM,
    "pypi": SourceKind.PYPI,
    "oci": SourceKind.OCI,
}

# Package kinds the v0.1 scanner can actually fetch and read. OCI is excluded by
# `04` §2 ("v0.3+; not in v0.1"), so it is resolved, reported, and not scanned.
_SCANNABLE_PACKAGE_KINDS = frozenset({SourceKind.NPM, SourceKind.PYPI})

_REPO_HOST_TO_KIND: dict[str, SourceKind] = {
    "github.com": SourceKind.GITHUB,
    "www.github.com": SourceKind.GITHUB,
    "gitlab.com": SourceKind.GITLAB,
    "www.gitlab.com": SourceKind.GITLAB,
}


@dataclass(frozen=True, slots=True)
class Package:
    """A published artifact the server is distributed as."""

    registry_type: str
    identifier: str
    version: str
    transport: str | None = None

    @property
    def kind(self) -> SourceKind:
        return _REGISTRY_TYPE_TO_KIND.get(self.registry_type, SourceKind.OTHER)


@dataclass(frozen=True, slots=True)
class Remote:
    """A hosted endpoint the server is reachable at."""

    type: str
    url: str


@dataclass(frozen=True, slots=True)
class Repository:
    url: str
    source: str | None = None
    subfolder: str | None = None

    @property
    def kind(self) -> SourceKind:
        host = (urlparse(self.url).hostname or "").lower()
        return _REPO_HOST_TO_KIND.get(host, SourceKind.OTHER)

    @property
    def slug(self) -> str | None:
        """`owner/repo` for a recognised forge URL, else None.

        Tolerates the shapes that actually appear: a trailing `.git`, a trailing
        slash, and a deep link (`/tree/<ref>/<path>`) whose extra segments are a
        monorepo path rather than part of the repository name.
        """
        if self.kind not in (SourceKind.GITHUB, SourceKind.GITLAB):
            return None
        parts = [p for p in urlparse(self.url).path.split("/") if p]
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        return f"{owner}/{repo}" if owner and repo else None

    @property
    def path_subfolder(self) -> str | None:
        """Monorepo subdirectory encoded in a `/tree/<ref>/<path>` deep link.

        `subfolder` (a declared field) wins when present; this is the fallback
        for entries that encode the same thing in the URL. Sparse checkout
        (`04` §2) needs one or the other — `modelcontextprotocol/servers` alone
        holds dozens of servers in subdirectories.
        """
        if self.subfolder:
            return self.subfolder.strip("/") or None
        parts = [p for p in urlparse(self.url).path.split("/") if p]
        if len(parts) > 3 and parts[2] in ("tree", "blob"):
            return "/".join(parts[4:]) or None
        return None


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """One (server, version) pair as the registry describes it."""

    name: str
    version: str
    description: str = ""
    title: str | None = None
    website_url: str | None = None
    repository: Repository | None = None
    packages: tuple[Package, ...] = ()
    remotes: tuple[Remote, ...] = ()
    status: str = "active"
    is_latest: bool = False
    published_at: str | None = None
    updated_at: str | None = None
    content_hash: str = ""

    @property
    def key(self) -> str:
        """Stable identity for diffing: `name@version`.

        `name` is already namespaced by the registry (`io.github.foo/bar`), so
        the pair is unique without a surrogate id — and unlike the registry's
        own cursor it does not change shape between API versions.
        """
        return f"{self.name}@{self.version}"


@dataclass(frozen=True, slots=True)
class SourceResolution:
    """Where the scanner should look, and what to say when it cannot look.

    `04` §2: the published package is primary because it is what a user actually
    installs; the repository is a supplement for maintenance signals and file
    context. Both may be present, and a discrepancy between them is itself a
    Transparency finding.
    """

    primary: str | None = None
    supplement: str | None = None
    kind: SourceKind | None = None
    subfolder: str | None = None
    skip_reason: str | None = None

    @property
    def scannable(self) -> bool:
        return self.primary is not None


def _clean(value: Any) -> str | None:
    """Normalise an optional string field: absent, null and '' all become None."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def canonical_json(payload: Any) -> str:
    """Deterministic JSON for hashing: sorted keys, no incidental whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_entry(raw: Mapping[str, Any]) -> RegistryEntry:
    """Parse one `servers[]` element into a `RegistryEntry`.

    Tolerant by construction. The nightly poll reads several thousand entries
    written by several thousand different people, so an unexpected field shape
    must degrade that one entry rather than fail the run — a poll that aborts on
    entry 4,000 leaves the whole registry unscanned, which is a far worse
    outcome than one server with a missing description.

    The content hash covers the `server` object ONLY, deliberately excluding
    `_meta`. The registry rewrites `updatedAt` on bookkeeping changes that do
    not touch the artifact, and hashing those would re-scan the entire registry
    on a day nothing shipped.
    """
    server = raw.get("server")
    if not isinstance(server, Mapping):
        raise ValueError("registry entry has no 'server' object")

    name = _clean(server.get("name"))
    version = _clean(server.get("version"))
    if not name or not version:
        raise ValueError(f"registry entry missing name/version: {name!r}@{version!r}")

    repository = None
    raw_repo = server.get("repository")
    if isinstance(raw_repo, Mapping):
        url = _clean(raw_repo.get("url"))
        if url:
            repository = Repository(
                url=url,
                source=_clean(raw_repo.get("source")),
                subfolder=_clean(raw_repo.get("subfolder")),
            )

    packages = tuple(
        Package(
            registry_type=_clean(p.get("registryType")) or "unknown",
            identifier=_clean(p.get("identifier")) or "",
            version=_clean(p.get("version")) or version,
            transport=_clean((p.get("transport") or {}).get("type"))
            if isinstance(p.get("transport"), Mapping)
            else None,
        )
        for p in server.get("packages", [])
        if isinstance(p, Mapping)
    )

    remotes = tuple(
        Remote(type=_clean(r.get("type")) or "unknown", url=_clean(r.get("url")) or "")
        for r in server.get("remotes", [])
        if isinstance(r, Mapping)
    )

    meta = raw.get("_meta")
    official = meta.get(OFFICIAL_META_KEY, {}) if isinstance(meta, Mapping) else {}
    if not isinstance(official, Mapping):
        official = {}

    return RegistryEntry(
        name=name,
        version=version,
        description=_clean(server.get("description")) or "",
        title=_clean(server.get("title")),
        website_url=_clean(server.get("websiteUrl")),
        repository=repository,
        packages=packages,
        remotes=remotes,
        status=_clean(official.get("status")) or "active",
        is_latest=bool(official.get("isLatest", False)),
        published_at=_clean(official.get("publishedAt")),
        updated_at=_clean(official.get("updatedAt")),
        content_hash=_sha256(canonical_json(server)),
    )


def parse_page(payload: Mapping[str, Any]) -> tuple[list[RegistryEntry], str | None]:
    """Parse one API page into entries plus the next cursor.

    Unparseable entries are dropped, not raised — see `parse_entry`. They are
    recoverable from the stored snapshot, which keeps the raw manifest.
    """
    entries: list[RegistryEntry] = []
    for raw in payload.get("servers", []):
        if not isinstance(raw, Mapping):
            continue
        try:
            entries.append(parse_entry(raw))
        except ValueError:
            continue
    metadata = payload.get("metadata")
    cursor = (
        _clean(metadata.get("nextCursor")) if isinstance(metadata, Mapping) else None
    )
    return entries, cursor


def current_entries(entries: Iterable[RegistryEntry]) -> list[RegistryEntry]:
    """The one live entry per server: latest version, active status.

    Everything else is history. Scoring a superseded version would publish a
    grade against code nobody installs.
    """
    return [e for e in entries if e.is_latest and e.status == "active"]


def resolve_source(entry: RegistryEntry) -> SourceResolution:
    """Map an entry to the source spec the scanner consumes (`04` §2).

    Returns a resolution rather than a string so an unscannable entry carries a
    *reason*. That reason is a product surface, not a log line: a server we
    cannot analyse must say why on its page instead of rendering an absent score
    as a bad one.
    """
    repo = entry.repository
    supplement = None
    if repo is not None and (slug := repo.slug):
        supplement = f"{repo.kind.value}:{slug}@{entry.version}"

    for package in entry.packages:
        if package.kind in _SCANNABLE_PACKAGE_KINDS and package.identifier:
            return SourceResolution(
                primary=f"{package.kind.value}:{package.identifier}@{package.version}",
                supplement=supplement,
                kind=package.kind,
                subfolder=repo.path_subfolder if repo else None,
            )

    if supplement is not None and repo is not None:
        # No published artifact we can fetch, but the source is readable. Scan
        # the repository directly — weaker evidence than the installed artifact,
        # and the per-server page says so.
        return SourceResolution(
            primary=supplement,
            supplement=None,
            kind=repo.kind,
            subfolder=repo.path_subfolder,
        )

    if any(p.kind is SourceKind.OCI for p in entry.packages):
        return SourceResolution(skip_reason="container-only source; deferred to v0.3")
    if entry.packages:
        kinds = sorted({p.registry_type for p in entry.packages})
        return SourceResolution(
            skip_reason=f"no fetchable package source ({', '.join(kinds)})"
        )
    if entry.remotes:
        return SourceResolution(
            skip_reason="remote-only server; no published source to analyse"
        )
    return SourceResolution(skip_reason="no repository, package or remote declared")


@dataclass(frozen=True, slots=True)
class ManifestDiff:
    """What changed between two polls."""

    added: tuple[RegistryEntry, ...] = ()
    updated: tuple[RegistryEntry, ...] = ()
    unchanged: tuple[RegistryEntry, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def to_scan(self) -> tuple[RegistryEntry, ...]:
        """Entries the poll should enqueue. Unchanged entries are cache hits."""
        return self.added + self.updated

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.updated or self.removed)


def hashes_of(entries: Iterable[RegistryEntry]) -> dict[str, str]:
    """`key -> content_hash`, the projection a diff needs from a prior poll."""
    return {e.key: e.content_hash for e in entries}


def diff_entries(
    previous: Mapping[str, str],
    current: Sequence[RegistryEntry],
) -> ManifestDiff:
    """Diff current entries against `key -> content_hash` from the last poll.

    Takes hashes rather than entries so the caller can diff against a stored
    projection without rehydrating a whole snapshot.

    **`current` MUST be a complete manifest.** This function infers removal from
    absence, so handing it the result of an `updated_since` query — which returns
    only what changed — marks every untouched server as removed. Use
    `diff_incremental` for that. The two are separated precisely because the
    mistake is invisible: both inputs are a list of entries, and the wrong one
    produces a confident, catastrophic answer rather than an error.

    **An empty `previous` yields everything as added, which is correct for a
    first run and catastrophic as a failure mode.** A caller that silently
    substitutes `{}` for a failed snapshot read enqueues the entire registry.
    Fail the poll instead; `02` §146 makes the daily crawl skippable by design.
    """
    added, updated, unchanged = [], [], []
    for entry in current:
        prior = previous.get(entry.key)
        if prior is None:
            added.append(entry)
        elif prior != entry.content_hash:
            updated.append(entry)
        else:
            unchanged.append(entry)

    seen = {e.key for e in current}
    removed = tuple(sorted(k for k in previous if k not in seen))
    return ManifestDiff(
        added=tuple(added),
        updated=tuple(updated),
        unchanged=tuple(unchanged),
        removed=removed,
    )


def diff_incremental(
    previous: Mapping[str, str],
    changed: Sequence[RegistryEntry],
) -> ManifestDiff:
    """Diff the result of an `updated_since` query (a changelog, not a manifest).

    Two rules, both the opposite of `diff_entries`:

    1. **Absence means unchanged, never removed.** An incremental response only
       contains what moved, so nothing may be inferred about servers it omits.
       `removed` here is derived from entries the registry explicitly marks
       non-active — which is why it forces `include_deleted` on for these
       queries.
    2. **`unchanged` is always empty**, because this response cannot tell us
       about unchanged servers. Reporting 0 rather than a count we did not
       measure keeps "we did not look" from rendering as "we looked and found
       none" (`base.md` § *Signal design*).
    """
    added, updated, removed = [], [], []
    for entry in changed:
        if entry.status != "active":
            removed.append(entry.key)
            continue
        prior = previous.get(entry.key)
        if prior is None:
            added.append(entry)
        elif prior != entry.content_hash:
            updated.append(entry)
        # An active entry whose hash matches is a no-op: the registry considered
        # it updated, but nothing we score changed (see `parse_entry` on why
        # `_meta` is excluded from the hash).
    return ManifestDiff(
        added=tuple(added),
        updated=tuple(updated),
        unchanged=(),
        removed=tuple(sorted(removed)),
    )


def manifest_hash(entries: Iterable[RegistryEntry]) -> str:
    """Hash of the whole manifest, for `manifest_snapshots.hash` (`05` §3.8).

    Order-independent: the registry paginates by cursor and two polls may
    interleave differently, which must not read as a changed registry.
    """
    pairs = sorted((e.key, e.content_hash) for e in entries)
    return _sha256(canonical_json(pairs))


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """How much of the registry static analysis can actually reach.

    Surfaced rather than computed and dropped. A trust product that scans 45% of
    a registry and presents it as "the registry" is making the same unstated
    claim it exists to correct, so this number belongs on the site.
    """

    total: int = 0
    scannable: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        """Scannable share, 0.0-1.0. Zero entries reads as 0.0, never 1.0."""
        return self.scannable / self.total if self.total else 0.0


def coverage_report(entries: Iterable[RegistryEntry]) -> CoverageReport:
    """Count how many entries resolve to something the v0.1 scanner can read."""
    total = scannable = 0
    by_kind: dict[str, int] = {}
    skipped: dict[str, int] = {}
    for entry in entries:
        total += 1
        resolution = resolve_source(entry)
        if resolution.scannable and resolution.kind is not None:
            scannable += 1
            by_kind[resolution.kind.value] = by_kind.get(resolution.kind.value, 0) + 1
        else:
            reason = resolution.skip_reason or "unknown"
            skipped[reason] = skipped.get(reason, 0) + 1
    return CoverageReport(
        total=total, scannable=scannable, by_kind=by_kind, skipped=skipped
    )


class RegistryUnavailableError(RuntimeError):
    """The registry could not be read. `02` §146 owns the retry policy."""


def fetch_all(
    *,
    base_url: str = REGISTRY_BASE_URL,
    client: Any = None,
    limit: int = PAGE_LIMIT,
    latest_only: bool = True,
    updated_since: str | None = None,
    max_pages: int = 1000,
    attempts: int = 3,
    backoff: float = 1.0,
    pause: float = DEFAULT_PAUSE,
) -> list[RegistryEntry]:
    """Fetch every registry entry, following cursors.

    The one function here that touches the network. `client` accepts an existing
    `httpx.Client` so callers (and tests) control transport; otherwise one is
    created and closed.

    Retries transient failures `attempts` times with exponential backoff. The
    longer outer policy — retry every 15 minutes for 6 hours, then skip the
    crawl and alert — belongs to the job, not here (`02` §146).

    **Partial pages are never returned.** A truncated manifest diffed against a
    complete one marks every unfetched server as removed, which would delist
    most of the registry from a single network blip.

    `pause` defaults to `DEFAULT_PAUSE` because the registry throttles by
    timing out rather than by answering 429 — see that constant. Setting it to 0
    is a way to make a healthy registry look unreachable.

    `latest_only` sends `version=latest`, so the registry returns one entry per
    server instead of one per published version. On by default: the manifest we
    diff is a list of *servers*, and pulling every historical version to throw
    all but one away multiplies the page count — which, against a limiter that
    penalises sustained crawling, is the difference between a poll that finishes
    and one that degrades.

    `updated_since` (RFC3339) asks for only what changed since a prior poll.
    **It changes the meaning of the result, and therefore which diff you may
    use.** The response is no longer a manifest — it is a changelog, and absence
    from it means "unchanged", not "gone". Feed it to `diff_incremental`, never
    to `diff_entries`, which would read every untouched server as removed. The
    registry also forces `include_deleted` on for these queries, which is what
    makes deletions visible at all.
    """
    import httpx

    owns_client = client is None
    if owns_client:
        client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )

    entries: list[RegistryEntry] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    try:
        for _ in range(max_pages):
            params: dict[str, Any] = {"limit": limit}
            if latest_only:
                params["version"] = "latest"
            if updated_since:
                params["updated_since"] = updated_since
            if cursor:
                params["cursor"] = cursor
            payload = _get_json(
                client, f"{base_url}{SERVERS_PATH}", params, attempts, backoff
            )
            page, cursor = parse_page(payload)
            entries.extend(page)
            if not cursor:
                return entries
            # A repeated cursor means the server is looping us; stopping with a
            # partial result would silently delist the tail, so this is an error.
            if cursor in seen_cursors:
                raise RegistryUnavailableError(
                    f"registry returned a repeated cursor ({cursor!r}); "
                    "refusing to return a partial manifest"
                )
            seen_cursors.add(cursor)
            if pause:
                time.sleep(pause)
        raise RegistryUnavailableError(
            f"registry pagination exceeded {max_pages} pages; refusing to "
            "return a partial manifest"
        )
    finally:
        if owns_client:
            client.close()


def _get_json(
    client: Any,
    url: str,
    params: Mapping[str, Any],
    attempts: int,
    backoff: float,
) -> Mapping[str, Any]:
    """GET with bounded retry. Raises `RegistryUnavailableError` when exhausted."""
    import httpx

    last: Exception | None = None
    for attempt in range(attempts):
        try:
            response = client.get(url, params=params)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, Mapping):
                raise RegistryUnavailableError(f"non-object response from {url}")
            return payload
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
            if attempt < attempts - 1:
                time.sleep(backoff * (2**attempt))
    raise RegistryUnavailableError(f"registry unreachable after {attempts} attempts: {last}")
