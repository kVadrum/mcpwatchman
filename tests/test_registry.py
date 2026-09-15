"""Registry crawler invariants (`02` §2.1, `04` §2, `05` §3.8).

Aimed at the decisions that are expensive to get wrong — entry identity, what
counts as changed, what the diff does to entries it did not see, and whether an
unscannable server says why. Straight field-copying in `parse_entry` is not
tested: those assertions only restate the assignment.
"""

from __future__ import annotations

import pytest

from mcpwatchman.workers.crawler.registry import (
    OFFICIAL_META_KEY,
    RegistryUnavailableError,
    Repository,
    SourceKind,
    coverage_report,
    current_entries,
    diff_entries,
    diff_incremental,
    fetch_all,
    hashes_of,
    manifest_hash,
    parse_entry,
    parse_page,
    resolve_source,
)


def make_raw(
    name="io.github.acme/server",
    version="1.0.0",
    *,
    is_latest=True,
    status="active",
    **server_fields,
):
    server = {"name": name, "version": version, "description": "d", **server_fields}
    return {
        "server": server,
        "_meta": {
            OFFICIAL_META_KEY: {
                "status": status,
                "isLatest": is_latest,
                "publishedAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-02T00:00:00Z",
            }
        },
    }


# --- identity and hashing -------------------------------------------------


def test_content_hash_ignores_registry_bookkeeping():
    """`_meta` churn must not re-scan the registry.

    The registry rewrites `updatedAt` for changes that do not touch the
    artifact. If those fed the hash, a bookkeeping sweep on the registry side
    would enqueue every server we know about.
    """
    a = parse_entry(make_raw())
    b_raw = make_raw()
    b_raw["_meta"][OFFICIAL_META_KEY]["updatedAt"] = "2099-12-31T23:59:59Z"
    b = parse_entry(b_raw)
    assert a.content_hash == b.content_hash


def test_content_hash_tracks_the_artifact():
    a = parse_entry(make_raw())
    b = parse_entry(make_raw(description="something else"))
    assert a.content_hash != b.content_hash


def test_manifest_hash_is_order_independent():
    """Cursor pagination gives no ordering guarantee across polls."""
    one = parse_entry(make_raw(name="a/x"))
    two = parse_entry(make_raw(name="b/y"))
    assert manifest_hash([one, two]) == manifest_hash([two, one])


def test_manifest_hash_changes_when_an_entry_changes():
    one = parse_entry(make_raw(name="a/x"))
    two = parse_entry(make_raw(name="b/y"))
    three = parse_entry(make_raw(name="b/y", description="changed"))
    assert manifest_hash([one, two]) != manifest_hash([one, three])


def test_key_distinguishes_versions_of_one_server():
    a = parse_entry(make_raw(version="1.0.0"))
    b = parse_entry(make_raw(version="1.0.1"))
    assert a.key != b.key


# --- parsing tolerance ----------------------------------------------------


def test_parse_page_drops_a_bad_entry_without_losing_the_page():
    """One malformed entry must not cost us the other 99.

    A poll that aborts mid-registry leaves everything after it unscanned, which
    is strictly worse than skipping the entry that could not be read.
    """
    payload = {
        "servers": [make_raw(name="a/x"), {"server": {"name": "no-version"}}, "junk"],
        "metadata": {"nextCursor": "c1"},
    }
    entries, cursor = parse_page(payload)
    assert [e.name for e in entries] == ["a/x"]
    assert cursor == "c1"


def test_parse_page_reports_no_cursor_on_the_last_page():
    entries, cursor = parse_page({"servers": [make_raw()], "metadata": {"count": 1}})
    assert len(entries) == 1 and cursor is None


@pytest.mark.parametrize("missing", [{"server": {}}, {}, {"server": {"name": "x"}}])
def test_parse_entry_rejects_an_entry_without_identity(missing):
    with pytest.raises(ValueError):
        parse_entry(missing)


# --- current-entry filtering ----------------------------------------------


def test_current_entries_keeps_one_version_per_server():
    """The API returns every version; scoring a superseded one grades code
    nobody installs."""
    entries = [
        parse_entry(make_raw(version="1.0.0", is_latest=False)),
        parse_entry(make_raw(version="2.0.0", is_latest=True)),
    ]
    assert [e.version for e in current_entries(entries)] == ["2.0.0"]


def test_current_entries_drops_inactive_servers():
    entries = [parse_entry(make_raw(is_latest=True, status="deleted"))]
    assert current_entries(entries) == []


# --- source resolution ----------------------------------------------------


def test_published_package_outranks_the_repository():
    """`04` §2: the artifact users install is primary, the repo is supplement."""
    entry = parse_entry(
        make_raw(
            packages=[{"registryType": "npm", "identifier": "acme-mcp", "version": "1.2.3"}],
            repository={"url": "https://github.com/acme/server", "source": "github"},
        )
    )
    r = resolve_source(entry)
    assert r.primary == "npm:acme-mcp@1.2.3"
    assert r.supplement == "github:acme/server@1.0.0"
    assert r.kind is SourceKind.NPM


def test_repository_is_used_when_there_is_no_fetchable_package():
    entry = parse_entry(
        make_raw(repository={"url": "https://github.com/acme/server.git"})
    )
    r = resolve_source(entry)
    assert r.primary == "github:acme/server@1.0.0"
    assert r.supplement is None


def test_remote_only_server_is_unscannable_and_says_why():
    """The reason is a product surface: an absent score must not render as a
    bad one."""
    entry = parse_entry(
        make_raw(remotes=[{"type": "streamable-http", "url": "https://x.example"}])
    )
    r = resolve_source(entry)
    assert not r.scannable
    assert r.skip_reason and "remote-only" in r.skip_reason


def test_container_only_source_is_deferred_not_silently_dropped():
    entry = parse_entry(
        make_raw(packages=[{"registryType": "oci", "identifier": "acme/img", "version": "1"}])
    )
    r = resolve_source(entry)
    assert not r.scannable
    assert r.skip_reason and "v0.3" in r.skip_reason


def test_unknown_package_ecosystem_degrades_to_a_reason():
    """A new registry type is a coverage gap to report, never a crash."""
    entry = parse_entry(
        make_raw(packages=[{"registryType": "cargo", "identifier": "x", "version": "1"}])
    )
    r = resolve_source(entry)
    assert not r.scannable and "cargo" in r.skip_reason


def test_monorepo_subfolder_is_recovered_from_a_deep_link():
    """Sparse checkout needs the path; dozens of servers share one repo."""
    entry = parse_entry(
        make_raw(
            repository={
                "url": "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"
            }
        )
    )
    r = resolve_source(entry)
    # The subfolder rides the SPEC STRING as a fragment, not only the field —
    # `source_spec` is the wire format the scanner parses, and a path carried
    # beside it was silently dropped (Codex leg, 2026-09-14).
    assert r.primary == "github:modelcontextprotocol/servers@1.0.0#src/fetch"
    assert r.subfolder == "src/fetch"


def test_declared_subfolder_wins_over_the_url_path():
    repo = Repository(
        url="https://github.com/acme/servers/tree/main/wrong", subfolder="right/here"
    )
    assert repo.path_subfolder == "right/here"


@pytest.mark.parametrize(
    "url,slug",
    [
        ("https://github.com/acme/server", "acme/server"),
        ("https://github.com/acme/server.git", "acme/server"),
        ("https://github.com/acme/server/", "acme/server"),
        ("https://gitlab.com/acme/server", "acme/server"),
        ("https://example.com/acme/server", None),
        ("https://github.com/acme", None),
    ],
)
def test_repository_slug_shapes(url, slug):
    assert Repository(url=url).slug == slug


# --- diffing --------------------------------------------------------------


def test_diff_classifies_added_updated_unchanged_and_removed():
    before = [
        parse_entry(make_raw(name="a/x")),
        parse_entry(make_raw(name="b/y")),
        parse_entry(make_raw(name="c/z")),
    ]
    after = [
        parse_entry(make_raw(name="a/x")),
        parse_entry(make_raw(name="b/y", description="changed")),
        parse_entry(make_raw(name="d/w")),
    ]
    d = diff_entries(hashes_of(before), after)
    assert [e.name for e in d.added] == ["d/w"]
    assert [e.name for e in d.updated] == ["b/y"]
    assert [e.name for e in d.unchanged] == ["a/x"]
    assert d.removed == ("c/z@1.0.0",)
    assert {e.name for e in d.to_scan} == {"d/w", "b/y"}


def test_unchanged_entries_are_not_enqueued():
    """Hash-based cache hits are the reason a daily crawl is affordable."""
    entries = [parse_entry(make_raw(name=f"n/{i}")) for i in range(5)]
    d = diff_entries(hashes_of(entries), entries)
    assert d.to_scan == () and d.is_empty and len(d.unchanged) == 5


def test_empty_previous_treats_everything_as_added():
    """Pinned because it is the first-run behaviour AND the shape of a
    catastrophic failure: a caller defaulting a failed snapshot read to {}
    re-enqueues the entire registry."""
    entries = [parse_entry(make_raw(name=f"n/{i}")) for i in range(3)]
    d = diff_entries({}, entries)
    assert len(d.added) == 3 and d.removed == ()


def test_removed_keys_are_sorted_for_a_stable_diff():
    before = [parse_entry(make_raw(name=n)) for n in ("c/z", "a/x", "b/y")]
    d = diff_entries(hashes_of(before), [])
    assert d.removed == ("a/x@1.0.0", "b/y@1.0.0", "c/z@1.0.0")


# --- coverage reporting ---------------------------------------------------


def test_coverage_report_counts_scannable_against_total():
    entries = [
        parse_entry(
            make_raw(
                name="a/x",
                packages=[{"registryType": "npm", "identifier": "p", "version": "1"}],
            )
        ),
        parse_entry(make_raw(name="b/y", repository={"url": "https://github.com/a/b"})),
        parse_entry(make_raw(name="c/z", remotes=[{"type": "sse", "url": "https://x"}])),
    ]
    rep = coverage_report(entries)
    assert rep.total == 3 and rep.declared_scannable == 2
    assert rep.by_kind == {"npm": 1, "github": 1}
    assert sum(rep.skipped.values()) == 1


def test_empty_coverage_reads_as_zero_not_total():
    """Unknown must not render as perfect — `base.md` signal-design rule."""
    assert coverage_report([]).declared_coverage == 0.0


def test_coverage_is_declared_not_verified():
    """⚠ The crawler makes no network call, so it cannot know what is FETCHABLE.

    Measured 2026-09-15: 45.3% of repo-declaring entries point at a repository
    that is not publicly reachable. `declared_coverage` is therefore an upper
    bound, and `verified_*` must read None — not 0 — because "we have not
    checked" and "nothing was reachable" are opposite claims and this number is
    bound for a public page.
    """
    entries = [
        parse_entry(make_raw(name="b/y", repository={"url": "https://github.com/a/b"}))
    ]
    rep = coverage_report(entries)
    assert rep.declared_scannable == 1
    assert rep.declared_coverage == 1.0
    assert rep.verified_scannable is None
    assert rep.verified_coverage is None


def test_verified_coverage_computes_once_outcomes_are_known():
    rep = coverage_report(
        [parse_entry(make_raw(name="b/y", repository={"url": "https://github.com/a/b"})),
         parse_entry(make_raw(name="c/z", repository={"url": "https://github.com/c/d"}))]
    )
    from dataclasses import replace
    # One of the two declarations turned out to be unreachable on fetch.
    assert replace(rep, verified_scannable=1).verified_coverage == 0.5


# --- fetch_all: partial results are never returned ------------------------


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _RecordingClient:
    """Captures the query params each call was made with."""

    def __init__(self, pages):
        self._pages = list(pages)
        self.params = []

    def get(self, url, params=None):
        self.params.append(dict(params or {}))
        return _FakeResponse(self._pages.pop(0))


class _FakeClient:
    def __init__(self, pages):
        self._pages = list(pages)
        self.calls = 0

    def get(self, url, params=None):
        self.calls += 1
        return _FakeResponse(self._pages.pop(0))


def test_fetch_all_follows_cursors_to_the_end():
    client = _FakeClient(
        [
            {"servers": [make_raw(name="a/x")], "metadata": {"nextCursor": "c1"}},
            {"servers": [make_raw(name="b/y")], "metadata": {}},
        ]
    )
    entries = fetch_all(client=client, pause=0)
    assert [e.name for e in entries] == ["a/x", "b/y"] and client.calls == 2


def test_repeated_cursor_raises_rather_than_returning_a_partial_manifest():
    """A partial manifest diffed against a complete one delists the tail."""
    client = _FakeClient(
        [
            {"servers": [make_raw(name="a/x")], "metadata": {"nextCursor": "c1"}},
            {"servers": [make_raw(name="b/y")], "metadata": {"nextCursor": "c1"}},
        ]
    )
    with pytest.raises(RegistryUnavailableError, match="repeated cursor"):
        fetch_all(client=client, pause=0)


def test_page_cap_raises_rather_than_truncating():
    client = _FakeClient(
        [
            {"servers": [make_raw(name=f"n/{i}")], "metadata": {"nextCursor": f"c{i}"}}
            for i in range(5)
        ]
    )
    with pytest.raises(RegistryUnavailableError, match="exceeded"):
        fetch_all(client=client, max_pages=3, pause=0)


def test_default_pause_is_nonzero():
    """The registry throttles by timing out, not by answering 429 (measured
    2026-09-14). A zero pause makes a healthy registry look unreachable, and
    nothing else in the suite would notice — the fake client is not rate
    limited, so every fetch test passes at any pause."""
    from mcpwatchman.workers.crawler.registry import DEFAULT_PAUSE

    assert DEFAULT_PAUSE >= 1.0


# --- incremental polling --------------------------------------------------


def test_fetch_all_requests_latest_only_by_default():
    """One entry per server, not per version — the page count is what the
    registry's limiter punishes."""
    client = _RecordingClient([{"servers": [], "metadata": {}}])
    fetch_all(client=client, pause=0)
    assert client.params[0]["version"] == "latest"


def test_fetch_all_can_ask_for_every_version():
    client = _RecordingClient([{"servers": [], "metadata": {}}])
    fetch_all(client=client, pause=0, latest_only=False)
    assert "version" not in client.params[0]


def test_updated_since_is_passed_through():
    client = _RecordingClient([{"servers": [], "metadata": {}}])
    fetch_all(client=client, pause=0, updated_since="2026-09-13T00:00:00Z")
    assert client.params[0]["updated_since"] == "2026-09-13T00:00:00Z"


def test_incremental_diff_never_infers_removal_from_absence():
    """THE footgun this function exists to prevent: an incremental response
    omits unchanged servers, so `diff_entries` would delist the whole registry."""
    previous = {"a/x@1.0.0": "h1", "b/y@1.0.0": "h2", "c/z@1.0.0": "h3"}
    changed = [parse_entry(make_raw(name="b/y", description="new"))]
    d = diff_incremental(previous, changed)
    assert d.removed == ()
    assert [e.name for e in d.updated] == ["b/y"]


def test_full_diff_does_infer_removal_from_absence():
    """The contrast that makes the pair worth having — same inputs, opposite
    and correct answer, because a full manifest means absence is real."""
    previous = {"a/x@1.0.0": "h1", "b/y@1.0.0": "h2"}
    current = [parse_entry(make_raw(name="b/y", description="new"))]
    d = diff_entries(previous, current)
    assert d.removed == ("a/x@1.0.0",)


def test_incremental_removal_comes_from_an_explicit_status():
    previous = {"a/x@1.0.0": "h1"}
    changed = [parse_entry(make_raw(name="a/x", status="deleted"))]
    d = diff_incremental(previous, changed)
    assert d.removed == ("a/x@1.0.0",) and d.added == () and d.updated == ()


def test_incremental_reports_no_unchanged_rather_than_a_number_it_cannot_know():
    """0 here means "not measured". A count would be a claim we never made."""
    changed = [parse_entry(make_raw(name="a/x"))]
    assert diff_incremental({"a/x@1.0.0": "h"}, changed).unchanged == ()


def test_incremental_ignores_an_entry_the_registry_touched_but_did_not_change():
    """`_meta` churn marks a server updated without changing what we score."""
    e = parse_entry(make_raw(name="a/x"))
    d = diff_incremental({e.key: e.content_hash}, [e])
    assert d.added == () and d.updated == () and d.is_empty


# --- malformed input (Codex review, 2026-09-14) ---------------------------


def test_page_without_a_servers_array_raises_rather_than_reading_as_empty():
    """A 200 with a malformed body must not look like an empty registry.

    A proxy error page, a gateway's JSON, or a moved API version would otherwise
    parse as zero entries with no cursor — a COMPLETE empty manifest — and the
    next `diff_entries` would mark every known server removed. One bad response
    delists the registry.
    """
    for bad in ({"error": "gateway"}, {"servers": None}, {"servers": "nope"}, {}):
        with pytest.raises(RegistryUnavailableError, match="servers"):
            parse_page(bad)


@pytest.mark.parametrize("field", ["packages", "remotes"])
def test_a_null_list_degrades_the_entry_instead_of_aborting_the_crawl(field):
    """`.get(k, [])` returns None when the key is present and null, and
    iterating that raises TypeError — which `parse_page` does not catch, so one
    publisher's malformed entry would abort the whole poll."""
    entry = parse_entry(make_raw(**{field: None}))
    assert getattr(entry, field) == ()


def test_parse_page_survives_a_null_list_in_one_entry():
    payload = {
        "servers": [make_raw(name="a/x", packages=None), make_raw(name="b/y")],
        "metadata": {},
    }
    entries, _ = parse_page(payload)
    assert [e.name for e in entries] == ["a/x", "b/y"]


# --- GitLab subgroups (Codex review, 2026-09-14) --------------------------


@pytest.mark.parametrize(
    "url,slug",
    [
        ("https://gitlab.com/acme/platform/server", "acme/platform/server"),
        ("https://gitlab.com/acme/a/b/c/server", "acme/a/b/c/server"),
        ("https://gitlab.com/acme/platform/server.git", "acme/platform/server"),
        ("https://gitlab.com/acme/platform/server/-/tree/main/src", "acme/platform/server"),
        # GitHub does NOT nest — owner/repo, and the rest is a deep link.
        ("https://github.com/acme/server/tree/main/src", "acme/server"),
    ],
)
def test_gitlab_subgroups_survive_slug_extraction(url, slug):
    """A GitLab subgroup path is ONE project. Taking the first two segments
    names a different repository that may well exist — so the scan succeeds
    against the wrong code rather than failing visibly."""
    assert Repository(url=url).slug == slug


def test_gitlab_deep_link_subfolder_uses_the_dash_separator():
    repo = Repository(url="https://gitlab.com/acme/platform/servers/-/tree/main/src/fetch")
    assert repo.path_subfolder == "src/fetch"


def test_crawler_never_emits_a_traversing_subfolder():
    """The scanner joins this onto its workspace path. Emitting `../../../etc`
    would point the file walk at the host filesystem — so it is rejected at the
    source, and re-rejected in the scanner (defence in depth, not redundancy)."""
    for url in (
        "https://github.com/acme/repo/tree/main/../../../etc",
        "https://gitlab.com/acme/repo/-/tree/main/../../etc",
    ):
        assert Repository(url=url).path_subfolder is None
    assert Repository(url="https://github.com/a/b", subfolder="../../etc").path_subfolder is None
    assert Repository(url="https://github.com/a/b", subfolder="-x").path_subfolder is None
    # positive control
    ok = Repository(url="https://github.com/a/b", subfolder="src/fetch")
    assert ok.path_subfolder == "src/fetch"


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/a/b/blob/main/src/server.py", "src"),
        ("https://github.com/a/b/blob/main/server.py", None),
        ("https://gitlab.com/a/b/-/blob/main/src/server.py", "src"),
        ("https://github.com/a/b/tree/main/src/fetch", "src/fetch"),
    ],
)
def test_blob_links_resolve_to_the_containing_directory(url, expected):
    """A `/blob/` link names a FILE; the scan root must be a directory. Returning
    the file made every blob-linked source unfetchable at the `is_dir()` guard."""
    assert Repository(url=url).path_subfolder == expected


def test_subfolder_rides_the_spec_string_not_just_the_field():
    """`source_spec` is the wire format; a path carried beside it was dropped."""
    e = parse_entry(make_raw(repository={"url": "https://github.com/m/s/tree/main/src/fetch"}))
    assert resolve_source(e).primary == "github:m/s@1.0.0#src/fetch"


@pytest.mark.parametrize(
    "sub", ["apps/server/dist", "a/node_modules/x", "pkg/.git/objects", "x/vendor"]
)
def test_crawler_never_emits_a_subfolder_the_scanner_will_reject(sub):
    """⚠ The two ends of one wire format must agree, and they did not.

    The crawler accepted `apps/server/dist` and wrote it into a source spec that
    `SourceSpec.parse` then refused, so the planner enqueued jobs the worker
    could never run. Nothing failed loudly: the crawler logged a resolution, the
    scanner logged a parse failure, and the server was silently never scanned.

    Both sides now read one `EXCLUDED_DIRS`, which is why it lives in
    `workers.excluded` — `scanner.source` already imports `crawler.registry`, so
    the constant could not sit in either module without closing a cycle.
    """
    from mcpwatchman.workers.crawler.registry import _safe_subpath
    from mcpwatchman.workers.scanner.source import FetchError, SourceSpec

    assert _safe_subpath(sub) is None, f"crawler would emit {sub!r}"

    # And the scanner's end still rejects it, so the agreement is mutual rather
    # than the crawler having simply gone quiet.
    with pytest.raises(FetchError, match="excluded directory"):
        SourceSpec.parse(f"github:a/b@1.0.0#{sub}")


def test_crawler_still_emits_an_ordinary_subfolder():
    """Positive control: the fix must not reject every monorepo path, which
    would pass the test above by disabling the feature."""
    from mcpwatchman.workers.crawler.registry import _safe_subpath
    from mcpwatchman.workers.scanner.source import SourceSpec

    assert _safe_subpath("apps/server") == "apps/server"
    assert SourceSpec.parse("github:a/b@1.0.0#apps/server").subfolder == "apps/server"


# --- Codex leg 2: a JSON boolean, not Python truthiness -------------------


def test_a_string_false_does_not_declare_a_credential():
    """`bool("false")` is `True`, and every field here is attacker-supplied.

    A remote declaring `"isSecret": "false"` was read as declaring a
    credential, so `03` §4's authentication ladder scored a value that says the
    opposite of what we read it as. The string form is not schema-legal, which
    is exactly why nothing else rejects it.
    """
    raw = make_raw()
    raw["server"]["remotes"] = [{
        "type": "streamable-http",
        "url": "https://a.example/mcp",
        "headers": [{"name": "X-Api-Key", "isSecret": "false", "isRequired": "false"}],
    }]
    entry = parse_entry(raw)
    assert entry.remotes[0].credential_headers == ()
    assert entry.remotes[0].headers[0].is_required is False


def test_a_real_boolean_still_declares_a_credential():
    """Control: the coercion must not swallow the legitimate form."""
    raw = make_raw()
    raw["server"]["remotes"] = [{
        "type": "streamable-http",
        "url": "https://a.example/mcp",
        "headers": [{"name": "Authorization", "isSecret": True, "isRequired": True}],
    }]
    entry = parse_entry(raw)
    assert len(entry.remotes[0].credential_headers) == 1
    assert entry.remotes[0].credential_headers[0].is_required is True


def test_a_quoted_true_is_honoured_as_the_same_publisher_error():
    """The other direction of the same mistake; reading it False drops a real
    declared credential on a technicality."""
    raw = make_raw()
    raw["server"]["remotes"] = [{
        "type": "streamable-http",
        "url": "https://a.example/mcp",
        "headers": [{"name": "Authorization", "isSecret": "true", "isRequired": "TRUE"}],
    }]
    header = parse_entry(raw).remotes[0].credential_headers[0]
    assert header.is_secret is True and header.is_required is True


def test_a_string_false_does_not_mark_an_entry_latest():
    """The neighbour of the finding, fixed with it: one registry-supplied
    boolean corrected and its sibling left truthy is the shape `CLAUDE.md`
    records every bounds defect in this repo having taken."""
    assert parse_entry(make_raw(is_latest="false")).is_latest is False
