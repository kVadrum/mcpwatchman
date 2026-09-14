"""Source-spec and fetch-path invariants (`04-scanner-design.md` §2, §9).

The load-bearing test here is the ROUND-TRIP: the crawler emits source-spec
strings and this module parses them, and until now nothing checked that the two
halves agreed on a format. Both sides can be individually correct and mutually
incompatible, and the symptom would be a scan of the wrong artifact — a failure
with no outward signal, since the scan succeeds and only the subject is wrong.
"""

from __future__ import annotations

import tarfile
import zipfile

import pytest
from tests.test_registry import make_raw

from mcpwatchman.workers.crawler.registry import (
    ManifestDiff,
    SourceKind,
    parse_entry,
    resolve_source,
)
from mcpwatchman.workers.scanner.source import (
    EXCLUDED_DIRS,  # noqa: F401 - re-exported for the parametrised test below
    MAX_MEMBERS,
    FetchError,
    SourceSpec,
    _safe_extract,
    _single_wrapper_dir,
    _tree_size,
    fetch,
    scan_workspace,
)

NPM = [{"registryType": "npm", "identifier": "pkg", "version": "1.2.3"}]


# --- THE contract: crawler output parses here ----------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"packages": NPM},
        {"packages": [{"registryType": "pypi", "identifier": "thing", "version": "2.0"}]},
        {"repository": {"url": "https://github.com/acme/server"}},
        {"repository": {"url": "https://gitlab.com/acme/sub/group/server"}},
        {"repository": {"url": "https://github.com/mcp/servers/tree/main/src/fetch"}},
        {"packages": NPM, "repository": {"url": "https://github.com/acme/server"}},
    ],
)
def test_every_spec_the_crawler_emits_parses_here(fields):
    """The seam. If this breaks, the scanner fetches the wrong thing or nothing,
    and no other test in either module would notice."""
    entry = parse_entry(make_raw(**fields))
    resolution = resolve_source(entry)
    assert resolution.primary, "fixture should resolve"
    spec = SourceSpec.parse(resolution.primary)
    assert spec.kind in SourceKind
    assert spec.identifier and spec.version


def test_supplement_specs_parse_too():
    """`supplement` is a second spec string on the same seam and is easy to
    forget — it only appears when a package AND a repo are both declared."""
    entry = parse_entry(
        make_raw(packages=NPM, repository={"url": "https://github.com/acme/server"})
    )
    r = resolve_source(entry)
    assert r.supplement
    assert SourceSpec.parse(r.supplement).kind is SourceKind.GITHUB


def test_scan_jobs_from_a_plan_carry_parseable_specs():
    """One level up: the planner's ScanJob is what a worker actually receives."""
    from mcpwatchman.workers.crawler.enqueue import plan_from_diff

    entry = parse_entry(make_raw(packages=NPM))
    job = plan_from_diff(ManifestDiff(added=(entry,))).jobs[0]
    assert SourceSpec.parse(job.source_spec).identifier == "pkg"


# --- spec round-trip ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "npm:pkg@1.2.3",
        "npm:@scope/pkg@1.2.3",
        "pypi:thing@2.0",
        "github:acme/server@1.0.0",
        "gitlab:acme/sub/group/server@1.0.0",
        "github:mcp/servers@1.0.0#src/fetch",
    ],
)
def test_spec_round_trips(text):
    assert str(SourceSpec.parse(text)) == text


def test_scoped_npm_name_survives_the_at_sign():
    """`@scope/pkg@1.2.3` has two '@' and only the last one is the version
    separator — a left-partition here would yield an empty identifier."""
    spec = SourceSpec.parse("npm:@scope/pkg@1.2.3")
    assert spec.identifier == "@scope/pkg" and spec.version == "1.2.3"


@pytest.mark.parametrize(
    "bad", ["", "npm", "npm:", "npm:pkg", ":pkg@1", "quantum:pkg@1", "npm:@1.2.3"]
)
def test_malformed_specs_raise_rather_than_defaulting(bad):
    """A default here fetches SOMETHING and scans it, so the score would be about
    the wrong artifact with nothing to signal it."""
    with pytest.raises(FetchError):
        SourceSpec.parse(bad)


# --- archive safety -------------------------------------------------------


def _spec():
    return SourceSpec(SourceKind.NPM, "pkg", "1.0.0")


def test_tar_path_traversal_is_refused(tmp_path):
    """The classic: a member named ../../escaped. `filter='data'` is what stops
    it, and hand-rolling this check is CVE-2007-4559."""
    payload = tmp_path / "evil.tar"
    victim = tmp_path / "inside"
    with tarfile.open(payload, "w") as tf:
        f = tmp_path / "x"
        f.write_text("owned")
        tf.add(f, arcname="../../escaped.txt")
    # tarfile's own filter raises OutsideDestinationError, not our FetchError —
    # naming it keeps the test honest about WHICH guard fired. A bare `Exception`
    # here would also pass if extraction simply crashed for an unrelated reason.
    with pytest.raises(tarfile.OutsideDestinationError):
        _safe_extract(payload, victim, _spec())
    assert not (tmp_path.parent / "escaped.txt").exists()


def test_zip_path_traversal_is_refused(tmp_path):
    """zipfile has no `filter=`, so this check is ours and must exist."""
    payload = tmp_path / "evil.zip"
    with zipfile.ZipFile(payload, "w") as zf:
        zf.writestr("../../escaped.txt", "owned")
    with pytest.raises(FetchError, match="escapes destination"):
        _safe_extract(payload, tmp_path / "inside", _spec())


def test_absolute_path_member_is_refused(tmp_path):
    payload = tmp_path / "abs.zip"
    with zipfile.ZipFile(payload, "w") as zf:
        zf.writestr("/etc/cron.d/x", "owned")
    with pytest.raises(FetchError, match="escapes destination"):
        _safe_extract(payload, tmp_path / "inside", _spec())


def test_member_count_is_capped(tmp_path):
    payload = tmp_path / "many.zip"
    with zipfile.ZipFile(payload, "w") as zf:
        for i in range(MAX_MEMBERS + 5):
            zf.writestr(f"f{i}", "")
    with pytest.raises(FetchError, match="members"):
        _safe_extract(payload, tmp_path / "inside", _spec())


def test_a_normal_archive_extracts(tmp_path):
    """Positive control — the guards above would 'pass' vacuously if extraction
    were simply broken."""
    payload = tmp_path / "ok.tar"
    src = tmp_path / "src"
    src.mkdir()
    (src / "index.js").write_text("console.log(1)")
    with tarfile.open(payload, "w") as tf:
        tf.add(src / "index.js", arcname="package/index.js")
    dest = tmp_path / "out"
    _safe_extract(payload, dest, _spec())
    assert (dest / "package" / "index.js").read_text() == "console.log(1)"


# --- tree measurement and wrapper descent --------------------------------


def test_wrapper_directory_is_descended(tmp_path):
    """npm wraps in `package/`, sdists in `<name>-<version>/`. Returning the
    wrapper makes every evidence path wrong by one component — a silent defect,
    since the scan still succeeds."""
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "index.js").write_text("x")
    assert _single_wrapper_dir(tmp_path).name == "package"


def test_multiple_top_level_entries_are_not_descended(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert _single_wrapper_dir(tmp_path) == tmp_path


def test_tree_size_skips_symlinks(tmp_path):
    """An archive can point a symlink at /etc/passwd or a parent; following it
    would both inflate the measurement and read outside the workspace."""
    (tmp_path / "real.txt").write_text("12345")
    (tmp_path / "link").symlink_to("/etc/passwd")
    size, count = _tree_size(tmp_path)
    assert size == 5 and count == 1


# --- workspace lifecycle --------------------------------------------------


def test_workspace_is_removed_even_when_the_scan_raises():
    """Leaving scratch behind is not untidiness — the next job inherits
    attacker-controlled files under a path it believes it owns."""
    captured = None
    with pytest.raises(RuntimeError), scan_workspace() as ws:
        captured = ws
        (ws / "artifact").write_text("x")
        raise RuntimeError("scan blew up")
    assert captured is not None and not captured.exists()


def test_workspace_is_removed_on_success():
    with scan_workspace() as ws:
        captured = ws
        assert ws.is_dir()
    assert not captured.exists()


def test_unfetchable_kind_raises_instead_of_scanning_nothing():
    """OCI resolves in the crawler but is deferred to v0.3 (`04` §2). Silently
    producing an empty scan would score a container-only server as if it had
    been read."""
    with scan_workspace() as ws, pytest.raises(FetchError, match="no fetcher"):
        fetch(SourceSpec(SourceKind.OCI, "acme/img", "1"), ws)


# --- ref selection (found by fetching a real repo, 2026-09-14) ------------


def test_git_clone_requests_the_version_as_a_ref(monkeypatch, tmp_path):
    """⚠ THE bug this exists for: `--single-branch` without `--branch` clones the
    remote's DEFAULT branch and silently ignores the version, so a scan of
    `github:acme/repo@1.2.3` reads `main` and scores it as the release.

    The clone succeeds and returns a valid tree of the wrong code, so nothing
    downstream can notice. Verified against a real repository: tag `2025.9.12`
    yields 84 files where `main` yields 156.
    """
    from mcpwatchman.workers.scanner import source as S

    seen: list[list[str]] = []
    monkeypatch.setattr(S, "_run", lambda cmd, **kw: seen.append(cmd))
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)
    clone = seen[0]
    assert "--branch" in clone
    assert clone[clone.index("--branch") + 1] == "1.2.3"


def test_git_clone_falls_back_to_a_v_prefixed_tag(monkeypatch, tmp_path):
    """Registries publish `1.2.3`; repositories commonly tag `v1.2.3`."""
    from mcpwatchman.workers.scanner import source as S

    seen: list[list[str]] = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        if "--branch" in cmd and cmd[cmd.index("--branch") + 1] == "1.2.3":
            raise FetchError("no such ref")

    monkeypatch.setattr(S, "_run", fake_run)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)
    tried = [c[c.index("--branch") + 1] for c in seen if "--branch" in c]
    assert tried == ["1.2.3", "v1.2.3"]


def test_no_matching_tag_falls_back_to_default_branch_and_SAYS_SO(monkeypatch, tmp_path):
    """Falling back is fine; doing it silently is not. The score then describes
    the branch tip rather than the release, which the per-server page owes the
    reader (`04` §2, Transparency)."""
    from mcpwatchman.workers.scanner import source as S

    def fake_run(cmd, **kw):
        if "--branch" in cmd:
            raise FetchError("no such ref")

    monkeypatch.setattr(S, "_run", fake_run)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "9.9.9"), tmp_path)
    assert S._GIT_REF_USED[tmp_path] is None


# --- excluded directories -------------------------------------------------


def test_git_directory_is_not_counted_as_scannable(tmp_path):
    """A shallow clone still leaves a packfile — measured as the majority of a
    1.9 MB checkout — and semgrep matching inside object storage produces
    findings about bytes that are not source."""
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "pack").write_bytes(b"x" * 10_000)
    (tmp_path / "index.js").write_text("ok")
    size, count = _tree_size(tmp_path)
    assert count == 1 and size == 2


@pytest.mark.parametrize("d", ["node_modules", ".venv", "vendor", "dist", "__pycache__"])
def test_vendored_directories_are_excluded(d):
    """`04` §3 — vendored trees are not the subject of the scan."""

    assert d in EXCLUDED_DIRS


# --- traversal and argument injection (QA pass, 2026-09-14) --------------
#
# Every value here originates in a PUBLIC REGISTRY, so an attacker controls it
# by publishing a server entry. The archive path was guarded from the start;
# these tests exist because the GIT path was not, and the same traversal class
# arrived through a different door.


@pytest.mark.parametrize(
    "sub",
    ["../../../etc", "a/../../../../etc", "..", "../.ssh", "/etc/passwd", "-x", "--help"],
)
def test_traversing_or_flaglike_subfolder_is_refused_at_parse(sub):
    """`scan_root` is what the file walk and semgrep are pointed at. A subfolder
    that escapes aims the entire scanner at the host filesystem."""
    with pytest.raises(FetchError):
        SourceSpec.parse(f"github:acme/repo@1.0.0#{sub}")


@pytest.mark.parametrize("ident", ["../../../etc", "acme/../../../etc", "-e"])
def test_traversing_or_flaglike_identifier_is_refused(ident):
    with pytest.raises(FetchError):
        SourceSpec.parse(f"github:{ident}@1.0.0")


def test_flaglike_version_is_refused():
    """The version reaches `git clone --branch <value>`."""
    with pytest.raises(FetchError):
        SourceSpec.parse("github:acme/repo@--upload-pack=x")


def test_a_legitimate_subfolder_still_parses():
    """Positive control — the guards above would 'pass' vacuously if the parser
    simply rejected everything."""
    spec = SourceSpec.parse("github:mcp/servers@1.0.0#src/fetch")
    assert spec.subfolder == "src/fetch"


def test_confine_rejects_a_scan_root_outside_the_workspace(tmp_path):
    """Last line of defence, and the only one that survives a bug in the two
    validations upstream."""
    from mcpwatchman.workers.scanner.source import _confine

    root = tmp_path / "ws"
    root.mkdir()
    assert _confine(root / "sub", root) or True  # inside is fine (may not exist)
    with pytest.raises(FetchError, match="escapes the workspace"):
        _confine(root / ".." / ".." / "etc", root)


def test_confine_follows_symlinks_before_judging(tmp_path):
    """A symlink INSIDE the fetched tree can redirect a path that looks
    confined — the tree is attacker-controlled, so the check must resolve."""
    from mcpwatchman.workers.scanner.source import _confine

    root = tmp_path / "ws"
    root.mkdir()
    (root / "evil").symlink_to("/etc")
    with pytest.raises(FetchError, match="escapes the workspace"):
        _confine(root / "evil", root)


def test_git_commands_terminate_options_before_positionals(monkeypatch, tmp_path):
    """Without `--`, a URL or path beginning with `-` is parsed as a flag."""
    from mcpwatchman.workers.scanner import source as S

    seen: list[list[str]] = []
    monkeypatch.setattr(S, "_run", lambda cmd, **kw: seen.append(cmd))
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.0.0", "src/x"), tmp_path)
    clone = seen[0]
    assert "--" in clone and clone.index("--") < clone.index(str(tmp_path))
    sparse = next(c for c in seen if "sparse-checkout" in c)
    assert sparse[-2] == "--" and sparse[-1] == "src/x"


# --- Codex leg findings, 2026-09-14 ---------------------------------------


def test_the_subfolder_SURVIVES_into_the_spec_string():
    """⚠ The hole in this file's own round-trip test.

    `test_scan_jobs_from_a_plan_carry_parseable_specs` asserted the IDENTIFIER
    survived and never checked the subfolder — so a monorepo job carried its
    path in `ScanJob.subfolder` while `source_spec` had no fragment, and parsing
    the spec yielded `subfolder=None`. The scanner would have scanned the entire
    repository instead of the declared server directory, succeeding the whole
    way. A contract test that checks one field of a contract is not a contract
    test.
    """
    from mcpwatchman.workers.crawler.enqueue import plan_from_diff

    entry = parse_entry(
        make_raw(repository={"url": "https://github.com/mcp/servers/tree/main/src/fetch"})
    )
    job = plan_from_diff(ManifestDiff(added=(entry,))).jobs[0]
    assert SourceSpec.parse(job.source_spec).subfolder == "src/fetch"
    assert job.subfolder == "src/fetch"  # the field agrees with the string


def test_declared_size_is_checked_BEFORE_extraction(tmp_path):
    """A zip bomb must be refused on its declared size, not after it has already
    filled the scratch disk — checking afterwards reports a failure the attacker
    has already caused."""
    from mcpwatchman.workers.scanner.source import MAX_UNPACKED_BYTES

    payload = tmp_path / "bomb.zip"
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big", b"\0" * (MAX_UNPACKED_BYTES + 1))
    dest = tmp_path / "out"
    with pytest.raises(FetchError, match="declares"):
        _safe_extract(payload, dest, _spec())
    # Nothing was written: the refusal happened before extraction.
    assert not dest.exists() or not any(dest.rglob("*"))


def test_resource_cap_counts_excluded_directories(tmp_path):
    """`_tree_size` omits node_modules because it is not SCANNABLE. That is the
    right answer for 'how much source is here' and the wrong one for 'how much
    disk did this consume' — a payload hidden there was invisible to the cap."""
    from mcpwatchman.workers.scanner.source import _measure_all, _tree_size

    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "blob").write_bytes(b"x" * 5000)
    (tmp_path / "index.js").write_text("ok")
    assert _tree_size(tmp_path)[0] == 2        # scannable source only
    assert _measure_all(tmp_path) == 5002      # everything, for the cap


def test_a_zip_sdist_is_detected_by_magic_not_by_name(tmp_path):
    """PyPI sdists are usually .tar.gz and legitimately sometimes .zip. Naming
    the download by assumption and dispatching on that name handed a zip to
    tarfile — unfetchable, failing like corruption rather than like a format we
    declined to notice."""
    from mcpwatchman.workers.scanner.source import _is_zip

    misnamed = tmp_path / "pkg.tar.gz"
    with zipfile.ZipFile(misnamed, "w") as zf:
        zf.writestr("package/index.js", "ok")
    assert _is_zip(misnamed)
    dest = tmp_path / "out"
    _safe_extract(misnamed, dest, _spec())
    assert (dest / "package" / "index.js").exists()


@pytest.mark.parametrize("d", [".git", "node_modules", ".venv"])
def test_an_excluded_directory_cannot_be_the_scan_root(d):
    """`_is_excluded` tests paths RELATIVE to the chosen root, so `#.git` puts
    the `.git` component outside every relative path and git metadata reports as
    scannable source — the exclusion defeating itself."""
    with pytest.raises(FetchError, match="excluded directory"):
        SourceSpec.parse(f"github:acme/repo@1.0.0#{d}")
