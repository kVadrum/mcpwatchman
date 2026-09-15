"""Source-spec and fetch-path invariants (`04-scanner-design.md` §2, §9).

The load-bearing test here is the ROUND-TRIP: the crawler emits source-spec
strings and this module parses them, and until now nothing checked that the two
halves agreed on a format. Both sides can be individually correct and mutually
incompatible, and the symptom would be a scan of the wrong artifact — a failure
with no outward signal, since the scan succeeds and only the subject is wrong.
"""

from __future__ import annotations

import subprocess
import tarfile
import types
import zipfile

import pytest
from tests.test_registry import make_raw

from mcpwatchman.workers.crawler.registry import (
    ManifestDiff,
    SourceKind,
    parse_entry,
    resolve_source,
)
from mcpwatchman.workers.scanner import source
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
        # ⚠ The stub must model the TAG FETCH too. It previously only rejected
        # `--branch`, so when the explicit `refs/tags/` lookup was added the
        # fake returned success for a tag that does not exist and the test
        # asserted a fallback that real git would not have taken. A stub that
        # does not model a call silently answers for it.
        if "--branch" in cmd or any(str(a).startswith("refs/tags/") for a in cmd):
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


def test_confine_refuses_a_symlinked_component_outright(tmp_path):
    """A symlink INSIDE the fetched tree can redirect a path that looks confined.

    Previously this was caught by resolving and then testing containment, which
    only works when the link points OUT of the workspace. It is now refused
    before resolution, so the inward case below is covered by the same guard.
    """
    from mcpwatchman.workers.scanner.source import _confine

    root = tmp_path / "ws"
    root.mkdir()
    (root / "evil").symlink_to("/etc")
    with pytest.raises(FetchError, match="is a symlink"):
        _confine(root / "evil", root)


def test_confine_refuses_a_symlink_pointing_INSIDE_the_workspace(tmp_path):
    """The case containment cannot see, and the one that was exploitable.

    A repository may TRACK a symlink, so a declared subfolder `server -> .git`
    resolves to a path still inside the workspace: the containment test passes
    and the scanner is aimed at the git object store. `_is_excluded` misses it
    too — it tests the declared name, and once `.git` is the scan ROOT it sits
    outside every path taken relative to it.

    Third route to the same place: v0.7.1 closed `../../../etc`, v0.7.2 closed
    the literal `#.git`, and both guards were written without the symlink.
    """
    from mcpwatchman.workers.scanner.source import _confine

    root = tmp_path / "ws"
    (root / ".git").mkdir(parents=True)
    (root / "server").symlink_to(".git")

    with pytest.raises(FetchError, match="is a symlink"):
        _confine(root / "server", root)

    # Positive control: an ordinary subdirectory still resolves.
    (root / "real").mkdir()
    assert _confine(root / "real", root) == (root / "real").resolve()


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
    # And there is no second copy to disagree with it — `ScanJob` deliberately
    # has no `subfolder` field, because the value meant different things for a
    # git primary and an npm primary.
    assert not hasattr(job, "subfolder")


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


# --- Codex leg, second pass (2026-09-14) ---------------------------------


def test_a_missing_binary_surfaces_as_FetchError(monkeypatch, tmp_path):
    """⚠ The shipped worker image had no git at all (`python:3.12-slim` + pip),
    so every git-sourced scan died on `FileNotFoundError` — which escaped past
    every FetchError handler as a traceback rather than a scan result."""
    from mcpwatchman.workers.scanner import source as S

    def missing(*a, **kw):
        raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr(S.subprocess, "run", missing)
    with pytest.raises(FetchError, match="not installed in this image"):
        S._run(["git", "--version"])


def test_the_worker_image_provides_git():
    """A contract between this module and `docker/Dockerfile`: the code shells
    out to git, so the image must install it. Nothing else links the two, and
    the failure only appears in a built container."""
    import pathlib

    dockerfile = pathlib.Path(__file__).resolve().parents[1] / "docker/Dockerfile"
    if not dockerfile.is_file():
        pytest.skip("no Dockerfile in this checkout")
    assert "git" in dockerfile.read_text()


def test_tar_member_limit_fires_during_the_walk_not_after(tmp_path):
    """`getmembers()` builds a TarInfo for EVERY entry before any limit is
    consulted, so millions of zero-length headers — which compress to almost
    nothing — exhaust memory before the cap can fire. The guard has to run
    during the walk."""
    payload = tmp_path / "many.tar"
    with tarfile.open(payload, "w") as tf:
        for i in range(MAX_MEMBERS + 5):
            info = tarfile.TarInfo(f"f{i}")
            info.size = 0
            tf.addfile(info)
    with pytest.raises(FetchError, match="members"):
        _safe_extract(payload, tmp_path / "out", _spec())


@pytest.mark.parametrize(
    "sub", ["apps/server/dist", "a/node_modules/x", "pkg/.git/objects", "x/vendor"]
)
def test_an_excluded_directory_is_rejected_at_ANY_depth(sub):
    """Only the first component was checked. `_is_excluded` later sees paths
    relative to the chosen root, so a root inside `dist` makes the excluded
    component vanish and those files read as scannable source."""
    with pytest.raises(FetchError, match="excluded directory"):
        SourceSpec.parse(f"github:a/b@1.0.0#{sub}")


def test_a_branch_named_like_the_version_is_not_reported_as_a_tag(monkeypatch, tmp_path):
    """⚠ `git clone --branch` accepts a TAG OR A BRANCH, so a successful clone is
    not evidence of a release. A repo with a moving branch called `1.2.3` would
    otherwise be reported `ref_matched_version=True` and its branch tip scored as
    tagged source. A tag detaches HEAD; a branch does not."""
    from mcpwatchman.workers.scanner import source as S

    calls: list[list[str]] = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        # This scenario is a branch `1.2.3` with NO tag of that name, so the
        # explicit tag fetch must fail — see the stub note above.
        if any(str(a).startswith("refs/tags/") for a in cmd):
            raise FetchError("no such ref")
        # symbolic-ref SUCCEEDS => HEAD is on a branch => not a tag.
        if "symbolic-ref" in cmd:
            return None
        return None

    monkeypatch.setattr(S, "_run", fake_run)
    monkeypatch.setattr(S, "_measure_all", lambda p: 0)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)
    assert S._GIT_REF_USED[tmp_path] is None  # fell back, correctly


def test_a_real_tag_detaches_head_and_IS_reported(monkeypatch, tmp_path):
    """Positive control for the check above — otherwise rejecting every ref
    would pass it while breaking the feature."""
    from mcpwatchman.workers.scanner import source as S

    def fake_run(cmd, **kw):
        if "symbolic-ref" in cmd:
            raise FetchError("detached")  # a tag
        return None

    monkeypatch.setattr(S, "_run", fake_run)
    monkeypatch.setattr(S, "_measure_all", lambda p: 0)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)
    assert S._GIT_REF_USED[tmp_path] == "1.2.3"


def test_an_oversized_checkout_is_refused(monkeypatch, tmp_path):
    """A clone was the one fetch path with no ceiling — the archive caps applied
    to archives only, and `_tree_size` merely measured afterwards."""
    from mcpwatchman.workers.scanner import source as S

    def fake_run(cmd, **kw):
        if "symbolic-ref" in cmd:
            raise FetchError("detached")
        return None

    monkeypatch.setattr(S, "_run", fake_run)
    monkeypatch.setattr(S, "_measure_all", lambda p: S.MAX_UNPACKED_BYTES + 1)
    with pytest.raises(FetchError, match="over the"):
        S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)


# ── Codex leg (v0.9.2): real-git verification of ref resolution ──────────────


def _git(repo, *args):
    """Run git in a fixture repo. Fixed argv, fixture-only paths — the S603/S607
    warnings are about untrusted input and a PATH lookup, neither of which
    applies to a test driving its own tmp_path."""
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
    )


def test_a_tag_SHADOWED_by_a_same_named_branch_is_still_found(tmp_path):
    """⚠ Real git, not a stub — the defect lives in git's ref precedence.

    `git clone --branch 1.2.3` resolves `refs/heads/` FIRST, so a repository
    carrying both a branch and a tag named `1.2.3` hands back the branch. The
    detached-HEAD test correctly rejects it, and the old code then fell through
    to the default branch — having never asked for the tag that does exist. It
    would have scored the wrong revision and attached the result to a release it
    never read: the same failure v0.7.0 fixed for the no-tag case, by a
    different route.

    Stubbed `_run` cannot show this: the whole defect is which ref real git
    picks for an ambiguous name.
    """
    # ⚠ THREE DISTINCT CONTENTS, and that is what makes this test able to fail.
    # The first version of this fixture put the tag on a commit that was also
    # `main`'s tip, so the buggy fallback-to-default-branch produced byte-identical
    # content and the test passed with the fix removed — a fixture that cannot
    # distinguish the right answer from the wrong one. Caught by the negative
    # control, which is the only thing that could have caught it.
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "release.py").write_text("RELEASE = 'tag'\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "the tagged release")
    _git(origin, "tag", "1.2.3")

    # A MOVING branch of the same name, with different content.
    _git(origin, "checkout", "-qb", "1.2.3")
    (origin / "release.py").write_text("RELEASE = 'branch'\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "branch tip, not the release")

    # And `main` moves on past the tag, so falling back is distinguishable too.
    _git(origin, "checkout", "-q", "main")
    (origin / "release.py").write_text("RELEASE = 'main'\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "main tip")

    from mcpwatchman.workers.scanner import source as S

    spec = SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3")
    dest = tmp_path / "checkout"
    monkey = pytest.MonkeyPatch()
    monkey.setattr(S, "_git_url", lambda _spec: f"file://{origin}")
    try:
        S.fetch_git(spec, dest)
    finally:
        monkey.undo()

    got = (dest / "release.py").read_text().strip()
    assert got == "RELEASE = 'tag'", (
        f"scanned {got} instead of the same-named release tag — "
        f"'branch' means git's ref precedence won, 'main' means we fell back"
    )
    assert S._GIT_REF_USED.get(dest) == "1.2.3"


def test_zip_member_cap_fires_BEFORE_zipfile_parses_the_directory(tmp_path, monkeypatch):
    """⚠ `ZipFile(...)` builds a `ZipInfo` for EVERY entry in its constructor.

    So `MAX_MEMBERS`, consulted on `infolist()`, could never protect the zip
    path: by the time it ran the allocation had already happened. A ZIP64
    archive of millions of empty entries compresses to almost nothing and stays
    far under the download cap.

    The tar path was given a lazy guard-during-the-walk form at v0.7.2 and this
    one was left eager — the same asymmetry, a third time in this file.
    """
    from mcpwatchman.workers.scanner import source as S

    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(60):
            zf.writestr(f"f{i:03d}.txt", b"")

    monkeypatch.setattr(S, "MAX_MEMBERS", 10)

    def explode(*a, **kw):
        raise AssertionError("ZipFile was constructed before the member cap ran")

    monkeypatch.setattr(S.zipfile, "ZipFile", explode)

    spec = SourceSpec(SourceKind.PYPI, "pkg", "1.0.0")
    with pytest.raises(FetchError, match="declares 60 members"):
        S._safe_extract(archive, tmp_path / "out", spec)


def test_zip_entry_count_reads_a_real_archive(tmp_path):
    """Positive control: the preflight must return the true count, not just
    refuse things. A parser that returned None always would pass the cap test
    above by disabling the guard entirely."""
    from mcpwatchman.workers.scanner.source import _zip_entry_count

    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(7):
            zf.writestr(f"f{i}.txt", b"x")
    assert _zip_entry_count(archive) == 7

    # A comment pushes the EOCD away from the very end of the file.
    commented = tmp_path / "commented.zip"
    with zipfile.ZipFile(commented, "w") as zf:
        zf.writestr("a.txt", b"x")
        zf.comment = b"c" * 400
    assert _zip_entry_count(commented) == 1


def test_measure_all_is_bounded_by_entry_count(tmp_path, monkeypatch):
    """`MAX_UNPACKED_BYTES` sums logical lengths, so millions of EMPTY files sit
    under it while consuming inodes without limit. A bound that measures the
    wrong resource is not a bound — and a git clone has no member cap upstream,
    because a clone is not an archive."""
    from mcpwatchman.workers.scanner import source as S

    tree = tmp_path / "tree"
    tree.mkdir()
    for i in range(80):
        (tree / f"f{i:03d}").write_text("")

    monkeypatch.setattr(S, "MAX_TREE_ENTRIES", 20)
    with pytest.raises(FetchError, match="exceeds 20 entries"):
        S._measure_all(tree)

    # Positive control: an ordinary tree still measures, and measures correctly.
    monkeypatch.setattr(S, "MAX_TREE_ENTRIES", 250_000)
    (tree / "sized.bin").write_bytes(b"x" * 1234)
    assert S._measure_all(tree) == 1234


def test_sparse_checkout_uses_cone_mode_for_a_literal_path(monkeypatch, tmp_path):
    """`--no-cone` reads its argument as a `.gitignore` PATTERN, not a path.

    A valid declared directory containing metacharacters — `apps/[server]`, or a
    name beginning with `!` — is then matched wrongly or not at all, while the
    code that follows looks for the literal path.
    """
    from mcpwatchman.workers.scanner import source as S

    seen: list[list[str]] = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        if "symbolic-ref" in cmd:
            return None
        return None

    monkeypatch.setattr(S, "_run", fake_run)
    monkeypatch.setattr(S, "_measure_all", lambda p: 0)
    monkeypatch.setattr(S, "_confine", lambda c, r: c)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "a/b", "1.0.0", "apps/server"), tmp_path)

    sparse = next(c for c in seen if "sparse-checkout" in c)
    assert "--cone" in sparse, f"sparse-checkout still in pattern mode: {sparse}"
    assert "--no-cone" not in sparse


def test_download_enforces_a_wall_clock_deadline(tmp_path, monkeypatch):
    """httpx's timeout is per network OPERATION and resets on each one, so a
    server dribbling a byte inside every interval never trips it. The cap on
    SIZE cannot see a slow read."""
    from mcpwatchman.workers.scanner import source as S

    class _Response:
        def raise_for_status(self):
            return None

        def iter_bytes(self, _n):
            for _ in range(1000):
                yield b"x"

    class _Stream:
        def __enter__(self):
            return _Response()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(S, "_download_stream", lambda *a, **kw: _Stream(), raising=False)

    clock = iter([0.0] + [100.0] * 50)
    monkeypatch.setattr(S.time, "monotonic", lambda: next(clock))

    import httpx

    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: _Stream())
    with pytest.raises(FetchError, match="wall clock"):
        S._download("https://example.invalid/p.tgz", tmp_path / "out.tgz", timeout=30)


# --- declared source that is not publicly reachable ------------------------
#
# ⚠ Measured 2026-09-15 over 200 registry entries: of the 95 classed scannable
# that declared a repository URL, 43 (45.3%) were not publicly reachable. That
# is not our fetch breaking — it is the publisher's declaration being wrong, and
# the two must not arrive as the same exception.


def test_missing_repository_is_unreachable_not_a_generic_fetch_error(monkeypatch):
    proc = types.SimpleNamespace(
        returncode=128,
        stderr="fatal: repository 'https://github.com/nope/nope.git/' not found\n",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.SourceUnreachableError):
        source._run(["git", "clone", "https://github.com/nope/nope"], remote=True)


@pytest.mark.parametrize(
    "stderr",
    [
        # GitHub answers 404 for a PRIVATE repo too, deliberately, so as not to
        # leak its existence — it arrives identically to a deleted one.
        "fatal: repository 'https://github.com/x/y.git/' not found",
        # A private repo over HTTPS with prompts disabled asks for credentials.
        "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
        "remote: Permission denied\nfatal: Could not read from remote repository.",
        "ERROR: Repository not found.",
        "fatal: Authentication failed for 'https://github.com/x/y.git/'",
    ],
)
def test_every_shape_of_not_public_classifies_as_unreachable(monkeypatch, stderr):
    # Leaving the auth phrasings out would classify the PRIVATE half as an
    # infrastructure fault and retry it forever.
    proc = types.SimpleNamespace(returncode=128, stderr=stderr, stdout="")
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.SourceUnreachableError):
        source._run(["git", "clone", "https://example.invalid/x"], remote=True)


@pytest.mark.parametrize(
    "stderr",
    [
        "fatal: unable to access 'https://github.com/x/y': Could not resolve host",
        "error: RPC failed; curl 56 GnuTLS recv error",
        "fatal: early EOF",
    ],
)
def test_our_own_failures_stay_generic_and_retryable(monkeypatch, stderr):
    # A DNS failure or a torn transfer is OUR problem. Classifying it as the
    # publisher's would publish a finding about a server we simply failed to
    # reach — the exact over-claim this project exists to avoid.
    proc = types.SimpleNamespace(returncode=128, stderr=stderr, stdout="")
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.FetchError) as exc:
        source._run(["git", "clone", "https://example.invalid/x"], remote=True)
    assert not isinstance(exc.value, source.SourceUnreachableError)


def test_unreachable_is_still_a_fetch_error_so_existing_handlers_hold():
    # Subclass, not sibling: every caller that already catches FetchError keeps
    # working, and only callers that WANT the distinction have to ask for it.
    assert issubclass(source.SourceUnreachableError, source.FetchError)


def test_timeout_is_not_mistaken_for_an_absent_repository(monkeypatch):
    def boom(*a, **k):
        raise source.subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(source.subprocess, "run", boom)
    with pytest.raises(source.FetchError) as exc:
        source._run(["git", "clone", "https://example.invalid/x"])
    assert not isinstance(exc.value, source.SourceUnreachableError)


# --- who is at fault: OUR failure must never be published as THEIRS ---------
#
# ⚠ Found by a Deep review, 2026-09-15. `_is_unreachable` ran on the output of
# EVERY git call in the module, including ones that execute AFTER the remote was
# reached successfully. "Permission denied" is a local-filesystem error at least
# as often as a remote one, so a read-only scratch mount or a full disk would
# have flipped a whole night's batch into a published accusation about named
# third parties — and none of it would have been retried.


@pytest.mark.parametrize(
    "cmd",
    [
        ["git", "gc", "--prune=now"],
        ["git", "sparse-checkout", "set", "--cone", "--", "pkg"],
        ["git", "checkout", "--detach", "FETCH_HEAD"],
        ["git", "symbolic-ref", "-q", "HEAD"],
    ],
)
def test_post_clone_local_git_is_never_the_publishers_fault(monkeypatch, cmd):
    proc = types.SimpleNamespace(
        returncode=128,
        stderr="fatal: could not create work tree dir '/scans/abc': Permission denied",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.FetchError) as exc:
        source._run(cmd)  # no remote=True — these never contact a remote
    assert not isinstance(exc.value, source.SourceUnreachableError)


def test_a_missing_TAG_is_not_a_missing_REPOSITORY(monkeypatch):
    # `fetch_git` retries tag candidates by design; reading "not found" here as
    # an absent repository both misreports and defeats that fallback.
    proc = types.SimpleNamespace(
        returncode=128,
        stderr="fatal: Remote branch v1.2.3 not found in upstream origin",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.FetchError) as exc:
        source._run(["git", "fetch", "origin", "refs/tags/v1.2.3"], remote=True)
    assert not isinstance(exc.value, source.SourceUnreachableError)


def test_a_hostile_repository_url_cannot_steer_the_classifier(monkeypatch, tmp_path):
    # git echoes the URL it was given, and that URL comes from a public registry
    # entry. Without redaction a publisher could name their repo
    # `.../access denied/` and turn OUR DNS failure into THEIR permanent verdict.
    url = "https://gh.example/p/access denied/"
    proc = types.SimpleNamespace(
        returncode=128,
        stderr=f"fatal: unable to access '{url}': Could not resolve host",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.FetchError) as exc:
        source._run(["git", "clone", "--", url, str(tmp_path)], remote=True, url=url)
    assert not isinstance(exc.value, source.SourceUnreachableError)


def test_permission_denied_still_counts_when_git_names_the_REMOTE(monkeypatch):
    # The narrowing must not lose the real SSH case.
    proc = types.SimpleNamespace(
        returncode=128,
        stderr="git@github.com: Permission denied (publickey).\n"
               "fatal: Could not read from remote repository.",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.SourceUnreachableError):
        source._run(["git", "clone", "git@github.com:x/y"], remote=True)


def test_the_remote_guard_holds_even_for_unambiguous_remote_wording(monkeypatch):
    """Isolates the `remote=` scoping from the `_UNREACHABLE_PAIRS` narrowing.

    The two are independent defences with overlapping coverage, so the
    Permission-denied fixture above cannot distinguish them — it is excluded by
    the pairs rule whether or not the guard exists. This one uses wording that
    IS unambiguously remote, on a command that never contacts a remote: git can
    echo such text out of a repo's own config or a submodule URL, and without
    the guard that becomes a published accusation about the publisher.
    """
    proc = types.SimpleNamespace(
        returncode=128,
        stderr="fatal: Authentication failed for 'https://github.com/x/y.git/'",
        stdout="",
    )
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: proc)
    with pytest.raises(source.FetchError) as exc:
        source._run(["git", "gc", "--prune=now"])  # local-only, no remote=True
    assert not isinstance(exc.value, source.SourceUnreachableError)


# ── Codex leg 2: a permanent failure must not be retried ────────────────────

def test_an_unreachable_repository_is_attempted_ONCE(monkeypatch, tmp_path):
    """`SourceUnreachableError` was swallowed by the `except FetchError` ladder.

    The split of this exception from its parent exists precisely to say that a
    repository the world cannot read will not become readable on retry — and
    then every handler in `fetch_git` caught the parent, so the ladder made
    three network attempts at a URL the first one had already settled. Counting
    the attempts is the reproduction; asserting the exception type alone would
    pass against the defect, since the last attempt raises the same class.
    """
    from mcpwatchman.workers.scanner import source as S

    clones: list[list[str]] = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["git", "clone"]:
            clones.append(cmd)
            raise S.SourceUnreachableError("git failed (rc=128): repository not found")

    monkeypatch.setattr(S, "_run", fake_run)
    with pytest.raises(S.SourceUnreachableError):
        S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/gone", "1.2.3"), tmp_path)
    assert len(clones) == 1


def test_a_missing_TAG_is_still_retried_across_candidates(monkeypatch, tmp_path):
    """Control for the above, and the distinction the whole split turns on.

    `fatal: Remote branch v1.2.3 not found` is a repository that answered us
    perfectly well, so the ladder must keep walking. A fix that stopped on any
    fetch failure would break the `1.2.3` / `v1.2.3` fallback and never be
    noticed by a test that only checks the unreachable case.
    """
    from mcpwatchman.workers.scanner import source as S

    tried: list[str] = []

    def fake_run(cmd, **kw):
        if "--branch" in cmd:
            tried.append(cmd[cmd.index("--branch") + 1])
            raise FetchError("git failed (rc=128): Remote branch not found")
        if any(str(a).startswith("refs/tags/") for a in cmd):
            raise FetchError("no such ref")

    monkeypatch.setattr(S, "_run", fake_run)
    monkeypatch.setattr(S, "_measure_all", lambda p: 0)
    S.fetch_git(SourceSpec(SourceKind.GITHUB, "acme/repo", "1.2.3"), tmp_path)
    assert tried == ["1.2.3", "v1.2.3"]
