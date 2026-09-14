"""File enumeration invariants (`04-scanner-design.md` §3).

The tree under test is **attacker-controlled** — freshly fetched from a public
registry — so most of these pin refusals rather than features: what the walk
must not follow, must not open, and must not silently omit.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from mcpwatchman.workers.scanner import inventory
from mcpwatchman.workers.scanner.inventory import (
    LARGE_FILE_BYTES,
    Inventory,
    Language,
    Role,
    enumerate_tree,
)


@pytest.fixture
def tree(tmp_path):
    """A small, realistic server tree."""
    (tmp_path / "index.js").write_text("console.log(1)")
    (tmp_path / "server.json").write_text('{"name":"x"}')
    (tmp_path / "README.md").write_text("# x")
    (tmp_path / "LICENSE").write_text("MIT")
    (tmp_path / "package.json").write_text('{"bin":{"srv":"index.js"},"main":"index.js"}')
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("assert 1")
    return tmp_path


# --- refusals: the tree is hostile ---------------------------------------


def test_symlinks_are_recorded_as_skipped_never_followed(tmp_path):
    """Following one reads the host filesystem. It is counted, not silently
    dropped — a silent skip is indistinguishable from an empty directory."""
    (tmp_path / "real.js").write_text("ok")
    (tmp_path / "escape").symlink_to("/etc/passwd")
    (tmp_path / "dir-escape").symlink_to("/etc")
    inv = enumerate_tree(tmp_path)
    assert [f.path for f in inv.files] == ["real.js"]
    assert inv.skipped.get("symlink") == 2


def test_non_regular_files_are_skipped_without_being_opened(tmp_path):
    """A FIFO blocks forever on open. `is_file()` is False for it, and that
    check must come before anything that reads."""
    (tmp_path / "real.js").write_text("ok")
    os.mkfifo(tmp_path / "pipe")
    inv = enumerate_tree(tmp_path)  # must return, not hang
    assert [f.path for f in inv.files] == ["real.js"]
    assert inv.skipped.get("not a regular file") == 1


def test_excluded_directories_are_omitted_but_not_counted_as_skipped(tmp_path):
    """Policy exclusion, not failure. Counting `node_modules` as 'skipped' would
    make a healthy tree look damaged in the report."""
    (tmp_path / "index.js").write_text("ok")
    for d in ("node_modules", ".git", "dist"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "junk.js").write_text("x" * 100)
    inv = enumerate_tree(tmp_path)
    assert [f.path for f in inv.files] == ["index.js"]
    assert inv.skipped == {}


def test_recorded_paths_are_relative_and_posix(tree):
    """An absolute path in the evidence trail leaks the worker's scratch layout
    and does not identify a file inside the artifact."""
    for f in enumerate_tree(tree).files:
        assert not f.path.startswith("/")
        assert "\\" not in f.path


def test_dotfiles_ARE_enumerated(tmp_path):
    """Pinned because it is the opposite of shell-glob behaviour and therefore
    easy to assume wrong: `Path.rglob('*')` includes hidden entries. Dotfiles
    are where CI workflows, `.npmrc` and the `.mcp.json` manifest live, so
    skipping them would blind several checks at once."""
    (tmp_path / ".mcp.json").write_text("{}")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflows").mkdir()
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push")
    inv = enumerate_tree(tmp_path)
    paths = {f.path for f in inv.files}
    assert ".mcp.json" in paths
    assert ".github/workflows/ci.yml" in paths


# --- the MCP manifest -----------------------------------------------------


@pytest.mark.parametrize("name", ["server.json", "mcp.json", ".mcp.json"])
def test_the_mcp_manifest_is_found_under_each_conventional_name(tmp_path, name):
    """`04` §3 — the file saying what the server CLAIMS to do. auth_check and
    transparency_check both consume it."""
    (tmp_path / name).write_text('{"tools":[]}')
    inv = enumerate_tree(tmp_path)
    assert inv.mcp_manifest is not None
    assert inv.mcp_manifest.path == name
    assert inv.mcp_manifest.role is Role.MCP_MANIFEST


def test_absent_manifest_is_None_not_an_empty_record(tmp_path):
    (tmp_path / "index.js").write_text("ok")
    assert enumerate_tree(tmp_path).mcp_manifest is None


# --- entry points ---------------------------------------------------------


def test_entry_points_come_from_package_json_and_pyproject(tmp_path):
    (tmp_path / "package.json").write_text('{"bin":{"srv":"cli.js"},"main":"index.js"}')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="1"\n[project.scripts]\nsrv="pkg.cli:main"\n'
    )
    eps = enumerate_tree(tmp_path).entry_points
    assert "cli.js" in eps and "index.js" in eps and "pkg.cli:main" in eps


@pytest.mark.parametrize(
    "content", ["not json at all", "[]", '{"bin": 42}', '{"bin": {"a": null}}', ""]
)
def test_a_malformed_package_json_yields_no_entry_points_and_does_not_raise(
    tmp_path, content
):
    """The manifest is attacker-controlled. Failing the scan over a malformed one
    would let any publisher stop themselves being scanned."""
    (tmp_path / "package.json").write_text(content)
    assert enumerate_tree(tmp_path).entry_points == ()


def test_a_malformed_pyproject_yields_no_entry_points_and_does_not_raise(tmp_path):
    (tmp_path / "pyproject.toml").write_text("this is not = valid toml [[[")
    assert enumerate_tree(tmp_path).entry_points == ()


def test_entry_points_are_deduplicated_in_declaration_order(tmp_path):
    (tmp_path / "package.json").write_text('{"bin":{"a":"x.js","b":"x.js"},"main":"x.js"}')
    assert enumerate_tree(tmp_path).entry_points == ("x.js",)


# --- language classification ---------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("a.py", Language.PYTHON), ("a.ts", Language.TYPESCRIPT),
        ("a.mjs", Language.JAVASCRIPT), ("a.go", Language.GO),
        ("a.rs", Language.RUST), ("a.yml", Language.YAML),
        ("a.toml", Language.TOML), ("Dockerfile", Language.DOCKERFILE),
        ("a.bin", Language.UNKNOWN),
    ],
)
def test_language_from_extension(tmp_path, name, expected):
    (tmp_path / name).write_text("x")
    assert enumerate_tree(tmp_path).files[0].language is expected


@pytest.mark.parametrize(
    "shebang,expected",
    [
        ("#!/usr/bin/env python3\n", Language.PYTHON),
        ("#!/bin/bash\n", Language.SHELL),
        ("#!/usr/bin/env node\n", Language.JAVASCRIPT),
        ("no shebang here\n", Language.UNKNOWN),
    ],
)
def test_extensionless_files_fall_back_to_the_shebang(tmp_path, shebang, expected):
    """`bin/server` with no extension is a real and common shape."""
    (tmp_path / "server").write_text(shebang + "print(1)")
    assert enumerate_tree(tmp_path).files[0].language is expected


# --- role classification --------------------------------------------------


def test_roles_are_assigned_from_name_and_location(tree):
    by_path = {f.path: f.role for f in enumerate_tree(tree).files}
    assert by_path["server.json"] is Role.MCP_MANIFEST
    assert by_path["package.json"] is Role.PACKAGE_MANIFEST
    assert by_path["package-lock.json"] is Role.LOCKFILE
    assert by_path["LICENSE"] is Role.LICENSE
    assert by_path["README.md"] is Role.DOCS
    assert by_path["src/app.py"] is Role.SOURCE
    assert by_path["tests/test_app.py"] is Role.TEST


def test_tests_are_separated_from_served_source(tmp_path):
    """`03` §3 grades what runs. A deliberately-unsafe fixture is evidence of
    testing, not of risk, so a finding there must not score like one in the
    served code."""
    (tmp_path / "app.py").write_text("x")
    (tmp_path / "test_app.py").write_text("x")
    (tmp_path / "a.test.ts").write_text("x")
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "thing.js").write_text("x")
    roles = {f.path: f.role for f in enumerate_tree(tmp_path).files}
    assert roles["app.py"] is Role.SOURCE
    assert roles["test_app.py"] is Role.TEST
    assert roles["a.test.ts"] is Role.TEST
    assert roles["spec/thing.js"] is Role.TEST


# --- size handling --------------------------------------------------------


def test_oversized_files_are_flagged_and_prefix_hashed(tmp_path):
    """`04` §3: flagged, not deeply inspected. The hash is then over a prefix,
    which the record says so a caller cannot mistake it for a whole-file digest."""
    big = tmp_path / "big.py"
    big.write_bytes(b"x" * (LARGE_FILE_BYTES + 5000))
    rec = enumerate_tree(tmp_path).files[0]
    assert rec.oversized and rec.size_bytes == LARGE_FILE_BYTES + 5000
    assert len(rec.sha256) == 64


def test_scannable_excludes_oversized_and_unclassifiable(tmp_path):
    (tmp_path / "ok.py").write_text("x")
    (tmp_path / "blob.bin").write_text("x")
    (tmp_path / "big.py").write_bytes(b"x" * (LARGE_FILE_BYTES + 1))
    inv = enumerate_tree(tmp_path)
    assert {f.path for f in inv.scannable} == {"ok.py"}
    assert len(inv.files) == 3  # all three are still recorded


def test_total_bytes_counts_every_recorded_file(tmp_path):
    (tmp_path / "a.py").write_bytes(b"x" * 10)
    (tmp_path / "b.py").write_bytes(b"x" * 20)
    assert enumerate_tree(tmp_path).total_bytes == 30


# --- query helpers --------------------------------------------------------


def test_by_language_and_by_role(tree):
    inv = enumerate_tree(tree)
    assert {f.path for f in inv.by_language(Language.PYTHON)} == {
        "src/app.py", "tests/test_app.py"
    }
    assert {f.path for f in inv.by_role(Role.DOCS)} == {"README.md"}


def test_an_empty_tree_is_empty_not_an_error(tmp_path):
    inv = enumerate_tree(tmp_path)
    assert inv == Inventory()


# ── v0.9.1 QA: the walk's bounds, and the manifest read's ────────────────────


def test_walk_does_not_descend_into_a_symlinked_directory(tmp_path: Path) -> None:
    """A symlink to a directory outside the tree must not be walked THROUGH.

    The old `rglob` form got this right by interpreter behaviour rather than by
    contract, and the interpreter CI runs (3.12) is not installable on the box
    this was written on. `os.walk(followlinks=False)` is a documented guarantee,
    so this test pins the property rather than the version.

    ⚠ NEGATIVE CONTROL: INCONCLUSIVE, not passing. Reverting to `sorted(rglob)`
    leaves this test green, because 3.14's `rglob` does not descend through a
    symlinked directory either. That is the whole reason the fix exists — the
    behaviour is correct on the interpreter we can measure and unverifiable on
    the one CI runs — so this is a contract pin, not a regression test, and must
    not be counted as evidence that the defect was reachable.
    """
    outside = tmp_path / "outside"
    (outside / "nested").mkdir(parents=True)
    (outside / "nested" / "host_secret.py").write_text("SECRET = 1")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("x = 1")
    (repo / "escape").symlink_to(outside)

    inv = enumerate_tree(repo)
    paths = {f.path for f in inv.files}

    assert paths == {"real.py"}
    assert not any("host_secret" in p for p in paths)
    assert inv.skipped.get("symlink") == 1


@contextlib.contextmanager
def _count_scandir():
    """Count `os.scandir` calls, the primitive BOTH traversals go through.

    ⚠ This replaced a probe that counted `Path.is_file` calls, which could not
    have failed on the defect: the eager `sorted(rglob(...))` form materialises
    every path but the loop still breaks at the cap, so it makes the same small
    number of `is_file` calls the streaming form does. The cost is in building
    the list, and `os.scandir` is where that cost is spent — measured 82 calls
    eager vs 8 streaming on a 40-directory tree.
    """
    calls: list[str] = []
    real = os.scandir

    def counting(path=".", *a, **kw):  # type: ignore[no-untyped-def]
        calls.append(str(path))
        return real(path, *a, **kw)

    with mock.patch.object(os, "scandir", counting):
        yield calls


def test_file_count_cap_bounds_the_walk_not_just_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`MAX_FILES` must stop the TRAVERSAL, not only truncate the record list.

    Negative control for the eager form: `sorted(root.rglob("*"))` enumerates
    the whole tree before the first cap check can run, so the cap bounded the
    list it built and not the peak work it exists to bound.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(40):
        d = repo / f"d{i:02d}"
        d.mkdir()
        (d / "a.py").write_text("x = 1")

    monkeypatch.setattr(inventory, "MAX_FILES", 5)

    with _count_scandir() as calls:
        inv = enumerate_tree(repo)

    assert inv.truncated is True
    assert len(inv.files) == 5
    # Positive control: the instrument ran. Without this the assertion below
    # would also pass on a probe that was never invoked — which is exactly how
    # the first version of this test passed on the broken code.
    assert calls, "os.scandir was never called — the probe did not run"
    assert len(calls) < 20, (
        f"traversal did not stop at the cap: {len(calls)} scandir calls over a "
        f"40-directory tree (streaming is ~6, eager is ~82)"
    )


def test_excluded_directory_is_pruned_not_walked(tmp_path: Path) -> None:
    """An excluded directory must cost nothing, not be walked and then discarded."""
    repo = tmp_path / "repo"
    (repo / "node_modules" / "deep").mkdir(parents=True)
    for i in range(30):
        (repo / "node_modules" / "deep" / f"v{i}.js").write_text("x")
    (repo / "index.js").write_text("x")

    with _count_scandir() as calls:
        inv = enumerate_tree(repo)

    assert [f.path for f in inv.files] == ["index.js"]
    assert calls, "os.scandir was never called — the probe did not run"
    assert not any("node_modules" in c for c in calls), (
        f"walked into an excluded directory: {[c for c in calls if 'node_modules' in c]}"
    )


def test_ordering_is_by_path_component_not_by_string(tmp_path: Path) -> None:
    """`a/b.py` sorts before `a.py`, as path-component comparison gives.

    A plain string sort inverts this, because "/" (0x2f) > "." (0x2e). Pinned
    because the streaming walk has to restore an order the global `sorted()`
    used to provide for free.
    """
    repo = tmp_path / "repo"
    (repo / "a").mkdir(parents=True)
    (repo / "a" / "b.py").write_text("x = 1")
    (repo / "a.py").write_text("x = 1")

    inv = enumerate_tree(repo)
    assert [f.path for f in inv.files] == ["a/b.py", "a.py"]


def test_oversized_manifest_degrades_to_no_entry_points(tmp_path: Path) -> None:
    """A manifest past `MANIFEST_MAX_BYTES` is not read into memory.

    `source.py`'s archive caps allow a single member far larger than this, and
    these two files are the only ones parsed whole — so their size becomes
    resident memory where every other file's does not.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    padding = "A" * (inventory.MANIFEST_MAX_BYTES + 1024)
    (repo / "package.json").write_text(
        json.dumps({"bin": {"cli": "./cli.js"}, "_pad": padding})
    )

    inv = enumerate_tree(repo)
    assert inv.entry_points == ()

    # Positive control: the same manifest under the cap DOES yield the entry
    # point, so the test above is measuring the cap and not a broken parser.
    (repo / "package.json").write_text(json.dumps({"bin": {"cli": "./cli.js"}}))
    assert enumerate_tree(repo).entry_points == ("./cli.js",)
