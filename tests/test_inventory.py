"""File enumeration invariants (`04-scanner-design.md` §3).

The tree under test is **attacker-controlled** — freshly fetched from a public
registry — so most of these pin refusals rather than features: what the walk
must not follow, must not open, and must not silently omit.
"""

from __future__ import annotations

import os

import pytest

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
