"""License detection and the `03` §7 license ladder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.license_check import (
    assess_license,
    identify_license,
    license_facts,
)

MIT_TEXT = (
    "MIT License\n\nCopyright (c) 2026 Someone\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
    "of this software and associated documentation files...\n"
)
APACHE_TEXT = "Licensed under the Apache License, Version 2.0 (the \"License\");\n"


def _tree(tmp_path: Path, **files: str) -> Path:
    for name, body in files.items():
        target = tmp_path / name.replace("__", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return tmp_path


def _assess(root: Path):
    return assess_license(root, enumerate_tree(root))


def _facts(root: Path):
    return license_facts(root, enumerate_tree(root))


# ── the ladder ──────────────────────────────────────────────────────────────

def test_spdx_matching_manifest_is_a_hundred(tmp_path: Path) -> None:
    root = _tree(tmp_path, LICENSE="SPDX-License-Identifier: MIT\n" + MIT_TEXT,
                 **{"package.json": '{"license": "MIT"}'})
    assert _assess(root).score == 100


def test_spdx_with_no_manifest_field_is_seventy(tmp_path: Path) -> None:
    # `03` §7 reserves 100 for the file and the metadata AGREEING; with nothing
    # to cross-check against, the agreement is unestablished.
    root = _tree(tmp_path, LICENSE="SPDX-License-Identifier: MIT\n" + MIT_TEXT)
    assert _assess(root).score == 70


def test_license_file_without_spdx_is_seventy(tmp_path: Path) -> None:
    root = _tree(tmp_path, LICENSE=MIT_TEXT)
    result = _assess(root)
    assert result.score == 70
    assert "identified as 'MIT'" in result.evidence[0]


def test_unidentifiable_license_still_scores_seventy(tmp_path: Path) -> None:
    # The absent classifier must never COST a server a point — it only ever
    # adds evidence. A file nobody can name is still a file that ships terms.
    root = _tree(tmp_path, LICENSE="Do whatever you like, honestly.\n")
    result = _assess(root)
    assert result.score == 70
    assert "not wired" in result.evidence[0]


def test_manifest_license_with_no_file_is_thirty(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"package.json": '{"license": "MIT"}'})
    assert _assess(root).score == 30


def test_nothing_anywhere_is_zero(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"README.md": "hello"})
    result = _assess(root)
    assert result.score == 0
    assert "no grant to use" in result.evidence[0]


def test_disagreement_scores_lower_than_either_absence(tmp_path: Path) -> None:
    # A consumer who reads one source comes away confident and wrong, which is
    # worse than reading nothing.
    root = _tree(tmp_path, LICENSE="SPDX-License-Identifier: MIT\n" + MIT_TEXT,
                 **{"package.json": '{"license": "GPL-3.0"}'})
    facts = _facts(root)
    assert facts.mismatch
    assert _assess(root).score == 30


def test_spdx_comparison_is_case_insensitive(tmp_path: Path) -> None:
    # SPDX ids are case-insensitive by specification; nobody types them
    # consistently, and a false mismatch is a published accusation.
    root = _tree(tmp_path, LICENSE="SPDX-License-Identifier: mit\n" + MIT_TEXT,
                 **{"package.json": '{"license": "MIT"}'})
    assert not _facts(root).mismatch
    assert _assess(root).score == 100


def test_no_source_abstains(tmp_path: Path) -> None:
    result = assess_license(None, None)
    assert result.score is None and result.reason


# ── where the facts come from ───────────────────────────────────────────────

def test_vendored_license_does_not_decide_the_repository(tmp_path: Path) -> None:
    # A bundled dependency's LICENSE describes somebody else's terms.
    #
    # ⚠ The vendored directory is named to sort BEFORE "LICENSE". With a name
    # like `vendor/`, the inventory's own path ordering already puts the root
    # file first, so an index-0 pick passes this test while being wrong — which
    # is what the first negative control caught. Depth must decide, not order.
    root = _tree(tmp_path, **{
        "AAA_vendor__sub__LICENSE": "SPDX-License-Identifier: GPL-3.0\n",
        "LICENSE": "SPDX-License-Identifier: MIT\n" + MIT_TEXT,
    })
    assert _facts(root).spdx_in_file == "MIT"
    assert _assess(root).score == 70  # MIT, no manifest to cross-check


@pytest.mark.parametrize(
    ("manifest", "body", "expected"),
    [
        ("package.json", '{"license": "MIT"}', "MIT"),
        # npm's deprecated object form still occurs in the wild.
        ("package.json", '{"license": {"type": "MIT", "url": "x"}}', "MIT"),
        ("pyproject.toml", '[project]\nlicense = "MIT"\n', "MIT"),
        # PEP 621's table form predates the string form and still occurs.
        ("pyproject.toml", '[project]\nlicense = {text = "MIT"}\n', "MIT"),
        ("Cargo.toml", '[package]\nlicense = "MIT"\n', "MIT"),
    ],
)
def test_manifest_license_shapes(tmp_path: Path, manifest: str, body: str, expected: str) -> None:
    root = _tree(tmp_path, **{manifest: body})
    assert _facts(root).spdx_in_manifest == expected


def test_malformed_manifest_degrades_to_nothing_declared(tmp_path: Path) -> None:
    # Attacker-controlled input must never fail the scan.
    root = _tree(tmp_path, **{"package.json": "{not json at all"})
    assert _facts(root).spdx_in_manifest is None


def test_license_field_pointing_at_a_file_is_not_an_spdx_id(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"pyproject.toml": '[project]\nlicense = {file = "LICENSE"}\n'})
    assert _facts(root).spdx_in_manifest is None


# ── fingerprinting ──────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("text", "expected"),
    [(MIT_TEXT, "MIT"), (APACHE_TEXT, "Apache-2.0"),
     ("GNU AFFERO GENERAL PUBLIC LICENSE\n", "AGPL-3.0"),
     ("This is free and unencumbered software released into the public domain\n", "Unlicense")],
)
def test_identify_license_by_distinctive_phrase(text: str, expected: str) -> None:
    assert identify_license(text) == expected


def test_identify_returns_none_rather_than_guessing() -> None:
    # Matching on a NAME would fire on any README mentioning a license.
    assert identify_license("This project is MIT licensed, probably.\n") is None
    assert identify_license("") is None


def test_spdx_tag_must_be_a_declaration_not_a_mention(tmp_path: Path) -> None:
    root = _tree(tmp_path, LICENSE="We considered using SPDX tags.\n" + MIT_TEXT)
    assert _facts(root).spdx_in_file is None


# ── SPDX expressions: the false-positive class found on a real server ───────

@pytest.mark.parametrize(
    ("tag", "expression", "expected_score"),
    [
        ("MIT", "MIT", 100),
        # ⚠ The real case. `ac.tandem/docs-mcp` ships an MIT LICENSE against a
        # `MIT OR Apache-2.0` manifest — the standard Rust dual license. This
        # scored 30 as "the two disagree" until 2026-09-15.
        ("MIT", "MIT OR Apache-2.0", 100),
        ("Apache-2.0", "MIT OR Apache-2.0", 100),
        # AND requires every listed license; only one text ships.
        ("MIT", "MIT AND Apache-2.0", 70),
        # A WITH exception binds to one license and introduces no alternative.
        ("GPL-3.0-only", "GPL-3.0-only WITH Classpath-exception-2.0", 100),
        # A genuine conflict still scores 30.
        ("GPL-3.0", "MIT OR Apache-2.0", 30),
        ("MIT", "GPL-3.0", 30),
    ],
)
def test_spdx_expressions(tmp_path: Path, tag: str, expression: str,
                          expected_score: int) -> None:
    root = _tree(tmp_path, LICENSE=f"SPDX-License-Identifier: {tag}\n" + MIT_TEXT,
                 **{"package.json": f'{{"license": {expression!r}}}'.replace("'", '"')})
    assert _assess(root).score == expected_score


def test_text_identified_license_can_never_establish_a_conflict(tmp_path: Path) -> None:
    # ⚠ A fingerprint match is evidence of what the file IS, never grounds for
    # accusing a maintainer of contradicting themselves. It also cannot tell a
    # family from a grant — the fingerprints say `GPL-3.0` where manifests say
    # `GPL-3.0-or-later` — so comparing on it manufactures conflicts out of
    # correct metadata.
    root = _tree(tmp_path, LICENSE=MIT_TEXT, **{"package.json": '{"license": "GPL-3.0"}'})
    facts = _facts(root)
    assert facts.identified == "MIT"
    assert facts.spdx_in_file is None
    assert not facts.mismatch
    assert facts.relation == "unknown"
    assert _assess(root).score == 70


def test_root_manifest_wins_over_a_workspace_member(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "Cargo.toml": '[package]\nlicense = "MIT"\n',
        "crates__inner__Cargo.toml": '[package]\nlicense = "GPL-3.0"\n',
    })
    assert _facts(root).spdx_in_manifest == "MIT"


def test_cargo_workspace_package_table_is_read(tmp_path: Path) -> None:
    # A workspace root puts the inherited license under [workspace.package].
    root = _tree(tmp_path, **{"Cargo.toml": '[workspace.package]\nlicense = "MIT"\n'})
    assert _facts(root).spdx_in_manifest == "MIT"


def test_workspace_inheritance_marker_is_not_a_license(tmp_path: Path) -> None:
    # `license.workspace = true` says "inherit", not "the license is true".
    root = _tree(tmp_path, **{"crates__a__Cargo.toml": "[package]\nlicense.workspace = true\n"})
    assert _facts(root).spdx_in_manifest is None


@pytest.mark.parametrize(
    ("tag", "expression", "expected"),
    [
        # ⚠ SPDX binds WITH tighter than OR, so the operators must be split in
        # that order. Splitting on WITH first kept only the head and discarded
        # every later alternative — and the damage depended on which operand
        # carried the exception, so the first row passed while the rest did not.
        ("MIT", "MIT OR Apache-2.0 WITH LLVM-exception", 100),
        ("MIT", "Apache-2.0 WITH LLVM-exception OR MIT", 100),
        # A real, widely used Rust crate license string.
        ("MIT", "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", 100),
        # A genuine conflict must still be reported.
        ("GPL-3.0", "Apache-2.0 WITH LLVM-exception OR MIT", 30),
    ],
)
def test_with_binds_tighter_than_or(tmp_path: Path, tag: str, expression: str,
                                    expected: int) -> None:
    root = _tree(tmp_path, LICENSE=f"SPDX-License-Identifier: {tag}\n" + MIT_TEXT,
                 **{"package.json": json.dumps({"license": expression})})
    assert _assess(root).score == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # ⚠ "GNU GENERAL PUBLIC LICENSE" is GPL-2.0's header too, and
        # "Version 3, 29 June 2007" is LGPL-3.0's — so both published
        # "identified as 'GPL-3.0'". Copyleft-tier confusion about a third
        # party's licence, not a cosmetic slip.
        ("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n", "GPL-2.0"),
        ("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n", "GPL-3.0"),
        ("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n", "LGPL-3.0"),
        ("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n", "AGPL-3.0"),
        # BSD-3 texts substitute the holder, so the old holder-specific phrase
        # missed and they fell through to BSD-2, whose clause BSD-3 contains.
        ("Redistribution and use in source and binary forms, with or without\n"
         "Neither the name of <organization> nor the names of its contributors\n",
         "BSD-3-Clause"),
        ("Redistribution and use in source and binary forms, with or without\n"
         "modification, are permitted provided that...\n", "BSD-2-Clause"),
    ],
)
def test_license_families_are_not_confused_with_each_other(text: str, expected: str) -> None:
    assert identify_license(text) == expected


# ── Codex leg 2: the regressions the first pass could not have seen ─────────

def test_exception_on_the_file_side_is_not_a_conflict(tmp_path: Path) -> None:
    """The `WITH` strip was applied to the manifest's operands only.

    Reproduction, not paraphrase: the operand split removed the exception from
    each arm of `MIT OR Apache-2.0 WITH LLVM-exception` and then looked up the
    file's tag WHOLE, so `apache-2.0 with llvm-exception` was absent from
    `["mit", "apache-2.0"]` and the pair published a licence CONFLICT at 30 —
    the same false accusation the operand split was written to remove, one layer
    down, on a real Rust crate string.
    """
    root = _tree(
        tmp_path,
        LICENSE="SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n" + APACHE_TEXT,
        **{"Cargo.toml": '[package]\nlicense = "MIT OR Apache-2.0 WITH LLVM-exception"\n'},
    )
    facts = _facts(root)
    assert facts.relation == "alternative"
    assert facts.mismatch is False
    assert _assess(root).score == 100


def test_exception_on_either_side_alone_still_matches(tmp_path: Path) -> None:
    """An exception never names a second licence, so it cannot create a gap."""
    root = _tree(
        tmp_path,
        LICENSE="SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n" + APACHE_TEXT,
        **{"Cargo.toml": '[package]\nlicense = "Apache-2.0"\n'},
    )
    assert _facts(root).relation == "exact"
    assert _assess(root).score == 100


def test_a_real_conflict_still_reports_one(tmp_path: Path) -> None:
    """The control for the two above: stripping exceptions must not strip teeth."""
    root = _tree(
        tmp_path,
        LICENSE="SPDX-License-Identifier: GPL-3.0 WITH Classpath-exception-2.0\n",
        **{"package.json": '{"license": "MIT OR Apache-2.0"}'},
    )
    facts = _facts(root)
    assert facts.relation == "conflict"
    assert _assess(root).score == 30


def test_an_spdx_identifier_in_prose_is_not_a_declaration(tmp_path: Path) -> None:
    """The regex's comment claimed it was anchored; it was not.

    A LICENSE file whose text discusses an identifier it rejected would declare
    that identifier — and the manifest naming the real licence then publishes a
    CONFLICT against a correctly-licensed project.
    """
    root = _tree(
        tmp_path,
        LICENSE=("We considered SPDX-License-Identifier: GPL-3.0 and chose "
                 "otherwise.\n\n" + MIT_TEXT),
        **{"package.json": '{"license": "MIT"}'},
    )
    facts = _facts(root)
    assert facts.spdx_in_file is None
    assert facts.mismatch is False


def test_a_commented_spdx_tag_still_declares(tmp_path: Path) -> None:
    """Control for the anchor: `#`, `//` and ` * ` prefixes are real tags."""
    for prefix in ("# ", "// ", " * ", "<!-- "):
        root = _tree(
            tmp_path / prefix.strip(" <!-/*") or tmp_path,
            LICENSE=f"{prefix}SPDX-License-Identifier: MIT\n" + MIT_TEXT,
        )
        assert _facts(root).spdx_in_file == "MIT", prefix


def test_a_large_but_valid_manifest_is_not_truncated_into_a_parse_failure(
    tmp_path: Path,
) -> None:
    """Manifests were read through the 512 KB SOURCE reader, which TRUNCATES.

    A valid `package.json` over that bound reached `json.loads` as a guaranteed
    -invalid document, so its declared licence vanished by a route that reads
    as the publisher shipping a malformed file. Padded with a real field rather
    than junk so the only thing under test is the size.
    """
    padding = "x" * (600 * 1024)
    manifest = json.dumps({"name": "big", "description": padding, "license": "MIT"})
    assert len(manifest) > 512 * 1024
    root = _tree(tmp_path, LICENSE=MIT_TEXT, **{"package.json": manifest})
    assert _facts(root).spdx_in_manifest == "MIT"


# ── Codex leg 3: the exception strip truncated a COMPOUND tag ──────────────

@pytest.mark.parametrize("tag,manifest,relation", [
    # The regression: stripping WITH from the whole tag discarded `OR MIT`,
    # leaving "apache-2.0" to compare EXACT against a manifest declaring only
    # Apache-2.0 — two differing declarations scored 100.
    ("Apache-2.0 WITH LLVM-exception OR MIT", "Apache-2.0", "alternative"),
    ("MIT OR Apache-2.0 WITH LLVM-exception", "MIT", "alternative"),
    # An AND operand was swallowed the same way.
    ("GPL-2.0-only WITH Classpath-exception-2.0 AND MIT", "GPL-2.0-only", "alternative"),
    # Order independence, in BOTH operands — the point of the whole thread.
    ("MIT OR Apache-2.0", "Apache-2.0 OR MIT", "exact"),
    # The cases that must keep working.
    ("Apache-2.0 WITH LLVM-exception", "MIT OR Apache-2.0 WITH LLVM-exception", "alternative"),
    ("Apache-2.0 WITH LLVM-exception", "Apache-2.0", "exact"),
    ("MIT", "MIT AND Apache-2.0", "partial"),
    # And a real disagreement must still be one.
    ("GPL-3.0 WITH Classpath-exception-2.0", "MIT OR Apache-2.0", "conflict"),
    ("MIT", "Apache-2.0", "conflict"),
])
def test_compound_tags_keep_every_operand(tag, manifest, relation) -> None:
    """A LICENSE file may carry a compound identifier — `SPDX-License-Identifier:
    MIT OR Apache-2.0` is ordinary in Rust — so the tag needs the same
    decomposition the manifest expression always got.

    This is the function's ORIGINAL defect (keep only the head before the first
    `WITH`) reintroduced on the tag side by the fix for it on the manifest side.
    """
    from mcpwatchman.workers.scanner.license_check import _spdx_relation
    assert _spdx_relation(tag, manifest) == relation


def test_a_compound_tag_against_a_single_manifest_does_not_score_exact(
    tmp_path: Path,
) -> None:
    """End to end, because the relation is only half the defect: `exact` was
    reached and it published "SPDX 'X' in LICENSE, matching <manifest>" — a
    claim of agreement between declarations that differ."""
    root = _tree(
        tmp_path,
        LICENSE="SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT\n"
                + APACHE_TEXT,
        **{"Cargo.toml": '[package]\nlicense = "Apache-2.0"\n'},
    )
    facts = _facts(root)
    assert facts.relation == "alternative"
    assert facts.mismatch is False
    result = _assess(root)
    assert result.score == 100
    assert "dual license" in result.evidence[0]


@pytest.mark.parametrize("tag,manifest", [
    ("MIT OR Apache-2.0", "MIT AND Apache-2.0"),
    ("MIT AND Apache-2.0", "MIT OR Apache-2.0"),
])
def test_equal_operand_sets_with_a_different_operator_abstain(
    tmp_path: Path, tag, manifest
) -> None:
    """`OR` lets a consumer pick one; `AND` obliges them to satisfy both.

    Comparing operand SETS — the fix for the compound-tag truncation — made
    those `exact` and published a 100-point *matching* claim over two
    declarations that differ on the only question a licence answers. `03` §7
    assigns no band to it, so it abstains rather than inventing one, and rather
    than being smuggled into `conflict` (which would accuse the publisher of
    shipping a licence the manifest excludes — false here).
    """
    root = _tree(
        tmp_path,
        LICENSE=f"SPDX-License-Identifier: {tag}\n" + MIT_TEXT,
        **{"package.json": '{"license": "' + manifest + '"}'},
    )
    assert _facts(root).relation == "operator-mismatch"
    result = _assess(root)
    assert result.score is None
    assert "different operator" in result.reason


def test_the_same_operator_still_matches_regardless_of_order(tmp_path: Path) -> None:
    """Control: order independence must survive the operator check."""
    root = _tree(
        tmp_path,
        LICENSE="SPDX-License-Identifier: MIT OR Apache-2.0\n" + MIT_TEXT,
        **{"package.json": '{"license": "Apache-2.0 OR MIT"}'},
    )
    assert _facts(root).relation == "exact"
    assert _assess(root).score == 100
