"""License detection (`04` §7) and the Transparency license sub-check (`03` §7).

Three questions, and `03` §7's ladder needs all three: is there a LICENSE file,
does it carry an SPDX identifier, and does that identifier match what the
package metadata declares? A mismatch between the two is a Transparency finding
in its own right (`04` §7) — the file and the manifest disagreeing about the
terms is worse than either being absent, because a consumer reading one of them
comes away confident and wrong.

⚠ **`04` §7's fallback tool is not wired, and this file says so rather than
scoring around it.** For a LICENSE with no SPDX tag, §7 calls for Google's
`license-classifier` to identify the license from its text. That is an external
Go binary and it is not a declared dependency. What stands in for it here is a
**narrow, high-precision** text match on the distinctive phrase of the handful
of licenses that cover most of this ecosystem — which is enough to reach `03`
§7's 70 band ("LICENSE present, no SPDX, identifiable content") for those, and
which reports UNIDENTIFIED rather than guessing for anything else. An
unidentified license still scores 70 on the strength of the file existing; the
identification only ever adds evidence, never subtracts a point, so the missing
tool cannot cost a server anything.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_text
from mcpwatchman.workers.scoring.axes import SubCheck

# `SPDX-License-Identifier: MIT`, and the `license = "MIT"` / `"license": "MIT"`
# manifest forms. Deliberately anchored: an SPDX id mentioned in prose ("we
# considered SPDX-License-Identifier: GPL-3.0") is not a declaration.
_SPDX_TAG = re.compile(
    r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+]+(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.\-+]+)*)"
)

# Distinctive phrases, one per license family. Each is a sentence that appears
# in that license and in no other — matching on a name ("MIT") would fire on any
# README mentioning it.
_LICENSE_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("MIT", "Permission is hereby granted, free of charge, to any person obtaining a copy"),
    ("Apache-2.0", "Licensed under the Apache License, Version 2.0"),
    ("Apache-2.0", "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"),
    ("BSD-3-Clause", "Neither the name of the copyright holder nor the names of its"),
    ("BSD-2-Clause", "Redistribution and use in source and binary forms, with or without"),
    ("GPL-3.0", "GNU GENERAL PUBLIC LICENSE"),
    ("GPL-3.0", "Version 3, 29 June 2007"),
    ("AGPL-3.0", "GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("LGPL-3.0", "GNU LESSER GENERAL PUBLIC LICENSE"),
    ("MPL-2.0", "Mozilla Public License Version 2.0"),
    ("ISC", "Permission to use, copy, modify, and/or distribute this software for any"),
    ("Unlicense", "This is free and unencumbered software released into the public domain"),
)

# How many bytes of a LICENSE file to fingerprint. Every phrase above appears in
# the opening preamble; reading further only lets a hostile file bury a decoy.
LICENSE_SNIFF_BYTES = 8192


@dataclass(frozen=True, slots=True)
class LicenseFacts:
    """What the repository says about its own license, from both sources."""

    file_path: str | None = None
    # SPDX id from the LICENSE file's own tag, if it carries one.
    spdx_in_file: str | None = None
    # SPDX id from `package.json` / `pyproject.toml` / `Cargo.toml`.
    spdx_in_manifest: str | None = None
    manifest_path: str | None = None
    # Identified from the text, when there was no tag to read.
    identified: str | None = None

    @property
    def declared(self) -> str | None:
        """The license as best we know it, tag first, then manifest, then text."""
        return self.spdx_in_file or self.spdx_in_manifest or self.identified

    @property
    def relation(self) -> str:
        """How the LICENSE file's SPDX tag relates to the manifest's expression.

        One of `exact`, `alternative`, `partial`, `conflict`, or `unknown`.

        ⚠ **Only an explicit SPDX TAG can establish a conflict — never a license
        identified from text.** Text identification is a fingerprint match, so
        using it to accuse a maintainer of contradicting themselves publishes a
        heuristic as a finding. It also cannot distinguish the variants that
        matter: the fingerprints name a family (`GPL-3.0`) while manifests
        declare a grant (`GPL-3.0-or-later`), so a text-identified comparison
        manufactures conflicts out of correct metadata.
        """
        tag = self.spdx_in_file
        if not tag or not self.spdx_in_manifest:
            return "unknown"
        return _spdx_relation(tag, self.spdx_in_manifest)

    @property
    def mismatch(self) -> bool:
        """File and manifest declare incompatible licenses (`04` §7).

        A compound expression is NOT a disagreement. `MIT OR Apache-2.0` with an
        MIT LICENSE file is a dual-license offer shipping one of its arms —
        standard practice, especially in Rust — and calling it a contradiction
        is a false accusation on a product whose entire claim is that its
        numbers can be checked. Measured against a real registry server
        (`ac.tandem/docs-mcp`, 2026-09-15), which this scored 30 before the fix.
        """
        return self.relation == "conflict"


def _normalise_spdx(value: str) -> str:
    return value.strip().strip("()").casefold()


def _spdx_relation(tag: str, expression: str) -> str:
    """Relate one SPDX identifier to a (possibly compound) SPDX expression.

    Minimal on purpose — a full SPDX expression parser is a dependency this
    needs no part of. It distinguishes the four cases `03` §7's ladder reacts
    to, and treats anything it cannot decompose as a plain comparison.

    - `exact`       — the same identifier.
    - `alternative` — the expression OFFERS several licenses and the file ships
                      one of them. Consistent; `MIT OR Apache-2.0` is the type case.
    - `partial`     — the expression REQUIRES several and only one text ships.
                      Not a contradiction, but not a clean match either: we can
                      only see one of the documents the metadata says apply.
    - `conflict`    — the file's licence appears nowhere in the expression.
    """
    tag_norm = _normalise_spdx(tag)
    expr_norm = _normalise_spdx(expression)
    if tag_norm == expr_norm:
        return "exact"

    # `WITH` binds an exception to one licence (`GPL-3.0 WITH Classpath-exception`)
    # and does not introduce an alternative, so it is split away first.
    head = re.split(r"\s+with\s+", expr_norm)[0]
    if " or " in head:
        operands = [_normalise_spdx(p) for p in re.split(r"\s+or\s+", head)]
        return "alternative" if tag_norm in operands else "conflict"
    if " and " in head:
        operands = [_normalise_spdx(p) for p in re.split(r"\s+and\s+", head)]
        return "partial" if tag_norm in operands else "conflict"
    return "exact" if tag_norm == head else "conflict"


def _license_record(inventory: Inventory):
    """The LICENSE file, preferring a root-level one over a nested one.

    A vendored dependency's LICENSE sits several directories down and describes
    somebody else's terms; grading the server on it would report a bundled MIT
    dependency as the server's own license.
    """
    candidates = [f for f in inventory.by_role(Role.LICENSE)]
    if not candidates:
        return None
    return min(candidates, key=lambda f: (f.path.count("/"), len(f.path)))


def _manifest_license(root: Path, inventory: Inventory) -> tuple[str | None, str | None]:
    """SPDX id declared in the package manifest, and which file declared it.

    Every parse failure degrades to "nothing declared" — a malformed manifest is
    an attacker-controlled input and must not fail the scan.
    """
    # Root-most first, for the same reason `_license_record` prefers it: a
    # workspace member's manifest describes that crate, not the server. Measured
    # on a real server whose root Cargo.toml carries no license field and whose
    # nested crate does — the nested one is a legitimate fallback, but only
    # after the root has been tried.
    manifests = sorted(
        inventory.by_role(Role.PACKAGE_MANIFEST),
        key=lambda f: (f.path.count("/"), len(f.path)),
    )
    for record in manifests:
        name = record.path.rsplit("/", 1)[-1]
        text = read_text(root, record.path)
        if not text:
            continue
        value: str | None = None
        if name == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            raw = data.get("license") if isinstance(data, dict) else None
            # npm's deprecated object form: {"type": "MIT", "url": ...}
            if isinstance(raw, dict):
                raw = raw.get("type")
            value = raw if isinstance(raw, str) else None
        elif name in ("pyproject.toml", "Cargo.toml"):
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            # `[workspace.package]` is where a Cargo workspace root puts the
            # license its members inherit via `license.workspace = true`; a
            # member read alone would report nothing declared.
            workspace = data.get("workspace") if isinstance(data, dict) else None
            table = (
                data.get("project")
                or data.get("package")
                or (workspace.get("package") if isinstance(workspace, dict) else None)
                or {}
            )
            raw = table.get("license") if isinstance(table, dict) else None
            # `license.workspace = true` is an inheritance marker, not a license.
            if isinstance(raw, dict) and "workspace" in raw:
                raw = None
            # PEP 621 allowed a table ({text = "MIT"} / {file = "LICENSE"})
            # before 0.__ made the string form canonical; both still occur.
            if isinstance(raw, dict):
                raw = raw.get("text")
            value = raw if isinstance(raw, str) else None
        if value and value.strip():
            return value.strip(), record.path
    return None, None


def identify_license(text: str) -> str | None:
    """Name a license from its text, or return None rather than guess.

    Stands in for `04` §7's `license-classifier`, narrowly: a hit is
    high-confidence because each phrase is unique to its license, and a miss
    says nothing at all. Never used to lower a score — see the module docstring.
    """
    head = text[:LICENSE_SNIFF_BYTES]
    for name, phrase in _LICENSE_FINGERPRINTS:
        if phrase in head:
            return name
    return None


def license_facts(root: Path, inventory: Inventory) -> LicenseFacts:
    """Everything `03` §7 and `04` §7 need to know about the license."""
    record = _license_record(inventory)
    manifest_spdx, manifest_path = _manifest_license(root, inventory)

    if record is None:
        return LicenseFacts(spdx_in_manifest=manifest_spdx, manifest_path=manifest_path)

    text = read_text(root, record.path)
    tag = _SPDX_TAG.search(text[:LICENSE_SNIFF_BYTES])
    return LicenseFacts(
        file_path=record.path,
        spdx_in_file=tag.group(1).strip() if tag else None,
        spdx_in_manifest=manifest_spdx,
        manifest_path=manifest_path,
        identified=identify_license(text) if not tag else None,
    )


def score_license(facts: LicenseFacts) -> SubCheck:
    """`03` §7's license ladder.

    100 — SPDX in LICENSE and it matches the package metadata.
     70 — LICENSE present without an SPDX tag.
     30 — a license is referenced in metadata but no file ships with the repo.
      0 — nothing anywhere. "Legally radioactive" is `03` §7's own phrase, and
          the 0 is not a judgement about code quality: without a license nobody
          may use the server at all.
    """
    name = "license"

    if facts.file_path is None:
        if facts.spdx_in_manifest:
            return SubCheck(
                name, 30,
                evidence=(f"{facts.manifest_path} declares "
                          f"{facts.spdx_in_manifest!r} but no LICENSE file ships "
                          "with the source",),
            )
        return SubCheck(
            name, 0,
            evidence=("no LICENSE file and no license field in any package "
                      "manifest — `03` §7: without a license, a consumer has no "
                      "grant to use the server at all",),
        )

    if facts.mismatch:
        # A disagreement is worse than an absence: a consumer who reads one
        # source comes away confident and wrong.
        return SubCheck(
            name, 30,
            evidence=(f"{facts.file_path} declares SPDX {facts.spdx_in_file!r} but "
                      f"{facts.manifest_path} declares "
                      f"{facts.spdx_in_manifest!r}, which does not include it",),
        )

    if facts.spdx_in_file:
        relation = facts.relation
        if relation == "exact":
            return SubCheck(
                name, 100,
                evidence=(f"SPDX {facts.spdx_in_file!r} in {facts.file_path}, "
                          f"matching {facts.manifest_path}",),
            )
        if relation == "alternative":
            # A dual-license offer shipping one of its arms. The two sources
            # agree; treating it as anything less would penalise the standard
            # Rust convention.
            return SubCheck(
                name, 100,
                evidence=(f"{facts.manifest_path} offers "
                          f"{facts.spdx_in_manifest!r} and {facts.file_path} ships "
                          f"the {facts.spdx_in_file!r} arm — a dual license, not a "
                          "disagreement",),
            )
        if relation == "partial":
            return SubCheck(
                name, 70,
                evidence=(f"{facts.manifest_path} declares {facts.spdx_in_manifest!r}, "
                          f"which requires every listed license, but only the "
                          f"{facts.spdx_in_file!r} text ships",),
            )
        if facts.spdx_in_manifest:
            return SubCheck(
                name, 100,
                evidence=(f"SPDX {facts.spdx_in_file!r} in {facts.file_path}, "
                          f"matching {facts.manifest_path}",),
            )
        return SubCheck(
            name, 70,
            evidence=(f"SPDX {facts.spdx_in_file!r} in {facts.file_path}, but no "
                      "license field in any package manifest to cross-check it "
                      "against — `03` §7 reserves 100 for the two agreeing",),
        )

    identified = (
        f"identified as {facts.identified!r} from its text"
        if facts.identified
        else "text not matched against any license this build can identify "
             "(`04` §7's classifier is not wired; see module docstring)"
    )
    return SubCheck(
        name, 70,
        evidence=(f"{facts.file_path} present with no SPDX-License-Identifier "
                  f"tag; {identified}",),
    )


def assess_license(root: Path | None, inventory: Inventory | None) -> SubCheck:
    """The license sub-check, or an honest abstention when there is no source."""
    if root is None or inventory is None:
        return SubCheck(
            "license", None,
            reason="no source was fetched, so neither a LICENSE file nor a "
                   "package manifest could be read",
        )
    return score_license(license_facts(root, inventory))
