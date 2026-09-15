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

from mcpwatchman.workers.scanner.inventory import (
    Inventory,
    Role,
    read_manifest,
    read_text,
)
from mcpwatchman.workers.scoring.axes import SubCheck

# `SPDX-License-Identifier: MIT` as a DECLARATION — the tag standing on its own
# line, optionally behind a comment marker.
#
# ⚠ **The comment said "deliberately anchored" and the pattern was not**, which
# is the worse half: a false citation reads as provenance and stops the next
# reader from checking. Unanchored, any prose containing the string declared the
# file's licence — "we considered SPDX-License-Identifier: GPL-3.0 and chose
# MIT" would have the LICENSE file declaring GPL-3.0, and the manifest saying
# MIT then publishes a licence CONFLICT against a correctly-licensed project.
# Now anchored for real, with the leading run restricted to comment punctuation
# and whitespace so `#`, `//`, ` * ` and `<!--` still qualify and prose does not.
_SPDX_TAG = re.compile(
    r"^[\s#/*<!;%-]{0,20}"
    r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+]+(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.\-+]+)*)",
    re.MULTILINE,
)

# Distinctive phrases, one per license family. Each is a sentence that appears
# in that license and in no other — matching on a name ("MIT") would fire on any
# README mentioning it.
# ⚠ **Each entry needs EVERY phrase, and the order is most-specific-first.
# Both properties were missing and each produced a misnamed license.**
#
# The old table keyed GPL-3.0 on `"GNU GENERAL PUBLIC LICENSE"` alone — which is
# equally GPL-2.0's header — and separately on `"Version 3, 29 June 2007"`,
# which is *also* LGPL-3.0's header line. Sitting above the AGPL and LGPL rows,
# the broader phrase always won, so GPL-2.0 and LGPL-3.0 texts both published
# the evidence *"identified as 'GPL-3.0' from its text"*. That is copyleft-tier
# confusion about a named third party's licence, not a cosmetic slip.
#
# BSD-3 keyed on `"…nor the names of its"`, but real BSD-3 texts substitute the
# holder (`"Neither the name of <organization> nor…"`), so those fell through to
# the BSD-2 row whose clause BSD-3 also contains. The invariant prefix is the
# part that does not vary.
_LICENSE_FINGERPRINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Most specific first: every GNU family text contains the GPL body, so a
    # broader row placed above a narrower one shadows it permanently.
    ("AGPL-3.0", ("GNU AFFERO GENERAL PUBLIC LICENSE",)),
    ("LGPL-3.0", ("GNU LESSER GENERAL PUBLIC LICENSE",)),
    ("GPL-3.0", ("GNU GENERAL PUBLIC LICENSE", "Version 3, 29 June 2007")),
    ("GPL-2.0", ("GNU GENERAL PUBLIC LICENSE", "Version 2, June 1991")),
    ("Apache-2.0", ("Licensed under the Apache License, Version 2.0",)),
    ("Apache-2.0", ("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",)),
    ("MPL-2.0", ("Mozilla Public License Version 2.0",)),
    ("Unlicense", ("This is free and unencumbered software released into the public domain",)),
    ("ISC", ("Permission to use, copy, modify, and/or distribute this software for any",)),
    ("MIT", ("Permission is hereby granted, free of charge, to any person obtaining a copy",)),
    # BSD-3 before BSD-2: BSD-3 text contains BSD-2's clause verbatim.
    ("BSD-3-Clause", ("Neither the name of",)),
    ("BSD-2-Clause", ("Redistribution and use in source and binary forms, with or without",)),
)

# How many bytes of a LICENSE file to fingerprint. Every phrase above appears in
# the opening preamble; reading further only lets a hostile file bury a decoy.
LICENSE_SNIFF_BYTES = 8192

# Root-most manifests are sorted first, so the license-bearing one is at the
# front in every realistic tree; this bounds the hostile case.
MAX_MANIFESTS_READ = 40


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

        One of `exact`, `alternative`, `partial`, `conflict`, `operator-mismatch`,
        or `unknown`.

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


def _expression_kind(expr: str) -> str:
    """Whether an SPDX expression OFFERS a choice, REQUIRES all, or names one."""
    if " or " in expr:
        return "or"
    if " and " in expr:
        return "and"
    return "single"


def _license_operands(expr: str) -> set[str]:
    """The distinct licences an SPDX expression names, exceptions removed.

    `OR` and `AND` are both operand separators here — this answers only WHICH
    licences appear, never how they combine; the caller inspects the operator
    itself when it needs to tell an offer from a requirement. Splitting on both
    is what stops a compound operand being swallowed by the exception strip.
    """
    return {_strip_exception(part) for part in re.split(r"\s+(?:or|and)\s+", expr)}


def _strip_exception(value: str) -> str:
    """Drop a `WITH <exception>` clause from one SPDX operand.

    An exception (`LLVM-exception`, `Classpath-exception-2.0`) grants additional
    permissions under the licence it attaches to; it never introduces a second
    licence. So it is noise for the only question `_spdx_relation` asks — which
    licences does this expression offer — and has to be removed from whichever
    side carries it.
    """
    return _normalise_spdx(re.split(r"\s+with\s+", value)[0])


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

    # ⚠ **BOTH SIDES ARE DECOMPOSED INTO OPERAND SETS — stripping the exception
    # from the WHOLE tag truncates a compound one at its first `WITH`.**
    #
    #   tag `Apache-2.0 WITH LLVM-exception OR MIT`    -> "apache-2.0"  (OR MIT lost)
    #   tag `GPL-2.0 WITH Classpath-exception AND MIT` -> "gpl-2.0"     (AND MIT lost)
    #
    # That is the ORIGINAL defect of this function — keeping only the head
    # before the first `WITH` — reintroduced on the TAG side by the fix for it
    # on the MANIFEST side. A LICENSE file may carry a compound identifier
    # (`SPDX-License-Identifier: MIT OR Apache-2.0` is ordinary in Rust), and a
    # tag truncated to its first operand then compared `exact` against a
    # single-licence manifest, awarding 100 to two declarations that differ.
    #
    # Comparing SETS rather than heads also makes the relation order-independent
    # in both operands, which is what this whole `WITH`/`OR` precedence thread
    # has been about: `MIT OR Apache-2.0` and `Apache-2.0 OR MIT` are one offer.
    tag_ops = _license_operands(tag_norm)
    expr_ops = _license_operands(expr_norm)
    if tag_ops == expr_ops:
        # ⚠ **EQUAL OPERAND SETS ARE NOT AN EQUAL GRANT — the operator decides.**
        # `MIT OR Apache-2.0` lets a consumer pick one; `MIT AND Apache-2.0`
        # obliges them to satisfy both. Comparing sets alone made those `exact`
        # and published a 100-point *matching* claim over two declarations that
        # differ on the only question a licence answers. That is the set
        # comparison — introduced to fix the compound-tag truncation — creating
        # its own false claim one layer up.
        #
        # `03` §7 specifies no band for "same licences, different operator", and
        # `CLAUDE.md` is explicit that where the methodology specifies no band we
        # ABSTAIN rather than invent one. It is a real discrepancy and a reader
        # is owed it, so it is surfaced as unassessed with the reason, not
        # smuggled into `conflict` (which would accuse the publisher of shipping
        # a licence the manifest excludes — false here) nor into `partial`.
        tag_kind, expr_kind = _expression_kind(tag_norm), _expression_kind(expr_norm)
        if tag_kind != expr_kind and "single" not in (tag_kind, expr_kind):
            return "operator-mismatch"
        return "exact"
    if not tag_ops & expr_ops:
        # The file's licence appears nowhere in the expression — the only shape
        # that is a real disagreement, and the only one that may accuse anyone.
        return "conflict"
    if " and " in expr_norm and " or " not in expr_norm and tag_ops < expr_ops:
        # A conjunctive expression REQUIRES every operand; shipping a subset of
        # the texts is incomplete rather than contradictory.
        return "partial"
    # Overlapping offers, in either direction — a dual licence, not a dispute.
    return "alternative"


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
    # ⚠ Bounded like every other content reader here — `transport_check` and
    # `auth_check` both cap at 40, and `CLAUDE.md` records that every bounds
    # defect in this repo has been a guard written in one place and omitted from
    # its neighbour. This loop was the omission: it opened and parsed manifests
    # until one yielded a license, up to `inventory.MAX_FILES` (100,000) of them
    # at ≤512 KB each. `EXCLUDED_DIRS` covers `node_modules` and `vendor`, so a
    # crafted tree simply puts them somewhere else.
    for record in manifests[:MAX_MANIFESTS_READ]:
        name = record.path.rsplit("/", 1)[-1]
        # Parsed, not grepped — so read it whole or not at all. See
        # `inventory.read_manifest`.
        text = read_manifest(root, record.path)
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
    for name, phrases in _LICENSE_FINGERPRINTS:
        if all(phrase in head for phrase in phrases):
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
        if relation == "operator-mismatch":
            return SubCheck(
                name, None,
                reason=(f"{facts.file_path} declares SPDX {facts.spdx_in_file!r} "
                        f"and {facts.manifest_path} declares "
                        f"{facts.spdx_in_manifest!r} — the same licences combined "
                        "by a different operator, so one offers a choice where "
                        "the other requires both. `03` §7 assigns no band to "
                        "that discrepancy and this build will not invent one."),
            )
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
