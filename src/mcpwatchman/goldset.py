"""The calibration gold set (`03` §9, `09` §5): format, loading, and comparison.

A gold-set entry is a HAND AUDIT of one server at a pinned version: what a
security engineer expects each axis to score and why, and a true/false-positive
label on every finding the scanner reported. Calibration is the scanner being
checked against those expectations — and it is what licenses the two things the
methodology withholds until then: a rule claiming `high` confidence (`03` §3
defines the tiers as measured false-positive rates on this set) and a published
composite (`03` §8).

⚠ **`status` is the load-bearing field.** An entry can be DRAFTED by anyone —
including an agent — but only a human's ratification makes it a hand audit, and
only ratified entries count towards calibration (`ratified_entries`). Drafts
live in the gitignored `drafts/` directory; a flaw an audit finds that the
scanner missed is Track B under `08-disclosure-policy.md` §3 and goes to the
gitignored `private/` directory, never into an entry, because a committed entry
is public before the embargo that finding is owed.

Stdlib only (`tomllib`), so the CI job without the workers extra can gate it.

File shape — TOML front matter between `+++` lines, then free-form notes:

    +++
    name = "io.github.owner/server"
    version = "1.2.3"
    category = "filesystem"
    status = "draft"                 # or "ratified"
    audited_by = "..."
    audited_on = "2026-09-29"
    ratified_by = ""
    ratified_on = ""

    [expected]
    composite = [70, 80]             # or "unassessed"

    [expected.axes]
    code_safety = [85, 100]          # an inclusive range, or "unassessed"
    ...

    [[findings]]
    rule = "mcp-js-ssrf-nonliteral-url"
    path = "src/fetch.ts"
    line = 33
    label = "fp"                     # "tp" or "fp"
    why = "the URL is a constant after validation on line 30"
    +++
    ## Notes
    ...
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

AXES = ("code_safety", "auth_posture", "dependency_health", "maintenance", "transparency")
UNASSESSED = "unassessed"
STATUSES = frozenset({"draft", "ratified"})
LABELS = frozenset({"tp", "fp"})

# `09` §5: drift tolerances.
COMPOSITE_TOLERANCE = 5
AXIS_TOLERANCE = 8

# `03` §3: the confidence tiers ARE these measured rates.
HIGH_MAX_FP_RATE = 0.05
MEDIUM_MAX_FP_RATE = 0.20
# A rate over a handful of labels is not a measurement. Below this many labelled
# findings a rule's tier is reported as unmeasured rather than as a rate.
MIN_LABELS_PER_RULE = 10

# `03` §9: "approximately 30"; calibration may not be declared on fewer than
# this many ratified entries.
MIN_RATIFIED_ENTRIES = 25

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "evals" / "gold-set"


class GoldSetError(ValueError):
    """An entry that cannot be read as a hand audit."""


@dataclass(frozen=True, slots=True)
class Label:
    rule: str
    path: str
    line: int
    label: str
    why: str


@dataclass(frozen=True, slots=True)
class GoldEntry:
    name: str
    version: str
    category: str
    status: str
    audited_by: str
    audited_on: str
    ratified_by: str
    ratified_on: str
    expected_composite: tuple[int, int] | None
    expected_axes: dict[str, tuple[int, int] | None]
    findings: tuple[Label, ...] = ()
    path: Path | None = field(default=None, compare=False)

    @property
    def ratified(self) -> bool:
        return self.status == "ratified" and bool(self.ratified_by) and bool(self.ratified_on)


def _range(value: Any, where: str) -> tuple[int, int] | None:
    if value == UNASSESSED:
        return None
    if (
        isinstance(value, list) and len(value) == 2
        and all(isinstance(v, int) and not isinstance(v, bool) for v in value)
        and 0 <= value[0] <= value[1] <= 100
    ):
        return (value[0], value[1])
    raise GoldSetError(
        f"{where}: expected [low, high] within 0..100 or {UNASSESSED!r}, got {value!r}"
    )


def _iso_date(value: Any, where: str, *, required: bool) -> str:
    if isinstance(value, date):
        return value.isoformat()
    if value in ("", None) and not required:
        return ""
    try:
        return date.fromisoformat(str(value)).isoformat()
    except ValueError as exc:
        raise GoldSetError(f"{where}: not an ISO date: {value!r}") from exc


def parse(text: str, *, source: str = "<entry>") -> GoldEntry:
    """One entry from its file text. Raises `GoldSetError` on anything unreadable."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "+++":
        raise GoldSetError(f"{source}: must open with a '+++' TOML front-matter line")
    try:
        end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "+++")
    except StopIteration as exc:
        raise GoldSetError(f"{source}: front matter is not closed with '+++'") from exc
    try:
        data = tomllib.loads("\n".join(lines[1:end]))
    except tomllib.TOMLDecodeError as exc:
        raise GoldSetError(f"{source}: front matter is not TOML: {exc}") from exc

    for key in ("name", "version", "category", "status", "audited_by"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise GoldSetError(f"{source}: `{key}` is required")
    if data["status"] not in STATUSES:
        raise GoldSetError(f"{source}: status must be one of {sorted(STATUSES)}")

    expected = data.get("expected") or {}
    axes_raw = expected.get("axes") or {}
    unknown = sorted(set(axes_raw) - set(AXES))
    missing = sorted(set(AXES) - set(axes_raw))
    if unknown or missing:
        raise GoldSetError(
            f"{source}: expected.axes must name exactly the five axes "
            f"(missing {missing}, unknown {unknown}) — an omitted axis is not an expectation"
        )
    axes = {k: _range(axes_raw[k], f"{source}: expected.axes.{k}") for k in AXES}
    composite = _range(expected.get("composite", UNASSESSED), f"{source}: expected.composite")
    if composite is not None and any(v is None for v in axes.values()):
        raise GoldSetError(
            f"{source}: a composite is expected while an axis is expected unassessed — "
            "the composite needs all five"
        )

    labels = []
    for i, raw in enumerate(data.get("findings") or []):
        where = f"{source}: findings[{i}]"
        if raw.get("label") not in LABELS:
            raise GoldSetError(f"{where}: label must be 'tp' or 'fp'")
        if not str(raw.get("why", "")).strip():
            raise GoldSetError(f"{where}: an unexplained label is not an audit — `why` is required")
        if not isinstance(raw.get("line"), int) or not raw.get("rule") or not raw.get("path"):
            raise GoldSetError(f"{where}: `rule`, `path` and integer `line` are required")
        labels.append(Label(raw["rule"], raw["path"], raw["line"], raw["label"], raw["why"]))

    status = data["status"]
    ratified_by = str(data.get("ratified_by", "")).strip()
    ratified_on = _iso_date(data.get("ratified_on"), f"{source}: ratified_on", required=False)
    if status == "ratified" and not (ratified_by and ratified_on):
        raise GoldSetError(f"{source}: a ratified entry names who ratified it and when")

    return GoldEntry(
        name=data["name"],
        version=data["version"],
        category=data["category"],
        status=status,
        audited_by=data["audited_by"],
        audited_on=_iso_date(data.get("audited_on"), f"{source}: audited_on", required=True),
        ratified_by=ratified_by,
        ratified_on=ratified_on,
        expected_composite=composite,
        expected_axes=axes,
        findings=tuple(labels),
    )


def load(path: Path) -> GoldEntry:
    return replace(parse(path.read_text(encoding="utf-8"), source=path.name), path=path)


def entry_files(root: Path = DEFAULT_ROOT, *, include_drafts: bool = False) -> list[Path]:
    """Entry files: the tracked directory, plus `drafts/` when asked. Never `private/`."""
    files = sorted(p for p in root.glob("*.md") if p.name not in ("README.md", "CHANGELOG.md"))
    if include_drafts:
        files += sorted((root / "drafts").glob("*.md"))
    return files


def ratified_entries(root: Path = DEFAULT_ROOT) -> list[GoldEntry]:
    """What calibration may count. Drafts never do — see the module docstring."""
    return [e for e in (load(p) for p in entry_files(root)) if e.ratified]


def compare(entry: GoldEntry, report: Mapping[str, Any], composite: int | None) -> list[str]:
    """Every way `report` drifts from the entry's expectations (`09` §5 tolerances)."""
    drift = []
    for axis in AXES:
        want = entry.expected_axes[axis]
        got = report["axes"][axis]["score"]
        if want is None:
            if got is not None:
                drift.append(f"{axis}: expected unassessed, scored {got}")
            continue
        if got is None:
            drift.append(f"{axis}: expected {want[0]}–{want[1]}, unassessed")
        elif not want[0] - AXIS_TOLERANCE <= got <= want[1] + AXIS_TOLERANCE:
            drift.append(f"{axis}: expected {want[0]}–{want[1]} (±{AXIS_TOLERANCE}), scored {got}")
    want_c = entry.expected_composite
    if want_c is not None:
        if composite is None:
            drift.append(f"composite: expected {want_c[0]}–{want_c[1]}, not computable")
        elif not want_c[0] - COMPOSITE_TOLERANCE <= composite <= want_c[1] + COMPOSITE_TOLERANCE:
            drift.append(
                f"composite: expected {want_c[0]}–{want_c[1]} (±{COMPOSITE_TOLERANCE}), "
                f"computed {composite}"
            )
    return drift


def fp_rates(entries: Iterable[GoldEntry]) -> dict[str, tuple[int, int]]:
    """Per rule: (false positives, labelled findings), across every entry given."""
    counts: dict[str, list[int]] = {}
    for entry in entries:
        for f in entry.findings:
            fp_total = counts.setdefault(f.rule, [0, 0])
            fp_total[1] += 1
            if f.label == "fp":
                fp_total[0] += 1
    return {rule: (fp, total) for rule, (fp, total) in counts.items()}


def measured_tier(fp: int, total: int) -> str:
    """The confidence tier a rule's labels support: `high`, `medium`, `low`, or
    `unmeasured` when there are too few labels for a rate to mean anything."""
    if total < MIN_LABELS_PER_RULE:
        return "unmeasured"
    rate = fp / total
    if rate < HIGH_MAX_FP_RATE:
        return "high"
    if rate < MEDIUM_MAX_FP_RATE:
        return "medium"
    return "low"


__all__ = [
    "AXES",
    "AXIS_TOLERANCE",
    "COMPOSITE_TOLERANCE",
    "DEFAULT_ROOT",
    "GoldEntry",
    "GoldSetError",
    "Label",
    "MIN_RATIFIED_ENTRIES",
    "compare",
    "entry_files",
    "fp_rates",
    "load",
    "measured_tier",
    "parse",
    "ratified_entries",
]
