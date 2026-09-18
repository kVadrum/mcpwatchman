"""Sub-check-weighted axis scoring (`03` §4, §5, §7) and the ladder primitive.

Three of the five axes are scored by weighting named sub-checks rather than by
deducting for findings: Auth Posture, Maintenance, Transparency. This module is
their scorer. `composite.axis_score` is the deduction-scored axes' (`03` §3, §6);
the two are not interchangeable and neither one's input type fits the other.

**The load-bearing decision here is what an UNASSESSED sub-check means**, and it
is not a scoring question — it is the difference between "this server is bad"
and "we did not look". Both of the obvious answers are wrong in a way that
reaches a public page:

- Scoring an unknown as **0** publishes an accusation we did not measure. A
  remote-only server ships no source, so `secret_handling` cannot be evaluated;
  scored as 0 that is a 20% haircut on Auth Posture for the crime of not handing
  us a repository.
- Scoring it as **100** hides risk behind a number that looks assessed.

So an unassessed sub-check is **excluded from the weighting and its weight is
renormalised away**, and the axis carries `assessed_weight` saying how much of
itself was actually measured. The score then means what it says: *of what we
could assess, this is the result.*

⚠ **Renormalising silently would be its own defect** — an axis measured on 25%
of its weight renders identically to one measured on 100%. That is why
`assessed_weight` is a field on the result rather than a local variable, and why
`score` is `None` rather than 0 when nothing could be assessed. A surface that
prints the score without the coverage is publishing a number it cannot support;
`06` owns that rendering and this module owns making it impossible to do by
accident.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import KW_ONLY, dataclass
from decimal import Decimal

from mcpwatchman.workers.scoring.composite import AXIS_MAX, dec, round_half_up
from mcpwatchman.workers.scoring.weights import (
    CURRENT_METHODOLOGY_VERSION,
    subcheck_weights_for,
)


@dataclass(frozen=True, slots=True)
class SubCheck:
    """One sub-check's result, with the evidence that produced it.

    `score` is `None` when the sub-check could not be evaluated — which is a
    first-class outcome here, not an error. `reason` is then required: "not
    assessed" with no reason is the shape that reaches a page as a mystery gap,
    and `03` §10 commits us to evidence for every point.
    """

    name: str
    score: int | None
    reason: str = ""
    # Paths (relative to the scan root) or URLs backing the score. `03` §10:
    # every point subtracted traces to an artifact.
    evidence: tuple[str, ...] = ()
    # ⚠ KEYWORD-ONLY, for the reason `runner.AxisScore` is: this class is built
    # positionally at 67 sites, so a field inserted ahead of `evidence` would
    # silently capture an evidence tuple.
    _: KW_ONLY
    # WHOSE gap this abstention is, when `score is None` — a `reachability.Fault`
    # value, carried as a plain string so the scoring layer keeps its
    # independence from the scanner layer (nothing else here imports it).
    #
    # ⚠ THIS EXISTS BECAUSE AN AXIS-LEVEL ATTRIBUTION CANNOT SEE INSIDE A SCORED
    # AXIS. `score_axis` renormalises an abstention away, so an axis whose
    # sub-check failed for reasons of OURS still publishes a number, and
    # `cohort.unpublishable_gaps` — which only examines axes where `score is
    # None` — never looks at it. Measured: with `detect-secrets` timing out,
    # Auth Posture went 85 -> 80 at coverage 0.85 -> 0.65, publication reported
    # ZERO gaps, and the page carried *"`detect-secrets` was not available to
    # this worker"* as a fact about a third party.
    #
    # Empty means "no separate claim": the abstention is already explained by
    # the axis-level fault, which is the common case (no source was fetched, so
    # every sub-check needing source abstains for the publisher's reason).
    # Attribute explicitly wherever a sub-check can abstain because OUR tooling
    # did not run — that is the case the axis-level fault structurally cannot
    # represent.
    fault: str = ""

    def __post_init__(self) -> None:
        if self.score is None:
            if not self.reason:
                raise ValueError(
                    f"sub-check {self.name!r} is unassessed and must say why"
                )
        elif not 0 <= self.score <= AXIS_MAX:
            raise ValueError(
                f"sub-check {self.name!r} score {self.score} outside 0..{AXIS_MAX}"
            )


@dataclass(frozen=True, slots=True)
class AxisResult:
    """A sub-check-scored axis.

    `score` is `None` exactly when `assessed_weight` is 0 — no sub-check could be
    evaluated, so there is no axis score, as distinct from a bad one.
    """

    axis: str
    score: int | None
    # Share of the axis's total sub-check weight that was actually evaluated,
    # as an exact fraction of 1. A surface rendering `score` owes the reader
    # this number whenever it is below 1.
    assessed_weight: Decimal
    subchecks: tuple[SubCheck, ...] = ()
    methodology_version: str = CURRENT_METHODOLOGY_VERSION

    @property
    def fully_assessed(self) -> bool:
        return self.assessed_weight == 1

    @property
    def unassessed(self) -> tuple[SubCheck, ...]:
        """The sub-checks that could not be evaluated, each carrying its reason."""
        return tuple(s for s in self.subchecks if s.score is None)


def score_axis(
    axis: str,
    subchecks: Iterable[SubCheck],
    version: str = CURRENT_METHODOLOGY_VERSION,
) -> AxisResult:
    """Weight one axis's sub-checks into a 0-100 score (`03` §4, §5, §7).

    Every sub-check the methodology version declares for this axis must be
    present. **Absence raises; it is not treated as unassessed** — an omitted
    sub-check and an unassessable one are different facts, and collapsing them
    means a detector that forgets to emit one silently renormalises it away with
    no reason recorded anywhere. Say "I could not assess this, because X" by
    passing `SubCheck(name, None, reason=...)`, which is cheap and leaves a
    trail. The same discipline as `composite_score`'s missing-axis check.
    """
    weights = subcheck_weights_for(axis, version)
    # Materialise once: `subchecks` may be a generator, and a second pass over a
    # consumed one silently sees nothing — which would make the duplicate check
    # below always pass and the missing check below fire on everything.
    given = tuple(subchecks)
    supplied = {s.name: s for s in given}

    if len(supplied) != len(given):
        duplicated = sorted({s.name for s in given if sum(o.name == s.name for o in given) > 1})
        raise ValueError(
            f"axis {axis!r} got duplicate sub-check(s): {', '.join(duplicated)} — "
            "the later one would silently win"
        )

    missing = sorted(set(weights) - set(supplied))
    if missing:
        raise ValueError(
            f"axis {axis!r} at {version} is missing sub-check(s): "
            f"{', '.join(missing)} — pass SubCheck(name, None, reason=...) for "
            "anything that could not be assessed"
        )
    unknown = sorted(set(supplied) - set(weights))
    if unknown:
        raise ValueError(
            f"axis {axis!r} at {version} has no such sub-check(s): "
            f"{', '.join(unknown)}; declared: {', '.join(sorted(weights))}"
        )

    assessed = Decimal(0)
    weighted = Decimal(0)
    for name, weight in weights.items():
        result = supplied[name]
        if result.score is None:
            continue
        assessed += dec(weight)
        weighted += dec(weight) * dec(result.score)

    # Ordered by the methodology's own declaration order, not the caller's, so
    # two scans of the same server always render their sub-checks the same way.
    ordered = tuple(supplied[name] for name in weights)

    if assessed == 0:
        return AxisResult(
            axis=axis,
            score=None,
            assessed_weight=Decimal(0),
            subchecks=ordered,
            methodology_version=version,
        )

    # Renormalise over what was assessed. Dividing by `assessed` rather than by
    # the declared total is what makes the score mean "of what we could measure"
    # — without it, an axis with one unassessable sub-check could never exceed
    # its assessed share, so a server doing everything right but shipping no
    # source would read as an 80 rather than a 100-on-80%-of-the-axis.
    return AxisResult(
        axis=axis,
        score=round_half_up(weighted / assessed),
        assessed_weight=assessed,
        subchecks=ordered,
        methodology_version=version,
    )


def ladder(value: float | int | None, rungs: Sequence[tuple[float, int]], floor: int = 0) -> int:
    """Score a smaller-is-better measurement against `03`'s threshold ladders.

    `03` §5 states its sub-checks as "100 — within 30 days; 80 — within 90 days;
    …", and hand-rolling that comparison chain per sub-check is how an off-by-one
    on a boundary gets into one ladder and not its neighbours. **Boundaries are
    inclusive** ("within 30 days" includes day 30), matching the prose.

    `rungs` must be ascending by threshold; `floor` is the score for a value past
    the last rung. A `None` value means unmeasurable and is the caller's problem
    — it raises here, because a ladder silently answering `floor` for missing
    data is the score-the-unknown-as-zero mistake this module exists to prevent.
    """
    if value is None:
        raise ValueError(
            "ladder() cannot score a missing value; emit "
            "SubCheck(name, None, reason=...) instead"
        )
    thresholds = [t for t, _ in rungs]
    if thresholds != sorted(thresholds):
        raise ValueError(f"ladder rungs must ascend by threshold: {thresholds}")
    for threshold, score in rungs:
        if value <= threshold:
            return score
    return floor
