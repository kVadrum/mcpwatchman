# The calibration gold set

A **hand audit** of about thirty MCP servers at pinned versions: what a security engineer expects each axis to score and why, and a true- or false-positive label on every finding the scanner reported.
It is the ground truth `03-scoring-methodology.md` §9 calibrates against, and it is what licenses the two things the methodology withholds until then:

- a rule claiming **`high` confidence** — `03` §3 defines the tiers as false-positive rates *measured here* (under 5% for `high`, under 20% for `medium`);
- a published **composite** — `03` §8 keeps it computed and withheld until the weights are validated here.

## Where things live

| path | tracked | what |
|---|---|---|
| `evals/gold-set/<slug>.md` | yes | **ratified** entries only — a human has reviewed the audit and cleared it for disclosure |
| `evals/gold-set/drafts/<slug>.md` | no | drafts, including agent-drafted ones; never counted |
| `evals/gold-set/private/<slug>.md` | no | Track B candidates — see *Disclosure* |
| `evals/gold-set/CHANGELOG.md` | yes | every change to an expected range, with its reason (`03` §9) |

The format is TOML front matter between `+++` lines followed by free-form notes; `src/mcpwatchman/goldset.py` is canonical for it and refuses an entry that is not an audit (an axis with no expectation, a label with no reason, a ratification with no name).

## Drafting is not auditing

Anyone may draft an entry, an agent included, and a draft is useful: it proposes expectations and labels a human can check far faster than they could produce them.
It is not a hand audit until a human ratifies it — sets `status = "ratified"`, `ratified_by` and `ratified_on`, and moves the file out of `drafts/`.
Only ratified entries count towards calibration, and `tests/test_gold_set.py` refuses `RULESET_CALIBRATED` or `COMPOSITE_PUBLISHED` being set while fewer than 25 are ratified.

A reviewer ratifying an entry is checking three things: the expected ranges follow from `03`'s rubric and the code rather than from the scanner's output; every label's reason holds up against the cited line; and nothing in the entry is a Track B finding.

## Disclosure

An audit reads code more closely than the scanner does, so it will sometimes find a real flaw the scanner missed.
That is **Track B** under `08-disclosure-policy.md` §3 — manual review finding what automated tools did not — and it is owed maintainer contact and an embargo before it is public.
A committed entry is public, so such a finding goes in `private/<slug>.md`, never in the entry.
The entry may say that the audit found an issue the scanner does not detect, and in which *class*; it does not say where or how until the embargo has run.

## Running calibration

```sh
PATH=.venv-workers/bin:$PATH .venv/bin/python ops/calibrate.py                   # ratified entries
PATH=.venv-workers/bin:$PATH .venv/bin/python ops/calibrate.py --include-drafts  # while iterating
```

It scans every entry at its pinned version, reports drift against the expected ranges (`09` §5: ±8 per axis, ±5 composite), and prints each rule's measured tier from the labels.
It flips nothing.
Declaring calibration is a deliberate edit to `weights.py`, made when the report says it may be declared and reviewed like any methodology change (`03` §11).
It is a scan, so never run it beside another scan or the test suite.

## Composition

`03` §9 asks for a spread across categories (filesystem, browser, database, communication, productivity, niche tools) and across expected scores — about three known-excellent, three known-bad, and the rest in between.
A rule's tier cannot be measured from fewer than ten labelled findings, so the set also deliberately covers the rules that fire most.
