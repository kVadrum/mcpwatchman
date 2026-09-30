#!/usr/bin/env bash
# mcpwatchman nightly rescan — the nightly batch `10-operations.md` §2 specifies.
#
# Rescans the pinned cohort, gates the result, commits the data to `dev`, and
# (only when MCPW_PUBLISH=1) deploys it. Run by ops/systemd/mcpwatchman-nightly.*;
# safe to run by hand.
#
# ⚠ CODE FROM `main`, DATA FROM `dev`. `main` is the human gate: an unreviewed
# scanner change on `dev` must not publish statements about third parties
# overnight, so the scanner, the site and the gates all run from a worktree at
# origin/main. The data files — the cohort and the last published scans — are
# the running record, and come from origin/dev, where every previous night's
# commit landed; reading them from `main` would drop pins that have not been
# synced yet and 404 pages already in the sitemap.
#
# ⚠ Never beside another scan or the test suite: concurrent load dominates the
# failure rate (`CLAUDE.md`). The lock below serialises nightly runs only; a
# manual scan started during one is on whoever started it.
#
# Exit status: 0 published — or, when not publishing, committed or nothing to
# commit. 11 a quiet skip: nothing committed or deployed because origin/main has
# not caught up with dev (the unit counts it a success). Any other non-zero
# means nothing was deployed: scan_cohort.py's own codes pass through — 2 a
# refused page set, 3 a systemic our-side failure — and 10+ are this wrapper's.

set -euo pipefail
umask 077

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y-%m-%d)"
WORK="$REPO/scratch/nightly/$STAMP-$$"
PY="$REPO/.venv/bin/python"
PUBLISH="${MCPW_PUBLISH:-0}"
# PINNED: the newest wrangler this box has deployed with (npx cache, 2026-09-29).
# The manual recipe is a bare `npx wrangler deploy`, which fetches whatever is
# latest — acceptable with a human watching, not in a timer. Run from site/, so
# its .npmrc (`ignore-scripts=true`) governs the install.
WRANGLER="wrangler@4.134.0"

log() { printf '[nightly %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FAILED: $2"; exit "$1"; }

cleanup() {
  git -C "$REPO" worktree remove --force "$WORK/main" 2>/dev/null || true
  git -C "$REPO" worktree remove --force "$WORK/dev" 2>/dev/null || true
  git -C "$REPO" worktree prune
  rm -rf "$WORK"
}

mkdir -p "$REPO/scratch/nightly"
exec 9>"$REPO/scratch/nightly/.lock"
flock -n 9 || die 10 "another nightly run holds the lock"
trap cleanup EXIT

# Node is installed through nvm, whose directory no systemd unit PATH carries —
# measured: under the unit's environment `npm` is not found, and the build step
# would have died after a 46-minute scan. Resolve it here, and check every tool
# the run needs BEFORE the scan, so a broken toolchain costs seconds.
if ! command -v npm >/dev/null 2>&1; then
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  if [[ -s "$NVM_DIR/nvm.sh" ]]; then
    set +u  # nvm.sh is not nounset-clean
    # shellcheck disable=SC1091
    . "$NVM_DIR/nvm.sh" && nvm use --silent default >/dev/null
    set -u
  fi
fi
for tool in git npm npx; do
  command -v "$tool" >/dev/null 2>&1 || die 18 "$tool is not on PATH — nothing was scanned"
done

# The token is read from the environment (the unit's EnvironmentFile), else from
# the operator's `gh` login — into the environment only, never argv, never
# printed. Without one every server takes an our-side gap on Maintenance.
if [[ -z "${MCPWATCHMAN_GITHUB_TOKEN:-}" && -z "${GITHUB_TOKEN:-}" ]]; then
  MCPWATCHMAN_GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
  export MCPWATCHMAN_GITHUB_TOKEN
fi

log "fetching origin/main and origin/dev"
git -C "$REPO" fetch -q origin main dev
MAIN_SHA="$(git -C "$REPO" rev-parse origin/main)"
DEV_SHA="$(git -C "$REPO" rev-parse origin/dev)"
git -C "$REPO" worktree add -q --detach "$WORK/main" "$MAIN_SHA"
MAIN="$WORK/main"

# Fail closed on a `main` that predates the systemic-staleness guard: without it
# an exhausted token writes our outage onto every page and exits 0. Asked of
# the COMMIT, not of an import — the import also fails on a broken venv, and
# exit 11 is a quiet success to the unit, so a broken environment would have
# read as "waiting for a sync" forever (base.md § Signal design).
git -C "$REPO" grep -q 'def systemic_staleness' "$MAIN_SHA" -- src/mcpwatchman/cohort.py \
  || { log "SKIPPED: origin/main (${MAIN_SHA:0:9}) predates cohort.systemic_staleness — waiting for a sync"; exit 11; }
# The environment itself, loudly: any failure here is a fault, never a skip.
PYTHONPATH="$MAIN/src" "$PY" -c 'import mcpwatchman.cohort, mcpwatchman.workers.scanner.runner' \
  || die 19 "main's code does not import under $PY — the venv needs rebuilding"

for f in site/src/data/scans.json ops/cohort.json; do
  git -C "$REPO" show "$DEV_SHA:$f" > "$MAIN/$f"
done
log "code at main ${MAIN_SHA:0:9}, data from dev ${DEV_SHA:0:9}"

log "scanning the pinned cohort"
set +e
PATH="$REPO/.venv-workers/bin:$PATH" PYTHONPATH="$MAIN/src" nice -n 10 \
  "$PY" "$MAIN/ops/scan_cohort.py" \
  --out "$MAIN/site/src/data/scans.json" --cohort "$MAIN/ops/cohort.json"
rc=$?
set -e
[[ $rc -eq 0 ]] || die "$rc" "scan_cohort.py exited $rc — nothing committed or deployed"

log "building the site"
( cd "$MAIN/site" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent ) \
  || die 12 "site build failed"

# The same artifact gates CI runs, against the site about to be published.
log "running the publication gates"
( cd "$MAIN" && PYTHONPATH="$MAIN/src" "$PY" -m pytest -q -p no:cacheprovider \
    tests/test_site_scans.py tests/test_site_example.py tests/test_cohort.py ) \
  || die 13 "publication gates failed on the new data"

# The scoring CONTRACT each ref publishes under: ruleset version (the first
# release heading of the rules changelog) and methodology version.
# Fails rather than printing an empty field: a parse that stopped matching (an
# annotation on the constant, a moved file) is not a version, and an empty one
# on one side reads as "the contracts differ" — a quiet skip every night.
contract() {
  local rules method
  rules=$(git -C "$REPO" show "$1:rules/_meta/changelog.md" | sed -n 's/^## \([0-9][0-9.]*\).*/\1/p' | head -1)
  method=$(git -C "$REPO" show "$1:src/mcpwatchman/workers/scoring/weights.py" \
    | sed -n 's/^CURRENT_METHODOLOGY_VERSION = "\(.*\)"/\1/p')
  [[ -n "$rules" && -n "$method" ]] || return 1
  printf 'ruleset %s, methodology %s' "$rules" "$method"
}
MAIN_CONTRACT="$(contract "$MAIN_SHA")" || die 20 "could not read main's scoring contract"
DEV_CONTRACT="$(contract "$DEV_SHA")" || die 20 "could not read dev's scoring contract"

# committed | unchanged | contract — what happened to the data, so every log
# line below reports what was DONE rather than what was attempted.
DATA=contract
if [[ "$MAIN_CONTRACT" != "$DEV_CONTRACT" ]]; then
  # dev moved to a newer ruleset or methodology and has not been synced. Its
  # contract gate requires every row to carry dev's versions, so committing
  # main-scored data would turn dev's CI red and overwrite data dev already
  # regenerated under the newer contract. Publish main's consistent pair;
  # leave dev's data alone until the sync brings the contracts back together.
  log "NOT committing to dev: main scores under $MAIN_CONTRACT, dev under $DEV_CONTRACT"
else
log "committing the data to dev"
git -C "$REPO" worktree add -q --detach "$WORK/dev" "$DEV_SHA"
cp "$MAIN/site/src/data/scans.json" "$WORK/dev/site/src/data/scans.json"
# The subshell reports its outcome by exit code: 0 committed, 30 nothing to
# commit, 31 dev's contract moved during the run; anything else is a fault.
rc=0
(
  cd "$WORK/dev"
  if git diff --quiet; then
    log "data unchanged — nothing to commit"
    exit 30
  fi
  summary="$(PYTHONPATH="$MAIN/src" "$PY" - <<'EOF'
import json
rows = json.load(open("site/src/data/scans.json"))
states = [r.get("registry_state") for r in rows]
print(f"{len(rows)} servers, {states.count('stale')} kept an older scan")
EOF
)" || exit 17
  # Data only: no version bump. The version names the software, and the
  # software did not change — each record carries its own scanner_version and
  # scanned_at. `bump-audit.sh` lists these at sync; that is the review.
  # ⚠ EVERY STEP IS CHECKED BY HAND. This subshell sits on the left of `||`,
  # and there bash IGNORES `set -e` for everything inside it — measured. A
  # rejected commit (the pre-commit telemetry guard, say) left HEAD at the
  # detached $DEV_SHA, the push then answered "Everything up-to-date" with
  # exit 0, and the run logged "committed" and went on to deploy.
  git add site/src/data/scans.json || exit 17
  git commit -q -m "data — nightly rescan ${STAMP}: ${summary}" \
    -m "Scanned with main at ${MAIN_SHA:0:9}. Code from main, data from dev (ops/nightly.sh)." \
    || exit 17
  [[ "$(git rev-parse HEAD)" != "$DEV_SHA" ]] || exit 17
  for attempt in 1 2; do
    git push -q origin HEAD:dev && exit 0
    # dev moved during the run. Rebase only if nobody else touched the data:
    # two writers of the published record is a conflict to surface, not merge.
    git fetch -q origin dev || exit 15
    if ! git diff --quiet "$DEV_SHA" origin/dev -- site/src/data/scans.json ops/cohort.json; then
      log "dev's data changed during the run — not overwriting it"
      exit 14
    fi
    # The contract was compared against the dev we STARTED from. A ruleset or
    # methodology change landing mid-run would otherwise be rebased over and
    # pushed under — main-scored rows in a dev whose gates reject them (Codex
    # leg, 2026-09-29). It is the same ordinary between-syncs state the check
    # above handles quietly, so it ends the same way, not as a fault.
    moved="$(contract origin/dev)" || { log "could not read dev's scoring contract"; exit 20; }
    if [[ "$moved" != "$MAIN_CONTRACT" ]]; then
      log "dev's scoring contract changed during the run — not committing"
      exit 31
    fi
    git rebase -q origin/dev || { git rebase --abort; exit 15; }
  done
  exit 15
) || rc=$?
case "$rc" in
  0)  DATA=committed ;;
  30) DATA=unchanged ;;
  31) DATA=contract ;;
  *)  die "$rc" "could not commit the data to dev" ;;
esac
fi

if [[ "$PUBLISH" != "1" ]]; then
  case "$DATA" in
    committed)
      log "committed to dev; MCPW_PUBLISH is not 1, so not deployed (the next sync publishes it)"
      exit 0 ;;
    unchanged)
      log "nothing to commit; MCPW_PUBLISH is not 1, so not deployed"
      exit 0 ;;
  esac
  # Neither committed nor deployed. The contract mismatch behind it is the
  # ordinary between-syncs state, so this is the same quiet "waiting for a
  # sync" as a main without the guard — never a success that claims a commit.
  log "SKIPPED: nothing committed or deployed — the contracts differ until the next sync"
  exit 11
fi

log "deploying"
( cd "$MAIN/site" && npx --yes "$WRANGLER" deploy ) || die 16 "wrangler deploy failed"
log "published"
