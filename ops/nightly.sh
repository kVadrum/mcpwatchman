#!/usr/bin/env bash
# mcpwatchman nightly rescan — `10-operations.md` §2's poseidon batch.
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
# Exit status: 0 published (or committed, when not publishing); non-zero means
# nothing was deployed. scan_cohort.py's own codes pass through — 2 a refused
# page set, 3 a systemic our-side failure — and 10+ are this wrapper's.

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
# an exhausted token writes our outage onto every page and exits 0.
PYTHONPATH="$MAIN/src" "$PY" -c 'from mcpwatchman.cohort import systemic_staleness' 2>/dev/null \
  || { log "SKIPPED: origin/main (${MAIN_SHA:0:9}) predates cohort.systemic_staleness — waiting for a sync"; exit 11; }

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

log "committing the data to dev"
git -C "$REPO" worktree add -q --detach "$WORK/dev" "$DEV_SHA"
cp "$MAIN/site/src/data/scans.json" "$WORK/dev/site/src/data/scans.json"
(
  cd "$WORK/dev"
  if git diff --quiet; then
    log "data unchanged — nothing to commit"
    exit 0
  fi
  summary="$(PYTHONPATH="$MAIN/src" "$PY" - <<'EOF'
import json
rows = json.load(open("site/src/data/scans.json"))
states = [r.get("registry_state") for r in rows]
print(f"{len(rows)} servers, {states.count('stale')} kept an older scan")
EOF
)"
  # Data only: no version bump. The version names the software, and the
  # software did not change — each record carries its own scanner_version and
  # scanned_at. `bump-audit.sh` lists these at sync; that is the review.
  git add site/src/data/scans.json
  git commit -q -m "data — nightly rescan ${STAMP}: ${summary}" \
    -m "Scanned with main at ${MAIN_SHA:0:9}. Code from main, data from dev (ops/nightly.sh)."
  for attempt in 1 2; do
    git push -q origin HEAD:dev && exit 0
    # dev moved during the run. Rebase only if nobody else touched the data:
    # two writers of the published record is a conflict to surface, not merge.
    git fetch -q origin dev
    if ! git diff --quiet "$DEV_SHA" origin/dev -- site/src/data/scans.json ops/cohort.json; then
      log "dev's data changed during the run — not overwriting it"
      exit 14
    fi
    git rebase -q origin/dev
  done
  exit 15
) || die $? "could not commit the data to dev"

if [[ "$PUBLISH" != "1" ]]; then
  log "committed to dev; MCPW_PUBLISH is not 1, so not deployed (the next sync publishes it)"
  exit 0
fi

log "deploying"
( cd "$MAIN/site" && npx --yes "$WRANGLER" deploy ) || die 16 "wrangler deploy failed"
log "published"
