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
# The deploy runs the wrangler that `npm ci` installed from site/package-lock.json,
# where every transitive dependency is pinned with an integrity hash: `npx
# wrangler@X` pins only the top package and resolves the rest fresh on a cold
# cache, inside the process holding the Cloudflare login. The npx form remains
# only for a `main` whose lockfile predates wrangler, and is pinned to the
# version the lockfile now carries.
WRANGLER="wrangler@4.149.0"

log() { printf '[nightly %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FAILED: $2"; exit "$1"; }

# Every stage that runs code we did not write — the scanner's tools over
# attacker-controlled repositories, npm's dependencies in the build, wrangler,
# and the gates over the data they produced — starts from an EMPTY environment
# plus what it names: an allowlist, for the reason `bounded.py` gives for the
# scanner's own children. The denylist it replaces removed the tokens and the
# bus address and passed everything else, which here was SSH_AUTH_SOCK,
# GPG_AGENT_INFO, DISPLAY, XAUTHORITY, WAYLAND_DISPLAY and XDG_RUNTIME_DIR —
# where libdbus finds the session bus, and so the keyring holding the `gh`
# login, with its address unset. Removing a variable deters rather than
# confines (the unit says why); what is kept is what the stages were measured
# to need, HOME above all: npm's cache and wrangler's login live there.
STAGE_ENV=" PATH HOME USER LOGNAME LANG LANGUAGE TZ TMPDIR XDG_CONFIG_HOME XDG_CACHE_HOME \
XDG_DATA_HOME SSL_CERT_FILE SSL_CERT_DIR HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY \
http_proxy https_proxy no_proxy all_proxy "

# stage [NAME...] -- COMMAND...: run COMMAND with STAGE_ENV, the LC_* locale and
# the variables NAMEd. Names, never values: a value on a command line is
# readable in /proc by every process of this user, so a credential reaches the
# one stage that uses it by being named here, and only non-secret settings ride
# on `env VAR=value` inside COMMAND.
stage() {
  local keep="$STAGE_ENV" name
  while (($#)) && [[ $1 != -- ]]; do keep+="$1 "; shift; done
  shift
  (
    for name in $(compgen -e); do
      [[ $keep == *" $name "* || $name == LC_* ]] || unset "$name" 2>/dev/null || true
    done
    exec "$@"
  )
}
GITHUB_CREDENTIAL=(MCPWATCHMAN_GITHUB_TOKEN GITHUB_TOKEN)
DEPLOY_CREDENTIAL=(CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID)

# Where the scan unpacks third-party trees: TMPDIR, which every mkdtemp in the
# scanner and every scanner binary honours. Not /tmp — on this box a tmpfs, so
# a hostile tree is written into RAM on a machine with no memory cap — and not
# $WORK, under ~/dev, whose ZFS snapshots would keep attacker-supplied files
# for months. /var/tmp is disk, unsnapshotted, and swept by systemd-tmpfiles.
SCAN_TMP="${MCPW_SCAN_TMP:-/var/tmp/mcpwatchman-$(id -u)}"

# The data push. With MCPW_DEPLOY_KEY (a write deploy key for this repository
# alone) it goes over SSH with that key; without it, through the operator's git
# credential helper — whatever `gh` holds, which is every repository they can
# write. Only the deploy key lets a tag ruleset stop this process creating a
# release tag, because a deploy key is not the operator.
push_dev() {
  if [[ -z "${MCPW_DEPLOY_KEY:-}" ]]; then
    git push -q origin HEAD:dev
    return
  fi
  local url
  url="$(git remote get-url origin)"
  [[ "$url" == https://github.com/* ]] \
    || { log "MCPW_DEPLOY_KEY is set but origin is not a github.com https URL: $url"; return 21; }
  # GitHub's published host keys, pinned in the repo: BatchMode cannot answer a
  # first-use prompt, and trusting whatever answers on first use is the thing
  # a pinned key exists to avoid.
  GIT_SSH_COMMAND="ssh -i $(printf '%q' "$MCPW_DEPLOY_KEY") -o IdentitiesOnly=yes -o BatchMode=yes \
-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$(printf '%q' "$REPO/ops/github_known_hosts")" \
    git push -q "git@github.com:${url#https://github.com/}" HEAD:dev
}

cleanup() {
  git -C "$REPO" worktree remove --force "$WORK/main" 2>/dev/null || true
  git -C "$REPO" worktree remove --force "$WORK/dev" 2>/dev/null || true
  git -C "$REPO" worktree prune
  rm -rf "$WORK"
  # A scan killed mid-fetch (the unit's timeout) leaves its workspace behind.
  # Ours alone: the directory is checked to be our own, and the lock is held.
  [[ -n "${SCAN_TMP_OK:-}" ]] && rm -rf "$SCAN_TMP"/mcpw-scan-* 2>/dev/null
  true
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

# /var/tmp is world-writable, so the directory must be ours and not a link
# planted by someone else. If it is not, the scan keeps the default TMPDIR —
# the old behaviour, which survives — and says so.
mkdir -p -m 700 "$SCAN_TMP" 2>/dev/null || true
if [[ -d "$SCAN_TMP" && ! -L "$SCAN_TMP" && -O "$SCAN_TMP" ]] && chmod 700 "$SCAN_TMP"; then
  SCAN_TMP_OK=1
  SCAN_ENV=(TMPDIR="$SCAN_TMP")
else
  log "scan scratch $SCAN_TMP is not a directory we own: scanning under the default TMPDIR"
  SCAN_ENV=()
fi

# The token is read from the environment (the unit's EnvironmentFile), else from
# the operator's `gh` login — into the environment only, never argv, never
# printed. Without one every server takes an our-side gap on Maintenance.
if [[ -z "${MCPWATCHMAN_GITHUB_TOKEN:-}" && -z "${GITHUB_TOKEN:-}" ]]; then
  log "no MCPWATCHMAN_GITHUB_TOKEN in the environment: using the operator's gh login, far broader than the public-read token this run needs"
  MCPWATCHMAN_GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
  export MCPWATCHMAN_GITHUB_TOKEN
fi

log "fetching origin/main and origin/dev"
git -C "$REPO" fetch -q origin main dev
MAIN_SHA="$(git -C "$REPO" rev-parse origin/main)"
DEV_SHA="$(git -C "$REPO" rev-parse origin/dev)"
git -C "$REPO" worktree add -q --detach "$WORK/main" "$MAIN_SHA"
MAIN="$WORK/main"

# Without the systemic-staleness guard an exhausted token writes our outage onto
# every page and exits 0, so a `main` without it is refused. This was once a
# quiet skip (exit 11, "waiting for a sync"), while `main` predated the guard;
# it has carried it since v0.33.0 and only moves forward, so its absence now
# means a moved or renamed guard, and a quiet success would hide that forever
# (base.md § Signal design).
git -C "$REPO" grep -q 'def systemic_staleness' "$MAIN_SHA" -- src/mcpwatchman/cohort.py \
  || die 23 "origin/main (${MAIN_SHA:0:9}) has no cohort.systemic_staleness — moved or renamed? Nothing was scanned"
# The environment itself, loudly: any failure here is a fault, never a skip.
PYTHONPATH="$MAIN/src" "$PY" -c 'import mcpwatchman.cohort, mcpwatchman.workers.scanner.runner' \
  || die 19 "main's code does not import under $PY — the venv needs rebuilding"

for f in site/src/data/scans.json ops/cohort.json; do
  git -C "$REPO" show "$DEV_SHA:$f" > "$MAIN/$f"
done
log "code at main ${MAIN_SHA:0:9}, data from dev ${DEV_SHA:0:9}"

log "scanning the pinned cohort"
# The scan's git never sees the operator's git config. That config carries a
# `gh` credential helper, and the scan clones URLs that third parties put in
# public registry entries — so a pinned publisher naming a private repository
# the operator can read had it cloned with the operator's login and its code,
# paths and dependencies published (measured 2026-10-19). Set HERE as well as
# in the scanner (bounded.GIT_ISOLATION, v0.38.4) because the scanner that runs
# is `main`'s, and this wrapper is live the moment it is saved. The data push
# below keeps the operator's config: it is ours, to our own repository.
SCAN_GIT=(GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0)
set +e
stage "${GITHUB_CREDENTIAL[@]}" -- env "${SCAN_ENV[@]}" "${SCAN_GIT[@]}" \
    PATH="$REPO/.venv-workers/bin:$PATH" PYTHONPATH="$MAIN/src" nice -n 10 \
  "$PY" "$MAIN/ops/scan_cohort.py" \
  --out "$MAIN/site/src/data/scans.json" --cohort "$MAIN/ops/cohort.json"
rc=$?
set -e
[[ $rc -eq 0 ]] || die "$rc" "scan_cohort.py exited $rc — nothing committed or deployed"

# Maintenance is read with whatever GitHub token this run holds — the
# operator's own login until a public-read token is configured — and main's
# scanner does not yet ask whether a repository is public. So before anything
# leaves the box, every repository scored tonight must answer anonymously
# (ops/visibility_gate.py). A row that does not is withheld — that server keeps
# its previous page, labelled — and the night goes on; only a refusal of the
# whole run, too many withheld at once, stops it here.
log "checking that every repository scored this run is publicly readable"
git -C "$REPO" show "$DEV_SHA:site/src/data/scans.json" > "$WORK/scans.before.json"
# It keeps the GitHub token: a repository the public cannot read is asked about
# with it, because "private" and "deleted" fail the same anonymous probe. Its
# report goes into the data commit, so what was withheld is on the record.
stage "${GITHUB_CREDENTIAL[@]}" -- env "${SCAN_GIT[@]}" "$PY" "$REPO/ops/visibility_gate.py" \
    --before "$WORK/scans.before.json" --after "$MAIN/site/src/data/scans.json" \
    | tee "$WORK/visibility.txt" \
  || die 22 "the visibility gate refused this run — nothing committed or deployed"

log "building the site"
( cd "$MAIN/site" && stage -- npm ci --no-audit --no-fund --loglevel=error \
    && stage -- npm run build --silent ) \
  || die 12 "site build failed"

# The same artifact gates CI runs, against the site about to be published.
log "running the publication gates"
( cd "$MAIN" && stage -- env PYTHONPATH="$MAIN/src" "$PY" -m pytest -q -p no:cacheprovider \
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
    -m "$(<"$WORK/visibility.txt")" \
    || exit 17
  [[ "$(git rev-parse HEAD)" != "$DEV_SHA" ]] || exit 17
  for attempt in 1 2; do
    push_dev && exit 0
    [[ $? -eq 21 ]] && exit 21  # misconfigured push credential: a fault, not a race
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
if [[ -x "$MAIN/site/node_modules/.bin/wrangler" ]]; then
  deploy=("$MAIN/site/node_modules/.bin/wrangler" deploy)
else
  log "main's site lockfile carries no wrangler: deploying with npx $WRANGLER (transitive dependencies unpinned)"
  deploy=(npx --yes "$WRANGLER" deploy)
fi
( cd "$MAIN/site" && stage "${DEPLOY_CREDENTIAL[@]}" -- env WRANGLER_SEND_METRICS=false "${deploy[@]}" ) \
  || die 16 "wrangler deploy failed"
log "published"
