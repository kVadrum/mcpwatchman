"""`ops/nightly.sh`, run for real against a throwaway origin.

The nightly is a gate whose failure mode is reporting success while doing
nothing, so each outcome is pinned by what the run DID — what reached
`origin/dev`, whether a deploy was attempted — alongside its exit code and the
line it logs. The world is small but real: a bare origin with `main` and `dev`,
a clone running the committed script, `npm`/`npx` stubbed on PATH, and a stub
scanner standing in for the 46-minute cohort run (`FAKE_SCAN` shapes it).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "ops" / "nightly.sh"
GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "bash"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("bash", "git", "flock")),
    reason="needs bash, git and flock",
)

# Stands in for ops/scan_cohort.py: rewrites the published data (or not), and
# can push to origin/dev mid-run the way a concurrent session would.
SCAN_STUB = '''\
import argparse, json, os, subprocess, sys, tempfile
ap = argparse.ArgumentParser()
ap.add_argument("--out"); ap.add_argument("--cohort")
a = ap.parse_args()
if os.environ.get("FAKE_SCAN") != "same":
    rows = json.load(open(a.out))
    rows[0]["v"] += 1
    json.dump(rows, open(a.out, "w"))
move = os.environ.get("FAKE_MOVE")
if move:
    d = tempfile.mkdtemp()
    run = lambda *c: subprocess.run(c, cwd=d, check=True, capture_output=True)
    run("git", "clone", "-q", "-b", "dev", os.environ["FAKE_ORIGIN"], ".")
    path, body = (("rules/_meta/changelog.md", "## 0.1.2 — moved\\n")
                  if move == "contract" else ("README.md", "moved\\n"))
    open(os.path.join(d, path), "w").write(body)
    # Another session, with its own identity: the scan it runs inside reads
    # no git config, by design.
    run("git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
        "commit", "-qam", f"concurrent: {move}")
    run("git", "push", "-q", "origin", "dev")
sys.exit(0)
'''

FILES = {
    "README.md": "fixture\n",
    "ops/cohort.json": "{}\n",
    "ops/scan_cohort.py": SCAN_STUB,
    "site/src/data/scans.json": '[{"name": "a", "registry_state": "listed", "v": 1}]\n',
    "rules/_meta/changelog.md": "## 0.1.1 — fixture\n",
    "src/mcpwatchman/__init__.py": "",
    "src/mcpwatchman/cohort.py": "def systemic_staleness():\n    pass\n",
    "src/mcpwatchman/workers/__init__.py": "",
    "src/mcpwatchman/workers/scanner/__init__.py": "",
    "src/mcpwatchman/workers/scanner/runner.py": "",
    "src/mcpwatchman/workers/scoring/weights.py": 'CURRENT_METHODOLOGY_VERSION = "0.2.0"\n',
    "tests/test_site_scans.py": "def test_ok():\n    pass\n",
    "tests/test_site_example.py": "def test_ok():\n    pass\n",
    "tests/test_cohort.py": "def test_ok():\n    pass\n",
}


@dataclass
class World:
    root: Path
    env: dict[str, str]

    @property
    def origin(self) -> Path:
        return self.root / "origin.git"

    def git(self, *args: str, cwd: Path | None = None) -> str:
        done = subprocess.run(  # noqa: S603 - argument list, never a shell string
            [GIT, *args], cwd=cwd or self.root / "seed", env=self.env,
            check=True, capture_output=True, text=True,
        )
        return done.stdout

    def commit_to(self, branch: str, path: str, body: str) -> None:
        """A commit on origin's `branch`, made the way another seat would."""
        seed = self.root / "seed"
        self.git("checkout", "-q", "-B", branch, f"origin/{branch}")
        (seed / path).write_text(body)
        self.git("commit", "-qam", f"edit {path}")
        self.git("push", "-q", "origin", branch)
        self.git("checkout", "-q", "main")

    def dev_log(self) -> list[str]:
        return self.git("--git-dir", str(self.origin), "log", "--format=%s", "dev").splitlines()

    def run(self, **extra: str) -> tuple[int, str]:
        repo = self.root / "repo"
        self.git("fetch", "-q", "origin", cwd=repo)
        done = subprocess.run(  # noqa: S603 - argument list, never a shell string
            [BASH, str(repo / "ops" / "nightly.sh")], cwd=repo,
            env={**self.env, **extra}, capture_output=True, text=True, timeout=180,
        )
        return done.returncode, done.stdout + done.stderr

    @property
    def deployed(self) -> bool:
        return (self.root / "deployed").exists()


@pytest.fixture
def world(tmp_path: Path) -> World:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "npm").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "npx").write_text(f'#!/bin/sh\necho "$@" > "{tmp_path}/deployed"\n')
    for stub in bin_dir.iterdir():
        stub.chmod(0o755)
    (tmp_path / "hooks").mkdir()
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(
        "[user]\n\tname = t\n\temail = t@example.invalid\n"
        f"[core]\n\thooksPath = {tmp_path / 'hooks'}\n"
        "[init]\n\tdefaultBranch = main\n"
    )
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GIT_CONFIG_GLOBAL": str(gitconfig),
        "GIT_CONFIG_NOSYSTEM": "1",
        "MCPWATCHMAN_GITHUB_TOKEN": "unused-by-the-stub",
        "FAKE_ORIGIN": str(tmp_path / "origin.git"),
        # Never the real /var/tmp from a test.
        "MCPW_SCAN_TMP": str(tmp_path / "scan-tmp"),
    }
    w = World(tmp_path, env)

    w.git("init", "-q", "--bare", str(w.origin), cwd=tmp_path)
    seed = tmp_path / "seed"
    seed.mkdir()
    w.git("init", "-q")
    real = {"ops/nightly.sh": SCRIPT.read_text(),
            "ops/visibility_gate.py": (SCRIPT.parent / "visibility_gate.py").read_text()}
    for rel, body in {**FILES, **real}.items():
        (seed / rel).parent.mkdir(parents=True, exist_ok=True)
        (seed / rel).write_text(body)
    w.git("add", "-A")
    w.git("commit", "-qm", "seed")
    w.git("remote", "add", "origin", str(w.origin))
    w.git("push", "-q", "origin", "main", "main:dev")
    w.git("fetch", "-q", "origin")

    repo = tmp_path / "repo"
    w.git("clone", "-q", str(w.origin), str(repo), cwd=tmp_path)
    # The script runs "$REPO/.venv/bin/python". A wrapper, not a symlink: a
    # symlinked venv interpreter resolves its prefix from the link's location
    # and loses the venv's pytest.
    venv_bin = repo / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    (venv_bin / "python").chmod(0o755)
    return w


def test_a_run_commits_the_new_data_to_dev(world: World) -> None:
    rc, out = world.run()
    assert rc == 0, out
    assert "committed to dev" in out
    assert world.dev_log()[0].startswith("data — nightly rescan")
    assert not world.deployed


def test_nothing_to_commit_never_says_committed(world: World) -> None:
    rc, out = world.run(FAKE_SCAN="same")
    assert rc == 0, out
    assert "nothing to commit" in out
    assert "committed to dev" not in out
    assert world.dev_log() == ["seed"]


def test_a_contract_mismatch_at_start_is_a_quiet_skip(world: World) -> None:
    world.commit_to("dev", "rules/_meta/changelog.md", "## 0.1.2 — newer\n")
    rc, out = world.run()
    assert rc == 11, out
    assert "SKIPPED" in out and "committed to dev" not in out
    assert not world.dev_log()[0].startswith("data")


def test_a_contract_mismatch_with_publishing_on_deploys_mains_pair(world: World) -> None:
    world.commit_to("dev", "rules/_meta/changelog.md", "## 0.1.2 — newer\n")
    rc, out = world.run(MCPW_PUBLISH="1")
    assert rc == 0, out
    assert world.deployed
    assert not world.dev_log()[0].startswith("data")


def test_a_contract_change_mid_run_ends_like_one_at_start(world: World) -> None:
    """It failed the unit (exit 14) where the same state found at start is the
    quiet between-syncs skip (base.md § Signal design)."""
    rc, out = world.run(FAKE_MOVE="contract")
    assert rc == 11, out
    assert "scoring contract changed during the run" in out
    assert world.dev_log()[0] == "concurrent: contract"


def test_an_unrelated_move_mid_run_is_rebased_over(world: World) -> None:
    rc, out = world.run(FAKE_MOVE="other")
    assert rc == 0, out
    log = world.dev_log()
    assert log[0].startswith("data — nightly rescan") and log[1] == "concurrent: other"


def test_an_unparseable_contract_is_a_fault_not_a_skip(world: World) -> None:
    """An empty parse on one side reads as "the contracts differ" — which was
    a quiet exit 11 every night."""
    world.commit_to(
        "dev", "src/mcpwatchman/workers/scoring/weights.py",
        'CURRENT_METHODOLOGY_VERSION: str = "0.2.0"\n',
    )
    rc, out = world.run()
    assert rc == 20, out
    assert "could not read dev's scoring contract" in out


def test_a_main_without_the_staleness_guard_waits_for_a_sync(world: World) -> None:
    world.commit_to("main", "src/mcpwatchman/cohort.py", "")
    rc, out = world.run()
    assert rc == 11, out
    assert "predates cohort.systemic_staleness" in out
    assert world.dev_log() == ["seed"]


# ── Each stage gets only the credentials it uses ────────────────────────────
#
# The build and the deploy run third-party npm code and the scan reads
# attacker-controlled repositories, so a credential a stage does not need is
# one it can leak for nothing. Pinned by what each stage's process actually
# received, not by reading the script.


def _recording(world: World, name: str, extra: str = "") -> Path:
    """Replace a stubbed binary with one that records its environment — every
    call APPENDED, so a credential reaching any one invocation (`npm ci` as well
    as `npm run build`) is caught, not just whichever ran last."""
    record = world.root / f"{name}.env"
    stub = world.root / "bin" / name
    stub.write_text(f'#!/bin/sh\nenv >> "{record}"\n{extra}exit 0\n')
    stub.chmod(0o755)
    return record


def test_only_the_scan_sees_the_github_token_and_nothing_sees_it_twice(world: World) -> None:
    npm = _recording(world, "npm")
    npx = _recording(world, "npx", f'echo "$@" > "{world.root}/deployed"\n')
    scan_seen = world.root / "scan.env"
    # The scan stub is main's committed file; record before it runs.
    world.commit_to("main", "ops/scan_cohort.py",
                    f"import os\nopen({str(scan_seen)!r}, 'w').write('\\n'.join(os.environ))\n"
                    + SCAN_STUB)
    rc, out = world.run(MCPW_PUBLISH="1", CLOUDFLARE_API_TOKEN="cf-sentinel",
                        DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent")
    assert rc == 0, out
    assert world.deployed
    built, deployed = npm.read_text(), npx.read_text()
    assert "MCPWATCHMAN_GITHUB_TOKEN" not in built and "MCPWATCHMAN_GITHUB_TOKEN" not in deployed
    assert "DBUS_SESSION_BUS_ADDRESS" not in built and "DBUS_SESSION_BUS_ADDRESS" not in deployed
    assert "cf-sentinel" not in built, "the build has no use for the Cloudflare credential"
    assert "cf-sentinel" in deployed, "the deploy does"
    assert "WRANGLER_SEND_METRICS=false" in deployed
    scanned = scan_seen.read_text().splitlines()
    assert "MCPWATCHMAN_GITHUB_TOKEN" in scanned, "Maintenance needs it"
    assert "CLOUDFLARE_API_TOKEN" not in scanned


def test_a_lockfile_wrangler_is_deployed_rather_than_npx(world: World) -> None:
    """`npm ci` installing wrangler from the lockfile is what pins its transitive
    dependencies; once it is there, the npx fallback must not run."""
    fake = f'#!/bin/sh\\necho locked > "{world.root}/locked"\\n'
    _recording(world, "npm", "mkdir -p node_modules/.bin\n"
               f"printf '{fake}' > node_modules/.bin/wrangler\n"
               "chmod +x node_modules/.bin/wrangler\n")
    rc, out = world.run(MCPW_PUBLISH="1")
    assert rc == 0, out
    assert (world.root / "locked").exists()
    assert not world.deployed, "npx ran although the lockfile's wrangler was installed"


def test_without_a_lockfile_wrangler_the_pinned_npx_still_deploys(world: World) -> None:
    rc, out = world.run(MCPW_PUBLISH="1")
    assert rc == 0, out
    assert world.deployed
    assert "transitive dependencies unpinned" in out


def test_a_deploy_key_with_a_non_github_origin_is_a_fault_not_a_push(world: World) -> None:
    rc, out = world.run(MCPW_DEPLOY_KEY=str(world.root / "no-such-key"))
    assert rc == 21, out
    assert "not a github.com https URL" in out
    assert not world.dev_log()[0].startswith("data"), "pushed through the fallback anyway"


def _record_scan_env(world: World) -> Path:
    """Commit a scan stub to main that records its environment as JSON."""
    seen = world.root / "scan.env"
    record = f"open({str(seen)!r}, 'w').write(json.dumps(dict(os.environ)))\n"
    world.commit_to("main", "ops/scan_cohort.py", "import json, os\n" + record + SCAN_STUB)
    return seen


def test_the_scan_unpacks_on_disk_in_a_directory_only_we_can_read(world: World) -> None:
    """The default temp dir is a tmpfs here, so a hostile tree unpacked there
    is unpacked into RAM on a box with no memory cap; mkdtemp follows TMPDIR."""
    scan_tmp = world.root / "scan-tmp"
    scan_tmp.mkdir(mode=0o755)
    stale = scan_tmp / "mcpw-scan-left-by-a-killed-run"
    stale.mkdir()
    seen = _record_scan_env(world)
    rc, out = world.run()
    assert rc == 0, out
    env = json.loads(seen.read_text())
    assert env["TMPDIR"] == str(scan_tmp)
    assert stat.S_IMODE(scan_tmp.stat().st_mode) == 0o700
    assert not stale.exists(), "a killed run's workspace outlived the next run"


def test_a_scratch_path_we_do_not_own_is_never_used(world: World) -> None:
    """The disk temp dir is world-writable: a link planted at our path must not
    steer where the scan writes. The run survives on the default TMPDIR and
    says so."""
    elsewhere = world.root / "planted"
    elsewhere.mkdir()
    (world.root / "scan-tmp").symlink_to(elsewhere)
    seen = _record_scan_env(world)
    rc, out = world.run()
    assert rc == 0, out
    assert "not a directory we own" in out
    env = json.loads(seen.read_text())
    assert env.get("TMPDIR") != str(world.root / "scan-tmp")


def test_the_npx_fallback_pins_the_lockfiles_wrangler() -> None:
    """Two declarations of one version: the fallback exists for a `main` whose
    lockfile predates wrangler, and is meant to deploy the same release the
    lockfile would. Moving one and not the other is silent until a deploy."""
    declared = json.loads((SCRIPT.parent.parent / "site" / "package.json").read_text())
    locked = declared["devDependencies"]["wrangler"]
    assert f'WRANGLER="wrangler@{locked}"' in SCRIPT.read_text()


UNIT = SCRIPT.parent / "systemd" / "mcpwatchman-nightly.service"

# Directives a USER unit can only honour by mounting inside a user namespace,
# which AppArmor's unprivileged_userns profile denies on Ubuntu 24.04+; systemd
# then skips them and starts the unit anyway (measured 2026-10-19, systemd 259).
_SILENT_IN_A_USER_UNIT = (
    "PrivateTmp", "PrivateDevices", "PrivateMounts", "ProtectHome", "ProtectSystem",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectControlGroups", "ProtectProc", "ProcSubset", "ReadWritePaths",
    "ReadOnlyPaths", "InaccessiblePaths", "TemporaryFileSystem", "BindPaths",
    "BindReadOnlyPaths",
)


def test_the_unit_claims_no_confinement_it_does_not_get() -> None:
    """A hardening line that is silently skipped reads as confinement in every
    review and confines nothing. If this unit ever becomes a system unit
    (User=kv), these directives start working and this test should go."""
    keys = {
        line.split("=", 1)[0].strip()
        for line in UNIT.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    assert keys & set(_SILENT_IN_A_USER_UNIT) == set()
    assert {"NoNewPrivileges", "RestrictNamespaces", "RestrictSUIDSGID"} <= keys


# Published at docs.github.com, "GitHub's SSH key fingerprints" (checked
# 2026-10-19 against that page and https://api.github.com/meta).
_GITHUB_FINGERPRINTS = {
    "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",  # ed25519
    "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",  # ecdsa
    "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",  # rsa
}


def test_the_pinned_host_keys_are_githubs_published_ones() -> None:
    """The deploy-key push trusts exactly this file, so a key in it that is
    not GitHub's would be a host the nightly pushes to without asking."""
    import base64
    import hashlib

    pinned = set()
    for line in (SCRIPT.parent / "github_known_hosts").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            host, _kind, blob = line.split()[:3]
            assert host == "github.com"
            digest = hashlib.sha256(base64.b64decode(blob)).digest()
            pinned.add("SHA256:" + base64.b64encode(digest).decode().rstrip("="))
    assert pinned == _GITHUB_FINGERPRINTS


def test_the_deploy_key_push_verifies_the_host_against_the_pinned_keys() -> None:
    """Static, because the push needs a real github.com: with `BatchMode` an
    unknown host fails, and without the pin the only fix is trust-on-first-use
    (measured 2026-10-19: this file → `Permission denied (publickey)`, i.e.
    host verified; an empty one → `Host key verification failed`)."""
    script = SCRIPT.read_text()
    assert "-o StrictHostKeyChecking=yes" in script
    assert '-o UserKnownHostsFile=$(printf \'%q\' "$REPO/ops/github_known_hosts")' in script


def test_the_scans_git_never_reads_the_operators_git_config(world: World) -> None:
    """The operator's config carries a `gh` credential helper, and the scan
    clones URLs third parties put in public registry entries. The scanner that
    runs is main's, so the wrapper must cut it off too — and only for the scan:
    the data push still needs the operator's credential."""
    seen = _record_scan_env(world)
    rc, out = world.run()
    assert rc == 0, out
    env = json.loads(seen.read_text())
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert world.dev_log()[0].startswith("data"), "the push lost its credential"


def test_a_visibility_refusal_stops_the_run_before_anything_leaves(world: World) -> None:
    """The gate is the only thing standing between main's forge lookup (which
    reads with the operator's token) and a public page, so its refusal must
    stop the build, the commit and the deploy — not log and carry on."""
    (world.root / "repo" / "ops" / "visibility_gate.py").write_text(
        "import sys\nprint('refused for the test')\nsys.exit(1)\n")
    rc, out = world.run(MCPW_PUBLISH="1")
    assert rc == 22, out
    assert "visibility gate refused" in out
    assert not world.deployed
    assert not world.dev_log()[0].startswith("data"), "committed despite the refusal"


def test_the_real_gate_passes_a_run_with_nothing_to_ask(world: World) -> None:
    rc, out = world.run()
    assert rc == 0, out
    assert "visibility gate: 0 repositories asked anonymously" in out
    assert "0 refused" in out
