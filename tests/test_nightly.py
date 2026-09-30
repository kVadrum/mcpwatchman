"""`ops/nightly.sh`, run for real against a throwaway origin.

The nightly is a gate whose failure mode is reporting success while doing
nothing, so each outcome is pinned by what the run DID — what reached
`origin/dev`, whether a deploy was attempted — alongside its exit code and the
line it logs. The world is small but real: a bare origin with `main` and `dev`,
a clone running the committed script, `npm`/`npx` stubbed on PATH, and a stub
scanner standing in for the 46-minute cohort run (`FAKE_SCAN` shapes it).
"""

from __future__ import annotations

import os
import shutil
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
    run("git", "commit", "-qam", f"concurrent: {move}")
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
    }
    w = World(tmp_path, env)

    w.git("init", "-q", "--bare", str(w.origin), cwd=tmp_path)
    seed = tmp_path / "seed"
    seed.mkdir()
    w.git("init", "-q")
    for rel, body in {**FILES, "ops/nightly.sh": SCRIPT.read_text()}.items():
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
