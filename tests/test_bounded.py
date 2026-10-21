"""`workers.bounded` — the deadline that ends grandchildren too.

⚠ **This exists because `subprocess.run(..., timeout=N)` does not.** It kills
the process it spawned and leaves that process's children running. For this
scanner the child is a thin Python wrapper and the grandchild is where all the
CPU goes, so every expired deadline leaked a process holding 2-3 cores — which
made the next deadline likelier to expire, which leaked another. A 492-server
run reached six live `semgrep-core` processes and a 16-in-20 failure rate by
server 300.

The tests use a shell grandchild rather than semgrep: the bug is about process
TREES, not about any scanner, and a shell reproduces it in a second with no
network and no binaries.

⚠ **They track the grandchild by PID, never by `pgrep -f` on a pattern.** The
first version matched a sentinel string in the full command line and the
positive control fired immediately — `pgrep -f` was matching the *test
harness's own shell*, whose argv contained the pattern because the test file
had just been written through it. A probe that can match the thing running the
probe proves nothing in either direction.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import time

import pytest

from mcpwatchman.workers.bounded import run_bounded, stream_bounded


def _spawner(pidfile) -> list[str]:
    """A child that spawns a long-lived grandchild and reports its PID."""
    return ["sh", "-c", f"sleep 300 & echo $! > {pidfile}; wait"]


def _read_pid(pidfile, tries: int = 50) -> int:
    for _ in range(tries):
        try:
            text = pidfile.read_text().strip()
            if text:
                return int(text)
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("the grandchild never reported its PID")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _gone_within(pid: int, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


def test_a_timeout_kills_the_grandchild_not_just_the_child(tmp_path) -> None:
    """⚠ THE WHOLE POINT. `subprocess.run` fails this; `run_bounded` passes it."""
    pidfile = tmp_path / "gc.pid"
    result = run_bounded(_spawner(pidfile), timeout=1)
    assert result.timed_out is True

    grandchild = _read_pid(pidfile)
    assert _gone_within(grandchild, 5.0), (
        "the grandchild outlived its deadline — the process group was not "
        "killed, which is the leak that compounds across a 492-server run"
    )


def test_the_stdlib_call_really_does_leak_it(tmp_path) -> None:
    """The negative control, and it is what makes the test above meaningful.

    Without it, `run_bounded` passing proves only that the shell exits
    eventually. This asserts the failure mode is real on this platform — then
    cleans up, because a test that leaks the process it demonstrates would
    slow every run after it.
    """
    pidfile = tmp_path / "gc.pid"
    with contextlib.suppress(subprocess.TimeoutExpired):
        subprocess.run(  # noqa: S603 - fixed argv, no shell string from input
            _spawner(pidfile), timeout=1, capture_output=True
        )

    grandchild = _read_pid(pidfile)
    leaked = _alive(grandchild)
    if leaked:
        with contextlib.suppress(ProcessLookupError):
            os.kill(grandchild, 9)
    assert leaked, (
        "the stdlib call did NOT leak here, so this platform does not exhibit "
        "the bug and the test above is not evidence of a fix"
    )


def test_a_command_that_finishes_is_returned_untouched() -> None:
    result = run_bounded(["sh", "-c", "printf out; printf err >&2; exit 3"], timeout=10)
    assert (result.returncode, result.stdout, result.stderr) == (3, "out", "err")
    assert result.timed_out is False


def test_cancellation_kills_the_grandchild_too(tmp_path) -> None:
    """The half of the leak fix that `start_new_session=True` CREATES.

    A timeout is not the only way out of `communicate`, and the others were
    unhandled. Because the child is put in its own process group, a Ctrl-C at
    the driver is delivered to the parent and never to the tree — so a
    cancelled 492-server run left exactly the orphan this module exists to
    end, reached through the mechanism that fixes the timeout case.

    Asserts on the GRANDCHILD, by PID, for the reason this file's docstring
    gives: the bug is about process trees, and `pgrep -f` can match the
    harness running the probe.

    `KeyboardInterrupt` rather than a plain exception, because that is the
    real shape and it is not an `Exception` — an `except Exception` arm would
    pass a test written with the wrong one.
    """
    pidfile = tmp_path / "gc.pid"
    real = subprocess.Popen.communicate
    calls = {"n": 0}

    def interrupt_once(self, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        calls["n"] += 1
        if calls["n"] == 1:
            _read_pid(pidfile)  # let the grandchild exist before we bail
            raise KeyboardInterrupt
        return real(self, *a, **kw)  # the cleanup reap must still work

    subprocess.Popen.communicate = interrupt_once  # type: ignore[method-assign]
    try:
        with pytest.raises(KeyboardInterrupt):
            run_bounded(_spawner(pidfile), timeout=60)
    finally:
        subprocess.Popen.communicate = real  # type: ignore[method-assign]

    gc_pid = int(pidfile.read_text().strip())
    for _ in range(100):
        try:
            os.kill(gc_pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    with contextlib.suppress(ProcessLookupError):
        os.kill(gc_pid, signal.SIGKILL)
    pytest.fail("the grandchild outlived a cancelled run_bounded — the orphan is back")


# ── The child environment: an allowlist, never ours ─────────────────────────
#
# Every child started through `run_bounded` reads attacker-controlled input
# (a fetched repository, a published archive), so it must not inherit the
# operator's tokens, D-Bus session (which reaches the keyring) or git
# configuration (which carried a `gh` credential helper: measured 2026-10-19, a
# scanner-shaped `git ls-remote` read a private repository through it).


def _child_env(**kwargs) -> dict[str, str]:
    out = run_bounded(["env", "-0"], timeout=10, **kwargs).stdout
    return dict(item.split("=", 1) for item in out.split("\0") if "=" in item)


def test_a_child_never_inherits_credentials_or_the_session_bus(monkeypatch) -> None:
    for name in ("MCPWATCHMAN_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
                 "CLOUDFLARE_API_TOKEN", "SEMGREP_APP_TOKEN", "DBUS_SESSION_BUS_ADDRESS"):
        monkeypatch.setenv(name, "sentinel-must-not-reach-the-child")
    env = _child_env()
    assert "sentinel-must-not-reach-the-child" not in env.values()
    assert env.get("PATH") == os.environ["PATH"], "the tools still have to find themselves"
    assert env.get("GIT_CONFIG_GLOBAL") == os.devnull
    assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
    assert env.get("GIT_TERMINAL_PROMPT") == "0"


def test_a_callers_extra_env_reaches_the_child() -> None:
    env = _child_env(extra_env={"EIO_BACKEND": "posix"})
    assert env.get("EIO_BACKEND") == "posix"
    assert env.get("GIT_CONFIG_GLOBAL") == os.devnull, "extras are layered, not substituted"


def test_the_stdlib_env_keyword_is_refused_rather_than_layered() -> None:
    """`env={**os.environ, ...}` is the ordinary `subprocess` idiom. Under the
    stdlib's name it would read as a replacement while being layered, so the
    parameter is named for what it does and the familiar keyword fails loudly."""
    with pytest.raises(TypeError):
        run_bounded(["true"], timeout=10, env={})  # type: ignore[call-arg]
    with pytest.raises(TypeError), stream_bounded(["true"], timeout=10, env={}):  # type: ignore[call-arg]
        pass


def test_semgreps_environment_carries_no_credentials(monkeypatch) -> None:
    """The caller that hands a whole environment to `extra_env=`, and the
    reason layering matters: it used to build `{**os.environ, ...}`, which no
    chokepoint can scrub once a caller hands it over. Every semgrep launch —
    scanner and tests — uses it."""
    from mcpwatchman.workers.scanner.semgrep_check import semgrep_env

    monkeypatch.setenv("GITHUB_TOKEN", "sentinel-must-not-reach-the-child")
    env = semgrep_env()
    assert "sentinel-must-not-reach-the-child" not in env.values()
    assert env.get("EIO_BACKEND") == "posix"


GIT = shutil.which("git") or "git"


def _git(repo, *args: str) -> None:
    subprocess.run(  # noqa: S603 - argument list, never a shell string
        [GIT, *args], cwd=repo, check=True, capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"},
    )


def test_git_children_ignore_the_operators_global_config(tmp_path, monkeypatch) -> None:
    """The real mechanism, end to end: a ~/.gitconfig carrying a credential
    helper and a hooks directory, as the operator's does. A post-checkout hook
    is the observable stand-in for the helper — both live in the same global
    file that `GIT_CONFIG_GLOBAL` replaces — and the helper itself is asked for
    directly. The negative control runs plain `subprocess` against the same
    fixture and must see both, or this test proves nothing."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "f.txt").write_text("x\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-qm", "c")

    hooks = tmp_path / "hooks"
    hooks.mkdir()
    marker = tmp_path / "hook-ran"
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        f"[core]\n\thooksPath = {hooks}\n"
        "[credential \"https://github.com\"]\n\thelper = !echo password=leaked\n"
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    # Negative control: an ordinary child DOES read that config.
    subprocess.run(  # noqa: S603 - argument list, never a shell string
        [GIT, "clone", "-q", "--", str(origin), str(tmp_path / "control")],
        check=True, capture_output=True,
    )
    assert marker.exists(), "fixture is inert: the hook never ran under plain subprocess"
    plain = subprocess.run(  # noqa: S603 - argument list, never a shell string
        [GIT, "config", "--get", "credential.https://github.com.helper"],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert "leaked" in plain.stdout
    marker.unlink()

    # Under test.
    cloned = run_bounded(
        ["git", "clone", "-q", "--", str(origin), str(tmp_path / "scanned")], timeout=60,
    )
    assert cloned.returncode == 0, cloned.stderr
    assert not marker.exists(), "the operator's hooks ran on a scanned checkout"
    helper = run_bounded(
        ["git", "config", "--get", "credential.https://github.com.helper"],
        timeout=10, cwd=tmp_path,
    )
    assert helper.returncode != 0 and "leaked" not in helper.stdout


# ── stream_bounded: the same rules for output too large to hold ─────────────


def test_a_stream_read_to_the_end_keeps_the_childs_real_status() -> None:
    """Positive control: a child that runs to completion reports its own exit
    status through the stream, not the -9 of a kill."""
    with stream_bounded(["sh", "-c", "head -c 300000 /dev/zero; exit 3"], timeout=30) as out:
        data = out.stdout.read()
    assert len(data) == 300_000
    assert (out.returncode, out.timed_out) == (3, False)


def test_a_streams_deadline_ends_the_group_while_the_caller_is_blocked(tmp_path) -> None:
    """A child that writes nothing leaves the caller blocked in `read()`, where
    no check of its own can run — the deadline has to be a timer."""
    pidfile = tmp_path / "gc.pid"
    started = time.monotonic()
    with stream_bounded(_spawner(pidfile), timeout=1) as out:
        assert out.stdout.read() == b""
    assert out.timed_out is True
    assert time.monotonic() - started < 10
    assert _gone_within(_read_pid(pidfile), 5.0)


def test_leaving_a_stream_early_ends_the_child_and_its_group(tmp_path) -> None:
    """A caller that crosses a cap stops reading and raises; the child is still
    writing, and its grandchild must not outlive the block either."""
    pidfile = tmp_path / "gc.pid"
    cmd = ["sh", "-c", f"sleep 300 & echo $! > {pidfile}; yes"]
    with pytest.raises(RuntimeError, match="cap crossed"), \
            stream_bounded(cmd, timeout=30) as out:
        assert out.stdout.read(4096)
        raise RuntimeError("cap crossed")
    assert out.returncode is not None
    assert _gone_within(_read_pid(pidfile), 5.0)


def test_a_streamed_child_never_inherits_credentials(monkeypatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "sentinel-not-a-token")
    with stream_bounded(["env", "-0"], timeout=30) as out:
        names = {kv.split(b"=", 1)[0] for kv in out.stdout.read().split(b"\0") if kv}
    assert b"GH_TOKEN" not in names
    assert b"GIT_CONFIG_GLOBAL" in names
