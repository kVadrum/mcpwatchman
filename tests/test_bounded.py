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
import subprocess
import time

from mcpwatchman.workers.bounded import run_bounded


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
