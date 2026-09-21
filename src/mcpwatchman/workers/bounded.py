"""Run an external scanner under a deadline that actually ends it (`04` §7).

⚠ **`subprocess.run(..., timeout=N)` KILLS THE CHILD AND ORPHANS ITS
GRANDCHILDREN**, and for this project's three scanner binaries that is not a
nuance — it is a compounding failure that ruined a 492-server run.

`semgrep` is a Python wrapper that spawns `semgrep-core`, an OCaml binary which
is where all the work happens. On timeout, `subprocess.run` kills the wrapper
and returns; `semgrep-core` keeps running, unparented, at 200-300% CPU. The
next server's scan therefore starts with fewer cores, so it is more likely to
exceed the same deadline, which leaks another orphan. **The failure rate is a
function of how many times it has already failed.**

Measured 2026-09-21 by watching it happen: a run that scanned its first 80
servers cleanly reached **six concurrent `semgrep-core` processes at 200-300%
CPU each — roughly 14 of 16 cores — while the driver was scanning strictly
sequentially, one subprocess at a time.** By server 300 it was failing 16 of
every 20, and the failures continued for minutes after the parent was killed,
because the orphans were still alive. With none running, every one of those
"failing" repositories scores normally on the first attempt.

⚠ **THE LEAK IS REAL AND IT WAS NOT THE MAIN CAUSE — this docstring claimed
it was, and the claim did not survive the re-run.** Six live `semgrep-core`
processes during a strictly sequential scan is impossible unless children are
outliving their parents, so the leak is established. But with the leak fixed
and zero orphans present, the same servers still failed: measured on one
repository, 12 runs of the real invocation with nothing else on the box went
**1/12 clean**. The dominant cause is a nondeterministic corruption in
semgrep-core's parallel worker pool, fixed by `--jobs 1` in `semgrep_check`
(12/12 clean) — a different bug that produces an identical symptom.

Recorded rather than quietly edited because the reasoning error is the
reusable part: a mechanism that is genuinely present, genuinely broken, and
genuinely fixed can still not be the thing you were chasing, and a plausible
mechanism plus a real fix is exactly the shape that stops an investigation one
step early. What settled it was re-running with the fix in place and finding
the failure rate unchanged.

The remedy is the standard one and it has two halves, both required:
`start_new_session=True` puts the child in its own process group, and killing
that GROUP on timeout reaches the grandchildren. Either half alone leaks.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from collections.abc import Sequence
from pathlib import Path


class Bounded:
    """What `subprocess.run` would have returned, plus whether time ran out.

    `timed_out` is a first-class field rather than an exception because every
    caller here treats a timeout as an outcome to attribute, not an error to
    propagate — a scanner that ran out of budget is `ENVIRONMENT`, and the
    report says so.
    """

    __slots__ = ("returncode", "stdout", "stderr", "timed_out")

    def __init__(self, returncode: int, stdout: str, stderr: str, timed_out: bool) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


def run_bounded(
    cmd: Sequence[str], *, timeout: float, cwd: Path | str | None = None
) -> Bounded:
    """Run `cmd` with a deadline, ending its whole process group if it expires.

    ⚠ **Never replace this with `subprocess.run(..., timeout=)`.** That call is
    what this module exists to stop using; the module docstring carries the
    measurement.

    The kill is `SIGKILL` to the group rather than `SIGTERM` to the child.
    `semgrep-core` is the process holding the cores, it is not the process
    Python is waiting on, and a polite signal to a wrapper that has already
    been killed reaches nothing.
    """
    proc = subprocess.Popen(  # noqa: S603 - argv form, no shell; callers build
        # `cmd` from a fixed binary name and paths they own.
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        # Half one: its own process group, so there is a group to kill.
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return Bounded(proc.returncode, stdout or "", stderr or "", timed_out=False)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        # Reap, so the pipes close and the zombie is collected. The child is
        # already dead, so this cannot block — but it is bounded anyway, since
        # a hung reap here would reintroduce the stall in a new place.
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        return Bounded(proc.returncode or -9, stdout or "", stderr or "", timed_out=True)


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's process group, falling back to the child alone.

    The fallback matters on a platform or a race where the group is already
    gone: `os.getpgid` raises `ProcessLookupError` for a reaped pid, and an
    exception escaping here would turn a timeout into a crash.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


__all__ = ["Bounded", "run_bounded"]
