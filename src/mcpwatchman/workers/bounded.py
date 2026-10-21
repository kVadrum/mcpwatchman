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

⚠ **EVERY CHILD STARTED HERE READS ATTACKER-CONTROLLED INPUT, SO NONE OF THEM
GETS OUR ENVIRONMENT OR OUR GIT CONFIGURATION.** `git` resolving a repository
URL from public registry metadata used to inherit the operator's global config,
including a `gh` credential helper: a registry entry naming a private repository
the operator could read was cloned with the operator's token, and its source
would have been published (measured 2026-10-19 — a scanner-shaped `git
ls-remote` read a private repository; with the helper disabled it was refused).
The scanners inherited the same environment, tokens included. So the child
environment is an ALLOWLIST (`untrusted_env`) applied here by default — one
chokepoint, so a new call site cannot forget it — and a caller's `extra_env` is
layered over it, never substituted for it.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import IO

# What a child may inherit. An allowlist rather than a denylist of secret-shaped
# names, because a denylist fails open on the next credential someone names
# differently (`SEMGREP_APP_TOKEN`, `NPM_CONFIG__AUTH`, a D-Bus session address
# that reaches the keyring). What is here is what the tools were measured to
# need: PATH to find themselves, HOME for semgrep's settings and osv-scanner's
# cache, locale, a temp dir, CA bundles and proxies for the network calls.
_INHERITED = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "TMPDIR",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "PYTHONIOENCODING", "PYTHONUTF8",
})
_INHERITED_PREFIXES = ("LC_",)

# git reads ~/.gitconfig (credential helpers, hooksPath, url rewrites) and
# /etc/gitconfig unless told not to; repository-level config is still read,
# which is what a local test remote relies on. No prompt: a child with no TTY
# that wants a password must fail, not hang until the timeout.
GIT_ISOLATION = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


def untrusted_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a child that reads attacker-controlled input."""
    env = {
        k: v for k, v in os.environ.items()
        if k in _INHERITED or k.startswith(_INHERITED_PREFIXES)
    }
    env.update(GIT_ISOLATION)
    if extra:
        env.update(extra)
    return env


# git's HTTPS transport is libcurl, which sends credentials from $HOME/.netrc
# whatever git's own configuration says — measured 2026-10-21: with every
# variable in GIT_ISOLATION set, a `.netrc` entry still reached the server.
# HOME stays in the allowlist (semgrep keeps its settings there, osv-scanner its
# cache), so git alone gets a HOME with nothing in it — here, keyed on the
# binary, so a git call site added later cannot forget it.
_GIT_HOME = {"HOME": os.devnull}


def _child_env(cmd: Sequence[str], extra: Mapping[str, str] | None) -> dict[str, str]:
    if cmd and Path(cmd[0]).name == "git":
        extra = {**_GIT_HOME, **(extra or {})}
    return untrusted_env(extra)


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
    cmd: Sequence[str], *, timeout: float, cwd: Path | str | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> Bounded:
    """Run `cmd` with a deadline, ending its whole process group if it expires.

    ⚠ **Never replace this with `subprocess.run(..., timeout=)`.** That call is
    what this module exists to stop using; the module docstring carries the
    measurement.

    The kill is `SIGKILL` to the group rather than `SIGTERM` to the child.
    `semgrep-core` is the process holding the cores, it is not the process
    Python is waiting on, and a polite signal to a wrapper that has already
    been killed reaches nothing.

    `extra_env` holds EXTRA variables, layered over `untrusted_env()` — never a
    replacement for it (module docstring).
    """
    proc = subprocess.Popen(  # noqa: S603 - argv form, no shell; callers build
        # `cmd` from a fixed binary name and paths they own.
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        env=_child_env(cmd, extra_env),
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
    except BaseException:
        # ⚠ **A TIMEOUT IS NOT THE ONLY WAY OUT OF `communicate`, AND THE OTHERS
        # LEAK THE SAME ORPHAN.** `start_new_session=True` is exactly what makes
        # this necessary: the child sits in its OWN process group, so a Ctrl-C
        # at the driver is delivered to us and never to it. Without this arm a
        # cancelled 492-server run leaves `semgrep-core` holding two or three
        # cores indefinitely — the precise failure this module was written to
        # end, arriving through the half of the fix that creates the group.
        #
        # `BaseException`, deliberately: `KeyboardInterrupt` and `SystemExit`
        # are the cases that matter and neither is an `Exception`. The group is
        # killed, reaped, and the exception re-raised unchanged — this arm
        # changes what is left running, never what the caller sees.
        _kill_group(proc)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=10)
        raise


class Streamed:
    """A child whose stdout is read incrementally, inside `stream_bounded`.

    `returncode` and `timed_out` are only meaningful once the block has exited.
    """

    __slots__ = ("returncode", "stdout", "timed_out")

    def __init__(self, stdout: IO[bytes]) -> None:
        self.stdout = stdout
        self.returncode: int | None = None
        self.timed_out = False


@contextlib.contextmanager
def stream_bounded(
    cmd: Sequence[str], *, timeout: float, cwd: Path | str | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> Iterator[Streamed]:
    """`run_bounded` for output too large to hold: the caller reads `stdout` as
    it arrives and may stop at any point.

    `communicate()` buffers everything, so a listing an attacker sizes — `git
    ls-tree -r` over a tree of nested self-references — is unbounded memory
    before the caller sees a byte. Here the caller counts as it reads and leaves
    the block (normally or by raising) the moment a cap is crossed; the deadline
    is a timer that ends the group even while the caller is blocked on a read.
    Same environment and process-group rules as `run_bounded`. stderr is
    discarded, because a pipe nobody drains blocks the child once it fills.
    """
    proc = subprocess.Popen(  # noqa: S603 - argv form, no shell; as run_bounded
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=str(cwd) if cwd is not None else None,
        env=_child_env(cmd, extra_env),
        start_new_session=True,
    )
    if proc.stdout is None:  # stdout=PIPE above; narrows the type
        raise RuntimeError("stream_bounded: child has no stdout pipe")
    streamed = Streamed(proc.stdout)

    def expire() -> None:
        streamed.timed_out = True
        _kill_group(proc)

    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        yield streamed
    except BaseException:
        timer.cancel()
        _kill_group(proc)
        with contextlib.suppress(Exception):
            proc.stdout.close()
            proc.wait(timeout=10)
        streamed.returncode = proc.returncode
        raise
    timer.cancel()
    # Normal exit: closing our end ends a child the caller stopped reading
    # (EPIPE), and one that already finished is reaped with its real status
    # rather than killed mid-exit into a false -9.
    proc.stdout.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)
    streamed.returncode = proc.returncode


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


__all__ = [
    "GIT_ISOLATION", "Bounded", "Streamed", "run_bounded", "stream_bounded", "untrusted_env",
]
