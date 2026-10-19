"""The hash-locked requirement files agree with what they were generated from.

`requirements/workers.txt` is what the worker image, CI's `workers-extra` job
and the nightly venv install; `requirements/build.txt` is the release build's
whole toolchain. Both are GENERATED (by uv, from `pyproject.toml` and
`requirements/build.in`), and nothing regenerates them when their source
changes — so a dependency added to the extra and not to the lock installs
nowhere that runs the scanner, with every import in a developer venv still
resolving from something else. These tests read the files as text, so they run
in every CI job, not only the one that installs the lock.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
REQS = ROOT / "requirements"


def _pins(path: Path) -> dict[str, tuple[str, int]]:
    """name → (version, hash count) for every `name==version` entry."""
    pins: dict[str, tuple[str, int]] = {}
    current: str | None = None
    for line in path.read_text().splitlines():
        if m := re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", line):
            current = canonicalize_name(m.group(1))
            pins[current] = (m.group(2), 0)
        elif current and line.strip().startswith("--hash=sha256:"):
            version, hashes = pins[current]
            pins[current] = (version, hashes + 1)
        elif not line.startswith(" "):
            current = None
    return pins


def _declared(*extras: str) -> list[Requirement]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    reqs = list(project["dependencies"])
    for extra in extras:
        reqs += project["optional-dependencies"][extra]
    return [Requirement(r) for r in reqs]


@pytest.mark.parametrize("lock", ["workers.txt", "build.txt"])
def test_every_pin_carries_a_hash(lock: str) -> None:
    pins = _pins(REQS / lock)
    assert pins, f"{lock} parsed to nothing — the reader, not the file, is broken"
    assert [n for n, (_, hashes) in pins.items() if hashes == 0] == []


def test_the_workers_lock_satisfies_everything_the_extra_declares() -> None:
    pins = _pins(REQS / "workers.txt")
    unmet = []
    for req in _declared("workers"):
        name = canonicalize_name(req.name)
        if name not in pins:
            unmet.append(f"{req} (absent)")
        elif not req.specifier.contains(pins[name][0], prereleases=True):
            unmet.append(f"{req} (locked {pins[name][0]})")
    assert unmet == [], "regenerate requirements/workers.txt (command in its header)"


def test_the_build_lock_holds_the_release_toolchain() -> None:
    """`release.yml` builds with --no-isolation, so the backend `pyproject.toml`
    names must come from this file or the build uses whatever is lying around."""
    backend = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    pins = _pins(REQS / "build.txt")
    for name in ["build", "twine", *(Requirement(r).name for r in backend)]:
        assert canonicalize_name(name) in pins, name


def test_the_reader_sees_a_missing_declaration() -> None:
    """Positive control: a declaration the lock lacks must be reported, or the
    test above passes by never finding anything to compare."""
    pins = _pins(REQS / "workers.txt")
    assert canonicalize_name("not-a-locked-package") not in pins
    assert canonicalize_name("semgrep") in pins
