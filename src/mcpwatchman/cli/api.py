"""The static API every CLI command reads — fetching, resolving, exit codes.

Stdlib only, and imported lazily from inside each command in `main`: the CLI's
startup path stays click + stdlib (`tests/test_cli_lazy_imports.py`). There is
no API server; the site publishes static JSON and Atom, and this module is the
one place that reads it, so every command answers the same question the same
way — which URL, what a 404 means, which `07` §3.5 exit code a failure gets.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

import click

from mcpwatchman import __version__
from mcpwatchman.slug import slugify

DEFAULT_BASE_URL = "https://mcpwatchman.com"
TIMEOUT_S = 20

# A response is read to this many bytes and refused past it. The largest
# per-server record is ~65 KB and the index a few hundred; the cap exists so a
# hostile or broken override cannot stream without end into memory.
MAX_JSON_BYTES = 16 * 1024 * 1024

# `07` §3.5.
EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_BELOW_THRESHOLD = 2
EXIT_NETWORK = 4
EXIT_USAGE = 5

AXES = (
    ("code_safety", "Code Safety", "code"),
    ("auth_posture", "Auth Posture", "auth"),
    ("dependency_health", "Dependency Health", "deps"),
    ("maintenance", "Maintenance", "maint"),
    ("transparency", "Transparency", "trans"),
)
AXIS_LABEL = {key: label for key, label, _ in AXES}


class CliError(click.ClickException):
    """A command outcome with its own `07` §3.5 exit code."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        # Click declares `exit_code` as a class attribute and reads it to pick
        # the process exit status; per-instance is the point here.
        self.exit_code = code  # type: ignore[misc]


def base_url() -> str:
    """The API root; `MCPWATCHMAN_API_URL` overrides it, http(s) only.

    `urlopen` also honours `file:` and custom schemes, and an override pointing
    at `file:///` would have the CLI read local files as if they were scans.
    """
    url = os.environ.get("MCPWATCHMAN_API_URL", DEFAULT_BASE_URL).rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise CliError(f"MCPWATCHMAN_API_URL must be an http(s) URL, not {url!r}", EXIT_USAGE)
    return url


def get_bytes(url: str, *, cap: int, accept: str) -> bytes | None:
    """GET a document of at most `cap` bytes. None on 404 — absence is an answer."""
    request = urllib.request.Request(  # noqa: S310 - scheme checked in base_url
        url, headers={"User-Agent": f"mcpwatchman/{__version__}", "Accept": accept},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:  # noqa: S310 - scheme checked in base_url
            body: bytes = response.read(cap + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise CliError(f"{url} answered HTTP {exc.code}", EXIT_NETWORK) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CliError(f"could not reach {url}: {exc}", EXIT_NETWORK) from exc
    if len(body) > cap:
        raise CliError(f"{url} is larger than {cap} bytes; refusing to read it", EXIT_NETWORK)
    return body


def get_json(url: str) -> dict[str, Any] | None:
    """GET a JSON object. None on 404."""
    body = get_bytes(url, cap=MAX_JSON_BYTES, accept="application/json")
    if body is None:
        return None
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError(f"{url} did not return JSON", EXIT_NETWORK) from exc
    if not isinstance(payload, dict):
        raise CliError(f"{url} returned an unexpected shape", EXIT_NETWORK)
    return payload


def _repo_key(url: str) -> str:
    url = url.strip().lower().removesuffix("/").removesuffix(".git")
    for prefix in ("https://", "http://", "www."):
        url = url.removeprefix(prefix)
    return url


def _pypi_key(name: str) -> str:
    """PEP 503 normalisation: PyPI treats `Foo_Bar`, `foo-bar`, `foo.bar` as one."""
    out = name.lower()
    for ch in "_.":
        out = out.replace(ch, "-")
    return out


def _package_matches(spec: str, wanted: str) -> bool:
    kind, _, rest = spec.partition(":")
    identifier = rest.rpartition("@")[0] if "@" in rest.lstrip("@") else rest
    if kind == "npm":
        return identifier == wanted
    if kind == "pypi":
        return _pypi_key(identifier) == _pypi_key(wanted)
    return False


def get_index(base: str) -> list[dict[str, Any]]:
    index = get_json(f"{base}/api/index.json")
    if index is None:
        raise CliError(f"{base}/api/index.json is missing", EXIT_NETWORK)
    servers = index.get("servers")
    if not isinstance(servers, list):
        raise CliError(f"{base}/api/index.json returned an unexpected shape", EXIT_NETWORK)
    return [entry for entry in servers if isinstance(entry, dict)]


def resolve(server: str, base: str) -> dict[str, Any] | None:
    """`07` §3.1's order: registry name or slug, npm name, PyPI name, repo URL."""
    looks_like_url = "://" in server or server.lower().startswith(("github.com/", "gitlab.com/"))
    if not looks_like_url:
        record = get_json(f"{base}/api/servers/{slugify(server)}.json")
        if record is not None:
            return record

    entries = get_index(base)
    if looks_like_url:
        wanted = _repo_key(server)
        matches = [e for e in entries if _repo_key(e.get("repository_url") or "") == wanted]
    else:
        matches = [
            e for e in entries if e.get("package") and _package_matches(e["package"], server)
        ]
    if not matches:
        return None
    if len(matches) > 1:
        # A monorepo declares one repository for many servers — 11 published
        # URLs are shared, one by 36. Picking the first would print one
        # stranger's scores as the answer for all of them.
        names = ", ".join(sorted(e["name"] for e in matches)[:10])
        more = f" (and {len(matches) - 10} more)" if len(matches) > 10 else ""
        raise CliError(
            f"{server!r} matches {len(matches)} published servers: {names}{more}. "
            "Name one by its registry name.",
            EXIT_USAGE,
        )
    return get_json(f"{base}/api/servers/{matches[0]['slug']}.json")


def load(server: str, base: str, version: str | None = None) -> dict[str, Any]:
    """The published record for SERVER, or the `07` §3.5 not-found exit."""
    record = resolve(server, base)
    if record is None:
        raise CliError(
            f"{server!r} is not published by mcpwatchman. That is not a judgement: "
            "the published set is a growing sample of the registry, and absence "
            "means only that we have not scanned it.",
            EXIT_NOT_FOUND,
        )
    data: dict[str, Any] = record.get("server", record)
    if version and version != data["version"]:
        raise CliError(
            f"the published scan of {data['name']} is for version {data['version']}, "
            f"not {version}; earlier or later versions are not kept.",
            EXIT_NOT_FOUND,
        )
    return data


def weight(axis: dict[str, Any]) -> float:
    """`assessed_weight` as a fraction in [0, 1]; unreadable reads as unmeasured."""
    try:
        return max(0.0, min(1.0, float(axis.get("assessed_weight") or 0)))
    except (TypeError, ValueError):
        return 0.0


def unicode_ok() -> bool:
    try:
        "▓░╱─▁█·│".encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


# C0 and C1 controls (tab and newline kept), DEL, and the bidi overrides and
# isolates. Paths, excerpts and registry names come from scanned repositories
# and the registry: printed raw, an ESC sequence in a file name rewrites the
# reader's terminal, and a bidi override makes a line read other than it is.
_UNPRINTABLE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(text: object, *, one_line: bool = False) -> str:
    """Third-party text made safe to print to a terminal."""
    out = _UNPRINTABLE.sub("\ufffd", str(text))
    return out.replace("\n", " ").replace("\t", " ") if one_line else out
