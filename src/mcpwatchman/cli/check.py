"""`mcpwatchman check` — read a server's published scan from the static API.

Stdlib only, and imported lazily from `main.check`: this is the command people
run BEFORE installing something, so its startup path stays click + stdlib
(`tests/test_cli_lazy_imports.py`). It reads the same JSON the site publishes —
`/api/servers/<slug>.json` for one server, `/api/index.json` to resolve a
package name or repository URL — so there is no second source of truth and no
server to run.

`07` §3 is the spec. Two deliberate departures, both toward saying less:
- No bare per-axis score. `07`'s JSON sample predates the rule that a score
  never travels without its `assessed_weight` (`CLAUDE.md`), and 80 of a
  quarter of an axis printed as "80" is the misreading this project exists to
  prevent. Every format carries the weight beside the score.
- No `--fresh`. It means an on-demand scan, and no worker serves one yet; a
  flag that silently did nothing would be worse than its absence.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

import click

from mcpwatchman import __version__
from mcpwatchman.slug import slugify

DEFAULT_BASE_URL = "https://mcpwatchman.com"
TIMEOUT_S = 20

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

BAR_WIDTH = 20


class CheckError(click.ClickException):
    """A `check` outcome with its own `07` §3.5 exit code."""

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
        raise CheckError(f"MCPWATCHMAN_API_URL must be an http(s) URL, not {url!r}", EXIT_USAGE)
    return url


def get_json(url: str) -> dict[str, Any] | None:
    """GET a JSON document. None on 404 — absence is an answer, not an error."""
    request = urllib.request.Request(  # noqa: S310 - scheme checked in base_url
        url,
        headers={"User-Agent": f"mcpwatchman/{__version__}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:  # noqa: S310 - scheme checked in base_url
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise CheckError(f"{url} answered HTTP {exc.code}", EXIT_NETWORK) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CheckError(f"could not reach {url}: {exc}", EXIT_NETWORK) from exc
    except json.JSONDecodeError as exc:
        raise CheckError(f"{url} did not return JSON", EXIT_NETWORK) from exc
    if not isinstance(payload, dict):
        raise CheckError(f"{url} returned an unexpected shape", EXIT_NETWORK)
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


def resolve(server: str, base: str) -> dict[str, Any] | None:
    """`07` §3.1's order: registry name or slug, npm name, PyPI name, repo URL."""
    looks_like_url = "://" in server or server.lower().startswith(("github.com/", "gitlab.com/"))
    if not looks_like_url:
        record = get_json(f"{base}/api/servers/{slugify(server)}.json")
        if record is not None:
            return record

    index = get_json(f"{base}/api/index.json")
    if index is None:
        raise CheckError(f"{base}/api/index.json is missing", EXIT_NETWORK)
    entries = index.get("servers", [])
    if looks_like_url:
        wanted = _repo_key(server)
        matches = [e for e in entries if _repo_key(e.get("repository_url", "")) == wanted]
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
        raise CheckError(
            f"{server!r} matches {len(matches)} published servers: {names}{more}. "
            "Name one by its registry name.",
            EXIT_USAGE,
        )
    return get_json(f"{base}/api/servers/{matches[0]['slug']}.json")


def _bar(score: int | None, weight: float, *, unicode_ok: bool) -> str:
    """The site's three regions — scored, lost, never measured — in text."""
    full, lost, void = ("▓", "░", "╱") if unicode_ok else ("#", "-", "/")
    measured = round(BAR_WIDTH * weight)
    scored = 0 if score is None else round(measured * score / 100)
    return full * scored + lost * (measured - scored) + void * (BAR_WIDTH - measured)


def _weight(axis: dict[str, Any]) -> float:
    try:
        return max(0.0, min(1.0, float(axis.get("assessed_weight") or 0)))
    except (TypeError, ValueError):
        return 0.0


def _unicode_ok() -> bool:
    try:
        "▓░╱─".encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def render_pretty(server: dict[str, Any], url: str) -> str:
    uni = _unicode_ok()
    head = f"{server['name']}  v{server['version']}"
    scanned = f"scanned {server['scanned_at'][:10]}"
    lines = [f"{head}{scanned:>{max(1, 72 - len(head))}}", ("─" if uni else "-") * 72]
    for key, label, _ in AXES:
        axis = server["axes"][key]
        if axis["score"] is None:
            whose = " (a limit of mcpwatchman)" if axis.get("fault") == "project" else ""
            reason = axis.get("reason") or "no reason recorded"
            lines.append(f"{label:<19}not assessed — {reason}{whose}")
            continue
        weight = _weight(axis)
        lines.append(
            f"{label:<19}{_bar(axis['score'], weight, unicode_ok=uni)}  "
            f"{axis['score']:>3}/100  measured {round(weight * 100)}%"
        )
    lines.append("")
    if server.get("registry_state", "listed") != "listed":
        lines.append(f"Registry: {server['registry_state']} — {server.get('registry_note', '')}")
    lines.append(
        "No composite score: it is withheld until a hand-audited gold set "
        "validates the weights. A score covers only the measured share of its axis."
    )
    lines.append(f"Details: {url}")
    return "\n".join(lines)


def render_json(server: dict[str, Any], url: str, api_url: str) -> str:
    payload = {
        "server": server["name"],
        "slug": server["slug"],
        "version": server["version"],
        "composite_score": None,
        "grade": None,
        "composite_published": False,
        "axes": {
            key: {
                "score": server["axes"][key]["score"],
                "assessed_weight": server["axes"][key]["assessed_weight"],
                "fault": server["axes"][key].get("fault"),
                "reason": server["axes"][key].get("reason", ""),
            }
            for key, _, _ in AXES
        },
        "registry_state": server.get("registry_state", "listed"),
        "registry_note": server.get("registry_note", ""),
        "methodology_version": server.get("methodology_version"),
        "scanned_at": server["scanned_at"],
        "url": url,
        "api_url": api_url,
    }
    return json.dumps(payload, indent=2)


def render_compact(server: dict[str, Any]) -> str:
    parts = [f"{server['name']}@{server['version']}"]
    for key, _, short in AXES:
        axis = server["axes"][key]
        parts.append(
            f"{short}=null" if axis["score"] is None
            else f"{short}={axis['score']}@{_weight(axis):.2f}"
        )
    parts.append("composite=withheld")
    return "  ".join(parts)


def run(server: str, fmt: str, threshold: int | None, version: str | None) -> None:
    base = base_url()
    record = resolve(server, base)
    if record is None:
        raise CheckError(
            f"{server!r} is not published by mcpwatchman. That is not a judgement: "
            "the published set is a growing sample of the registry, and absence "
            "means only that we have not scanned it.",
            EXIT_NOT_FOUND,
        )
    data = record.get("server", record)
    if version and version != data["version"]:
        raise CheckError(
            f"the published scan of {data['name']} is for version {data['version']}, "
            f"not {version}; earlier or later versions are not kept.",
            EXIT_NOT_FOUND,
        )
    url = f"{base}/servers/{data['slug']}/"
    api_url = f"{base}/api/servers/{data['slug']}.json"
    if fmt == "json":
        click.echo(render_json(data, url, api_url))
    elif fmt == "compact":
        click.echo(render_compact(data))
    else:
        click.echo(render_pretty(data, url))
    if threshold is not None:
        # `07` §14.1: a threshold compares the composite, which is withheld, so
        # it is a no-op with a notice — never a silent pass that reads as one.
        click.echo(
            "notice: --threshold is disabled until the composite is published; "
            "exiting 0 regardless of score.",
            err=True,
        )
