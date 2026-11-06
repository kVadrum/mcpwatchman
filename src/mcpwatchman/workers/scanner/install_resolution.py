"""What an install would resolve, from deps.dev — a LISTED block, never a score.

Operator ruling 2026-11-06 (1a): a registry-published npm or PyPI package that
ships no lockfile leaves Dependency Health unassessed, because only what a
publisher pinned is attributed to them (`03` §6, CLAUDE.md). What an install
of that package would actually fetch is still worth showing, so it is shown
beside the axis, separately labelled, deducting nothing.

**Never a package manager.** `04` §7 forbids code execution from scanned
source, and it was measured that this cannot be made safe here: npm 11.9.0 ran
a binary named in the scanned project's own `.npmrc` under
`--package-lock-only --ignore-scripts`, npm 11 runs a git dependency's
`prepare` despite the flag, and `.npmrc` / requirements files expand `${ENV}`
into URLs (2026-11-03). The resolved graph comes from deps.dev's v3
`:dependencies` endpoint instead: one fixed host, nothing executed here.

**The graph is read by the scorer's own reader.** The nodes become a synthetic
project, written by us into scratch space outside the scanned tree: a
manifest naming exactly deps.dev's `DIRECT` nodes and a lockfile pinning every
node. `osv_check.run_osv` then reads it, so the CVSS bands, groups, fixed
versions and timeouts are the ones the scored axis uses, and directness is
deps.dev's own. The resulting score is computed and thrown away; nothing here
is ever attributed to the publisher.

**What the label may claim** (`/rr` 2026-11-03): the date we fetched the
graph; that deps.dev records no resolution time and was measured lagging the
npm registry by up to about 30 hours; that its version picks can differ from
what a real install picks; that none of these versions was pinned by the
publisher. Nothing else.

deps.dev data is CC BY 4.0 (Open Source Insights); `LICENSE` carries the
carve-out and every rendering of this block names the source.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from mcpwatchman.workers.scanner.osv_check import OsvStatus, run_osv
from mcpwatchman.workers.scanner.reachability import Fault

SOURCE = "deps.dev"
SOURCE_URL = "https://deps.dev/"
ENDPOINT = (
    "https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}:dependencies"
)
_SYSTEMS = {"npm": "NPM", "pypi": "PYPI"}
_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}

# Bounds on the WORK (CLAUDE.md, attacker-controlled input): the graph's size
# is a consequence of what the publisher declared. A wall-clock deadline as
# well as a byte cap, for the reason `source._download` documents.
FETCH_TIMEOUT_S = 30
MAX_GRAPH_BYTES = 8 * 1024 * 1024
MAX_NODES = 5_000
MAX_LISTED = 50

# A name or version reaches a file we write, so it is checked against what the
# registry can legally hold before it is used; anything else is skipped and
# counted, and the block says the graph was read incompletely.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_!-]{0,63}$")

LABEL = (
    "Resolved by deps.dev, not pinned by the publisher: these are the versions "
    "deps.dev's resolver picked for an install of this package, which can "
    "differ from what a real install picks. deps.dev records no resolution "
    "time and has been measured lagging the npm registry by up to about 30 "
    "hours. Listed only — nothing here changes a score. Data: deps.dev (Open "
    "Source Insights), CC BY 4.0."
)


@dataclass(frozen=True, slots=True)
class InstallResolution:
    """The listed block. `status` is `ok` or `unavailable`; never a score."""

    status: str
    reason: str = ""
    # Whose gap an unavailable block is: `project` (deps.dev has no graph for
    # it, or it exceeds our bound) or `environment` (one run's network
    # accident). Never `publisher` — a missing third-party resolution says
    # nothing about what they shipped.
    fault: str | None = None
    source: str = SOURCE
    fetched_at: str = ""
    system: str = ""
    package: str = ""
    version: str = ""
    nodes: int = 0
    direct: int = 0
    skipped_nodes: int = 0
    findings: tuple[dict, ...] = field(default_factory=tuple)
    findings_total: int = 0
    label: str = LABEL

    def to_dict(self) -> dict:
        return {
            "status": self.status, "reason": self.reason, "fault": self.fault,
            "source": self.source, "source_url": SOURCE_URL,
            "fetched_at": self.fetched_at, "system": self.system,
            "package": self.package, "version": self.version, "nodes": self.nodes,
            "direct": self.direct, "skipped_nodes": self.skipped_nodes,
            "findings": list(self.findings), "findings_total": self.findings_total,
            "label": self.label,
        }




def fetch_graph(artifact: str, package: str, version: str) -> tuple[dict | None, str, Fault | None]:
    """deps.dev's resolved graph, or (None, reason, fault)."""
    import httpx

    url = ENDPOINT.format(
        system=_SYSTEMS[artifact], name=quote(package, safe=""), version=quote(version, safe="")
    )
    try:
        with httpx.stream("GET", url, timeout=FETCH_TIMEOUT_S, follow_redirects=False,
                          headers={"User-Agent": "mcpwatchman"}) as response:
            if response.status_code == 404:
                return None, "deps.dev holds no resolved graph for this version", Fault.PROJECT
            if response.status_code != 200:
                return None, f"deps.dev answered HTTP {response.status_code}", Fault.ENVIRONMENT
            body = bytearray()
            deadline = time.monotonic() + FETCH_TIMEOUT_S
            for chunk in response.iter_bytes(64 * 1024):
                if time.monotonic() > deadline:
                    return None, f"deps.dev did not answer within {FETCH_TIMEOUT_S}s", (
                        Fault.ENVIRONMENT)
                body += chunk
                if len(body) > MAX_GRAPH_BYTES:
                    return None, ("the resolved graph is larger than this scanner reads "
                                  f"({MAX_GRAPH_BYTES // (1024 * 1024)} MB)"), Fault.PROJECT
    except httpx.HTTPError as exc:
        return None, f"deps.dev could not be reached ({type(exc).__name__})", Fault.ENVIRONMENT
    try:
        doc = json.loads(bytes(body))
    except (ValueError, RecursionError):
        return None, "deps.dev's answer was not JSON", Fault.ENVIRONMENT
    if not isinstance(doc, dict):
        return None, "deps.dev's answer was not a graph", Fault.ENVIRONMENT
    return doc, "", None


def _nodes(doc: dict, artifact: str) -> tuple[list[tuple[str, str, str]], int, str]:
    """(name, version, relation) per usable node, the skipped count, any error."""
    error = doc.get("error")
    if isinstance(error, str) and error:
        return [], 0, error
    raw = doc.get("nodes")
    if not isinstance(raw, list):
        return [], 0, "the answer held no node list"
    if len(raw) > MAX_NODES:
        return [], 0, f"the resolved graph has more than {MAX_NODES} packages"
    name_ok = _NPM_NAME if artifact == "npm" else _PYPI_NAME
    out: list[tuple[str, str, str]] = []
    skipped = 0
    seen: set[tuple[str, str]] = set()
    for node in raw:
        key = node.get("versionKey") if isinstance(node, dict) else None
        relation = node.get("relation") if isinstance(node, dict) else None
        name = key.get("name") if isinstance(key, dict) else None
        version = key.get("version") if isinstance(key, dict) else None
        if relation == "SELF":
            continue
        if (relation not in ("DIRECT", "INDIRECT") or not isinstance(name, str)
                or not isinstance(version, str) or not name_ok.match(name)
                or not _VERSION.match(version)):
            skipped += 1
            continue
        if (name, version) in seen:
            continue
        seen.add((name, version))
        out.append((name, version, relation))
    return out, skipped, ""


def _key(name: str) -> str:
    """PEP 503 normalisation (a no-op for npm's lowercase names), so a name
    osv-scanner reports matches the one deps.dev resolved."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _write_project(dest: Path, artifact: str, nodes: list[tuple[str, str, str]]) -> None:
    """A synthetic project osv-scanner reads: our bytes, never the publisher's."""
    direct = sorted({n for n, _, r in nodes if r == "DIRECT"})
    if artifact == "npm":
        (dest / "package.json").write_text(json.dumps({
            "name": "mcpwatchman-install-resolution", "version": "0.0.0",
            "dependencies": {n: "*" for n in direct},
        }))
        packages: dict[str, dict] = {"": {"name": "mcpwatchman-install-resolution",
                                          "version": "0.0.0"}}
        for i, (name, version, _) in enumerate(nodes):
            # A name can resolve at two versions; each needs its own key, and
            # the extractor names a package by its LAST `node_modules/` segment.
            key = f"node_modules/{name}"
            if key in packages:
                key = f"node_modules/mcpw-dup-{i}/node_modules/{name}"
            packages[key] = {"version": version}
        (dest / "package-lock.json").write_text(json.dumps({
            "name": "mcpwatchman-install-resolution", "version": "0.0.0",
            "lockfileVersion": 3, "requires": True, "packages": packages,
        }))
    else:
        deps = ", ".join(json.dumps(n) for n in direct)
        (dest / "pyproject.toml").write_text(
            '[project]\nname = "mcpwatchman-install-resolution"\nversion = "0.0.0"\n'
            f"dependencies = [{deps}]\n"
        )
        lines = ['lock-version = "1.0"', 'created-by = "mcpwatchman"', ""]
        for name, version, _ in nodes:
            lines += ["[[packages]]", f"name = {json.dumps(name)}",
                      f"version = {json.dumps(version)}", ""]
        (dest / "pylock.toml").write_text("\n".join(lines))


def resolve(
    artifact: str, package: str, version: str, *, fetched_at: str, workdir: Path,
) -> InstallResolution:
    """The listed install-resolution block for one published package."""
    from mcpwatchman.workers.scanner.inventory import enumerate_tree

    system = _ECOSYSTEM[artifact]

    def block(status: str, reason: str = "", fault: Fault | None = None, *,
              nodes: int = 0, direct: int = 0, skipped: int = 0,
              findings: tuple[dict, ...] = (), total: int = 0) -> InstallResolution:
        return InstallResolution(
            status=status, reason=reason, fault=fault.value if fault else None,
            fetched_at=fetched_at, system=system, package=package, version=version,
            nodes=nodes, direct=direct, skipped_nodes=skipped,
            findings=findings, findings_total=total,
        )

    doc, why, fault = fetch_graph(artifact, package, version)
    if doc is None:
        return block("unavailable", why, fault or Fault.ENVIRONMENT)
    nodes, skipped, error = _nodes(doc, artifact)
    if error:
        return block("unavailable", f"deps.dev could not resolve this version: {error[:160]}",
                     Fault.PROJECT)
    n_nodes, n_direct = len(nodes), sum(1 for *_, r in nodes if r == "DIRECT")
    if not nodes:
        return block("ok", "deps.dev resolves no dependencies for this version",
                     skipped=skipped)
    scratch = Path(tempfile.mkdtemp(prefix="mcpw-resolve-", dir=workdir))
    try:
        _write_project(scratch, artifact, nodes)
        result = run_osv(scratch, enumerate_tree(scratch))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if result.status is not OsvStatus.OK:
        return block("unavailable", f"the resolved graph could not be checked: {result.reason}",
                     Fault.ENVIRONMENT, nodes=n_nodes, direct=n_direct, skipped=skipped)
    # Directness per (name, version) from deps.dev itself: the synthetic
    # manifest can only name packages, so a name resolved both directly and
    # underneath something at two versions would read "direct" twice.
    relation = {(_key(n), v): r for n, v, r in nodes}

    def direct_of(f) -> bool:
        r = relation.get((_key(f.package), f.version))
        return (r == "DIRECT") if r is not None else bool(f.direct)

    ranked = sorted(
        result.findings,
        key=lambda f: (0 if direct_of(f) else 1, -(f.cvss or 0), f.package, f.osv_id),
    )
    listed = tuple(
        {
            "package": f.package, "version": f.version, "osv_id": f.osv_id,
            "cve_id": f.cve_id, "severity": str(f.severity) if f.severity else "",
            "cvss": str(f.cvss) if f.cvss is not None else "",
            "relation": "direct" if direct_of(f) else "indirect",
            "fixed_version": f.fixed_version,
            "url": f"https://osv.dev/vulnerability/{f.osv_id}" if f.osv_id else "",
            "deducts": False,
        }
        for f in ranked[:MAX_LISTED]
    )
    return block("ok", nodes=n_nodes, direct=n_direct, skipped=skipped,
                 findings=listed, total=len(ranked))


__all__ = ["LABEL", "InstallResolution", "fetch_graph", "resolve"]
