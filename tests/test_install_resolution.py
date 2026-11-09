"""The listed install-resolution block from deps.dev (operator ruling 2026-11-06, 1a)."""

from __future__ import annotations

import json
import shutil

import pytest

from mcpwatchman.workers.scanner import install_resolution as ir
from mcpwatchman.workers.scanner import runner
from mcpwatchman.workers.scanner.reachability import Fault

needs_osv = pytest.mark.skipif(
    shutil.which("osv-scanner") is None,
    reason="osv-scanner is a Go binary installed in the worker image",
)


def _node(name: str, version: str, relation: str, system: str = "NPM") -> dict:
    return {"versionKey": {"system": system, "name": name, "version": version},
            "relation": relation, "bundled": False, "errors": []}


def _graph(*nodes: dict) -> dict:
    return {"nodes": [_node("self", "1.0.0", "SELF"), *nodes], "edges": [], "error": ""}


# --- reading the graph: attacker-influenced names reach files we write -----


def test_only_names_and_versions_a_registry_can_hold_are_read() -> None:
    nodes, skipped, error = ir._nodes(_graph(
        _node("lodash", "4.17.15", "DIRECT"),
        _node("@scope/pkg", "1.0.0", "INDIRECT"),
        _node("../../etc/passwd", "1.0.0", "INDIRECT"),
        _node("ok", '1.0.0"\n[[packages]]', "INDIRECT"),
        _node("lodash", "4.17.15", "DIRECT"),
        {"versionKey": "not a dict", "relation": "DIRECT"},
    ), "npm")
    assert error == ""
    assert nodes == [("lodash", "4.17.15", "DIRECT"), ("@scope/pkg", "1.0.0", "INDIRECT")]
    assert skipped == 3


def test_a_graph_past_our_bound_is_not_read(monkeypatch) -> None:
    monkeypatch.setattr(ir, "MAX_NODES", 2)
    _, _, error = ir._nodes(_graph(*[_node(f"p{i}", "1.0.0", "INDIRECT") for i in range(3)]),
                            "npm")
    assert "more than 2 packages" in error


def test_a_resolution_deps_dev_reports_as_failed_is_not_listed() -> None:
    _, _, error = ir._nodes({"nodes": [], "edges": [], "error": "no matching version"}, "npm")
    assert error == "no matching version"


# --- whose gap an unavailable block is: never the publisher's ---------------


class _Response:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status_code, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None

    def iter_bytes(self, size: int | None = None):
        step = size or 1024
        for i in range(0, len(self._body), step):
            yield self._body[i:i + step]


class _Trickle(_Response):
    """A body arriving one byte per network read. Follows httpx's chunker:
    given a `size`, it yields nothing until that many bytes have arrived."""

    def __init__(self) -> None:
        super().__init__(200)
        self.reads = 0

    def iter_bytes(self, size: int | None = None):
        buf = b""
        while self.reads < 10_000:
            self.reads += 1
            buf += b" "
            if size is None or len(buf) >= size:
                yield buf
                buf = b""


def _serve(monkeypatch, response=None, raises=None) -> list[str]:
    import httpx
    urls: list[str] = []

    def stream(method, url, **kw):
        urls.append(url)
        if raises:
            raise raises
        return response
    monkeypatch.setattr(httpx, "stream", stream)
    return urls


def test_the_package_name_is_escaped_into_one_path_segment(monkeypatch) -> None:
    urls = _serve(monkeypatch, _Response(200, json.dumps(_graph()).encode()))
    ir.fetch_graph("npm", "@scope/name", "1.0.0")
    assert urls == ["https://api.deps.dev/v3/systems/NPM/packages/%40scope%2Fname"
                    "/versions/1.0.0:dependencies"]


@pytest.mark.parametrize(("response", "raises", "fault", "phrase"), [
    (_Response(404), None, Fault.PROJECT, "holds no resolved graph"),
    (_Response(503), None, Fault.ENVIRONMENT, "HTTP 503"),
    (_Response(200, b"{not json"), None, Fault.ENVIRONMENT, "not JSON"),
    (None, "network", Fault.ENVIRONMENT, "could not be reached"),
])
def test_an_unavailable_graph_names_whose_gap_it_is(
    monkeypatch, response, raises, fault, phrase
) -> None:
    import httpx
    _serve(monkeypatch, response, httpx.ConnectError("x") if raises else None)
    doc, why, got = ir.fetch_graph("npm", "x", "1.0.0")
    assert doc is None and got is fault and phrase in why


def test_a_graph_larger_than_our_bound_is_our_limit(monkeypatch) -> None:
    monkeypatch.setattr(ir, "MAX_GRAPH_BYTES", 10)
    _serve(monkeypatch, _Response(200, b"x" * 100))
    doc, why, fault = ir.fetch_graph("npm", "x", "1.0.0")
    assert doc is None and fault is Fault.PROJECT and "larger than" in why


def test_a_trickling_answer_is_cut_off_at_the_deadline(monkeypatch) -> None:
    """One byte per read, each inside httpx's per-read timeout: the deadline
    must be checked per read, or this one server stalls the sequential nightly
    (Codex leg, 2026-11-09). The fake clock advances a second per look."""
    import itertools
    import types
    trickle = _Trickle()
    _serve(monkeypatch, trickle)
    ticks = itertools.count()
    monkeypatch.setattr(ir, "time", types.SimpleNamespace(monotonic=lambda: float(next(ticks))))
    doc, why, fault = ir.fetch_graph("npm", "x", "1.0.0")
    assert doc is None and fault is Fault.ENVIRONMENT and "did not answer within" in why
    assert trickle.reads < 100, f"read {trickle.reads} times past a {ir.FETCH_TIMEOUT_S}s deadline"


def _finding(package: str, cvss: str | None, version: str = "1.0.0"):
    from decimal import Decimal

    from mcpwatchman.workers.scanner.osv_check import DependencyFinding
    return DependencyFinding(
        package=package, ecosystem="npm", version=version, osv_id=f"GHSA-{package}",
        severity=None, cvss=Decimal(cvss) if cvss else None, direct=None,
        lockfile="package-lock.json")


def _osv_returns(monkeypatch, *findings) -> None:
    from mcpwatchman.workers.scanner.osv_check import OsvResult, OsvStatus
    monkeypatch.setattr(ir, "run_osv", lambda *a, **k: OsvResult(
        status=OsvStatus.OK, findings=tuple(findings)))


def test_the_listed_findings_are_the_most_severe_whatever_their_relation(
    monkeypatch, tmp_path
) -> None:
    """The page says "the N most severe are listed": a low direct finding may
    not displace a critical indirect one (Codex leg, 2026-11-09)."""
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (_graph(
        _node("low", "1.0.0", "DIRECT"), _node("crit", "1.0.0", "INDIRECT"),
    ), "", None))
    _osv_returns(monkeypatch, _finding("low", "3.1"), _finding("crit", "9.8"))
    monkeypatch.setattr(ir, "MAX_LISTED", 1)
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="t", workdir=tmp_path)
    assert [f["package"] for f in block.findings] == ["crit"]
    assert block.findings_total == 2


def test_requirements_deps_dev_could_not_resolve_are_counted(monkeypatch, tmp_path) -> None:
    """Measured 2026-11-09: @mux/mcp 12.8.0's SELF node carries "could not find
    a version that satisfies requirement …", so that subtree is missing and a
    clean list would read as complete."""
    graph = _graph(_node("ok", "1.0.0", "DIRECT"))
    graph["nodes"][0]["errors"] = ["could not find a version that satisfies requirement"]
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (graph, "", None))
    _osv_returns(monkeypatch)
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="t", workdir=tmp_path).to_dict()
    assert block["status"] == "ok" and block["unresolved"] == 1


def test_nothing_resolved_because_nothing_could_be_is_not_no_dependencies(
    monkeypatch, tmp_path
) -> None:
    graph = _graph()
    graph["nodes"][0]["errors"] = ["could not resolve a", "could not resolve b"]
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (graph, "", None))
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="t", workdir=tmp_path)
    assert block.status == "unavailable" and block.fault == Fault.PROJECT.value
    assert "could not resolve 2" in block.reason and "no dependencies" not in block.reason


def test_every_listed_block_deducts_nothing_and_names_its_source(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (_graph(), "", None))
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="2026-11-06T00:00:00Z",
                       workdir=tmp_path).to_dict()
    assert block["status"] == "ok" and block["nodes"] == 0
    assert "deps.dev" in block["label"] and "CC BY 4.0" in block["label"]
    assert "not read from a lockfile the publisher shipped" in block["label"]


# --- the scorer's own reader, against the real binary -----------------------


@needs_osv
def test_the_synthetic_project_is_read_with_deps_devs_directness(monkeypatch, tmp_path) -> None:
    """lodash resolved directly at one version and underneath at another: the
    synthetic manifest can only name packages, so directness comes from the
    graph per version, not from the name."""
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (_graph(
        _node("lodash", "4.17.21", "DIRECT"),
        _node("lodash", "4.17.15", "INDIRECT"),
        _node("minimist", "1.2.5", "INDIRECT"),
    ), "", None))
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="2026-11-06T00:00:00Z", workdir=tmp_path)
    assert block.status == "ok", block.reason
    assert block.nodes == 3 and block.direct == 1
    relation = {(f["package"], f["version"]): f["relation"] for f in block.findings}
    assert relation[("lodash", "4.17.15")] == "indirect"
    assert relation[("minimist", "1.2.5")] == "indirect"
    assert all(f["deducts"] is False for f in block.findings)
    assert not list(tmp_path.iterdir()), "the synthetic project is removed"


@needs_osv
def test_a_pypi_graph_is_read_through_pylock(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (_graph(
        _node("Requests", "2.19.1", "DIRECT", system="PYPI"),
    ), "", None))
    block = ir.resolve("pypi", "x", "1.0.0", fetched_at="2026-11-06T00:00:00Z", workdir=tmp_path)
    assert block.status == "ok", block.reason
    assert block.findings and block.findings[0]["relation"] == "direct"


# --- the runner: one block's defect never costs the report ------------------


def test_the_runner_block_never_raises(monkeypatch, tmp_path) -> None:
    def boom(*a, **k):
        raise RuntimeError("a defect of ours")
    monkeypatch.setattr(runner, "resolve_install", boom)
    resolution = type("R", (), {"primary": "npm:x@1.0.0"})()
    block = runner._install_resolution(resolution, "npm", tmp_path)
    assert block["status"] == "unavailable"
    assert block["fault"] == Fault.ENVIRONMENT.value
    assert "RuntimeError" in block["reason"]


def test_fetched_at_is_when_deps_dev_was_asked(monkeypatch, tmp_path) -> None:
    """Not the scan's start: a long scan can cross a UTC midnight before the
    request (Codex leg, 2026-11-09)."""
    from datetime import UTC, datetime
    seen: list[str] = []

    def fake(artifact, name, version, *, fetched_at, workdir):
        seen.append(fetched_at)
        return ir.InstallResolution(status="ok", fetched_at=fetched_at)
    monkeypatch.setattr(runner, "resolve_install", fake)
    before = datetime.now(UTC).replace(microsecond=0)
    runner._install_resolution(type("R", (), {"primary": "npm:x@1.0.0"})(), "npm", tmp_path)
    assert datetime.fromisoformat(seen[0]) >= before
