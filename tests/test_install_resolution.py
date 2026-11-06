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

    def iter_bytes(self, size: int):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]


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


def test_every_listed_block_deducts_nothing_and_names_its_source(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(ir, "fetch_graph", lambda *a: (_graph(), "", None))
    block = ir.resolve("npm", "x", "1.0.0", fetched_at="2026-11-06T00:00:00Z",
                       workdir=tmp_path).to_dict()
    assert block["status"] == "ok" and block["nodes"] == 0
    assert "deps.dev" in block["label"] and "CC BY 4.0" in block["label"]
    assert "not pinned by the publisher" in block["label"]


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
    block = runner._install_resolution(resolution, "npm", "2026-11-06T00:00:00Z", tmp_path)
    assert block["status"] == "unavailable"
    assert block["fault"] == Fault.ENVIRONMENT.value
    assert "RuntimeError" in block["reason"]
