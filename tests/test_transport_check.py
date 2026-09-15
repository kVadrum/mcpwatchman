"""Transport detection and the transport-security ladder (`04` §6, `03` §4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpwatchman.workers.crawler.registry import Package, RegistryEntry, Remote
from mcpwatchman.workers.scanner.inventory import enumerate_tree
from mcpwatchman.workers.scanner.transport_check import (
    TlsPosture,
    Transport,
    assess_transport,
    declared_transport,
    infer_transport,
    tls_posture,
)


def _entry(*, packages=(), remotes=()) -> RegistryEntry:
    return RegistryEntry(name="io.github.x/y", version="1.0.0",
                         packages=tuple(packages), remotes=tuple(remotes))


def _pkg(transport: str | None) -> Package:
    return Package(registry_type="npm", identifier="x", version="1", transport=transport)


# ── declaration ─────────────────────────────────────────────────────────────

def test_stdio_package_declares_stdio() -> None:
    assert declared_transport(_entry(packages=[_pkg("stdio")])) is Transport.STDIO


def test_network_transport_wins_over_stdio_when_both_declared() -> None:
    # Otherwise any server could opt out of transport scoring by also shipping
    # an npm package: it is exposed over the network either way.
    entry = _entry(packages=[_pkg("stdio")],
                   remotes=[Remote(type="streamable-http", url="https://x/mcp")])
    assert declared_transport(entry) is Transport.STREAMABLE_HTTP


def test_unrecognised_transport_string_is_unknown_not_a_crash() -> None:
    assert declared_transport(_entry(packages=[_pkg("carrier-pigeon")])) is Transport.UNKNOWN
    assert declared_transport(_entry(packages=[_pkg(None)])) is Transport.UNKNOWN


def test_nothing_declared_is_unknown() -> None:
    assert declared_transport(_entry()) is Transport.UNKNOWN


def test_sse_and_streamable_http_stay_distinct() -> None:
    # `03` §4 scores them identically, but collapsing them would erase a stale
    # declaration — a server declaring sse whose code wires streamable-http.
    assert Transport.SSE is not Transport.STREAMABLE_HTTP
    assert Transport.SSE.is_network and Transport.STREAMABLE_HTTP.is_network
    assert not Transport.STDIO.is_network


# ── TLS posture ─────────────────────────────────────────────────────────────

def test_stdio_has_no_transport_to_secure() -> None:
    assert tls_posture(_entry(packages=[_pkg("stdio")]), Transport.STDIO) is (
        TlsPosture.NOT_APPLICABLE
    )


@pytest.mark.parametrize(
    ("urls", "expected"),
    [
        (["https://a/mcp"], TlsPosture.HTTPS_ONLY),
        (["https://a/mcp", "https://b/mcp"], TlsPosture.HTTPS_ONLY),
        (["https://a/mcp", "http://b/mcp"], TlsPosture.MIXED),
        (["http://a/mcp"], TlsPosture.PLAINTEXT),
        ([], TlsPosture.UNKNOWN),
    ],
)
def test_tls_posture_from_declared_schemes(urls: list[str], expected: TlsPosture) -> None:
    entry = _entry(remotes=[Remote(type="streamable-http", url=u) for u in urls])
    assert tls_posture(entry, Transport.STREAMABLE_HTTP) is expected


def test_package_transport_url_template_is_not_read_as_a_scheme() -> None:
    # A package's transport URL is a template the installing user fills in, so
    # it describes their deployment, not the server. Only `remotes` count.
    entry = _entry(packages=[_pkg("streamable-http")])
    assert tls_posture(entry, Transport.STREAMABLE_HTTP) is TlsPosture.UNKNOWN


# ── the `03` §4 ladder ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("remotes", "packages", "expected"),
    [
        ((), [_pkg("stdio")], 100),
        ([Remote(type="streamable-http", url="https://a/mcp")], (), 80),
        ([Remote(type="streamable-http", url="https://a/mcp"),
          Remote(type="sse", url="http://a/mcp")], (), 50),
        ([Remote(type="sse", url="http://a/mcp")], (), 20),
    ],
)
def test_transport_security_bands(remotes, packages, expected: int) -> None:
    result = assess_transport(_entry(packages=packages, remotes=remotes))
    assert result.subcheck.score == expected


def test_https_only_is_capped_at_80_and_says_why() -> None:
    # `03` §4's 100 band needs an observed HSTS header and `04` §9 does not
    # connect. An 80 must not read as an observed missing header.
    result = assess_transport(_entry(remotes=[Remote(type="streamable-http",
                                                     url="https://a/mcp")]))
    assert result.subcheck.score == 80
    assert any("HSTS" in e for e in result.subcheck.evidence)
    assert any("not an observed absence" in e for e in result.subcheck.evidence)


def test_no_transport_declared_is_unassessed_not_zero() -> None:
    result = assess_transport(_entry())
    assert result.subcheck.score is None
    assert result.subcheck.reason


def test_network_transport_with_no_url_is_unassessed() -> None:
    result = assess_transport(_entry(remotes=[Remote(type="streamable-http", url="")]))
    assert result.subcheck.score is None


# ── code-level cross-check ──────────────────────────────────────────────────

def _tree(tmp_path: Path, **files: str) -> Path:
    for name, body in files.items():
        target = tmp_path / name.replace("__", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return tmp_path


def test_sdk_stdio_symbol_infers_stdio(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "from mcp.server.stdio import stdio_server\n"})
    assert infer_transport(root, enumerate_tree(root)) is Transport.STDIO


def test_sdk_http_symbol_beats_stdio_symbol(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "from x import StdioServerTransport, StreamableHTTPServerTransport\n"
    })
    assert infer_transport(root, enumerate_tree(root)) is Transport.STREAMABLE_HTTP


def test_generic_framework_is_a_weaker_fallback(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"app.py": "import fastapi\n"})
    assert infer_transport(root, enumerate_tree(root)) is Transport.STREAMABLE_HTTP


def test_test_files_do_not_decide_the_transport(tmp_path: Path) -> None:
    # An MCP test suite routinely instantiates every transport; a fixture must
    # not out-vote the server's own code.
    root = _tree(tmp_path, **{
        "server.py": "from mcp.server.stdio import stdio_server\n",
        "tests__test_http.py": "from x import StreamableHTTPServerTransport\n",
    })
    assert infer_transport(root, enumerate_tree(root)) is Transport.STDIO


def test_empty_tree_infers_unknown(tmp_path: Path) -> None:
    assert infer_transport(tmp_path, enumerate_tree(tmp_path)) is Transport.UNKNOWN


# ── mismatch ────────────────────────────────────────────────────────────────

def test_mismatch_when_code_contradicts_declaration(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "from x import StreamableHTTPServerTransport\n"})
    result = assess_transport(_entry(packages=[_pkg("stdio")]), root, enumerate_tree(root))
    assert result.declared is Transport.STDIO
    assert result.inferred is Transport.STREAMABLE_HTTP
    assert result.mismatch


def test_no_source_is_not_a_mismatch() -> None:
    # `inferred is None` means we never looked; UNKNOWN means we looked and
    # could not tell. Neither is a discrepancy.
    result = assess_transport(_entry(packages=[_pkg("stdio")]))
    assert result.inferred is None
    assert not result.mismatch


def test_unknown_inference_is_not_a_mismatch(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"notes.md": "nothing to see\n"})
    result = assess_transport(_entry(packages=[_pkg("stdio")]), root, enumerate_tree(root))
    assert result.inferred is Transport.UNKNOWN
    assert not result.mismatch


# --- regressions from the 2026-09-15 Deep review ---------------------------


@pytest.mark.parametrize(
    "source_text",
    [
        "// avoid the bottleneck here\n",          # 'bottle'
        "const s = tls.createServer(opts)\n",      # 'createServer('
        "// Koala-themed demo\n",                  # 'Koa'
        "import phonograph from 'phonograph'\n",   # 'hono'
    ],
)
def test_ordinary_source_does_not_manufacture_a_transport_mismatch(
    tmp_path: Path, source_text: str
) -> None:
    """⚠ These were bare substrings, and a hit makes `infer_transport` return
    STREAMABLE_HTTP — so a stdio server with no recognised SDK symbol became
    `mismatch=True`, which `04` §6 turns into a PUBLISHED Transparency finding
    that its declaration contradicts its code. An accusation built on the word
    "bottleneck"."""
    root = _tree(tmp_path, **{"server.py": source_text})
    result = assess_transport(_entry(packages=[_pkg("stdio")]), root, enumerate_tree(root))
    assert result.inferred is Transport.UNKNOWN
    assert not result.mismatch


@pytest.mark.parametrize(
    ("filename", "source_text"),
    [
        ("app.py", "from fastapi import FastAPI\n"),
        ("app.py", "import flask\n"),
        ("app.js", "import express from 'express'\n"),
        ("app.js", "const app = require('fastify')\n"),
        ("app.js", "const s = http.createServer(handler)\n"),
        ("main.go", 'import (\n\t"net/http"\n)\n'),
    ],
)
def test_a_real_framework_import_is_still_detected(
    tmp_path: Path, filename: str, source_text: str
) -> None:
    root = _tree(tmp_path, **{filename: source_text})
    assert infer_transport(root, enumerate_tree(root)) is Transport.STREAMABLE_HTTP
