"""Transport detection and the transport-security sub-check (`04` §6, `03` §4).

Two jobs that `04` §6 deliberately separates:

1. **What transport does this server use?** The manifest's declaration is the
   PRIMARY signal; code-level detection is a CROSS-CHECK, and a mismatch is a
   Transparency finding rather than a transport one. Stated that way round
   because the reverse — trusting the code and treating the declaration as
   noise — loses the ability to say the declaration was wrong, which is the
   finding a reader most wants.
2. **How secure is it?** `03` §4's transport-security ladder, which is 25% of
   Auth Posture.

⚠ **`03` §4's top band is structurally unreachable for a network server, and
this is a methodology gap rather than a scoring choice.** The 100 band is
"stdio, or HTTPS-only HTTP/SSE **with HSTS headers**" — and an HSTS header can
only be observed by connecting, which `04` §9 forbids on purpose. So every
remote server's ceiling here is 80, not because we found a missing header but
because we cannot look for one. The evidence string says exactly that rather
than letting an 80 read as an observed absence.

**stdio is scored 100 and is not a courtesy.** `03` §4: a stdio server is
launched by its client as a subprocess, so the security boundary is the client
process, not a network port. There is no transport to secure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from mcpwatchman.workers.crawler.registry import RegistryEntry
from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_text
from mcpwatchman.workers.scanner.reachability import Fault
from mcpwatchman.workers.scoring.axes import SubCheck

# How many source files the code-level cross-check will open. Entry points are
# read first and are normally one or two files; the rest is a bounded sweep of
# the largest source files, which is where a server's wiring lives. A tree can
# hold 100,000 files and this check is a heuristic cross-check, not a parser.
MAX_FILES_READ = 40


class Transport(StrEnum):
    """The registry's own vocabulary, not a normalised one.

    Keeping `streamable-http` and `sse` distinct matters for the cross-check: a
    server declaring `sse` whose code wires `StreamableHTTPServerTransport` has
    a stale declaration worth reporting, and a normalised `HTTP` would erase it.
    `03` §4 scores them identically, which is `is_network`'s job.
    """

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"
    UNKNOWN = "unknown"

    @property
    def is_network(self) -> bool:
        return self in (Transport.STREAMABLE_HTTP, Transport.SSE)


class TlsPosture(StrEnum):
    NOT_APPLICABLE = "not_applicable"  # stdio — no network transport at all
    HTTPS_ONLY = "https_only"
    MIXED = "mixed"
    PLAINTEXT = "plaintext"
    UNKNOWN = "unknown"


# MCP SDK transport symbols. These are the PRECISE signal — a server importing
# `StdioServerTransport` is stdio, full stop — so they are tested before the
# generic framework names below, which only say "there is an HTTP server in this
# repository" and are wrong whenever a stdio server ships an unrelated web demo.
_SDK_STDIO = (
    "StdioServerTransport",
    "stdio_server",
    "mcp.server.stdio",
    "serve_stdio",
)
_SDK_HTTP = (
    "StreamableHTTPServerTransport",
    "streamable_http_app",
    "StreamableHTTPSessionManager",
)
_SDK_SSE = (
    "SSEServerTransport",
    "sse_app",
    "SseServerTransport",
)

# Generic HTTP server frameworks, by language. Weaker evidence than the SDK
# symbols and used only when none of those appear.
# ⚠ **IMPORT CONTEXT, not bare substrings.** These were plain `in` tests, and
# ordinary source matched them:
#
#   "// avoid the bottleneck here"  -> 'bottle'
#   "tls.createServer(opts)"        -> 'createServer('
#   "// Koala-themed demo"          -> 'Koa'        ("hono" also hits "phono*")
#
# Any hit makes `infer_transport` return STREAMABLE_HTTP, so a server declaring
# stdio with no recognised SDK symbol becomes `mismatch=True` — which `04` §6
# turns into a PUBLISHED Transparency finding that its declaration contradicts
# its code. An accusation built on the word "bottleneck".
_HTTP_FRAMEWORK_RE = re.compile(
    # Python: an actual import of the framework.
    r"^\s*(?:from|import)\s+(?:fastapi|flask|starlette|quart|tornado|sanic|bottle|aiohttp)\b"
    r"|^\s*from\s+aiohttp\s+import\s+web\b"
    # JS/TS: import or require of a named framework.
    r"|(?:from|require\s*\()\s*['\"](?:express|fastify|koa|hono|@hapi/hapi)['\"]"
    # Node's own servers, qualified so `tls.createServer` does not count.
    r"|\b(?:http|https)\.createServer\s*\("
    # Go: the import path, which is already quoted and unambiguous.
    r"|\"net/http\"",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class TransportAssessment:
    """What the transport is, how we know, and what it scores."""

    declared: Transport
    # None when there was no source to read — a remote-only server, or a fetch
    # that failed. Distinct from UNKNOWN, which means "we read the code and
    # could not tell"; collapsing the two would report a server we never
    # downloaded as one whose code was inscrutable.
    inferred: Transport | None
    tls: TlsPosture
    subcheck: SubCheck
    evidence: tuple[str, ...] = ()

    @property
    def mismatch(self) -> bool:
        """Declaration contradicts the code. A Transparency finding (`04` §6).

        Only a contradiction counts: either side being UNKNOWN, or there being
        no source at all, is missing evidence rather than a discrepancy.
        """
        if self.inferred is None:
            return False
        if Transport.UNKNOWN in (self.declared, self.inferred):
            return False
        return self.declared is not self.inferred


def declared_transport(entry: RegistryEntry) -> Transport:
    """The transport the registry entry declares (`04` §6's primary signal).

    A server may declare several: packages carry a transport each and remotes
    carry a type each. A network transport wins over stdio when both appear,
    because a server reachable over the network is exposed over the network
    regardless of also shipping a stdio package — and scoring the safer of two
    true declarations would let any server opt out of transport scoring by also
    publishing an npm package.
    """
    found: set[Transport] = set()
    for package in entry.packages:
        found.add(_as_transport(package.transport))
    for remote in entry.remotes:
        found.add(_as_transport(remote.type))

    for candidate in (Transport.STREAMABLE_HTTP, Transport.SSE, Transport.STDIO):
        if candidate in found:
            return candidate
    return Transport.UNKNOWN


def _as_transport(raw: str | None) -> Transport:
    if not raw:
        return Transport.UNKNOWN
    try:
        return Transport(raw.strip().lower())
    except ValueError:
        return Transport.UNKNOWN


def tls_posture(entry: RegistryEntry, declared: Transport) -> TlsPosture:
    """TLS from the declared endpoint URLs (`03` §4's transport-security ladder).

    Only `remotes` are consulted. A package's transport may also carry a URL,
    but it is a TEMPLATE the installing user fills in (`https://{HOST}:{PORT}/`),
    so it describes the user's future deployment rather than a property of the
    server — scoring it would grade a maintainer for their user's hostname.
    """
    if declared is Transport.STDIO:
        return TlsPosture.NOT_APPLICABLE
    schemes = {(urlparse(r.url).scheme or "").lower() for r in entry.remotes if r.url}
    schemes.discard("")
    if not schemes:
        return TlsPosture.UNKNOWN
    if schemes == {"https"}:
        return TlsPosture.HTTPS_ONLY
    if "https" in schemes:
        return TlsPosture.MIXED
    return TlsPosture.PLAINTEXT


def infer_transport(root: Path, inventory: Inventory) -> Transport:
    """Cross-check the declaration against the code (`04` §6).

    Entry points first — `04` §6 wants the file that actually runs, not an
    arbitrary match anywhere in the tree — then a bounded sweep. Tests are
    excluded: an MCP test suite routinely instantiates every transport, so a
    fixture would otherwise decide the server's transport.
    """
    text = _read_bounded(root, inventory)
    if not text:
        return Transport.UNKNOWN
    # SDK symbols beat framework names, and within them a network transport
    # beats stdio for the reason `declared_transport` gives.
    if any(token in text for token in _SDK_HTTP):
        return Transport.STREAMABLE_HTTP
    if any(token in text for token in _SDK_SSE):
        return Transport.SSE
    if any(token in text for token in _SDK_STDIO):
        return Transport.STDIO
    if _HTTP_FRAMEWORK_RE.search(text):
        return Transport.STREAMABLE_HTTP
    return Transport.UNKNOWN


def _read_bounded(root: Path, inventory: Inventory) -> str:
    """Concatenate entry points and the largest non-test source files."""
    entry_paths = {e.lstrip("./") for e in inventory.entry_points}
    scannable = [f for f in inventory.scannable if f.role is not Role.TEST]

    ordered = [f for f in scannable if f.path in entry_paths]
    ordered += [
        f
        for f in sorted(scannable, key=lambda f: -f.size_bytes)
        if f.path not in entry_paths and f.role in (Role.SOURCE, Role.ENTRY_POINT)
    ]

    chunks = [read_text(root, f.path) for f in ordered[:MAX_FILES_READ]]
    return "\n".join(chunks)


def assess_transport(
    entry: RegistryEntry,
    root: Path | None = None,
    inventory: Inventory | None = None,
) -> TransportAssessment:
    """Full transport assessment (`04` §6) plus its `03` §4 sub-check score.

    `root`/`inventory` are optional because roughly half the registry ships no
    fetchable source (measured 2026-09-14) and this check still has real work to
    do for those servers: the declaration and the endpoint scheme both come from
    the registry. Without source the cross-check is skipped, not failed.
    """
    declared = declared_transport(entry)
    inferred = (
        infer_transport(root, inventory)
        if root is not None and inventory is not None
        else None
    )
    posture = tls_posture(entry, declared)
    score, reason, evidence, fault = _score_transport_security(declared, posture, entry)

    return TransportAssessment(
        declared=declared,
        inferred=inferred,
        tls=posture,
        subcheck=SubCheck(
            name="transport_security", score=score, reason=reason,
            evidence=evidence, fault=fault,
        ),
        evidence=evidence,
    )


def _score_transport_security(
    declared: Transport, posture: TlsPosture, entry: RegistryEntry
) -> tuple[int | None, str, tuple[str, ...], str]:
    """`03` §4's transport-security ladder, applied to declared facts only.

    ⚠ **RETURNS THE FAULT AS A FOURTH ELEMENT, so a new branch cannot forget
    it.** Both abstentions here were reaching `SubCheck`'s default —
    `UNATTRIBUTED`, which `cohort.publication_errors` refuses — so an entry
    declaring no transport at all would have failed the whole run at
    publication with nothing naming this as the cause. It never fired because
    every entry the cohort holds declares a package or a remote; a synthetic
    entry built for an end-to-end smoke test found it in one call.

    Both are the PUBLISHER's: the entry's own declarations are what is missing,
    exactly as `authentication_model` already says one line away.
    """
    urls = tuple(r.url for r in entry.remotes if r.url)

    if declared is Transport.STDIO:
        return (
            100,
            "",
            ("declared transport: stdio — launched as a subprocess by the client, "
             "so the security boundary is the client process, not a network port "
             "(`03` §4)",),
            Fault.UNATTRIBUTED.value,
        )
    if declared is Transport.UNKNOWN:
        return (
            None,
            "the registry entry declares no transport for any package or remote",
            (),
            Fault.PUBLISHER.value,
        )

    if posture is TlsPosture.HTTPS_ONLY:
        return (
            80,
            "",
            (f"declared endpoint(s) are HTTPS: {', '.join(urls)}",
             "scored 80, not 100: `03` §4 reserves 100 for HTTPS *with HSTS*, and "
             "an HSTS header can only be seen by connecting, which `04` §9 does "
             "not do. This is an unverifiable band, not an observed absence."),
            Fault.UNATTRIBUTED.value,
        )
    if posture is TlsPosture.MIXED:
        return (
            50,
            "",
            (f"both HTTP and HTTPS endpoints declared: {', '.join(urls)}",),
            Fault.UNATTRIBUTED.value,
        )
    if posture is TlsPosture.PLAINTEXT:
        return (
            20,
            "",
            (f"declared endpoint(s) are plaintext HTTP: {', '.join(urls)}",),
            Fault.UNATTRIBUTED.value,
        )
    return (
        None,
        f"transport is {declared.value} but the entry declares no endpoint URL "
        "to read a scheme from",
        (),
        Fault.PUBLISHER.value,
    )
