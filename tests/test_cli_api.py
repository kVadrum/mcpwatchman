"""`cli.api`'s fetch, against a real local HTTP server rather than a stub.

The command tests stub `get_json`/`get_bytes`; these pin what those stubs
stand in for — a 404 is None, a body past the cap is refused rather than read
into memory, a non-JSON body is a network error — over a real socket.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator

import pytest

from mcpwatchman.cli import api

BODIES = {"/ok.json": b'{"a": 1}', "/list.json": b"[1]", "/text.json": b"not json",
          "/big": b"x" * 2048}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = BODIES.get(self.path)
        if body is None:
            self.send_error(404 if self.path != "/boom" else 500)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_a_404_is_none(server) -> None:
    assert api.get_bytes(f"{server}/missing", cap=10, accept="*/*") is None
    assert api.get_json(f"{server}/missing.json") is None


def test_a_body_at_the_cap_is_read_and_past_it_refused(server) -> None:
    assert api.get_bytes(f"{server}/big", cap=2048, accept="*/*") == b"x" * 2048
    with pytest.raises(api.CliError) as caught:
        api.get_bytes(f"{server}/big", cap=2047, accept="*/*")
    assert caught.value.exit_code == api.EXIT_NETWORK


def test_json_must_be_an_object(server) -> None:
    assert api.get_json(f"{server}/ok.json") == {"a": 1}
    for path in ("/list.json", "/text.json"):
        with pytest.raises(api.CliError) as caught:
            api.get_json(f"{server}{path}")
        assert caught.value.exit_code == api.EXIT_NETWORK


def test_a_server_error_is_a_network_error(server) -> None:
    with pytest.raises(api.CliError) as caught:
        api.get_bytes(f"{server}/boom", cap=10, accept="*/*")
    assert caught.value.exit_code == api.EXIT_NETWORK


def test_clean_replaces_controls_and_bidi_but_keeps_text() -> None:
    assert api.clean("a\x1b[31mb\u202ec\u2066d\x9be") == "a\ufffd[31mb\ufffdc\ufffdd\ufffde"
    assert api.clean("line1\n\tline2") == "line1\n\tline2"
    assert api.clean("line1\nline2", one_line=True) == "line1 line2"
    assert api.clean("naïve — ok") == "naïve — ok"
