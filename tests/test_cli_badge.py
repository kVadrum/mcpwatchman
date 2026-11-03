"""`mcpwatchman badge` (`07` §9): stdout is the snippet and nothing else."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from mcpwatchman.cli import api as cli_api
from mcpwatchman.cli import badge as badge_mod
from mcpwatchman.cli.main import cli

RECORD = {"server": {"name": "io.example/tool", "slug": "io-example-tool", "version": "1"}}
INDEX = {"servers": [{"name": "io.example/tool", "slug": "io-example-tool",
                      "package": "npm:@example/tool@1", "repository_url": ""}]}


@pytest.fixture
def served(monkeypatch):
    def setup(base, *, image=True):
        docs = {f"{base}/api/servers/io-example-tool.json": RECORD, f"{base}/api/index.json": INDEX}
        monkeypatch.setenv("MCPWATCHMAN_API_URL", base)
        monkeypatch.setattr(cli_api, "get_json", lambda url: docs.get(url))
        monkeypatch.setattr(
            badge_mod, "get_bytes",
            lambda url, **_: b"<svg/>" if image and url == f"{base}/badge/io-example-tool.svg"
            else None,
        )
    return setup


def run(*args):
    return CliRunner().invoke(cli, ["badge", *args])


def test_the_snippet_is_exact_and_alone_on_stdout(served) -> None:
    served("https://mcpwatchman.com")
    result = run("io.example/tool")
    assert result.exit_code == 0, result.output
    assert result.stdout == (
        "[![mcpwatchman](https://mcpwatchman.com/badge/io-example-tool.svg)]"
        "(https://mcpwatchman.com/servers/io-example-tool/)\n"
    )
    assert result.stderr == ""


def test_the_api_override_moves_both_urls(served) -> None:
    served("http://localhost:4321")
    result = run("@example/tool")  # an npm name resolves to the server's own slug
    assert result.stdout.strip() == (
        "[![mcpwatchman](http://localhost:4321/badge/io-example-tool.svg)]"
        "(http://localhost:4321/servers/io-example-tool/)"
    )


def test_an_unserved_image_is_said_on_stderr_only(served) -> None:
    served("https://mcpwatchman.com", image=False)
    result = run("io.example/tool")
    assert result.exit_code == 0
    assert result.stdout.startswith("[![mcpwatchman]")
    assert "not served yet" in result.stderr


def test_an_unpublished_server_gets_no_snippet(served) -> None:
    served("https://mcpwatchman.com")
    result = run("io.example/unknown")
    assert result.exit_code == cli_api.EXIT_NOT_FOUND
    assert "[![" not in result.stdout
