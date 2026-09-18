"""Auth Posture detection and scoring (`04` §6, `03` §4).

Two things here are worth more than the rest: that absence of a declared
credential header is never scored as "no authentication", and that the
`detect-secrets` invocation keeps the two flags that make it scan anything.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from mcpwatchman.workers.crawler.registry import Header, Package, RegistryEntry, Remote
from mcpwatchman.workers.scanner import auth_check
from mcpwatchman.workers.scanner import auth_check as ac
from mcpwatchman.workers.scanner.auth_check import (
    _DETECT_SECRETS_ARGV,
    SecretFinding,
    assess_auth,
    scan_secrets,
)
from mcpwatchman.workers.scanner.inventory import LARGE_FILE_BYTES, enumerate_tree
from mcpwatchman.workers.scanner.reachability import Fault
from mcpwatchman.workers.scanner.transport_check import assess_transport


def _remote_entry(*, headers=(), url="https://a.example/mcp") -> RegistryEntry:
    return RegistryEntry(
        name="io.github.x/y", version="1.0.0",
        remotes=(Remote(type="streamable-http", url=url, headers=tuple(headers)),),
    )


def _stdio_entry() -> RegistryEntry:
    return RegistryEntry(
        name="io.github.x/y", version="1.0.0",
        packages=(Package(registry_type="npm", identifier="x", version="1",
                          transport="stdio"),),
    )


def _assess(entry: RegistryEntry, root: Path | None = None, **kw):
    inventory = enumerate_tree(root) if root is not None else None
    transport = assess_transport(entry, root, inventory)
    return assess_auth(entry, transport, root, inventory, **kw)


def _sub(axis, name):
    return next(s for s in axis.subchecks if s.name == name)


# ── the ecological-inference guard ──────────────────────────────────────────

def test_no_declared_header_and_no_source_is_unassessed_never_thirty() -> None:
    # `03` §4's "30 — no authentication" band requires ESTABLISHING absence. A
    # server can require auth without declaring the header: measured 2026-09-15,
    # only 10 of 100 remotes declare one at all. This is the exact inference the
    # project's own remote-half ruling rejected.
    axis = _assess(_remote_entry())
    model = _sub(axis, "authentication_model")
    assert model.score is None
    assert "not an absent one" in model.reason


def test_declared_required_credential_scores_eighty_not_a_hundred() -> None:
    axis = _assess(_remote_entry(headers=[
        Header(name="Authorization", is_required=True, is_secret=True)]))
    model = _sub(axis, "authentication_model")
    assert model.score == 80
    assert any("enforcement is unverified" in e for e in model.evidence)


def test_optional_credential_header_is_the_sixty_band() -> None:
    axis = _assess(_remote_entry(headers=[
        Header(name="Authorization", is_required=False, is_secret=True)]))
    assert _sub(axis, "authentication_model").score == 60


def test_non_secret_header_is_not_a_credential() -> None:
    axis = _assess(_remote_entry(headers=[
        Header(name="X-Trace-Id", is_required=True, is_secret=False)]))
    assert _sub(axis, "authentication_model").score is None


# ── the stdio carve-out ─────────────────────────────────────────────────────

def test_stdio_is_not_penalised_for_absent_auth() -> None:
    axis = _assess(_stdio_entry())
    assert _sub(axis, "authentication_model").score == 100
    assert _sub(axis, "transport_security").score == 100


def test_unknown_transport_cannot_borrow_the_stdio_carveout() -> None:
    axis = _assess(RegistryEntry(name="a/b", version="1"))
    assert _sub(axis, "authentication_model").score is None


# ── code-level detection ────────────────────────────────────────────────────

def _tree(tmp_path: Path, **files: str) -> Path:
    for name, body in files.items():
        target = tmp_path / name.replace("__", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return tmp_path


def test_source_with_no_auth_anywhere_is_the_thirty_band(tmp_path: Path) -> None:
    # With source, absence IS establishable — this is the one path to 30.
    root = _tree(tmp_path, **{
        "server.py": "from fastapi import FastAPI\napp = FastAPI()\n"
                     "@app.get('/x')\ndef x(): return {}\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    model = _sub(axis, "authentication_model")
    assert model.score == 30
    assert "source we fetched" in model.evidence[0]


def test_enforced_and_documented_auth_reaches_a_hundred(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "from fastapi import Depends, FastAPI\n"
                     "from fastapi.security import HTTPBearer\n"
                     "@app.get('/x')\ndef x(cred=Depends(HTTPBearer())): ...\n",
        "README.md": "# srv\nSend an API key in the Authorization header.\n" + "x" * 600,
    })
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 100


def test_enforced_but_undocumented_auth_is_eighty(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "from fastapi import Depends\nfrom fastapi.security import HTTPBearer\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 80


def test_credential_read_without_enforcement_is_sixty(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "def handler(req):\n    k = req.headers.get('Authorization')\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 60


# ── secret handling ─────────────────────────────────────────────────────────

def test_detect_secrets_argv_keeps_both_flags_that_make_it_scan() -> None:
    # ⚠ Both were measured 2026-09-15 to be load-bearing, and each fails the
    # same silent way — `"results": {}`, exit 0, reading as a clean tree:
    #   no --all-files      -> git-tracked files only; a fetched archive has no .git
    #   an absolute path    -> scans nothing even WITH --all-files
    # `04` §6 specifies the first broken form. This pins the working one so a
    # tidy-up cannot quietly restore a scan that reads nothing.
    assert "--all-files" in _DETECT_SECRETS_ARGV
    assert _DETECT_SECRETS_ARGV[-1] == "."
    assert not any(a.startswith("/") for a in _DETECT_SECRETS_ARGV)


def test_scan_runs_from_the_scan_root() -> None:
    seen: dict[str, object] = {}

    def runner(argv: Sequence[str], cwd: Path) -> str:
        seen["argv"], seen["cwd"] = list(argv), cwd
        return json.dumps({"results": {}})

    root = Path("/nonexistent/tree")
    assert scan_secrets(root, runner=runner) == []
    assert seen["cwd"] == root
    assert seen["argv"] == list(_DETECT_SECRETS_ARGV)


def test_committed_secret_drops_the_subcheck_to_zero(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "import os\n"})
    axis = _assess(_stdio_entry(), root,
                   secrets=[SecretFinding(path="app.py", line=4, kind="AWS Access Key")])
    handling = _sub(axis, "secret_handling")
    assert handling.score == 0
    assert handling.evidence == ("AWS Access Key at app.py:4",)


def test_secret_evidence_never_carries_the_credential(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "import os\n"})
    axis = _assess(_stdio_entry(), root,
                   secrets=[SecretFinding(path="a.py", line=1, kind="Private Key")])
    joined = " ".join(_sub(axis, "secret_handling").evidence)
    assert "BEGIN" not in joined and "AKIA" not in joined


def test_missing_tool_is_unassessed_not_a_clean_bill_of_health(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "import os\n"})
    axis = _assess(_stdio_entry(), root, secrets=None, scan_for_secrets=False)
    handling = _sub(axis, "secret_handling")
    assert handling.score is None
    assert "never happened" in handling.reason


def test_unparseable_tool_output_is_unassessed_not_clean() -> None:
    assert scan_secrets(Path("/x"), runner=lambda a, c: "not json") is None
    assert scan_secrets(Path("/x"), runner=lambda a, c: json.dumps({"ok": 1})) is None


def test_env_vars_documented_scores_a_hundred(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "import os\nT = os.environ['API_TOKEN']\n",
        "README.md": "Set the API_TOKEN environment variable.\n" + "x" * 600})
    axis = _assess(_stdio_entry(), root, secrets=[])
    assert _sub(axis, "secret_handling").score == 100


def test_env_vars_undocumented_scores_seventy(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{
        "server.py": "import os\nT = os.environ['API_TOKEN']\n",
        "README.md": "A server that does things.\n" + "x" * 600})
    assert _sub(_assess(_stdio_entry(), root, secrets=[]), "secret_handling").score == 70


# ── authorization granularity ───────────────────────────────────────────────

def test_few_tools_need_no_segregation(tmp_path: Path) -> None:
    root = _tree(tmp_path, **{"server.py": "@server.tool\ndef a(): ...\n"})
    axis = _assess(_stdio_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authorization_granularity").score == 100


def test_many_tools_without_access_logic_is_unassessed_not_invented(tmp_path: Path) -> None:
    # ⚠ `03` §4 gives this sub-check a heuristic and NO score band. A number
    # here would be a published score whose band exists nowhere in the
    # methodology — the mystery number this project exists to not produce.
    body = "\n".join(f"@server.tool\ndef t{i}(): ..." for i in range(6))
    root = _tree(tmp_path, **{"server.py": body})
    axis = _assess(_stdio_entry(), root, scan_for_secrets=False)
    granularity = _sub(axis, "authorization_granularity")
    assert granularity.score is None
    assert "assigns it no score band" in granularity.reason


def test_many_tools_with_access_logic_scores_a_hundred(tmp_path: Path) -> None:
    body = "\n".join(f"@server.tool\ndef t{i}(): ..." for i in range(6))
    root = _tree(tmp_path, **{
        "server.py": body + "\ndef guard(u):\n    if not has_permission(u): raise\n"})
    axis = _assess(_stdio_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authorization_granularity").score == 100


# ── the axis as a whole ─────────────────────────────────────────────────────

def test_source_less_server_is_scored_on_a_quarter_of_the_axis() -> None:
    from decimal import Decimal
    axis = _assess(_remote_entry())
    assert axis.assessed_weight == Decimal("0.25")
    assert not axis.fully_assessed
    assert {s.name for s in axis.unassessed} == {
        "authentication_model", "secret_handling", "authorization_granularity"}


def test_tool_availability_is_checked_before_shelling_out(monkeypatch) -> None:
    monkeypatch.setattr(auth_check.shutil, "which", lambda _: None)
    assert scan_secrets(Path("/x")) is None


@pytest.mark.skipif(
    __import__("shutil").which("detect-secrets") is None,
    reason="detect-secrets lives in the `workers` extra; CI installs only `dev`",
)
def test_real_detect_secrets_finds_a_planted_credential(tmp_path: Path) -> None:
    """The positive control for every zero this module reports.

    Without it, a broken invocation returns `[]` and every other secret test in
    this file still passes — which is exactly how `04` §6's specified invocation
    went unnoticed while scanning nothing.

    ⚠ **The PEM banner is ASSEMBLED rather than written as a literal**, and the
    AWS key is the vendor's own documented `…EXAMPLE` placeholder. Both are
    fakes, but a literal banner makes this repository match a committed-private-
    key pattern, which trips `leak-sweep` on every run. Silencing that scanner —
    or accepting the finding in the fleet accept-list — would spend a real
    security control on a fixture. The bytes written to disk are identical, so
    the control still proves what it proved.
    """
    dashes = "-" * 5
    banner = f"{dashes}BEGIN RSA PRIVATE KEY{dashes}"
    footer = f"{dashes}END RSA PRIVATE KEY{dashes}"
    (tmp_path / "app.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "id_rsa").write_text(f"{banner}\nMIIEowIBAAKCAQEAxxxx\n{footer}\n")
    kinds = {f.kind for f in (scan_secrets(tmp_path) or [])}
    assert {"AWS Access Key", "Private Key"} <= kinds


# --- direction: a credential SENT is not a credential CHECKED --------------
#
# ⚠ Found by this repo's own /qa, 2026-09-15. The first cut matched the bare
# tokens `api_key`, `apiKey`, `Bearer ` and `X-API-Key`, so a server that merely
# CALLS another API scored `03` §4's 60 band ("authentication present but
# bypassable") instead of its 30 band ("no authentication"). It over-scored by
# 30 points on the sub-check carrying 40% of Auth Posture, and it did so on
# precisely the unauthenticated-HTTP cohort this project's opening argument is
# about — an error in the generous direction, which for a security product is
# the worse way to be wrong.


@pytest.mark.parametrize(
    "source_text",
    [
        'client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])',
        'headers = {"Authorization": f"Bearer {token}"}',
        # The same direction error via the subscript form. An optional-quantifier
        # lookahead does NOT stop this — the engine backtracks to a shorter match
        # that ends before the `=`. The delimiters must be required.
        'headers["Authorization"] = f"Bearer {token}"',
        "req.headers['Authorization'] = 'Bearer x'",
    ],
)
def test_sending_a_credential_is_not_reading_one(tmp_path: Path, source_text: str) -> None:
    root = _tree(tmp_path, **{"server.py": source_text + "\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    model = _sub(axis, "authentication_model")
    assert model.score == 30, f"{source_text!r} should not read as client auth"


@pytest.mark.parametrize(
    "source_text",
    [
        "key = request.headers.get('Authorization')",
        'const k = req.headers["x-api-key"]',
        "auth = request.META.get('HTTP_AUTHORIZATION')",
        # `04` §6 names Go HTTP middleware; this is how Go spells it.
        'v := r.Header.Get("X-Api-Key")',
        'token = c.get_header("Authorization")',
        # A comparison is a read; only assignment is a write.
        'if headers["authorization"] == expected:\n    pass',
    ],
)
def test_reading_an_inbound_credential_header_still_counts(
    tmp_path: Path, source_text: str
) -> None:
    root = _tree(tmp_path, **{"server.py": source_text + "\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 60


def test_a_go_server_with_no_auth_at_all_does_not_score_a_hundred(tmp_path: Path) -> None:
    """⚠ The exact case a Deep review demonstrated end to end, 2026-09-15.

    `http.HandlerFunc` is Go's ordinary handler adapter — present in every Go
    HTTP server ever written — and it sat in `_AUTH_MIDDLEWARE`. Combined with
    `documented` testing `"auth" in readme` by substring, an `## Authors`
    heading finished the job: an unauthenticated server scored **100**, with the
    published evidence *"refused without credentials established by reading the
    code rather than by connecting"*. That sentence was simply false.
    """
    root = _tree(tmp_path, **{
        "main.go": 'package main\nimport "net/http"\n'
                   'func main() { http.Handle("/", http.HandlerFunc(h)) }\n',
        "README.md": "# srv\n\n## Authors\n\nSomeone\n" + "x" * 600,
    })
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 30


def test_fastapi_dependency_injection_is_not_authentication(tmp_path: Path) -> None:
    # `Depends(` matches a DB session or a pagination helper just as happily.
    root = _tree(tmp_path, **{
        "app.py": "from fastapi import Depends, FastAPI\n"
                  "@app.get('/x')\ndef x(db=Depends(get_db), page=Depends(paginate)): ...\n",
        "README.md": "# srv\n\n## Authors\n\nSomeone\n" + "x" * 600,
    })
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 30


def test_an_authors_heading_alone_is_not_auth_documentation(tmp_path: Path) -> None:
    # Real enforcement present, but the README documents nothing about auth —
    # so 80 (enforced, undocumented), never 100.
    root = _tree(tmp_path, **{
        "app.py": "from fastapi.security import HTTPBearer\n"
                  "@app.get('/x')\ndef x(c=Security(HTTPBearer())): ...\n",
        "README.md": "# srv\n\n## Authors\n\nSomeone\n" + "x" * 600,
    })
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    assert _sub(axis, "authentication_model").score == 80


# ── Codex leg 2: presence of a symbol read as enforcement ───────────────────

def test_an_imported_but_unwired_auth_library_does_not_reach_a_hundred(
    tmp_path: Path,
) -> None:
    """A bare import reached "refused without credentials … by reading the code".

    Same family as the `http.HandlerFunc` defect: presence of a symbol read as
    the thing the symbol is used for. The reproduction is a real shape — an
    import left behind by a refactor, or added in anticipation — with no route
    depending on it anywhere.
    """
    root = _tree(tmp_path, **{
        "server.py": "from fastapi import FastAPI\n"
                     "from fastapi.security import HTTPBearer\n"
                     "app = FastAPI()\n"
                     "@app.get('/data')\ndef data():\n    return {'ok': True}\n",
        "README.md": "# srv\nSend an API key in the Authorization header.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 80
    assert "no call site" in model.evidence[0]


def test_an_outbound_oauth_token_call_is_not_inbound_authentication(
    tmp_path: Path,
) -> None:
    """A server CALLING somebody else's `/oauth/token` scored 100.

    The direction error the bare `X-API-Key` tokens were retired for, arriving
    through OAuth vocabulary: this server authenticates nobody and fetches a
    token to call an upstream API. `03` §4's 30 band is the correct answer, and
    the README documents auth — which is what lifted it to 100.
    """
    root = _tree(tmp_path, **{
        "server.py": "import httpx\n"
                     "def upstream_token():\n"
                     "    return httpx.post('https://api.example.com/oauth/token',\n"
                     "        data={'grant_type': 'client_credentials'})\n",
        "README.md": "# srv\nUses OAuth2 to authenticate to the upstream API.\n"
                     + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 30


def test_inbound_token_verification_still_reaches_a_hundred(tmp_path: Path) -> None:
    """Control for the pruning above — it must not blind us to a real verifier."""
    root = _tree(tmp_path, **{
        "server.py": "import jwt\n"
                     "def guard(request):\n"
                     "    token = request.headers.get('Authorization')\n"
                     "    return jwt.decode(token, key, algorithms=['RS256'])\n",
        "README.md": "# srv\nEvery request must carry a bearer token.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 100


def test_the_low_level_tool_list_shape_counts_every_tool(tmp_path: Path) -> None:
    """`ListToolsRequestSchema` + `tools: [` counted 2 for five real tools.

    Under `03` §4's threshold of 3, so the server published "there is no
    multi-tool surface to segregate" while exposing five. The markers were
    added to fix a zero and turned it into a constant — a plausible number,
    which is the harder failure to see.
    """
    tools = ",\n".join(
        f'    {{ name: "t{i}", description: "does {i}", inputSchema: {{ type: "object" }} }}'
        for i in range(5)
    )
    root = _tree(tmp_path, **{
        "index.ts": "server.setRequestHandler(ListToolsRequestSchema, async () => ({\n"
                    f"  tools: [\n{tools}\n  ],\n}}));\n",
    })
    gran = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                "authorization_granularity")
    # Five tools, no conditional access logic: `03` §4 calls this "needs human
    # review" and assigns no band, so the honest outcome is unassessed — NOT
    # the 100 the miscount produced.
    assert gran.score is None
    assert "5 tool registrations" in gran.reason


def test_a_mixed_remote_set_scores_the_WEAKEST_endpoint(tmp_path: Path) -> None:
    """`any(is_required)` over flattened headers scored the strongest endpoint.

    One remote requiring `Authorization` and one requiring nothing reached the
    80 band while the second answered anyone who asked. An attacker uses the
    weakest path, so the quantifier has to be `all` over REMOTES.
    """
    entry = RegistryEntry(
        name="io.github.x/y", version="1.0.0",
        remotes=(
            Remote(type="streamable-http", url="https://a.example/mcp",
                   headers=(Header(name="Authorization",
                                   is_required=True, is_secret=True),)),
            Remote(type="sse", url="https://b.example/sse", headers=()),
        ),
    )
    model = _sub(_assess(entry), "authentication_model")
    assert model.score == 60
    assert "https://b.example/sse" in " ".join(model.evidence)


def test_a_tree_whose_source_cannot_be_read_abstains_rather_than_scoring_thirty(
    tmp_path: Path,
) -> None:
    """`_source_text` returning "" was passed on as ASSESSED source.

    "" is not None, so the ladder ran on it and published `03` §4's 30 band —
    "no authentication … appears anywhere in the source we fetched" — about a
    tree in which nothing was read. The file here is over `04` §3's 1 MB
    large-file threshold, so `Inventory.scannable` excludes it and
    `_source_text` has nothing left to join: a real state for a server shipping
    a bundled `dist/index.js`, not a contrived one.
    """
    root = _tree(tmp_path, **{"server.py": "# " + "x" * (LARGE_FILE_BYTES + 1) + "\n"})
    axis = _assess(_remote_entry(), root, scan_for_secrets=False)
    model = _sub(axis, "authentication_model")
    assert model.score is None
    assert "every file in it was oversized" in model.reason


def test_reading_a_PORT_from_the_environment_is_not_handling_a_credential(
    tmp_path: Path,
) -> None:
    """`uses_env` matched the ACCESSOR, so `os.getenv("PORT")` published
    "credentials are read from the environment, but the README does not
    document which" — a 30-point deduction for reading a port number."""
    root = _tree(tmp_path, **{
        "server.py": "import os\nPORT = int(os.getenv('PORT', '8080'))\n"
                     "HOST = os.environ.get('HOST', '0.0.0.0')\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    secret = _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling")
    assert secret.score == 100
    assert "credential-shaped name" in secret.evidence[0]


def test_reading_an_API_KEY_from_the_environment_still_registers(
    tmp_path: Path,
) -> None:
    """Control for the name test: the signal it narrows must survive it."""
    root = _tree(tmp_path, **{
        "server.py": "import os\nkey = os.environ['OPENAI_API_KEY']\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    secret = _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling")
    assert secret.score == 70
    assert "OPENAI_API_KEY" in secret.evidence[0]


# ── Codex leg 3: the narrowing that kept the mechanism ─────────────────────

@pytest.mark.parametrize("line", [
    "rows = db.introspection()",
    "const parsed = validateTokenizer(input)",
    "user.verify_tokenization()",
])
def test_ordinary_apis_are_not_inbound_token_verification(tmp_path: Path, line) -> None:
    """The OAuth narrowing fixed the VOCABULARY and kept the MECHANISM.

    Pruning `/oauth/` and `/callback` from the list left `t in source` matching
    bare substrings, so `introspect` inside `db.introspection()` and
    `validateToken` inside `validateTokenizer(` still read as inbound
    verification — an unauthenticated server doing database or text work back at
    `03` §4's 80 band, or 100 with a README that mentions auth. Each alternative
    now has to end in a call or a word boundary.
    """
    root = _tree(tmp_path, **{
        "server.py": f"import db\ndef handler(req):\n    {line}\n    return 1\n",
        "README.md": "# srv\nSend an API key in the Authorization header.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 30, model.evidence


@pytest.mark.parametrize("line", [
    "claims = jwt.decode(tok, key, algorithms=['RS256'])",
    "const payload = await jwtVerify(tok, JWKS)",
    "res.setHeader('WWW-Authenticate', 'Bearer realm=\"api\"')",
])
def test_real_inbound_verification_still_registers(tmp_path: Path, line) -> None:
    """Control for the narrowing above — it must not blind the detector."""
    root = _tree(tmp_path, **{
        "server.py": f"def guard(req):\n    {line}\n",
        "README.md": "# srv\nEvery request must carry a bearer token.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 100


def test_a_destructured_env_credential_is_not_a_clean_bill_of_health(
    tmp_path: Path,
) -> None:
    """`const { OPENAI_API_KEY } = process.env` puts the accessor LAST.

    The accessor-then-name regex captured nothing, so with a clean secret scan
    the sub-check scored 100 and published "no environment variable with a
    credential-shaped name is read anywhere in the source" about a server whose
    first line reads an API key. It is the commonest form in modern JS/TS.
    """
    root = _tree(tmp_path, **{
        "index.js": "const { OPENAI_API_KEY } = process.env;\n"
                    "export const client = new OpenAI({ apiKey: OPENAI_API_KEY });\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    secret = _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling")
    assert secret.score == 70
    assert "OPENAI_API_KEY" in secret.evidence[0]


def test_destructuring_only_non_credential_vars_is_still_clean(tmp_path: Path) -> None:
    """Control: the name test still decides, destructured or not."""
    root = _tree(tmp_path, **{
        "index.js": "const { PORT, HOST } = process.env;\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    assert _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling").score == 100


def test_resources_and_prompts_are_not_counted_as_tools(tmp_path: Path) -> None:
    """MCP declares resources and prompts with the SAME `name`/`description`
    shape as tools, so an unscoped object scan counted four resources beside
    three real tools, crossed `03` §4's threshold, and turned an assessable 100
    into an abstention — the conservative direction, and still a claim about a
    server we could have assessed."""
    resources = ",".join(
        f'{{ name: "r{i}", description: "a resource" }}' for i in range(4)
    )
    tools = ",".join(
        f'{{ name: "t{i}", description: "d", inputSchema: {{ type: "object" }} }}'
        for i in range(3)
    )
    root = _tree(tmp_path, **{
        "index.ts": f"const resources = [{resources}];\n"
                    f"server.setRequestHandler(ListToolsRequestSchema, async () => ({{\n"
                    f"  tools: [{tools}],\n}}));\n",
    })
    gran = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                "authorization_granularity")
    assert gran.score == 100
    assert "3 tool registration" in gran.evidence[0]


# ── Codex leg 4: SEVEN findings, and every one a regression from leg 3 ─────

@pytest.mark.parametrize("line", [
    "fetch('https://up.example/.well-known/oauth-authorization-server')",
    "const META = '/.well-known/oauth-protected-resource';",
])
def test_a_well_known_url_is_not_inbound_enforcement(tmp_path: Path, line) -> None:
    """The THIRD spelling of one mistake: `X-API-Key` the server sends,
    `/oauth/token` it posts to, and now a well-known URL it GETs.

    `/.well-known/oauth-authorization-server` is the DISCOVERY document an OAuth
    *client* fetches from an upstream, so an unauthenticated server that merely
    talks to somebody else's IdP reached the 100 band again. A path in a string
    says nothing about who serves it — no URL literal survives in the pattern.
    """
    root = _tree(tmp_path, **{
        "server.py": f"import httpx\ndef upstream():\n    return {line}\n",
        "README.md": "# srv\nUses OAuth2 against the upstream API.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 30, model.evidence


@pytest.mark.parametrize("line", [
    "claims = verify_jwt(token)",
    "const payload = verifyJwt(token)",
    "result = token_introspection(token)",
])
def test_the_call_forms_the_regex_rewrite_dropped_still_match(tmp_path: Path, line) -> None:
    """Converting the list to a regex silently lost three live spellings.

    A false ACCUSATION produced by the fix for a false exoneration: servers doing
    real inbound verification fell from source-established auth to the 60 or 30
    band. Nothing reports an alternative that stopped being reachable, so the
    check is to enumerate the old list.
    """
    root = _tree(tmp_path, **{
        "server.py": f"def guard(req):\n    tok = req.headers.get('Authorization')\n"
                     f"    {line}\n",
        "README.md": "# srv\nEvery request must carry a bearer token.\n" + "x" * 600,
    })
    model = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                 "authentication_model")
    assert model.score == 100, model.evidence


def test_a_bracket_inside_a_string_does_not_close_the_tools_array(tmp_path: Path) -> None:
    """`"pattern": "^[^]]+$"` is an ordinary JSON-Schema constraint, and the raw
    character walk closed the array on its `]` — ending the region inside the
    FIRST tool, so four tools counted as one and scored 100 for having no
    multi-tool surface."""
    tools = ('{ name: "a", description: "d", inputSchema: { pattern: "^[^]]+$" } },'
             + "".join(f'{{ name: "t{i}", description: "d", inputSchema: {{}} }},'
                       for i in range(3)))
    root = _tree(tmp_path, **{"index.ts": f"const defs = {{ tools: [{tools}] }};\n"})
    gran = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                "authorization_granularity")
    assert gran.score is None
    assert "4 tool registrations" in gran.reason


def test_a_quoted_json_manifest_key_still_finds_the_tools(tmp_path: Path) -> None:
    """A JSON MCP manifest writes `"tools": [...]`, and the bare-key pattern
    required the colon to follow `tools` directly — so the commonest manifest
    shape found no region and every JSON-declared tool list counted zero. The
    narrowing meant to stop RESOURCES counting as tools stopped MANIFEST tools
    counting at all."""
    tools = ",".join(f'{{"name": "t{i}", "description": "d"}}' for i in range(2))
    root = _tree(tmp_path, **{"server.json": '{"tools": [' + tools + ']}'})
    gran = _sub(_assess(_remote_entry(), root, scan_for_secrets=False),
                "authorization_granularity")
    assert gran.score == 100
    assert "2 tool registration" in gran.evidence[0]


def test_a_destructuring_default_is_not_the_variable_name(tmp_path: Path) -> None:
    """Splitting on ":" alone left the DEFAULT attached, breaking both ways:
    `{ PORT = defaults.API_KEY }` reported a credential read for a port, and
    `{ OPENAI_API_KEY = fallback }` missed a real one because the
    boundary-anchored name test no longer saw `KEY` at the end."""
    root = _tree(tmp_path, **{
        "index.js": "const { PORT = defaults.API_KEY } = process.env;\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    assert _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling").score == 100

    root2 = _tree(tmp_path / "b", **{
        "index.js": "const { OPENAI_API_KEY = fallback } = process.env;\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    found = _sub(_assess(_remote_entry(), root2, secrets=[]), "secret_handling")
    assert found.score == 70 and "OPENAI_API_KEY" in found.evidence[0]


def test_the_deno_destructuring_branch_is_not_dead(tmp_path: Path) -> None:
    """`Deno.env.toObject()` ends in `)`, and the following `;` is also a
    non-word character — so the trailing `\\b` could NEVER match and the branch
    was dead from the moment it was written, still publishing a clean bill of
    health."""
    root = _tree(tmp_path, **{
        "mod.ts": "const { OPENAI_API_KEY } = Deno.env.toObject();\n",
        "README.md": "# srv\n" + "x" * 600,
    })
    secret = _sub(_assess(_remote_entry(), root, secrets=[]), "secret_handling")
    assert secret.score == 70
    assert "OPENAI_API_KEY" in secret.evidence[0]


def test_a_detect_secrets_RUNTIME_failure_is_attributed_and_named_honestly(
    tmp_path, monkeypatch
) -> None:
    """Present-and-broken is not absent, and the page says which.

    ⚠ TWO DEFECTS IN ONE BRANCH, both found by the Codex leg of a `/qaa`.
    `shutil.which()` proves only that the binary EXISTS; `scan_secrets` then
    collapses a timeout, a crash and unparseable output into the same `None`
    that absence produces. So a `detect-secrets` that ran and died published
    *"was not available to this worker"* — false about our own toolchain — and
    the abstention carried no fault, so the axis stayed scored and
    `cohort.unpublishable_gaps` never examined it.

    The fault is the load-bearing half: both cases are ours, both are refused.
    The wording is the honest half: only one of them is true at a time, and it
    appears on a named third party's page.
    """
    (tmp_path / "app.py").write_text("import os\nKEY = os.environ['API_KEY']\n")
    entry = _remote_entry()

    monkeypatch.setattr(ac.shutil, "which", lambda _: "/usr/bin/detect-secrets")
    monkeypatch.setattr(
        ac, "scan_secrets", lambda *a, **k: None  # ran, produced nothing usable
    )
    failed = _sub(_assess(entry, tmp_path), "secret_handling")
    assert failed.score is None
    assert failed.fault == Fault.ENVIRONMENT.value, (
        "a scan that did not complete was published as somebody else's gap"
    )
    assert "was available but its run did not complete" in failed.reason
    assert "was not available to this worker" not in failed.reason

    monkeypatch.setattr(ac.shutil, "which", lambda _: None)
    absent = _sub(_assess(entry, tmp_path), "secret_handling")
    assert absent.fault == Fault.ENVIRONMENT.value
    assert "was not available to this worker" in absent.reason
