"""Auth Posture detection and scoring (`04` §6, `03` §4).

Assembles all four of Auth Posture's sub-checks into one `AxisResult`.
`transport_security` is computed by `transport_check` and passed in rather than
recomputed, so the axis has one assembler and the transport ladder has one home.

**Two of this axis's four sub-checks have a top band that requires connecting to
the server, which `04` §9 forbids.** `03` §4's 100 for authentication model is
"OAuth 2.0 or robust API key required; documented in README; **refused without
credentials**", and its 100 for transport security needs an observed HSTS
header. Neither is reachable from metadata alone.

That is not a reason to score the top band anyway, and it is not a reason to
refuse the axis. It splits by whether we have SOURCE:

- **With source**, "refused without credentials" is establishable by reading the
  code — auth middleware wrapping the routes is evidence of enforcement — so
  100 is reachable, and shipping readable source is rewarded, which is the whole
  thesis of the product.
- **Without source**, a declared credential header evidences a *requirement* but
  not its *enforcement*, so the honest ceiling is 80 and the evidence string says
  which of the two we established.

⚠ **The absence of a declared header is NOT evidence of no authentication**, and
scoring it as `03` §4's "30 — no authentication" would be the ecological
inference this project's own remote-half ruling rejected. A server can require
auth without declaring the header in its registry entry; measured 2026-09-15,
only 10 of 100 remotes declare one at all. So no-header-and-no-source is
`None` — unassessed, with the reason recorded — never 30.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 — detect-secrets is a subprocess by `04` §6's design
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mcpwatchman.workers.crawler.registry import RegistryEntry
from mcpwatchman.workers.scanner.inventory import Inventory, Role, read_text
from mcpwatchman.workers.scanner.transport_check import Transport, TransportAssessment
from mcpwatchman.workers.scoring.axes import AxisResult, SubCheck, score_axis

AXIS = "auth_posture"

# `\bauth\b` deliberately, not `auth` — see `documented` below.
_AUTH_DOCUMENTED_RE = re.compile(
    r"\b(?:api[ _-]?keys?|authorization|authentication|oauth2?|bearer token"
    r"|access token|credentials?|\bauth\b)\b",
    re.IGNORECASE,
)

# `03` §4's authorization-granularity heuristic: "does the server expose more
# than 3 tools, and is there any conditional access logic?"
GRANULARITY_TOOL_THRESHOLD = 3

# Bound on the content sweep, same reasoning as `transport_check.MAX_FILES_READ`.
MAX_FILES_READ = 40

SECRET_SCAN_TIMEOUT = 120

# Auth middleware and credential validation, by ecosystem (`04` §6).
# ⚠ **Every entry must be an AUTH construct, not a construct auth happens to
# use.** Two were not, and together they scored a Go server with no
# authentication at all as `03` §4's **100** — "OAuth 2.0 or robust API key
# required; refused without credentials" — on the unauthenticated-HTTP cohort
# this product exists to flag:
#
#   `http.HandlerFunc`  — Go's ordinary handler adapter. Present in every Go
#                         HTTP server ever written, authenticated or not.
#   `Depends(`          — FastAPI's general dependency injection. Matches a DB
#                         session, a pagination helper, a settings object.
#
# The module docstring earns the 100 band only because "auth middleware wrapping
# the routes is evidence of enforcement". A bare `Depends(` is evidence of
# nothing, so the evidence string asserting *"refused without credentials
# established by reading the code"* was simply false.
_AUTH_MIDDLEWARE = (
    # Python — FastAPI security dependencies name what they secure.
    "HTTPBearer", "HTTPBasic", "APIKeyHeader", "APIKeyQuery", "APIKeyCookie",
    "OAuth2PasswordBearer", "OAuth2AuthorizationCodeBearer", "SecurityScopes",
    "Security(", "Depends(get_current_user", "Depends(verify_", "Depends(require_",
    "Depends(authenticate", "Depends(auth", "@requires_auth", "login_required",
    "@requires(",
    # JavaScript / TypeScript
    "passport.", "express-jwt", "expressJwt", "requireAuth", "authMiddleware",
    "ensureAuthenticated", "verifyToken", "checkJwt", "authenticateToken",
    # Go — the adapter type is not a signal; a named auth middleware is.
    "middleware.Auth", "AuthMiddleware", "RequireAuth", "requireAuth(",
)
# ⚠ **INBOUND header access only.** This list used to include the bare tokens
# `api_key`, `apiKey`, `Bearer ` and `X-API-Key`, and that was a real defect in
# the generous direction: a server that merely CALLS another API —
# `OpenAI(api_key=os.environ["OPENAI_API_KEY"])` — matched, which lifted its
# authentication model from `03` §4's 30 band ("no authentication") to its 60
# band ("present but bypassable"). A credential the server SENDS says nothing
# about whether it CHECKS one, and the population that mis-scores is exactly the
# unauthenticated-HTTP cohort this project's opening argument is about.
#
# So every pattern here has to be a read of an INBOUND request header. The
# regex covers the accessor shapes across ecosystems; a bare identifier cannot
# distinguish direction and so cannot appear.
# The header names that carry a client credential.
_CREDENTIAL_HEADER = (
    r"(?:HTTP_)?(?:authorization|x-api-key|x_api_key|api-key|apikey"
    r"|x-auth-token|proxy-authorization)"
)

# Two accessor SHAPES, because they need different guards:
#
#   `.get("Authorization")` / `.Get(...)`  — inherently a read.
#   `["Authorization"]`                    — a read ONLY if nothing assigns to it.
#
# ⚠ The subscript guard is the load-bearing half and an optional-quantifier
# lookahead does NOT work here: with `["']?` and `\]?` optional, the engine
# backtracks to a shorter match that ends before the `=` and the lookahead
# passes anyway. The delimiters have to be REQUIRED for the guard to bind.
# `headers["Authorization"] = f"Bearer {t}"` is the server SENDING a credential
# — the same direction error the retired bare-token list made, arriving through
# the subscript form.
#
# Go is covered because `04` §6 names Go HTTP middleware and `r.Header.Get(...)`
# is how that ecosystem spells this. `get_header(...)` is its own branch: it is
# a CALL, not an accessor, so it never matched the accessor shape at all.
_CREDENTIAL_READ_RE = re.compile(
    rf"""(?:
        (?:headers?|META)\s*\.\s*(?:get|get_all|getlist|Get)\s*\(\s*
            ["']{_CREDENTIAL_HEADER}["']
      | (?:headers?|META)\s*\[\s*["']{_CREDENTIAL_HEADER}["']\s*\](?!\s*=[^=])
      | (?:get_header|getHeader|header)\s*\(\s*["']{_CREDENTIAL_HEADER}["']
    )""",
    re.IGNORECASE | re.VERBOSE,
)
_OAUTH_INDICATORS = (
    "/oauth/", "oauth2", "OAuth2", "PKCE", "code_challenge", "/callback",
    "jwt.decode", "jwt.verify", "jwks", "id_token",
)

# Credentials read from the environment rather than committed (`03` §4's
# "env vars are used" clause).
# ⚠ Python and JS only, until now — and the consequence was not a missing
# signal but a WRONG published claim. A Go or Rust server reading a credential
# from the environment scored 100 with the evidence *"no credential is read from
# the environment either — this server appears to handle no secrets"*.
_ENV_READS = (
    "os.environ", "os.getenv", "process.env", "Deno.env",
    "dotenv", "pydantic_settings", "BaseSettings",
    # Go (`os.Getenv`/`LookupEnv`), Rust (`std::env::var`), C#, Ruby, shell,
    # PowerShell. `getenv(` is matched case-insensitively below for the C family.
    "LookupEnv(", "env::var", "GetEnvironmentVariable", "ENV[", "$env:",
)
_ENV_READ_RE = re.compile(r"\bgetenv\s*\(", re.IGNORECASE)

# Tool registration, for the granularity heuristic's tool count.
_TOOL_PATTERNS = (
    re.compile(r"@\w+\.tool\b"),                     # Python SDK decorator
    re.compile(r"@tool\b"),
    re.compile(r"\bserver\.tool\("),                 # TS SDK, high-level
    re.compile(r"\bregisterTool\("),
    re.compile(r"\baddTool\("),
    # ⚠ The LOW-LEVEL TS SDK shape, and the commonest one in the wild:
    # `server.setRequestHandler(ListToolsRequestSchema, …)` returning a
    # `tools: [...]` array. It counted ZERO, and zero is below the threshold, so
    # a 5-tool server published *"0 tool registration(s) detected — at or below
    # `03` §4's threshold, so there is no multi-tool surface to segregate"*: a
    # fact asserted about the server out of a detector miss.
    re.compile(r"ListToolsRequestSchema"),
    re.compile(r"\btools\s*:\s*\[")               ,  # the array it returns
    re.compile(r'"name"\s*:\s*"[^"]+"\s*,\s*"description"'),  # manifest-shaped
)
# Per-tool conditional access: a permission test inside the handler.
_CONDITIONAL_ACCESS_TOKENS = (
    "if not authorized", "if (!authorized", "has_permission", "hasPermission",
    "check_scope", "checkScope", "require_scope", "requireScope",
    "is_allowed", "isAllowed", "can_access", "canAccess",
    "PermissionError",
)

# ⚠ `403` and `Forbidden` were plain substrings in the list above, and both
# misfire on ordinary code: `const PORT = 4030`, `sha = "b403f1"`,
# `timeout: 1403` all matched, each publishing *"N tool registrations with
# conditional access logic present in the same source"*. Word-bounded, and
# `403` additionally has to look like a status rather than a number.
_CONDITIONAL_ACCESS_RE = re.compile(
    r"\b(?:Forbidden|PermissionDenied|Unauthorized)\b"
    r"|(?:status|code|statusCode|status_code|HTTPException)[^\n]{0,20}\b403\b"
    r"|\b403\b[^\n]{0,20}(?:Forbidden|forbidden)",
)


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """One committed credential, identified without reproducing its value.

    `detect-secrets` reports a `hashed_secret` and never the plaintext, and this
    record keeps it that way: the type, the path and the line are enough to act
    on, and a finding that carries the credential turns every downstream
    surface — the API, the page, this repo's own logs — into a disclosure.
    """

    path: str
    line: int
    kind: str


# `detect-secrets` is invoked with cwd=<scan root> and the literal path ".".
# ⚠ **BOTH halves are load-bearing, and each fails the same silent way** — an
# empty `results` object, exit 0, indistinguishable from a clean repository.
# Measured 2026-09-15 against a tree holding a planted AWS key and a PEM block:
#
#   detect-secrets scan <abs>                 -> {}   (no --all-files: git-tracked only)
#   detect-secrets scan --all-files <abs>     -> {}   (absolute path scans nothing)
#   detect-secrets scan --all-files .  (cwd)  -> 2 findings
#
# `04` §6 specifies the first of these. A fetched npm or PyPI tree is an
# unpacked archive with no `.git`, so the spec's literal invocation reports an
# all-clear having read nothing — and the second row is worse, because the
# obvious fix has been applied and the scan is still empty. Positive-control
# this call if it is ever changed; a zero here is not evidence of a clean tree.
#
# Running from the root also makes the reported filenames relative to it, which
# is the path convention `FileRecord` already uses for evidence.
_DETECT_SECRETS_ARGV = ("detect-secrets", "scan", "--all-files", ".")


def scan_secrets(
    root: Path,
    runner: Callable[[Sequence[str], Path], str] | None = None,
) -> list[SecretFinding] | None:
    """Run `detect-secrets` over a fetched tree (`04` §6).

    Returns `None` — meaning *not assessed* — when the tool is absent, which is
    the normal state outside a scanner worker: `detect-secrets` lives in the
    `workers` extra and CI installs only `dev`. Returning `[]` there would be a
    clean bill of health issued by a scan that never ran.
    """
    if runner is None:
        if shutil.which("detect-secrets") is None:
            return None
        runner = _default_runner

    try:
        raw = runner(_DETECT_SECRETS_ARGV, root)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, dict):
        return None

    findings: list[SecretFinding] = []
    for path, items in results.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(
                SecretFinding(
                    path=str(path),
                    line=int(item.get("line_number") or 0),
                    kind=str(item.get("type") or "unknown"),
                )
            )
    return findings


def _default_runner(argv: Sequence[str], cwd: Path) -> str:
    result = subprocess.run(  # noqa: S603 — argv list, never a shell string
        list(argv),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=SECRET_SCAN_TIMEOUT,
        check=False,
    )
    return result.stdout


def _source_text(root: Path, inventory: Inventory) -> str:
    """Bounded read of the non-test source, for the code-level heuristics."""
    candidates = [
        f
        for f in inventory.scannable
        if f.role in (Role.SOURCE, Role.ENTRY_POINT, Role.MCP_MANIFEST)
    ]
    candidates.sort(key=lambda f: -f.size_bytes)
    return "\n".join(read_text(root, f.path) for f in candidates[:MAX_FILES_READ])


def _readme_text(root: Path, inventory: Inventory) -> str:
    for record in inventory.by_role(Role.DOCS):
        if record.path.lower().startswith("readme"):
            return read_text(root, record.path)
    return ""


def _declared_credentials(entry: RegistryEntry) -> tuple[bool, bool]:
    """(any credential header declared, any of them required)."""
    headers = [h for remote in entry.remotes for h in remote.credential_headers]
    return bool(headers), any(h.is_required for h in headers)


def _authentication_model(
    entry: RegistryEntry,
    transport: TransportAssessment,
    source: str | None,
    readme: str,
) -> SubCheck:
    """`03` §4's authentication-model ladder."""
    name = "authentication_model"

    if transport.declared is Transport.STDIO:
        return SubCheck(
            name, 100,
            evidence=("stdio transport: the client launches the server as a "
                      "subprocess, so the OS process boundary is the auth "
                      "boundary — `03` §4 does not penalise absent auth here",),
        )
    if transport.declared is Transport.UNKNOWN:
        return SubCheck(
            name, None,
            reason="the registry entry declares no transport, so `03` §4's "
                   "stdio carve-out cannot be applied either way",
        )

    declared, required = _declared_credentials(entry)
    header_names = sorted(
        {h.name for r in entry.remotes for h in r.credential_headers}
    )

    if source is None:
        if declared and required:
            return SubCheck(
                name, 80,
                evidence=(f"registry declares required credential header(s): "
                          f"{', '.join(header_names)}",
                          "scored 80, not 100: `03` §4's top band also requires "
                          "that the server REFUSE an uncredentialed request, "
                          "which cannot be established without connecting "
                          "(`04` §9). The requirement is declared; its "
                          "enforcement is unverified."),
            )
        if declared:
            return SubCheck(
                name, 60,
                evidence=(f"registry declares OPTIONAL credential header(s): "
                          f"{', '.join(header_names)} — `03` §4's "
                          "\"authentication present but optional\" band",),
            )
        return SubCheck(
            name, None,
            reason="no source to read and no credential header declared. An "
                   "undeclared header is not an absent one — measured "
                   "2026-09-15, only 10 of 100 remotes declare one at all — so "
                   "`03` §4's \"no authentication\" band is not established.",
        )

    has_middleware = any(t in source for t in _AUTH_MIDDLEWARE)
    has_credential_read = bool(_CREDENTIAL_READ_RE.search(source))
    has_oauth = any(t in source for t in _OAUTH_INDICATORS)
    # ⚠ WORD-BOUNDED. This was substring containment over a list that included
    # a bare "auth", so an `## Authors` heading — in practically every README —
    # satisfied "documented in the README" and lifted the band to 100.
    documented = bool(readme) and _AUTH_DOCUMENTED_RE.search(readme) is not None

    if (has_oauth or has_middleware) and documented:
        return SubCheck(
            name, 100,
            evidence=(
                "auth enforcement present in source"
                + (" (OAuth/JWT indicators)" if has_oauth else " (auth middleware)")
                + " and documented in the README",
                "\"refused without credentials\" (`03` §4) established by "
                "reading the code rather than by connecting",
            ),
        )
    if has_oauth or has_middleware or (declared and required):
        return SubCheck(
            name, 80,
            evidence=("credential enforcement present in source but not "
                      "documented in the README" if not documented else
                      "credential requirement present; enforcement partially "
                      "evidenced",),
        )
    if has_credential_read:
        return SubCheck(
            name, 60,
            evidence=("source reads a credential header but no enforcing "
                      "middleware or rejection path was found — `03` §4's "
                      "\"present but optional or trivially bypassable\" band",),
        )
    return SubCheck(
        name, 30,
        evidence=("network transport, and no authentication middleware, "
                  "credential-header read, or OAuth indicator appears anywhere "
                  "in the source we fetched — `03` §4's \"no authentication; "
                  "HTTP transport\" band",),
    )


def _secret_handling(
    secrets: list[SecretFinding] | None, source: str | None, readme: str
) -> SubCheck:
    """`03` §4's secret-handling sub-check."""
    name = "secret_handling"

    if source is None:
        return SubCheck(
            name, None,
            reason="no source was fetched, so there is nothing to scan for "
                   "committed credentials",
        )
    if secrets is None:
        return SubCheck(
            name, None,
            reason="`detect-secrets` was not available to this worker, so the "
                   "committed-credential scan did not run. A clean result here "
                   "would be a scan that never happened.",
        )
    if secrets:
        # Path, line and type only — never the credential, which `detect-secrets`
        # does not return in the first place and this must not reintroduce.
        located = tuple(f"{f.kind} at {f.path}:{f.line}" for f in secrets[:10])
        return SubCheck(
            name, 0, evidence=located + (
                (f"…and {len(secrets) - 10} more",) if len(secrets) > 10 else ()
            ),
        )

    uses_env = any(t in source for t in _ENV_READS) or bool(_ENV_READ_RE.search(source))
    if not uses_env:
        return SubCheck(
            name, 100,
            evidence=("no committed credential found, and no credential is read "
                      "from the environment either — this server appears to "
                      "handle no secrets",),
        )
    documented = bool(readme) and any(
        t in readme.upper() for t in ("ENV", "ENVIRONMENT", "_KEY", "_TOKEN", "_SECRET")
    )
    return SubCheck(
        name, 100 if documented else 70,
        evidence=("credentials are read from the environment"
                  + (" and documented in the README" if documented
                     else ", but the README does not document which"),),
    )


def _authorization_granularity(source: str | None, inventory: Inventory | None) -> SubCheck:
    """`03` §4's authorization-granularity heuristic.

    ⚠ **`03` §4 states this sub-check's heuristic but assigns it no score
    band.** It gives the test — "does the server expose more than 3 tools, and
    is there any conditional access logic?" — and then says the ambiguous case
    is "tagged needs human review", without saying what it scores. So the two
    cases the heuristic actually determines are scored, and the undetermined one
    is returned UNASSESSED rather than given a number invented here. A public
    score whose band exists nowhere in the published methodology is the mystery
    number this project exists to not produce.
    """
    name = "authorization_granularity"

    if source is None:
        return SubCheck(
            name, None,
            reason="no source was fetched, so neither the tool count nor any "
                   "access-control logic can be read",
        )

    tools = sum(len(pattern.findall(source)) for pattern in _TOOL_PATTERNS)
    # ⚠ ZERO is a detector failure, not a measurement. An MCP server that
    # registers no tools at all is not a thing; counting none means we did not
    # recognise the shape, and scoring 100 on that would assert "≤3 tools" about
    # a server we failed to read — the vacuous positive `declared_scopes`
    # refuses on the transparency axis, reached by a different route.
    if tools == 0:
        return SubCheck(
            name, None,
            reason="no tool registration was recognised anywhere in the source. "
                   "An MCP server registers tools by definition, so this is a "
                   "gap in our detection rather than a server with none, and "
                   "`03` §4's threshold cannot be applied to it.",
        )
    if tools <= GRANULARITY_TOOL_THRESHOLD:
        return SubCheck(
            name, 100,
            evidence=(f"{tools} tool registration(s) detected — at or below "
                      f"`03` §4's threshold of {GRANULARITY_TOOL_THRESHOLD}, so "
                      "there is no multi-tool surface to segregate",),
        )
    has_access_logic = any(t in source for t in _CONDITIONAL_ACCESS_TOKENS) or bool(
        _CONDITIONAL_ACCESS_RE.search(source)
    )
    if has_access_logic:
        return SubCheck(
            name, 100,
            evidence=(f"{tools} tool registrations with conditional access "
                      "logic present in the same source",),
        )
    return SubCheck(
        name, None,
        reason=f"{tools} tool registrations and no conditional access logic "
               "found — `03` §4 calls this case 'needs human review' and "
               "assigns it no score band, so it is not scored here",
    )


def assess_auth(
    entry: RegistryEntry,
    transport: TransportAssessment,
    root: Path | None = None,
    inventory: Inventory | None = None,
    secrets: list[SecretFinding] | None = None,
    scan_for_secrets: bool = True,
) -> AxisResult:
    """Score the Auth Posture axis (`03` §4) for one server.

    `root`/`inventory` are optional: roughly half the registry ships no fetchable
    source, and this axis still has real work to do for those servers from the
    declared transport, endpoint scheme and credential headers alone.
    """
    has_source = root is not None and inventory is not None
    source = _source_text(root, inventory) if has_source else None
    readme = _readme_text(root, inventory) if has_source else ""

    if has_source and secrets is None and scan_for_secrets:
        secrets = scan_secrets(root)

    return score_axis(
        AXIS,
        [
            _authentication_model(entry, transport, source, readme),
            transport.subcheck,
            _secret_handling(secrets, source, readme),
            _authorization_granularity(source, inventory),
        ],
    )
