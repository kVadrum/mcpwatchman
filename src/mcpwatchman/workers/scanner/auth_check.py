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
from mcpwatchman.workers.scanner.reachability import Fault
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

# ⚠ **"No source" and "source we could not read" are different facts**, and
# collapsing them is how an unassessable became a finding. `_source_text`
# returns "" when every file in a fetched tree is oversized, unreadable or
# excluded — a real state, since `read_text` refuses files over 512 KB — and ""
# is not None, so the ladder ran on it and reached `03` §4's 30 band: *"no
# authentication … appears anywhere in the source we fetched"*, asserted about a
# tree in which nothing was read. The unknown-as-finding error, in a new place.
# Both states now abstain, and the reason says which one happened.
NO_SOURCE_FETCHED = "no source was fetched"
SOURCE_UNREADABLE = (
    "source was fetched but every file in it was oversized, unreadable or "
    "excluded, so no source text could be read"
)

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
# ⚠ **VERIFICATION, not PARTICIPATION** — the same direction error the bare
# credential tokens above were retired for, arriving through OAuth vocabulary.
# `/oauth/`, bare `oauth2`, `/callback`, `PKCE`, `code_challenge` and `id_token`
# were alternatives here, and every one of them is what an OAuth *client* looks
# like: a server POSTing to somebody else's `/oauth/token` to call their API
# matched, and — being an alternative to `has_middleware` in the 100 band —
# published *"refused without credentials established by reading the code"*
# about a server that authenticates nobody. Reading an upstream's token endpoint
# says exactly as much about inbound auth as sending an `X-API-Key` header did.
#
# What survives is the set that only makes sense when the server is CHECKING a
# token it received. A server that genuinely implements OAuth inbound also reads
# the Authorization header, so the honest floor for anything pruned here is
# `03` §4's 60 band, not its 30.
#
# ⚠ **A URL LITERAL CANNOT ESTABLISH DIRECTION, SO NO URL SURVIVES HERE.**
# `/.well-known/oauth` matched `/.well-known/oauth-authorization-server` — the
# DISCOVERY document an OAuth *client* fetches from an upstream — so an
# unauthenticated server that merely talks to somebody else's IdP reached the 100
# band again. That is the THIRD spelling of one mistake: `X-API-Key` the server
# sends, `/oauth/token` it posts to, and now a well-known URL it GETs. A path in
# a string says nothing about who serves it. `oauth-protected-resource` went with
# it for the same reason — a client discovering a resource's metadata writes the
# identical literal. `WWW-Authenticate` stays: a server only EMITS it when
# refusing an uncredentialed request, so it is the challenge itself, not a URL.
#
# ⚠ **THE REWRITE ALSO SILENTLY DROPPED THREE LIVE CALL FORMS.** Turning the
# list into a regex lost `verify_jwt(`, `verifyJwt(` and `token_introspection(`,
# so servers doing real inbound verification fell from source-established auth to
# the 60 or 30 band — a false ACCUSATION produced by the fix for a false
# exoneration. When converting a list to a pattern, enumerate the old list and
# check every entry is still reachable; nothing else reports the loss.
#
# ⚠ **A REGEX OF CALL FORMS, NOT A SUBSTRING LIST — the first cut of this
# narrowing was still substring containment and still over-matched.** `introspect`
# is inside `db.introspection()`, `validateToken` inside `validateTokenizer(`, and
# `verify_token` inside `verify_tokenization()` — so an unauthenticated server
# doing ordinary database or text work reached the 80 band, or 100 with a README
# that mentions auth. Narrowing the LIST while keeping `t in source` fixed the
# vocabulary and left the mechanism, which is how the same defect survives a fix
# aimed at it. Each alternative now has to end in a CALL or a word boundary.
_OAUTH_VERIFY_RE = re.compile(
    r"""
        \b(?:
            jwt\s*\.\s*(?:decode|verify)\s*\(
          | (?:jose\s*\.\s*)?jwtVerify\s*\(
          | jsonwebtoken\s*\.\s*verify\s*\(
          | (?:verify|validate|decode)_(?:token|jwt)\s*\(
          | (?:verify|validate|decode)(?:Token|Jwt|JWT)\s*\(
          | get_signing_key\s*\( | getSigningKey\s*\(
          | JwksClient\b
          | jwks(?:_uri|Uri|_url|Url|_client|Client|_endpoint)?\b
          | introspection_endpoint\b
          | (?:token_introspection|introspect_token|introspectToken)\s*\(
        )
      | WWW-Authenticate
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Import statements, which evidence a DEPENDENCY rather than a call site.
#
# ⚠ **A bare import is not enforcement, and the 100 band claims enforcement.**
# `from fastapi.security import HTTPBearer` with no route ever depending on it
# reached *"refused without credentials established by reading the code"* —
# established by reading an import line. The same shape as `http.HandlerFunc`:
# presence of a symbol read as the thing the symbol is used for.
#
# It is not scored as nothing either, which is the over-correction available
# here: importing an auth library IS evidence of intent, and dropping it
# entirely would push real servers toward `03` §4's 30 band ("no
# authentication") — a false accusation in the other direction. So an
# import-only match caps at 80 and says which of the two it established.
#
# Python's parenthesised form and JS's braced form span lines, and their
# continuation lines are bare names that read as uses; both are removed whole.
_PY_PAREN_IMPORT_RE = re.compile(
    r"^[ \t]*from\s+[\w.]+\s+import\s*\([^)]*\)", re.MULTILINE
)
_JS_BRACE_IMPORT_RE = re.compile(
    r"^[ \t]*import\s*(?:type\s*)?\{[^}]*\}\s*from\s*[\"\'`][^\"\'`]*[\"\'`]",
    re.MULTILINE,
)
_IMPORT_LINE_RE = re.compile(
    r"^[ \t]*(?:"
    r"from\s+[\w.]+\s+import\b.*"          # Python
    r"|import\b.*"                           # Python / JS / TS / Go member
    r"|(?:const|let|var)\s+[^\n=]*=\s*require\s*\(.*"   # CommonJS
    r"|use\s+[\w:]+.*"                       # Rust
    r")$",
    re.MULTILINE,
)


def _call_sites(source: str) -> str:
    """`source` with its import statements removed.

    What is left is where symbols are USED. Matching an auth construct here
    rather than over the whole file is the difference between a library being
    installed and a route being protected.
    """
    for pattern in (_PY_PAREN_IMPORT_RE, _JS_BRACE_IMPORT_RE, _IMPORT_LINE_RE):
        source = pattern.sub("", source)
    return source

# Credentials read from the environment rather than committed (`03` §4's
# "env vars are used" clause).
# ⚠ Python and JS only, until now — and the consequence was not a missing
# signal but a WRONG published claim. A Go or Rust server reading a credential
# from the environment scored 100 with the evidence *"no credential is read from
# the environment either — this server appears to handle no secrets"*.
# ⚠ **THE VARIABLE'S NAME IS THE SIGNAL, not the accessor.** This matched the
# accessor alone, so `os.getenv("PORT")` published *"credentials are read from
# the environment, but the README does not document which"* — a 30-point
# deduction on secret handling for reading a port number. Every server reads
# something from the environment; almost none of it is a credential.
#
# Both directions are fixed by naming, not just the over-report: the 100 band's
# old evidence read *"this server appears to handle no secrets"*, a claim about
# the server drawn from the absence of a substring. It now says only what a name
# test can support — that no credential-NAMED variable is read.
_ENV_ACCESS_RE = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[(\[]
        |os\.getenv\s*\(
        |process\.env\s*[.\[]
        |Deno\.env\.get\s*\(
        |(?:os\.)?(?:Getenv|LookupEnv)\s*\(
        |env::var(?:_os)?\s*\(
        |GetEnvironmentVariable\s*\(
        |\bENV\s*\[
        |\$env:
        |\bgetenv\s*\(
    )\s*["'`]?(?P<name>[A-Za-z_][A-Za-z0-9_]{0,80})""",
    re.VERBOSE,
)
# A credential-shaped variable name, in any of the conventions the ecosystems
# use. Word-segment anchored so `KEYBOARD` and `TOKENIZER` do not match.
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:^|_)(?:KEY|KEYS|TOKEN|TOKENS|SECRET|SECRETS|PASSWORD|PASSWD|PASS|PWD"
    r"|CREDENTIAL|CREDENTIALS|CREDS|AUTH|APIKEY|PAT|PRIVATE|CERT|SIGNING|DSN"
    r"|SESSION|COOKIE|SALT)(?:$|_)",
    re.IGNORECASE,
)
# A secrets-loading library. `dotenv` reads a `.env` file, which is where a
# project puts credentials by convention; unlike a bare accessor it carries its
# own intent. `pydantic_settings`/`BaseSettings` are deliberately NOT here —
# they are general configuration and were part of the over-report.
_SECRET_LOADERS = ("dotenv", "load_dotenv", "Dotenv", "godotenv")


# ⚠ **DESTRUCTURING READS THE ENVIRONMENT WITHOUT NAMING A VARIABLE AFTER IT.**
# `const { OPENAI_API_KEY } = process.env` puts the accessor LAST, so the
# accessor-then-name regex above captures nothing — and the consequence was not
# a missing signal but a false all-clear: with a clean secret scan,
# `_secret_handling` awarded 100 and published *"no environment variable with a
# credential-shaped name is read anywhere in the source"* about a server whose
# first line reads an API key. It is the commonest form in modern JS/TS.
# The alias form (`{ API_KEY: k }`) keys on the ENV NAME, which is the half
# before the colon — the local alias is the server's business.
# ⚠ The `\b` must sit on the alternatives that END IN A WORD CHARACTER, not on
# the group. `Deno.env.toObject()` ends in `)`, and the following `;` is also a
# non-word character, so a trailing `\b` can NEVER match there — the Deno branch
# was dead from the moment it was written and still published a clean bill of
# health for `const { OPENAI_API_KEY } = Deno.env.toObject()`.
_ENV_DESTRUCTURE_RE = re.compile(
    r"\{([^{}]{1,400})\}\s*=\s*(?:process\.env\b|Deno\.env\.toObject\s*\(\s*\)|os\.environ\b)"
)

# A destructured binding is `NAME`, `NAME: alias`, `NAME = default`, or
# `NAME: alias = default`. The ENV variable is always the leading identifier —
# the alias and the default are the server's own business.
_DESTRUCTURED_NAME_RE = re.compile(r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:[:=]|$)")


def _env_credential_names(source: str) -> tuple[str, ...]:
    """Environment variables the source reads whose NAMES look like secrets."""
    names = {
        m.group("name")
        for m in _ENV_ACCESS_RE.finditer(source)
        if _CREDENTIAL_NAME_RE.search(m.group("name"))
    }
    for block in _ENV_DESTRUCTURE_RE.finditer(source):
        for entry in block.group(1).split(","):
            # ⚠ ISOLATE THE IDENTIFIER FIRST. Splitting on ":" alone left the
            # DEFAULT attached, and it broke in both directions at once:
            #   `{ PORT = defaults.API_KEY }`     -> name "PORT = defaults.API_KEY",
            #      whose fallback matched, reporting a credential read for a port;
            #   `{ OPENAI_API_KEY = fallback }`   -> the boundary-anchored name test
            #      no longer saw `KEY` at the end, so a real credential was missed.
            identifier = _DESTRUCTURED_NAME_RE.match(entry)
            if identifier and _CREDENTIAL_NAME_RE.search(identifier.group(1)):
                names.add(identifier.group(1))
    return tuple(sorted(names))

# Tool registration, for the granularity heuristic's tool count.
#
# ⚠ **COUNT TOOLS, NOT LIST OPERATIONS.** `ListToolsRequestSchema` and the
# `tools: [` array it returns were counted as registrations, and they are ONE
# handler however many tools it serves — so the commonest low-level TS shape
# scored **2** for a five-tool server, landed under `03` §4's threshold of 3,
# and published *"there is no multi-tool surface to segregate"* about a server
# with exactly that. The markers were added to fix a zero and turned it into a
# constant, which is the harder failure to see: a plausible number.
#
# Three independent ways of counting the same set, and the count is the LARGEST
# rather than the sum — each family is one ecosystem's whole convention, so
# summing double-counts while `max` takes the best lower bound. Over-counting
# lands on "needs human review" (unassessed); under-counting publishes "≤3
# tools" about a server we mis-read, so the bias is deliberate.

# Per-tool registration CALLS that name the tool. The name is captured so
# repeated registrations of the same tool count once.
_TOOL_CALL_RE = re.compile(
    r"""\b(?:server\.tool|mcp\.tool|registerTool|addTool|setTool|tool)\s*\(\s*"""
    r"""["'`](?P<name>[^"'`]{1,120})["'`]""",
)
# Per-tool DECORATORS. One per decorated function, so these are already a count.
_TOOL_DECORATOR_RES = (
    re.compile(r"@\w+\.tool\b"),      # `@mcp.tool()` — Python SDK
    re.compile(r"@tool\b"),
    re.compile(r"\bserver\.tool\("),   # unnamed / variable-named TS registration
    re.compile(r"\bregisterTool\("),
    re.compile(r"\baddTool\("),
)
# Per-tool DEFINITION OBJECTS inside a `tools: [...]` array or an MCP manifest:
# a `name` key whose neighbourhood carries the other fields an MCP tool
# declaration has. Quoted and bare keys both occur (JSON vs TS object literal),
# and `description` appears either side of `name`, so the companion key is
# matched in a bounded window rather than in a fixed order.
_TOOL_OBJECT_RE = re.compile(
    r"""["'`]?\bname["'`]?\s*:\s*["'`][^"'`\n]{1,120}["'`]"""
    r"""(?=.{0,300}?["'`]?\b(?:description|inputSchema|input_schema)["'`]?\s*:)""",
    re.DOTALL,
)
# The low-level list handler. NOT a count — a marker that tools exist even when
# none of the counters above recognised one, which is the difference between
# "we failed to read this" and "this server has no tools".
_TOOL_LIST_HANDLER_RE = re.compile(r"ListToolsRequestSchema|\btools\s*:\s*\[")


# ⚠ **A `name` + `description` OBJECT IS NOT NECESSARILY A TOOL.** MCP declares
# RESOURCES and PROMPTS with the identical shape, so an unscoped scan counted
# four resources beside three real tools and pushed the count over `03` §4's
# threshold — turning a legitimate 100 into an abstention. That is the
# conservative direction and still wrong: it reports "needs human review" about
# a server we could in fact assess. So object counting is confined to the
# inside of a `tools:` array rather than run over the whole file.
# ⚠ Quoted keys too. A JSON MCP manifest writes `"tools": [ ... ]`, and the
# bare-key pattern required the colon to follow `tools` directly — so the
# commonest manifest shape found NO region at all and every JSON-declared tool
# list counted zero. The narrowing meant to stop resources being counted as
# tools stopped MANIFEST tools being counted at all.
_TOOLS_ARRAY_RE = re.compile(r"""["']?\btools\b["']?\s*:\s*\[""")
# Bounds, because the region walk reads attacker-controlled source: at most this
# many arrays, each scanned at most this far. A tool list longer than 64 KB is
# not a tool list.
MAX_TOOL_ARRAYS = 20
MAX_TOOL_ARRAY_BYTES = 64 * 1024


def _tools_array_regions(source: str) -> list[str]:
    """The bracket-balanced bodies of each `tools: [ ... ]` array."""
    regions: list[str] = []
    for opener in _TOOLS_ARRAY_RE.finditer(source):
        if len(regions) >= MAX_TOOL_ARRAYS:
            break
        start = opener.end()  # just past the '['
        depth, end = 1, min(len(source), start + MAX_TOOL_ARRAY_BYTES)
        i = start
        quote = ""
        while i < end:
            ch = source[i]
            # ⚠ BRACKETS INSIDE STRINGS ARE NOT DELIMITERS. A tool's own
            # inputSchema regularly carries one — `"pattern": "^[^]]+$"` is an
            # ordinary JSON-Schema constraint — and the raw character walk closed
            # the array on it, ending the region inside the FIRST tool. Four tools
            # then counted as one and scored 100 for having no multi-tool surface.
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "\"'`":
                quote = ch
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        regions.append(source[start:i])
    return regions


def _count_tools(source: str) -> int:
    """How many distinct tools the source registers (`03` §4's threshold)."""
    named = {m.group("name") for m in _TOOL_CALL_RE.finditer(source)}
    sites = max(
        (len(pattern.findall(source)) for pattern in _TOOL_DECORATOR_RES), default=0
    )
    objects = sum(
        len(_TOOL_OBJECT_RE.findall(region)) for region in _tools_array_regions(source)
    )
    return max(len(named), sites, objects)
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


def _declared_credentials(entry: RegistryEntry) -> tuple[bool, bool, tuple[str, ...]]:
    """(any credential header declared, EVERY remote requires one, the rest).

    ⚠ **Flattening every remote's headers into one list and asking `any()`
    scores the STRONGEST endpoint**, and an attacker uses the weakest. A server
    declaring two remotes — one requiring an `Authorization` header, one
    requiring nothing — reached `03` §4's 80 band ("credentials required") while
    the second endpoint answered anyone who asked. The requirement has to hold
    for every declared endpoint or it is not a requirement, so the quantifier is
    `all` over REMOTES, not `any` over headers, and the endpoints that fail it
    are returned to be named in the evidence rather than averaged away.
    """
    headers = [h for remote in entry.remotes for h in remote.credential_headers]
    unprotected = tuple(
        remote.url
        for remote in entry.remotes
        if not any(h.is_required for h in remote.credential_headers)
    )
    required = bool(entry.remotes) and not unprotected
    return bool(headers), required, unprotected


def _authentication_model(
    entry: RegistryEntry,
    transport: TransportAssessment,
    source: str | None,
    readme: str,
    absent_reason: str = NO_SOURCE_FETCHED,
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
            fault=Fault.PUBLISHER.value,
        )

    declared, required, unprotected = _declared_credentials(entry)
    header_names = sorted(
        {h.name for r in entry.remotes for h in r.credential_headers}
    )
    # Named rather than counted: the score is about a specific endpoint anyone
    # can reach, and `03` §10 commits every point to an artifact.
    bypassable = (
        (f"{len(unprotected)} of {len(entry.remotes)} declared remote endpoint(s) "
         f"require no credential header: {', '.join(unprotected[:3])}",)
        if unprotected and declared else ()
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
                evidence=(f"registry declares credential header(s) "
                          f"{', '.join(header_names)} that are not required on "
                          "every declared endpoint — `03` §4's "
                          "\"authentication present but optional\" band",)
                         + bypassable,
            )
        return SubCheck(
            name, None,
            reason=f"{absent_reason}, and no credential header is declared. An "
                   "undeclared header is not an absent one — measured "
                   "2026-09-15, only 10 of 100 remotes declare one at all — so "
                   "`03` §4's \"no authentication\" band is not established.",
            fault=Fault.PUBLISHER.value,
        )

    # ⚠ USE vs IMPORT, and the two reach different bands. See `_call_sites`.
    call_sites = _call_sites(source)
    has_middleware = any(t in call_sites for t in _AUTH_MIDDLEWARE)
    imports_middleware = not has_middleware and any(t in source for t in _AUTH_MIDDLEWARE)
    has_credential_read = bool(_CREDENTIAL_READ_RE.search(source))
    has_oauth = bool(_OAUTH_VERIFY_RE.search(call_sites))
    # ⚠ WORD-BOUNDED. This was substring containment over a list that included
    # a bare "auth", so an `## Authors` heading — in practically every README —
    # satisfied "documented in the README" and lifted the band to 100.
    documented = bool(readme) and _AUTH_DOCUMENTED_RE.search(readme) is not None

    # ⚠ NOT gated on `unprotected`. A remote that declares no required header
    # is not a remote that requires nothing — only 10 of 100 declare one at all
    # — so withholding the source-established 100 band on that basis would be
    # the ecological inference the module docstring rejects, applied to the one
    # cohort that did hand us readable code.
    if (has_oauth or has_middleware) and documented:
        return SubCheck(
            name, 100,
            evidence=(
                "auth enforcement present at a call site in the source"
                + (" (inbound token verification)" if has_oauth
                   else " (auth middleware)")
                + " and documented in the README",
                "\"refused without credentials\" (`03` §4) established by "
                "reading the code rather than by connecting",
            ),
        )
    if has_oauth or has_middleware or imports_middleware or (declared and required):
        if imports_middleware and not (has_oauth or has_middleware):
            # The library is a dependency; nothing shows it wrapping a route.
            # `03` §4's 100 band asserts refusal, and an import does not
            # establish refusal — so this stops at 80 and says which it is.
            return SubCheck(
                name, 80,
                evidence=("an authentication library is imported but no call "
                          "site wiring it to a request path was found, so the "
                          "requirement is evidenced and its enforcement is "
                          "not — `03` §4's 100 band asserts that an "
                          "uncredentialed request is refused",),
            )
        return SubCheck(
            name, 80,
            evidence=(("credential enforcement present in source but not "
                       "documented in the README" if not documented else
                       "credential requirement present; enforcement partially "
                       "evidenced"),) + bypassable,
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
                  "credential-header read, or inbound token verification "
                  "appears anywhere in the source we fetched — `03` §4's "
                  "\"no authentication; HTTP transport\" band",),
    )


# The two ways the credential scan does not happen. They are BOTH ours, so both
# carry `Fault.ENVIRONMENT` and are refused at publication — but they are not the
# same sentence, and the page states one of them about a named third party.
# Saying "was not available" about a binary that was present and then timed out
# is false, and it is false in the direction that hides a broken toolchain.
CREDENTIAL_SCAN_ABSENT = (
    "`detect-secrets` was not available to this worker, so the "
    "committed-credential scan did not run. A clean result here would be a "
    "scan that never happened."
)
CREDENTIAL_SCAN_FAILED = (
    "`detect-secrets` was available but its run did not complete — it timed "
    "out, or returned output this scanner could not read — so the "
    "committed-credential scan produced no result. A clean result here would "
    "be a scan that never finished."
)


def _secret_handling(
    secrets: list[SecretFinding] | None,
    source: str | None,
    readme: str,
    absent_reason: str = NO_SOURCE_FETCHED,
    *,
    tool_reason: str = CREDENTIAL_SCAN_ABSENT,
) -> SubCheck:
    """`03` §4's secret-handling sub-check."""
    name = "secret_handling"

    # ⚠ A committed credential is scored FIRST, before any source-text gate.
    # `detect-secrets` reads the tree from disk itself, so its findings stand
    # whether or not `_source_text` could read anything — and a found credential
    # is the one result on this sub-check that must never be lost to an
    # abstention.
    if secrets:
        # Path, line and type only — never the credential, which `detect-secrets`
        # does not return in the first place and this must not reintroduce.
        located = tuple(f"{f.kind} at {f.path}:{f.line}" for f in secrets[:10])
        return SubCheck(
            name, 0, evidence=located + (
                (f"…and {len(secrets) - 10} more",) if len(secrets) > 10 else ()
            ),
        )
    if source is None:
        return SubCheck(
            name, None,
            reason=f"{absent_reason}, so there is nothing to scan for "
                   "committed credentials",
            fault=Fault.PUBLISHER.value,
        )
    if secrets is None:
        # ⚠ ATTRIBUTED, and this is the whole point of the field. The axis
        # stays SCORED — `score_axis` renormalises this abstention away — so
        # `cohort.unpublishable_gaps`, which only examines axes with no score,
        # could not see it. Without the attribution our own broken toolchain
        # reaches a stranger's page inside a number that looks measured.
        return SubCheck(name, None, reason=tool_reason, fault=Fault.ENVIRONMENT.value)

    credential_vars = _env_credential_names(source)
    loads_secrets = any(t in source for t in _SECRET_LOADERS)
    if not credential_vars and not loads_secrets:
        return SubCheck(
            name, 100,
            evidence=("no committed credential found, and no environment "
                      "variable with a credential-shaped name is read anywhere "
                      "in the source",),
        )
    documented = bool(readme) and any(
        t in readme.upper() for t in ("ENV", "ENVIRONMENT", "_KEY", "_TOKEN", "_SECRET")
    )
    read_from = (
        f"credentials are read from the environment ({', '.join(credential_vars[:5])})"
        if credential_vars
        else "a dotenv-style secrets file is loaded"
    )
    return SubCheck(
        name, 100 if documented else 70,
        evidence=(read_from
                  + (" and documented in the README" if documented
                     else ", but the README does not document which"),),
    )


def _authorization_granularity(
    source: str | None,
    inventory: Inventory | None,
    absent_reason: str = NO_SOURCE_FETCHED,
) -> SubCheck:
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
            reason=f"{absent_reason}, so neither the tool count nor any "
                   "access-control logic can be read",
            fault=Fault.PUBLISHER.value,
        )

    tools = _count_tools(source)
    # ⚠ ZERO is a detector failure, not a measurement. An MCP server that
    # registers no tools at all is not a thing; counting none means we did not
    # recognise the shape, and scoring 100 on that would assert "≤3 tools" about
    # a server we failed to read — the vacuous positive `declared_scopes`
    # refuses on the transparency axis, reached by a different route.
    if tools == 0:
        seen_handler = _TOOL_LIST_HANDLER_RE.search(source) is not None
        return SubCheck(
            name, None,
            reason="no tool registration was recognised anywhere in the source. "
                   "An MCP server registers tools by definition, so this is a "
                   "gap in our detection rather than a server with none, and "
                   "`03` §4's threshold cannot be applied to it."
                   + (" A tool-list handler IS present, so the tools are built "
                      "in a shape this counter could not enumerate."
                      if seen_handler else ""),
            fault=Fault.PROJECT.value,
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
        fault=Fault.PROJECT.value,
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
    # The narrowing is inlined rather than held in `has_source`, because a
    # type checker cannot carry `root is not None` through a boolean variable
    # — and mypy is the only reason this file's five arg-type errors existed.
    has_source = root is not None and inventory is not None
    source = (
        _source_text(root, inventory)
        if root is not None and inventory is not None
        else None
    )
    readme = (
        _readme_text(root, inventory)
        if root is not None and inventory is not None
        else ""
    )

    # See NO_SOURCE_FETCHED / SOURCE_UNREADABLE: an empty read is not an
    # assessed absence, and passing "" on as source text scored it as one.
    absent_reason = NO_SOURCE_FETCHED
    if source is not None and not source.strip():
        source, absent_reason = None, SOURCE_UNREADABLE

    # ⚠ WHICH FAILURE IT WAS IS DECIDED HERE, not inside `scan_secrets`, whose
    # `None` deliberately means only "not assessed" and is relied on by six
    # call sites. `shutil.which` before the run separates a binary that is
    # missing from one that is present and then times out or emits output we
    # cannot parse — Codex found the second case publishing the first case's
    # sentence. Both are ours and both are refused; only the wording differs,
    # and it is the wording that appears on someone else's page.
    # The `which` sits INSIDE the attempt deliberately: it separates a binary
    # that is missing from one that is present and then died, and it can only
    # say that about a scan this call actually made. Hoisting it out — tried,
    # and reverted — made a caller that never scanned publish "its run did not
    # complete", which is the same class of false sentence pointing the other
    # way.
    tool_reason = CREDENTIAL_SCAN_ABSENT
    if root is not None and has_source and secrets is None and scan_for_secrets:
        if shutil.which("detect-secrets") is not None:
            tool_reason = CREDENTIAL_SCAN_FAILED
        secrets = scan_secrets(root)

    return score_axis(
        AXIS,
        [
            _authentication_model(entry, transport, source, readme, absent_reason),
            transport.subcheck,
            _secret_handling(
                secrets, source, readme, absent_reason, tool_reason=tool_reason
            ),
            _authorization_granularity(source, inventory, absent_reason),
        ],
    )
