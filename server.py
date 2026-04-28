"""MRC Refresh MCP Server.

Wraps the bastion's `mrc-refresh` script as an MCP tool, served over HTTPS
behind an OAuth 2.0 surface that translates onto pre-issued bearer tokens.
Contractors connect via Claude Desktop's remote MCP support: they get
redirected through our /auth/login page where they paste the bearer token
Mark issued them.

Layout assumed on the bastion:
- /home/mrc/mrc-proxy/bin/mrc-refresh                — existing wrapper script
- /etc/mrc-refresh-mcp/tokens.yml                    — bearer token -> contractor map
- /home/mrc/mrc-proxy/logs/contractor-access.log     — existing audit log

Run via systemd; behind Caddy for TLS.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import os
import re
import time
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import urlencode

import yaml
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route

from oauth_provider import MRCOAuthProvider

LOG = logging.getLogger("mrc-refresh-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

TOKENS_PATH = Path(os.environ.get("TOKENS_PATH", "/etc/mrc-refresh-mcp/tokens.yml"))
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", "/home/mrc/mrc-proxy/logs/contractor-access.log"))
MRC_REFRESH = os.environ.get("MRC_REFRESH_BIN", "/home/mrc/mrc-proxy/bin/mrc-refresh")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://mcp.markroberts.io").rstrip("/")

ALLOWED_SITES = {"canoefp", "cavallo", "gormanbros", "mrmikes", "pathways", "selkirkcedar", "similkameen"}
ALLOWED_MODES = {"full", "files-only", "db-only", "dry-run"}
PROGRESS_RE = re.compile(r"^\[(\d+)/(\d+)\]")

current_contractor: ContextVar[str] = ContextVar("current_contractor", default="unknown")


def load_tokens() -> dict[str, str]:
    """Read tokens.yml on every request. Format: {token: contractor_name}.

    Reading on every request means token revocation is instant — edit the
    file, no service restart needed.
    """
    if not TOKENS_PATH.exists():
        LOG.warning("tokens file missing: %s", TOKENS_PATH)
        return {}
    try:
        data = yaml.safe_load(TOKENS_PATH.read_text()) or {}
    except yaml.YAMLError as e:
        LOG.error("malformed tokens.yml: %s", e)
        return {}
    return {str(k): str(v) for k, v in data.items()}


def validate_token(token: str) -> str | None:
    """Validate a bearer against tokens.yml and (as a side effect) set the
    current_contractor ContextVar so audit logging picks it up.

    The ContextVar set here propagates into the tool's execution context
    because FastMCP runs the tool inside the same async task that ran the
    auth check.
    """
    contractor = load_tokens().get(token)
    if contractor:
        current_contractor.set(contractor)
    return contractor


def audit(contractor: str, cmd: list[str], rc: int | None = None) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rc_field = f"rc={rc}" if rc is not None else "rc=running"
    line = f"{ts}\tvia=mcp\tcontractor={contractor}\t{rc_field}\tcmd={' '.join(cmd)}\n"
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(line)
    except OSError as e:
        LOG.warning("audit log write failed: %s", e)


# Hosts allowed in the request's Host header. FastMCP's DNS-rebinding
# protection rejects anything not in this list with HTTP 421. Override at
# deploy time via MCP_ALLOWED_HOSTS (comma-separated) — useful for staging.
_default_hosts = "mcp.markroberts.io,127.0.0.1:8765,127.0.0.1,localhost:8765,localhost"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", _default_hosts).split(",") if h.strip()]


def login_url_for_session(session_id: str) -> str:
    return f"{PUBLIC_BASE_URL}/auth/login?session={session_id}"


oauth_provider = MRCOAuthProvider(
    validate_token=validate_token,
    login_url_for_session=login_url_for_session,
)

mcp = FastMCP(
    "mrc-refresh",
    transport_security=TransportSecuritySettings(allowed_hosts=ALLOWED_HOSTS),
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=PUBLIC_BASE_URL,
        resource_server_url=PUBLIC_BASE_URL,
        client_registration_options=ClientRegistrationOptions(enabled=True),
    ),
)


@mcp.tool()
async def refresh_site(site: str, mode: str = "full", ctx: Context | None = None) -> str:
    """Refresh a Cloudways dev site with current live content.

    Use this whenever a contractor wants to pull live content into the dev
    environment for a client site. The dev DB is overwritten — do not run
    mid-task if there is in-progress wp-admin configuration on dev.

    Args:
        site: One of canoefp, cavallo, gormanbros, mrmikes, pathways, selkirkcedar, similkameen.
        mode: One of "full" (default), "files-only", "db-only", "dry-run".
            "full" pulls both files and DB. "dry-run" reports what would change.
    """
    if site not in ALLOWED_SITES:
        return f"ERROR: unknown site '{site}'. Allowed: {', '.join(sorted(ALLOWED_SITES))}"
    if mode not in ALLOWED_MODES:
        return f"ERROR: unknown mode '{mode}'. Allowed: {', '.join(sorted(ALLOWED_MODES))}"

    flag_map = {
        "full": [],
        "files-only": ["--files-only"],
        "db-only": ["--db-only"],
        "dry-run": ["--dry-run"],
    }
    cmd = [MRC_REFRESH, site, *flag_map[mode]]
    contractor = current_contractor.get()
    audit(contractor, cmd)

    LOG.info("running: %s (contractor=%s)", " ".join(cmd), contractor)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None

    output_chunks: list[str] = []
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace")
        output_chunks.append(line)
        match = PROGRESS_RE.match(line)
        if match and ctx is not None:
            current, total = int(match.group(1)), int(match.group(2))
            try:
                await ctx.report_progress(progress=current, total=total)
            except Exception:
                pass  # progress is best-effort

    rc = await proc.wait()
    audit(contractor, cmd, rc=rc)

    output = "".join(output_chunks)
    if rc != 0:
        return f"{output}\n\n[mrc-refresh exited with code {rc}]"
    return output


@mcp.tool()
async def list_sites() -> str:
    """List the client sites available for refresh."""
    return "Available sites:\n" + "\n".join(f"  - {s}" for s in sorted(ALLOWED_SITES))


async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok\n")


async def oauth_protected_resource_mcp(request: Request) -> JSONResponse:
    """RFC 9728 resource-specific protected-resource metadata for the /mcp
    endpoint. FastMCP only registers the suffix-less /.well-known/oauth-
    protected-resource path; Anthropic's connector probes both, so we
    serve the resource-specific variant ourselves."""
    return JSONResponse(
        {
            "resource": f"{PUBLIC_BASE_URL}/mcp",
            "authorization_servers": [f"{PUBLIC_BASE_URL}/"],
            "bearer_methods_supported": ["header"],
        }
    )


# -- /auth/login: contractor pastes their bearer token, we issue an OAuth
# auth code and redirect back to Anthropic's connector callback. --------

LOGIN_FORM = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize mrc-refresh</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 480px; margin: 6vh auto; padding: 0 1.5rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  p  {{ color: #555; line-height: 1.5; }}
  form {{ margin-top: 1.5rem; }}
  label {{ display: block; font-weight: 600; margin-bottom: 0.5rem; }}
  input[type="password"] {{ width: 100%; padding: 0.75rem; font-size: 1rem;
        border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  button {{ margin-top: 1rem; padding: 0.75rem 1.25rem; font-size: 1rem;
        font-weight: 600; background: #1a1a1a; color: white; border: none;
        border-radius: 6px; cursor: pointer; width: 100%; }}
  button:hover {{ background: #333; }}
  .err {{ color: #b00020; margin-top: 0.5rem; font-size: 0.95rem; }}
  .meta {{ color: #888; margin-top: 2rem; font-size: 0.85rem; }}
</style>
</head>
<body>
  <h1>Authorize mrc-refresh</h1>
  <p>Paste the bearer token Mark issued you. Claude Desktop will use it to refresh dev sites on your behalf.</p>
  <form method="POST" action="/auth/login">
    <input type="hidden" name="session" value="{session}">
    <label for="token">Bearer token</label>
    <input id="token" type="password" name="token" autocomplete="off" autofocus required>
    {error_html}
    <button type="submit">Authorize</button>
  </form>
  <p class="meta">If you don't have a token, contact Mark — he'll issue one in 1Password.</p>
</body>
</html>
"""


def _render_login(session_id: str, error: str | None = None) -> HTMLResponse:
    error_html = (
        f'<p class="err">{html.escape(error)}</p>' if error else ""
    )
    return HTMLResponse(
        LOGIN_FORM.format(session=html.escape(session_id), error_html=error_html)
    )


async def auth_login_get(request: Request) -> HTMLResponse:
    session_id = request.query_params.get("session", "")
    if not session_id or not oauth_provider.peek_login_session(session_id):
        return HTMLResponse(
            "<h1>Session not found or expired</h1>"
            "<p>Restart the Connect flow from Claude Desktop.</p>",
            status_code=404,
        )
    return _render_login(session_id)


async def auth_login_post(request: Request) -> HTMLResponse | RedirectResponse:
    form = await request.form()
    session_id = str(form.get("session", ""))
    token = str(form.get("token", "")).strip()

    # Peek (don't consume) so we can re-render on bad token without burning the session.
    session = oauth_provider.peek_login_session(session_id)
    if not session:
        return HTMLResponse(
            "<h1>Session expired</h1><p>Restart the Connect flow from Claude Desktop.</p>",
            status_code=400,
        )

    contractor = validate_token(token) if token else None
    if not contractor:
        client_host = request.client.host if request.client else "?"
        LOG.info("rejected token from %s during /auth/login", client_host)
        return _render_login(session_id, error="Invalid token. Check that you copied the full token from Mark's message.")

    # Token good — consume the session and issue an auth code.
    oauth_provider.consume_login_session(session_id)
    code = oauth_provider.issue_code(
        client_id=session["client_id"],
        params=session["params"],
        user_token=token,
    )
    LOG.info("authorized contractor=%s client_id=%s", contractor, session["client_id"])

    params = session["params"]
    qs_pairs = {"code": code}
    if params.state is not None:
        qs_pairs["state"] = params.state
    redirect = f"{params.redirect_uri}?{urlencode(qs_pairs)}"
    return RedirectResponse(redirect, status_code=303)


# -- ASGI app -----------------------------------------------------------

mcp_app = mcp.streamable_http_app()


@contextlib.asynccontextmanager
async def lifespan(_app):
    """FastMCP's streamable HTTP transport runs its session manager inside
    an async task group. When you Mount the FastMCP app inside a parent
    Starlette app, the parent's lifespan has to enter that context — otherwise
    every POST raises 'Task group is not initialized'.
    """
    async with mcp.session_manager.run():
        yield


app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            oauth_protected_resource_mcp,
            methods=["GET"],
        ),
        Route("/auth/login", auth_login_get, methods=["GET"]),
        Route("/auth/login", auth_login_post, methods=["POST"]),
        Mount("/", app=mcp_app),
    ],
    lifespan=lifespan,
)
