"""MRC Refresh MCP Server.

Wraps the bastion's `mrc-refresh` script as an MCP tool, served over HTTPS
with bearer-token auth. Contractors connect via Claude Desktop's remote MCP
support.

Layout assumed on the bastion:
- /usr/local/bin/mrc-refresh                      — existing wrapper script
- /etc/mrc-refresh-mcp/tokens.yml                  — bearer token -> contractor map
- /home/mrc/mrc-proxy/logs/contractor-access.log  — existing audit log

Run via systemd; behind Caddy for TLS.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from contextvars import ContextVar
from pathlib import Path

import yaml
from mcp.server.fastmcp import Context, FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route

LOG = logging.getLogger("mrc-refresh-mcp")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

TOKENS_PATH = Path(os.environ.get("TOKENS_PATH", "/etc/mrc-refresh-mcp/tokens.yml"))
AUDIT_LOG = Path(os.environ.get("AUDIT_LOG", "/home/mrc/mrc-proxy/logs/contractor-access.log"))
MRC_REFRESH = os.environ.get("MRC_REFRESH_BIN", "/home/mrc/mrc-proxy/bin/mrc-refresh")

ALLOWED_SITES = {"canoefp", "gormanbros", "mrmikes", "pathways", "selkirkcedar", "similkameen"}
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


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validate `Authorization: Bearer <token>` against tokens.yml.

    Sets the `current_contractor` ContextVar so tools can read which
    contractor invoked them, for audit logging.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/healthz":
            return await call_next(request)

        # Per RFC 6750: a Bearer-protected resource MUST advertise the scheme
        # in WWW-Authenticate on 401. MCP connector validators look for this
        # to know how to ask the user for credentials.
        challenge = {"WWW-Authenticate": 'Bearer realm="mrc-refresh-mcp"'}

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "missing bearer token"},
                status_code=401,
                headers=challenge,
            )

        token = auth[7:].strip()
        contractor = load_tokens().get(token)
        if not contractor:
            client_host = request.client.host if request.client else "?"
            LOG.info("rejected token from %s", client_host)
            return JSONResponse(
                {"error": "invalid token"},
                status_code=401,
                headers=challenge,
            )

        token_ctx = current_contractor.set(contractor)
        try:
            return await call_next(request)
        finally:
            current_contractor.reset(token_ctx)


mcp = FastMCP("mrc-refresh")


@mcp.tool()
async def refresh_site(site: str, mode: str = "full", ctx: Context | None = None) -> str:
    """Refresh a Cloudways dev site with current live content.

    Use this whenever a contractor wants to pull live content into the dev
    environment for a client site. The dev DB is overwritten — do not run
    mid-task if there is in-progress wp-admin configuration on dev.

    Args:
        site: One of canoefp, gormanbros, mrmikes, pathways, selkirkcedar, similkameen.
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
        Mount("/", app=mcp_app),
    ],
    middleware=[Middleware(BearerAuthMiddleware)],
    lifespan=lifespan,
)
