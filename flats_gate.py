#!/usr/bin/env python3
"""flats-gate: an authenticating reverse-proxy shim in front of the Flats management server.

Why this exists (Flats v0.12.0+)
---------------------------------
Flats has no authentication of its own, and anything that can reach its management
listener can approve deploys. Since v0.12.0 Flats understands external origins
(`console.external_origins`): it accepts the declared public Host, refuses foreign
Hosts and Origins itself, and builds approval links and the llms.txt documents with
the declared scheme. This shim no longer rewrites Host/Origin - Flats does that.

What it still does:
  - console gate: accepts only the configured public host (plus loopback for local
    calls), keeps /mcp OFF the console resource, and blocks the unauthenticated
    /metrics endpoint that v0.12.0 added (it exposes private flat slugs, CPU and
    memory to everyone who can reach the console).
  - mcp gate: serves /mcp only, and requires `Authorization: Bearer <key>` or
    `X-API-Key: <key>`. Agents cannot approve anything, so this surface is safe to
    expose without SSO as long as the key stays secret. Built-in authentication is
    tracked upstream in gosuda/flats#139.

Config: environment (see .env.example). Stdlib + aiohttp only.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
import sys
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

log = logging.getLogger("flats-gate")

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}
STRIP_REQ = HOP | {
    "accept-encoding",  # keep upstream bodies uncompressed
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
    "x-real-ip", "forwarded", "x-forwarded-server", "x-forwarded-uri",
    "cf-connecting-ip", "true-client-ip",
}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


UPSTREAM = env("FLATS_UPSTREAM", "http://127.0.0.1:7878").rstrip("/")
UP_HOSTPORT = urlsplit(UPSTREAM).netloc
BIND = env("FLATS_GATE_BIND", "127.0.0.1")
CONSOLE_PORT = int(env("FLATS_GATE_CONSOLE_PORT", "7880"))
MCP_PORT = int(env("FLATS_GATE_MCP_PORT", "7881"))
CONSOLE_PUBLIC_URL = env("FLATS_GATE_CONSOLE_PUBLIC_URL", "").rstrip("/")  # empty = local-only mode
MCP_PUBLIC_URL = env("FLATS_GATE_MCP_PUBLIC_URL", "").rstrip("/")
API_KEYS = [k for k in (s.strip() for s in env("FLATS_GATE_API_KEYS").split(",")) if k]
MIN_KEY_LEN = 24
BLOCK_METRICS = env("FLATS_GATE_BLOCK_METRICS", "1").lower() in ("1", "true", "yes")

if CONSOLE_PUBLIC_URL:
    _pub = urlsplit(CONSOLE_PUBLIC_URL)
    if _pub.scheme not in ("http", "https") or not _pub.netloc:
        sys.exit(f"flats-gate: FLATS_GATE_CONSOLE_PUBLIC_URL must be http(s)://host[:port], got {CONSOLE_PUBLIC_URL!r}")

# Host names the console gate accepts: the public name (Flats has it in
# console.external_origins) plus loopback names for local calls.
CONSOLE_HOSTS = {h.lower() for h in (
    ([urlsplit(CONSOLE_PUBLIC_URL).netloc] if CONSOLE_PUBLIC_URL else [])
    + [f"127.0.0.1:{CONSOLE_PORT}", f"localhost:{CONSOLE_PORT}", "127.0.0.1", "localhost", "[::1]"]
    + [s.strip() for s in env("FLATS_GATE_EXTRA_HOSTS").split(",") if s.strip()]
)}
# The Host we send upstream: the public authority (no default port) when the
# request came in on it, otherwise Flats' own loopback authority.
UPSTREAM_PUBLIC_HOST = urlsplit(CONSOLE_PUBLIC_URL).netloc if CONSOLE_PUBLIC_URL else ""


def clean_headers(src, drop=STRIP_REQ):
    return {k: v for k, v in src.items() if k.lower() not in drop}


def key_ok(request: web.Request) -> bool:
    if not API_KEYS:
        return True
    cand = request.headers.get("X-API-Key", "")
    auth = request.headers.get("Authorization", "")
    if not cand and auth[:7].lower() == "bearer ":
        cand = auth[7:].strip()
    if not cand:
        return False
    ok = False
    for k in API_KEYS:  # no early exit: compare against every key
        ok |= hmac.compare_digest(cand.encode(), k.encode())
    return ok


def upstream_host(request: web.Request) -> str:
    """Host to send upstream.

    The public authority goes through unchanged so Flats links and discovery
    documents use the public URL (v0.12.0 external origins). Local callers are
    mapped to Flats' loopback authority, which Flats always accepts.
    """
    host = request.headers.get("Host", "").lower()
    if UPSTREAM_PUBLIC_HOST and host.split(":")[0] == UPSTREAM_PUBLIC_HOST.split(":")[0]:
        return UPSTREAM_PUBLIC_HOST
    return UP_HOSTPORT


def upstream_host_for_client(request: web.Request) -> str:
    """Host to send upstream when the request came from a client (not a browser
    on the console page): the public authority when the client used it, so
    Flats builds public links on its own."""
    return upstream_host(request)


async def forward(request: web.Request, headers: dict, rewrite_body=None, rewrite_location=None):
    session: aiohttp.ClientSession = request.app["session"]
    url = UPSTREAM + request.rel_url.raw_path_qs
    data = request.content if request.can_read_body else None
    try:
        up = await session.request(
            request.method, url, headers=headers, data=data,
            allow_redirects=False, auto_decompress=True,
        )
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.warning("upstream error %s %s: %s", request.method, request.path, e)
        return web.json_response({"error": "flats upstream unavailable"}, status=502)
    try:
        out_headers = {}
        for k, v in up.headers.items():
            lk = k.lower()
            if lk in HOP or lk == "content-encoding":
                continue
            if lk == "location" and rewrite_location:
                v = rewrite_location(v)
            out_headers[k] = v
        if rewrite_body is not None:
            body = await up.read()
            return web.Response(status=up.status, headers=out_headers, body=rewrite_body(body))
        resp = web.StreamResponse(status=up.status, headers=out_headers)
        await resp.prepare(request)
        async for chunk in up.content.iter_any():
            await resp.write(chunk)
        await resp.write_eof()
        return resp
    finally:
        up.release()


# ---------------------------------------------------------------- console gate
def console_location(v: str) -> str:
    if CONSOLE_PUBLIC_URL and v.startswith(UPSTREAM):
        return CONSOLE_PUBLIC_URL + v[len(UPSTREAM):]
    return v


async def console_handler(request: web.Request):
    host = request.headers.get("Host", "").lower()
    if host not in CONSOLE_HOSTS:
        return web.json_response({"error": f"host {host!r} not served by this gate"}, status=403)
    if request.path == "/mcp" or request.path.startswith("/mcp/"):
        # the console resource sits behind SSO and must not expose the agent
        # surface; /mcp is served on the keyed MCP resource only.
        return web.json_response({"error": "MCP is served on the keyed MCP endpoint only"}, status=404)
    if BLOCK_METRICS and request.path == "/metrics":
        return web.json_response({"error": "metrics are not exposed"}, status=404)
    headers = clean_headers(request.headers)
    headers["Host"] = upstream_host(request)
    # Origin and Referer go through unchanged: Flats checks them against its own
    # declared origins and refuses anything foreign.
    return await forward(request, headers, rewrite_location=console_location)


# -------------------------------------------------------------------- mcp gate
def rewrite_mcp_body(body: bytes) -> bytes:
    if MCP_PUBLIC_URL:
        body = body.replace((UPSTREAM + "/mcp").encode(), (MCP_PUBLIC_URL + "/mcp").encode())
    if CONSOLE_PUBLIC_URL:
        body = body.replace(UPSTREAM.encode(), CONSOLE_PUBLIC_URL.encode())
    return body


# Static, host-independent agent docs that Flats serves from its own binary
# (mcpx.LLMsPaths). Exact paths only - there is no /docs tree.
DOC_PATHS = {"/llms.txt", "/llms-full.txt", "/docs/agent-guide.md",
             "/docs/runtime-api-v1.md", "/docs/content-types.md"}
# auto (default): on exactly when a public URL is configured; true/false force.
_docs = env("FLATS_GATE_PUBLIC_DOCS", "auto").lower()
PUBLIC_DOCS = bool(CONSOLE_PUBLIC_URL) if _docs == "auto" else _docs in ("1", "true", "yes")

ACCESS_NOTE = (
    "## Access\n\n"
    "This host's MCP endpoint requires an API key. Send `Authorization: Bearer <key>` "
    "(or `X-API-Key: <key>`); without it the endpoint answers 401. Claude Code: "
    "`claude mcp add --transport http flats {url}/mcp --header \"Authorization: Bearer <key>\"`. "
    "Approvals are decided by the operator in the web console ({url}), which sits behind SSO; "
    "agents cannot approve.\n\n"
)


def rewrite_docs_body(path: str):
    def fn(body: bytes) -> bytes:
        if CONSOLE_PUBLIC_URL:
            body = body.replace(UPSTREAM.encode(), CONSOLE_PUBLIC_URL.encode())
        # only advertise a key requirement that is actually enforced, and only with a URL to show
        if CONSOLE_PUBLIC_URL and API_KEYS and path in ("/llms.txt", "/llms-full.txt"):
            note = ACCESS_NOTE.format(url=CONSOLE_PUBLIC_URL).encode()
            body = body.replace(b"\n## Docs\n", b"\n" + note + b"## Docs\n", 1)
        return body
    return fn


async def mcp_handler(request: web.Request):
    if BLOCK_METRICS and request.path == "/metrics":
        return web.json_response({"error": "metrics are not exposed"}, status=404)
    if PUBLIC_DOCS and request.path in DOC_PATHS:
        if request.method not in ("GET", "HEAD"):
            return web.json_response({"error": "method not allowed"}, status=405,
                                     headers={"Allow": "GET, HEAD"})
        headers = {k: v for k, v in clean_headers(request.headers).items()
                   if k.lower() in ("accept", "user-agent")} | {"Host": upstream_host_for_client(request)}
        return await forward(request, headers, rewrite_body=rewrite_docs_body(request.path))
    if request.path != "/mcp":
        return web.json_response({"error": "not found"}, status=404)
    if not key_ok(request):
        log.warning("auth failure from %s", request.headers.get("X-Real-IP") or request.remote)
        return web.json_response({"error": "unauthorized"}, status=401,
                                 headers={"WWW-Authenticate": 'Bearer realm="flats-mcp"'})
    headers = clean_headers(request.headers) | {"Host": upstream_host_for_client(request)}
    for h in ("Origin", "Referer", "Authorization", "X-API-Key"):
        headers.pop(h, None)
        for k in [k for k in headers if k.lower() == h.lower()]:
            headers.pop(k, None)
    return await forward(request, headers, rewrite_body=rewrite_mcp_body)


async def health(_request):
    return web.json_response({"ok": True})


async def on_startup(app):
    app["session"] = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=None, connect=5, sock_read=120),
        auto_decompress=True,
    )


async def on_cleanup(app):
    await app["session"].close()


def make_app(handler) -> web.Application:
    app = web.Application(client_max_size=64 * 1024 * 1024)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/_gate/health", health)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


async def main():
    logging.basicConfig(level=env("FLATS_GATE_LOG", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    if API_KEYS and min(len(k) for k in API_KEYS) < MIN_KEY_LEN:
        sys.exit(f"flats-gate: refusing keys shorter than {MIN_KEY_LEN} chars")
    runners = []
    for app, port in ((make_app(console_handler), CONSOLE_PORT), (make_app(mcp_handler), MCP_PORT)):
        r = web.AppRunner(app, access_log=None)
        await r.setup()
        await web.TCPSite(r, BIND, port).start()
        runners.append(r)
    log.info("console gate %s:%s (public=%s, metrics_blocked=%s) | mcp gate %s:%s (keys=%d, public_docs=%s) -> %s",
             BIND, CONSOLE_PORT, CONSOLE_PUBLIC_URL or "off", BLOCK_METRICS,
             BIND, MCP_PORT, len(API_KEYS), PUBLIC_DOCS, UPSTREAM)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
