#!/usr/bin/env python3
"""flats-gate: authenticating reverse-proxy shim in front of the Flats management server.

Why this exists
---------------
Flats (gosuda/flats) has NO authentication of its own. Its management listener
(console + /api + /mcp on one port) only accepts loopback Host/Origin names and
treats "can reach the port" as operator authority (incl. approving deploys).
Behind a reverse proxy with a public hostname every request is refused (403,
DNS-rebinding guard), and exposing it as-is would be unsafe anyway.

This shim keeps Flats on loopback and offers two loopback-only listeners that
Pangolin (newt on this host) can target:

  console gate (default 127.0.0.1:7880)
      Full operator surface (console, /console/api, /api). NO auth here - it
      must sit behind Pangolin SSO. Rewrites Host/Origin/Referer from the
      public name to the loopback name Flats accepts. Foreign Host/Origin are
      refused (keeps Flats' CSRF / rebinding protection). /mcp is NOT served
      here so the keyed entrypoint is the only MCP path.

  mcp gate (default 127.0.0.1:7881)
      ONLY POST/GET/DELETE /mcp (agent surface, cannot approve anything).
      Requires `Authorization: Bearer <key>` or `X-API-Key: <key>` from
      FLATS_GATE_API_KEYS (comma separated; empty = no key check, then rely on
      Pangolin auth). Loopback console URLs in responses (approval_url,
      console_url) are rewritten to the public console URL.

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
    "accept-encoding",  # keep upstream bodies uncompressed (needed for rewriting)
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
CONSOLE_PUBLIC_URL = env("FLATS_GATE_CONSOLE_PUBLIC_URL", "https://flats.goetzken.dev").rstrip("/")
MCP_PUBLIC_URL = env("FLATS_GATE_MCP_PUBLIC_URL", "").rstrip("/")  # optional, for mcp_url rewrite
API_KEYS = [k for k in (s.strip() for s in env("FLATS_GATE_API_KEYS").split(",")) if k]
MIN_KEY_LEN = 24

_pub = urlsplit(CONSOLE_PUBLIC_URL)
# Host names the console gate accepts. Pangolin forwards the public Host.
CONSOLE_HOSTS = {h.lower() for h in (
    [_pub.netloc] + [f"127.0.0.1:{CONSOLE_PORT}", f"localhost:{CONSOLE_PORT}"]
    + [s.strip() for s in env("FLATS_GATE_EXTRA_HOSTS").split(",") if s.strip()]
)}
CONSOLE_ORIGINS = set()
for h in CONSOLE_HOSTS:
    CONSOLE_ORIGINS.add(f"https://{h}")
    CONSOLE_ORIGINS.add(f"http://{h}")


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
    for k in API_KEYS:  # no early exit: constant-ish time over all keys
        ok |= hmac.compare_digest(cand.encode(), k.encode())
    return ok


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
            body = rewrite_body(body)
            return web.Response(status=up.status, headers=out_headers, body=body)
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
    if v.startswith(UPSTREAM):
        return CONSOLE_PUBLIC_URL + v[len(UPSTREAM):]
    return v


async def console_handler(request: web.Request):
    host = request.headers.get("Host", "").lower()
    if host not in CONSOLE_HOSTS:
        return web.json_response({"error": f"host {host!r} not served by this gate"}, status=403)
    if request.path == "/mcp" or request.path.startswith("/mcp/"):
        return web.json_response({"error": "MCP is served on the keyed MCP endpoint only"}, status=404)
    headers = clean_headers(request.headers)
    headers["Host"] = UP_HOSTPORT
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin.lower() not in CONSOLE_ORIGINS:
            return web.json_response({"error": "cross-origin request refused"}, status=403)
        headers["Origin"] = UPSTREAM
    ref = request.headers.get("Referer")
    if ref:
        rs = urlsplit(ref)
        if f"{rs.scheme}://{rs.netloc}".lower() in CONSOLE_ORIGINS:
            headers["Referer"] = UPSTREAM + (rs.path or "/") + (f"?{rs.query}" if rs.query else "")
        else:
            headers.pop("Referer", None)
    return await forward(request, headers, rewrite_location=console_location)


# -------------------------------------------------------------------- mcp gate
def rewrite_mcp_body(body: bytes) -> bytes:
    if MCP_PUBLIC_URL:
        body = body.replace((UPSTREAM + "/mcp").encode(), (MCP_PUBLIC_URL + "/mcp").encode())
    return body.replace(UPSTREAM.encode(), CONSOLE_PUBLIC_URL.encode())


# Static, host-independent agent docs that Flats serves from its own binary
# (mcpx.LLMsPaths). Exact paths only - there is no /docs tree.
DOC_PATHS = {"/llms.txt", "/llms-full.txt", "/docs/agent-guide.md",
             "/docs/runtime-api-v1.md", "/docs/content-types.md"}
PUBLIC_DOCS = env("FLATS_GATE_PUBLIC_DOCS", "true").lower() in ("1", "true", "yes")

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
        body = body.replace(UPSTREAM.encode(), CONSOLE_PUBLIC_URL.encode())
        if path in ("/llms.txt", "/llms-full.txt"):
            note = ACCESS_NOTE.format(url=CONSOLE_PUBLIC_URL).encode()
            body = body.replace(b"\n## Docs\n", b"\n" + note + b"## Docs\n", 1)
        return body
    return fn


async def mcp_handler(request: web.Request):
    if PUBLIC_DOCS and request.path in DOC_PATHS:
        if request.method not in ("GET", "HEAD"):
            return web.json_response({"error": "method not allowed"}, status=405,
                                     headers={"Allow": "GET, HEAD"})
        headers = {k: v for k, v in clean_headers(request.headers).items()
                   if k.lower() in ("accept", "user-agent")} | {"Host": UP_HOSTPORT}
        return await forward(request, headers, rewrite_body=rewrite_docs_body(request.path))
    if request.path != "/mcp":
        return web.json_response({"error": "not found"}, status=404)
    if not key_ok(request):
        log.warning("auth failure from %s", request.headers.get("X-Real-IP") or request.remote)
        return web.json_response({"error": "unauthorized"}, status=401,
                                 headers={"WWW-Authenticate": 'Bearer realm="flats-mcp"'})
    headers = clean_headers(request.headers) | {"Host": UP_HOSTPORT}
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
    log.info("console gate %s:%s (public %s) | mcp gate %s:%s (keys=%d) -> %s",
             BIND, CONSOLE_PORT, CONSOLE_PUBLIC_URL, BIND, MCP_PORT, len(API_KEYS), UPSTREAM)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
