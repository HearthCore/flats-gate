"""Site gate: serve Flats flat sites under <slug>.<public-suffix> behind a reverse proxy.

Why this exists
---------------
Flats' local site listener routes by Host and accepts only `<slug>.localhost` hosts
(anything else answers 404 "unknown host; use http://<flat>.localhost:7879"). A
reverse proxy that forwards the public hostname therefore gets a 404 for every
request. This gate maps the public hostname back to the form Flats understands:

    <slug>.<public-suffix>  ->  Host: <slug>.localhost  ->  Flats site listener

The local listener serves every flat, including private ones - "private" in Flats
means "not published through a public provider", not "hidden from the operator's
own machine". A public wildcard therefore has to filter on visibility itself.

Access policy (FLATS_GATE_SITE_POLICY)
--------------------------------------
  public (default)  only flats that Flats reports as visibility=public
  allowlist         only slugs listed in FLATS_GATE_SITE_ALLOWLIST
  all               no filtering - exposes private flats too, do not use
"""
from __future__ import annotations

import logging
import os
import re
import time

from aiohttp import ClientSession, ClientTimeout, web

log = logging.getLogger("flats-site-gate")

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}
STRIP_REQ = HOP | {
    "accept-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-port", "x-real-ip", "forwarded", "cf-connecting-ip",
}
REWRITE_TYPES = ("text/", "application/json", "application/javascript", "text/javascript")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


UPSTREAM = env("FLATS_SITE_UPSTREAM", "http://127.0.0.1:7879").rstrip("/")
API_URL = env("FLATS_SITE_API", "http://127.0.0.1:7878").rstrip("/")
SUFFIX = env("FLATS_GATE_SITE_PUBLIC_SUFFIX", "").lower().strip(".")
ALLOWLIST_FILE = env("FLATS_GATE_SITE_ALLOWLIST", "")
POLICY = env("FLATS_GATE_SITE_POLICY", "public").lower()
CACHE_TTL = int(env("FLATS_GATE_SITE_CACHE_TTL", "15"))

_cache = {"at": 0.0, "public": set()}


def load_allowlist() -> set:
    if not ALLOWLIST_FILE:
        return set()
    try:
        with open(ALLOWLIST_FILE) as f:
            return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}
    except OSError as e:
        log.warning("allowlist %s unreadable: %s", ALLOWLIST_FILE, e)
        return set()


async def fetch_public_slugs(session) -> set:
    """Slugs Flats marks as public, straight from the management API."""
    try:
        async with session.get(f"{API_URL}/api/flats", timeout=ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                log.warning("flats api status %s", resp.status)
                return set()
            data = await resp.json()
    except Exception as e:
        log.warning("flats api unreachable: %s", e)
        return set()
    return {
        str(f.get("slug") or "").lower()
        for f in (data.get("flats") or [])
        if f.get("visibility") == "public" and f.get("slug")
    }


async def slug_allowed(slug: str, session) -> bool:
    if POLICY == "all":
        return True
    if POLICY == "allowlist":
        return slug in load_allowlist()
    now = time.monotonic()
    if now - _cache["at"] > CACHE_TTL:
        _cache["public"] = await fetch_public_slugs(session)
        _cache["at"] = now
    return slug in _cache["public"]


def rewrite_body(slug: str, body: bytes, content_type: str) -> bytes:
    """Point absolute links at the public hostname instead of the loopback name."""
    if not any(t in content_type for t in REWRITE_TYPES):
        return body
    public = f"{slug}.{SUFFIX}".encode()
    for loopback in (f"{slug}.localhost:7879".encode(), f"{slug}.localhost".encode()):
        body = body.replace(b"http://" + loopback, b"https://" + public)
        body = body.replace(b"http://" + public, b"https://" + public)
        body = body.replace(loopback, public)
    return body


def make_site_handler():
    async def site_handler(request: web.Request):
        host = request.headers.get("Host", "").lower().split(":")[0]
        if not SUFFIX or not host.endswith("." + SUFFIX):
            return web.json_response({"error": "unknown host"}, status=404)
        slug = host[: -(len(SUFFIX) + 1)]
        if not SLUG_RE.match(slug):
            return web.json_response({"error": "unknown host"}, status=404)
        session: ClientSession = request.app["session"]
        if not await slug_allowed(slug, session):
            return web.json_response({"error": "not found"}, status=404)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in STRIP_REQ}
        headers["Host"] = f"{slug}.localhost"
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = f"{slug}.{SUFFIX}"
        url = UPSTREAM + request.rel_url.raw_path_qs
        data = request.content if request.can_read_body else None
        try:
            up = await session.request(
                request.method, url, headers=headers, data=data,
                allow_redirects=False, auto_decompress=True,
            )
        except Exception as e:
            log.warning("upstream error %s %s: %s", request.method, request.path, e)
            return web.json_response({"error": "flats upstream unavailable"}, status=502)
        try:
            out_headers = {}
            for k, v in up.headers.items():
                if k.lower() in HOP or k.lower() == "content-encoding":
                    continue
                out_headers[k] = v
            ctype = up.headers.get("Content-Type", "")
            if not up.headers.get("Content-Encoding") and any(t in ctype for t in REWRITE_TYPES):
                body = rewrite_body(slug, await up.read(), ctype)
                return web.Response(status=up.status, headers=out_headers, body=body)
            resp = web.StreamResponse(status=up.status, headers=out_headers)
            await resp.prepare(request)
            async for chunk in up.content.iter_any():
                await resp.write(chunk)
            await resp.write_eof()
            return resp
        finally:
            up.release()

    return site_handler
