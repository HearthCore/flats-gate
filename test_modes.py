#!/usr/bin/env python3
"""Mode tests for flats-gate against a live Flats host.

Mode A checks the running service (public URL taken from .env when present).
Modes B-E spawn throw-away gate instances on :17880/:17881 against the same
upstream and cover the local-only / public / docs / bad-config matrix.

The gate no longer rewrites Host/Origin: since Flats v0.12.0 the host itself
accepts declared external origins and builds public links. The gate keeps the
key requirement, the /mcp separation and the /metrics block.
"""
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = ""
for line in open(os.path.join(HERE, ".env")):
    if line.startswith("FLATS_GATE_API_KEYS="):
        KEY = line.split("=", 1)[1].strip().split(",")[0]
INIT = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
MCPH = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
fails = []


def req(url, host=None, method="GET", data=None, headers=None):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if host:
        r.add_header("Host", host)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra != "" else ""))
    if not cond:
        fails.append(name)


def spawn(extra_env):
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLATS_GATE_")}
    env.update({"FLATS_GATE_CONSOLE_PORT": "17880", "FLATS_GATE_MCP_PORT": "17881", "FLATS_GATE_SITE_PORT": "17882"})
    env.update(extra_env)
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "flats_gate.py")], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    return p


C, M = "http://127.0.0.1:17880", "http://127.0.0.1:17881"

# live-service mode: derive the public URL + host from .env when available
PUB, PUBHOST = None, None
try:
    for line in open(os.path.join(HERE, ".env")):
        if line.startswith("FLATS_GATE_CONSOLE_PUBLIC_URL="):
            PUB = line.split("=", 1)[1].strip() or None
except FileNotFoundError:
    pass
if not PUB:
    PUB = os.environ.get("FLATS_GATE_CONSOLE_PUBLIC_URL") or None
if PUB:
    _pub = urllib.parse.urlsplit(PUB)
    PUBHOST = _pub.netloc

print("== A: live service (public URL configured)")
if not PUBHOST:
    print("SKIP mode A: no FLATS_GATE_CONSOLE_PUBLIC_URL in .env")
else:
    s, b = req("http://127.0.0.1:7881/llms.txt", host=PUBHOST)
    check("A docs served with public URLs", s == 200 and f"{PUB}/mcp" in b and "127.0.0.1" not in b, s)
    check("A access note present (keys configured)", "## Access" in b)
    s, _ = req("http://127.0.0.1:7880/", host=PUBHOST)
    check("A console public host ok", s == 200, s)
    s, _ = req("http://127.0.0.1:7880/", host="evil.example.org")
    check("A console foreign host refused", s == 403, s)
    s, _ = req("http://127.0.0.1:7880/mcp", host=PUBHOST)
    check("A console /mcp blocked", s == 404, s)
    s, _ = req("http://127.0.0.1:7880/metrics", host=PUBHOST)
    check("A console /metrics blocked", s == 404, s)
    s, _ = req("http://127.0.0.1:7881/metrics")
    check("A mcp /metrics blocked", s == 404, s)
    s, _ = req("http://127.0.0.1:7881/mcp", method="POST", data=INIT, headers=MCPH)
    check("A mcp without key refused", s == 401, s)
    s, b = req("http://127.0.0.1:7881/mcp", method="POST", data=INIT, headers={**MCPH, "Authorization": f"Bearer {KEY}"})
    check("A mcp with key ok", s == 200 and '"serverInfo"' in b, s)

print("== B: no public URL (local-only mode, no key)")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "", "FLATS_GATE_API_KEYS": ""})
s, _ = req(M + "/llms.txt")
check("B docs off by default (auto)", s == 404, s)
s, _ = req(C + "/", host="127.0.0.1:17880")
check("B console via loopback host ok", s == 200, s)
s, _ = req(C + "/", host="evil.example.org")
check("B console foreign host refused", s == 403, s)
s, _ = req(M + "/mcp", method="POST", data=INIT, headers=MCPH)
check("B mcp without key ok (no key configured)", s == 200, s)
p.terminate(); p.wait(5)

print("== C: docs forced on, no public URL, key set")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "", "FLATS_GATE_PUBLIC_DOCS": "true", "FLATS_GATE_API_KEYS": KEY})
s, b = req(M + "/llms.txt")
check("C docs served unchanged", s == 200, s)
check("C no access note without public URL", "## Access" not in b)
p.terminate(); p.wait(5)

print("== D: docs explicitly off with public URL")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": f"https://{PUBHOST}" if PUBHOST else "https://flats.example.org",
           "FLATS_GATE_PUBLIC_DOCS": "false", "FLATS_GATE_API_KEYS": KEY})
s, _ = req(M + "/llms.txt")
check("D docs off when false", s == 404, s)
s, _ = req(C + "/", host=PUBHOST if PUBHOST else "flats.example.org")
check("D console accepts the declared public host", s == 200, s)
p.terminate(); p.wait(5)

print("== D2: gate public URL not declared in Flats -> upstream refuses")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "https://not-declared.example.org", "FLATS_GATE_API_KEYS": KEY})
s, _ = req(C + "/", host="not-declared.example.org")
check("D2 undeclared origin refused by Flats", s == 403, s)
p.terminate(); p.wait(5)

print("== E: bad public URL")
r = subprocess.run([sys.executable, os.path.join(HERE, "flats_gate.py")], capture_output=True, text=True, timeout=10,
                   env={**os.environ, "FLATS_GATE_CONSOLE_PUBLIC_URL": "flats.example.org",
                        "FLATS_GATE_CONSOLE_PORT": "17880", "FLATS_GATE_MCP_PORT": "17881"})
check("E invalid URL aborts start", r.returncode != 0 and "must be http(s)" in (r.stdout + r.stderr))

print("== F: site gate (*.suffix -> <slug>.localhost)")
slug = None
try:
    import json as _json
    with urllib.request.urlopen("http://127.0.0.1:7878/api/flats", timeout=10) as _r:
        _flats = _json.load(_r).get("flats") or []
    slug = _flats[0]["slug"] if _flats else None
except Exception:
    pass
SUF = "flats.example.org"
if not slug:
    print("SKIP mode F: no flat on the local Flats host")
else:
    p = spawn({"FLATS_GATE_SITE_PUBLIC_SUFFIX": SUF, "FLATS_GATE_SITE_POLICY": "all", "FLATS_GATE_API_KEYS": KEY})
    S = "http://127.0.0.1:17882"
    s, _ = req(S + "/", host=f"{slug}.{SUF}")
    check("F policy=all serves an existing flat", s == 200, s)
    s, _ = req(S + "/", host=f"nope-{slug}.{SUF}")
    check("F unknown flat answers 404", s == 404, s)
    s, _ = req(S + "/", host="evil.example.org")
    check("F foreign host refused", s == 404, s)
    s, _ = req(S + "/", host=SUF)
    check("F apex refused", s == 404, s)
    s, _ = req(S + "/", host=f"a.{slug}.{SUF}")
    check("F multi-label host refused", s == 404, s)
    p.terminate(); p.wait(5)
    p = spawn({"FLATS_GATE_SITE_PUBLIC_SUFFIX": SUF, "FLATS_GATE_SITE_POLICY": "public", "FLATS_GATE_API_KEYS": KEY})
    private = [f["slug"] for f in _flats if f.get("visibility") != "public"]
    if private:
        s, _ = req(S + "/", host=f"{private[0]}.{SUF}")
        check("F policy=public hides a private flat", s == 404, s)
    p.terminate(); p.wait(5)

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
