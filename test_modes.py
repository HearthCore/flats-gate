#!/usr/bin/env python3
"""Mode test for flats-gate: public-URL mode (live service), local-only mode, forced-docs mode, bad config.
Spawns throw-away gate instances on :17880/:17881 against the live Flats on :7878. Needs the key in .env only for mode C."""
import os, subprocess, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = ""
for line in open(os.path.join(HERE, ".env")):
    if line.startswith("FLATS_GATE_API_KEYS="):
        KEY = line.split("=", 1)[1].strip().split(",")[0]
INIT = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
fails = []


def req(url, host=None, method="GET", data=None, headers=None):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if host:
        r.add_header("Host", host)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))
    if not cond:
        fails.append(name)


def spawn(extra_env):
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLATS_GATE_")}
    env.update({"FLATS_GATE_CONSOLE_PORT": "17880", "FLATS_GATE_MCP_PORT": "17881"})
    env.update(extra_env)
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "flats_gate.py")], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    return p


C, M = "http://127.0.0.1:17880", "http://127.0.0.1:17881"
MCPH = {"content-type": "application/json", "accept": "application/json, text/event-stream"}

print("== A: public URL set (live service on 7880/7881)")
s, b = req("http://127.0.0.1:7881/llms.txt")
check("A docs served + rewritten", s == 200 and "https://flats.goetzken.dev/mcp" in b and "127.0.0.1" not in b)
check("A access note present (keys configured)", "## Access" in b)
s, _ = req("http://127.0.0.1:7880/", host="flats.goetzken.dev")
check("A console public host ok", s == 200, s)

print("== B: no public URL (local-only mode, no key)")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "", "FLATS_GATE_API_KEYS": ""})
s, _ = req(M + "/llms.txt")
check("B docs off by default (auto)", s == 404, s)
s, _ = req(C + "/", host="127.0.0.1:17880")
check("B console via loopback host ok", s == 200, s)
s, _ = req(C + "/", host="flats.goetzken.dev")
check("B console public host refused", s == 403, s)
s, _ = req(M + "/mcp", method="POST", data=INIT, headers=MCPH)
check("B mcp without key ok (no key configured)", s == 200, s)
p.terminate(); p.wait(5)

print("== C: docs forced on, no public URL, key set")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "", "FLATS_GATE_PUBLIC_DOCS": "true", "FLATS_GATE_API_KEYS": KEY})
s, b = req(M + "/llms.txt")
check("C docs unchanged (loopback URLs kept)", s == 200 and "http://127.0.0.1:7878/mcp" in b)
check("C no access note without public URL", "## Access" not in b)
p.terminate(); p.wait(5)

print("== D: docs explicitly off with public URL")
p = spawn({"FLATS_GATE_CONSOLE_PUBLIC_URL": "https://flats.example.org", "FLATS_GATE_PUBLIC_DOCS": "false", "FLATS_GATE_API_KEYS": KEY})
s, _ = req(M + "/llms.txt")
check("D docs off when false", s == 404, s)
s, _ = req(C + "/", host="flats.example.org")
check("D console accepts configured public host", s == 200, s)
p.terminate(); p.wait(5)

print("== E: bad public URL")
r = subprocess.run([sys.executable, os.path.join(HERE, "flats_gate.py")], capture_output=True, text=True, timeout=10,
                   env={**os.environ, "FLATS_GATE_CONSOLE_PUBLIC_URL": "flats.goetzken.dev", "FLATS_GATE_CONSOLE_PORT": "17880", "FLATS_GATE_MCP_PORT": "17881"})
check("E invalid URL aborts start", r.returncode != 0 and "must be http(s)" in (r.stdout + r.stderr))

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
