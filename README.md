# flats-gate

Host/Origin rewrite + MCP API-key shim in front of [Flats](https://github.com/gosuda/flats) (tested against v0.11.1).

Flats has **no authentication of its own**, its management listener only accepts loopback
`Host`/`Origin` names, and anything that can reach the listener can approve deploys. A reverse
proxy with a public hostname therefore gets `403`, and an unmodified passthrough would be unsafe
anyway. This shim keeps Flats on loopback and exposes two auth boundaries:

| Listener | Serves | Auth | Typical reverse-proxy resource |
|---|---|---|---|
| `127.0.0.1:7880` console gate | console, `/console/api`, `/api` (not `/mcp`) | none here — put your proxy's SSO/login in front | `https://flats.example.org` (SSO) |
| `127.0.0.1:7881` mcp gate | `/mcp` only | `Authorization: Bearer <key>` or `X-API-Key: <key>` (keys in `.env`) | e.g. `https://flats-mcp.example.org` (no SSO) |

Console gate: `Host` must be the configured public name, `Origin` (if present) must be the public
origin; both are rewritten to `127.0.0.1:7878`. Foreign `Host`/`Origin` -> 403, so Flats' CSRF /
DNS-rebinding protection stays meaningful. MCP gate: loopback URLs inside responses
(`approval_url`, `console_url`) are rewritten to `FLATS_GATE_CONSOLE_PUBLIC_URL`. Approvals are
only possible through the console gate, never through MCP.

This is a **workaround shim**, not a feature: it is the reference implementation for the
external-console-hostname request in gosuda/flats [#137](https://github.com/gosuda/flats/issues/137). If an upstream release lets the
operator declare external console hostnames, retire this.

## Setup

```sh
python3 -m venv venv && venv/bin/pip install aiohttp
cp .env.example .env && chmod 600 .env
# set FLATS_GATE_CONSOLE_PUBLIC_URL and FLATS_GATE_API_KEYS
cp deploy/flats-gate.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now flats-gate
```

Requirements: Python 3.10+, `aiohttp`. Flats itself stays at `127.0.0.1:7878` (console/API/MCP)
and `127.0.0.1:7879` (flat sites). Rotate keys by editing `FLATS_GATE_API_KEYS` (comma separated,
one per client) and restarting. Give every client its own key so it can be revoked individually;
clients that lose the key get 401.

## Public agent docs (no key)

`FLATS_GATE_PUBLIC_DOCS` (`auto` = on exactly when `FLATS_GATE_CONSOLE_PUBLIC_URL` is set;
`true`/`false` force) serves exactly five static GET paths from Flats' own binary without a key:
`/llms.txt`, `/llms-full.txt`, `/docs/agent-guide.md`, `/docs/runtime-api-v1.md`,
`/docs/content-types.md`. Loopback URLs are rewritten to `FLATS_GATE_CONSOLE_PUBLIC_URL`;
`/llms*.txt` get an "Access" section (API-key hint) when API keys are configured. There is no
`/docs` tree — every other `/docs/...` path is 404. In the proxy, add auth-exempt path rules for
`/llms.txt`, `/llms-full.txt` and `/docs/*` pointing at :7881.

## Modes

- `FLATS_GATE_CONSOLE_PUBLIC_URL` empty = **local-only mode**: only loopback `Host` names accepted,
  no URL rewriting, no public docs, no access note.
- Public URL set = **public mode**: the configured host is accepted, URLs rewritten everywhere,
  docs on by default (`auto`). The "Access" note only appears when API keys are set.
- Mode tests: `python3 test_modes.py` — spawns throw-away instances on :17880/:17881; mode A checks
  the live service (public URL taken from `.env` when present).

## Security notes

- Flats treats "can reach the console" as operator authority. The console gate adds **no**
  authentication: put your proxy's SSO/login in front of it, and keep the management port
  (`7878`) off your network. The mcp gate's API key protects only the agent surface, which cannot
  approve anything (approvals live on `/console/api`, console gate only).
- Agent stdio (`flats mcp`) on the host and the keyed HTTP endpoint are separate paths and never
  share origins.
- Single-file Python service meant to be read before use — small, not a hardened edge proxy.
