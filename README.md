# flats-gate

Auth shim in front of [Flats](https://github.com/gosuda/flats) (tested against v0.12.0).

Flats has **no authentication of its own**: anyone who can reach its management listener can
approve deploys, and the agent surface (`/mcp`) is exposed with it. This shim keeps Flats on
loopback and puts two auth boundaries in front of it:

| Listener | Serves | Auth | Typical reverse-proxy resource |
|---|---|---|---|
| `127.0.0.1:7880` console gate | console, `/console/api`, `/api` (not `/mcp`, not `/metrics`) | none here — put your proxy's SSO/login in front | `https://flats.example.org` (SSO) |
| `127.0.0.1:7881` mcp gate | `/mcp` only | `Authorization: Bearer <key>` or `X-API-Key: <key>` (keys in `.env`) | e.g. `https://flats-mcp.example.org` (no SSO) |

The agent surface cannot approve anything (approvals live on `/console/api`, console gate only),
so a key is enough to expose it without SSO. Upstream tracks built-in authentication in
[gosuda/flats#139](https://github.com/gosuda/flats/issues/139); when that lands, the key gate can
be dropped.

## What the gate does and does not do

- **Does not rewrite Host/Origin.** Flats v0.12.0 understands external origins
  (`console.external_origins`): it accepts the declared public Host, refuses foreign Hosts and
  Origins itself, and builds approval links plus the `llms.txt` documents with the declared
  scheme. The gate passes the public Host through unchanged.
- **Refuses foreign Hosts on the console listener** (defence in depth; Flats refuses them too).
- **Keeps `/mcp` off the console resource**, so the SSO'd resource cannot be used to skip the key.
- **Blocks `/metrics`.** Flats v0.12.0 added it without a credential: it exposes private flat
  slugs, CPU and memory to everyone who can reach the console. Set `FLATS_GATE_BLOCK_METRICS=0`
  to allow it.
- **Rewrites loopback URLs** in responses to the public console URL as a fallback for hosts that
  still emit them, and adds an "Access" section to `llms.txt` / `llms-full.txt` when API keys are
  configured.

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

**`FLATS_GATE_CONSOLE_PUBLIC_URL` must match an entry in Flats' `console.external_origins`**
(Flats v0.12.0+). The gate passes the public Host through unchanged, so Flats itself accepts or
refuses it. A host the Flats host does not know about gets 403 from Flats, not from the gate.
Set it offline with the Flats host stopped:

```sh
flats config set console.external_origins 'https://flats.example.org'
```

## Site gate: `*.flats` wildcard (optional)

Flat sites are served by Flats on a separate loopback listener (`127.0.0.1:7879`) and only for the
host form `<slug>.localhost`. A reverse proxy that forwards `<slug>.flats.example.org` therefore gets a 404.
Set `FLATS_GATE_SITE_PUBLIC_SUFFIX=flats.example.org` and the gate opens a third listener (`:7882`) that
maps `<slug>.<suffix>` back to `<slug>.localhost`. Point a wildcard route at it.

- **Policy** (`FLATS_GATE_SITE_POLICY`): `public` (default, only flats with visibility=public, read live
  from the Flats API), `allowlist` (slugs in `FLATS_GATE_SITE_ALLOWLIST`), `all` (every flat, private
  ones included: only use it with authentication in front of the wildcard route).
- **Links**: Flats reports flat links as `http://<slug>.localhost:7879`. With a suffix set, the gate
  rewrites them to `https://<slug>.<suffix>` in console API JSON and MCP answers (HTML/JS are untouched).
- **Proxy side**: needs a wildcard certificate (DNS-01) and a wildcard route to `127.0.0.1:7882`.
- Off unless the suffix is set. Tests: mode F in `test_modes.py`.

## Public agent docs (no key)

`FLATS_GATE_PUBLIC_DOCS` (`auto` = on exactly when `FLATS_GATE_CONSOLE_PUBLIC_URL` is set;
`true`/`false` force) serves exactly five static GET paths from Flats' own binary without a key:
`/llms.txt`, `/llms-full.txt`, `/docs/agent-guide.md`, `/docs/runtime-api-v1.md`,
`/docs/content-types.md`. There is no `/docs` tree — every other `/docs/...` path is 404. In the
proxy, add auth-exempt path rules for `/llms.txt`, `/llms-full.txt` and `/docs/*`.

## Modes

- `FLATS_GATE_CONSOLE_PUBLIC_URL` empty = **local-only mode**: only loopback `Host` names accepted,
  no public docs, no access note.
- Public URL set = **public mode**: docs on by default (`auto`). The "Access" note only appears
  when API keys are set.
- Mode tests: `python3 test_modes.py` — mode A checks the live service, modes B-E spawn
  throw-away instances on :17880/:17881 and cover local-only, public, docs on/off, key on/off,
  an origin Flats does not know, and a bad URL.

## Security notes

- Flats treats "can reach the console" as operator authority. The console gate adds **no**
  authentication: put your proxy's SSO/login in front of it, and keep the management port
  (`7878`) off your network. The mcp gate's API key protects only the agent surface, which cannot
  approve anything.
- Agent stdio (`flats mcp`) on the host and the keyed HTTP endpoint are separate paths and never
  share origins.
- Single-file Python service meant to be read before use — small, not a hardened edge proxy.
