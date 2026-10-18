# flats-gate

Auth/Host shim in front of [Flats](https://github.com/gosuda/flats) (v0.11.1, systemd user unit `flats.service`, data in `~/.config/Flats`).

Flats has no auth of its own and only accepts loopback Host/Origin names, so a reverse proxy
with a public hostname gets 403. This shim keeps Flats on loopback and exposes:

| Listener | Serves | Auth | Pangolin resource |
|---|---|---|---|
| `127.0.0.1:7880` console gate | console, `/console/api`, `/api` (NOT `/mcp`) | none here -> Pangolin SSO | `https://flats.goetzken.dev` (SSO) |
| `127.0.0.1:7881` mcp gate | `/mcp` only | `Authorization: Bearer <key>` or `X-API-Key` (keys in `.env`) | e.g. `https://flats-mcp.goetzken.dev` (no Pangolin SSO) |

Console gate: Host must be the public name, Origin (if present) must be the public origin, both are
rewritten to `127.0.0.1:7878`. Foreign Host/Origin -> 403 (keeps Flats' CSRF protection).
MCP gate: loopback console URLs in responses (`approval_url`) are rewritten to `FLATS_GATE_CONSOLE_PUBLIC_URL`.
Approvals are only possible through the console gate (SSO), never through MCP.

Service: `systemctl status flats-gate` (system unit), config `/root/flats-gate/.env` (mode 600).
Rotate key: edit `FLATS_GATE_API_KEYS` (comma separated, one per client), `systemctl restart flats-gate`.
Hermes MCP: `mcp_servers.flats` = stdio `/root/.local/bin/flats mcp` (loopback, no key needed).
Skill: `~/.hermes/skills/devops/flats-deploy/SKILL.md` (refresh: `flats skill sync --output <path>`).
