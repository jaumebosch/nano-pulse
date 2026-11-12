# Nano Pulse

A lightweight, open-source control panel for a [Nano](https://nano.org) node — real‑time
confirmations, representative health, and system metrics in one glassy dashboard.

It runs as a single ~10 MB Docker image (static Go binary, `scratch` base) that you drop
into your node's `docker-compose.yml` so it starts alongside the node. The browser only
ever talks to **nano‑pulse**, which aggregates a read‑only summary from the node's RPC —
the node's RPC is never exposed.

> Status: **v0.1** — the dashboard is fully built and the backend serves live node data
> (sync, blocks, peers, voting weight, quorum, version, uptime, votes as PR). Opened as a
> static file it runs in a self‑contained **demo mode** with simulated data. The per‑block
> live confirmation feed (node WebSocket) is on the roadmap.

## Features

- **Live KPIs** — sync %, confirmations/s, voting weight (with Principal Rep badge), peers
- **Representative health** — votes cast as PR, vote rate/latency, weight vs quorum, health score
- **Live elections**, **weight history**, **peer map**, **version distribution** donut
- **Disk I/O + ETA**, system (CPU/RAM/disk/net), **confirmation‑latency** histogram
- **Alerts & webhooks** panel, **account explorer**
- **Widget toggles** (gear menu, per‑browser) + default set via config
- **5 languages** (EN/ES/FR/DE/IT), dark/light, **public read‑only mode**
- Three serving modes: HTTP, **self‑signed HTTPS**, or **Let's Encrypt** (no reverse proxy needed)

## Quick start

### Docker (standalone)

```bash
docker run -d --name nano-pulse -p 127.0.0.1:8080:8080 \
  -e NODE_HOST=127.0.0.1 -e NODE_RPC_PORT=7076 \
  -e REP_ACCOUNT=nano_your_representative_account \
  --add-host host.docker.internal:host-gateway \
  ghcr.io/jaumebosch/nano-pulse:latest
# open http://localhost:8080
```

### Alongside your node (recommended)

Copy `docker-compose.node.yml` into your node's stack and bring it up together:

```bash
docker compose -f docker-compose.yml -f docker-compose.node.yml up -d
```

Set `NODE_HOST` to the node's compose **service name** (e.g. `rsnano`) so it reaches the
RPC over the internal network.

### Config file

Everything is configurable via environment variables or a `nano-pulse.conf` file
(copy `nano-pulse.conf.example`). The binary reads `NP_CONFIG`, then `./nano-pulse.conf`,
then `/data/nano-pulse.conf`; env vars override the file. The same file works as a
docker‑compose `env_file`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NODE_HOST` | `127.0.0.1` | IP/hostname of the node RPC to monitor |
| `NODE_RPC_PORT` | `7076` | Node RPC port |
| `NODE_RPC_URL` | — | Full RPC URL (overrides HOST/PORT) |
| `REP_ACCOUNT` | — | Your representative account (enables the weight panel) |
| `NODE_LABEL` | — | Name under the title; if empty the node's own name is used |
| `NP_TITLE` | `Nano Pulse` | Dashboard title |
| `NP_DEFAULT_LANG` | `en` | `en`/`es`/`fr`/`de`/`it` |
| `NP_WIDGET_SWITCHES` | `true` | Show the gear menu to toggle widgets |
| `NP_PUBLIC_MODE` | `false` | Start read‑only (hide controls) |
| `NP_POLL_INTERVAL` | `5s` | Node poll interval |
| `NP_LISTEN` | `:8080` | HTTP listen address (plain mode) |
| `NP_TLS_SELFSIGNED` | `false` | HTTPS on `:443` with a self‑signed cert (no domain) |
| `NP_TLS_DOMAIN` | — | HTTPS via Let's Encrypt for this hostname |
| `NP_TLS_EMAIL` | — | ACME contact email |
| `NP_TLS_LISTEN` | `:443` | HTTPS listen address |
| `NP_TLS_HOSTS` | `127.0.0.1,localhost` | SANs for the self‑signed cert |
| `NP_TLS_CACHE` | `/data/certs` | Cert cache dir (mount a volume) |
| `NP_AUTH_USER` / `NP_AUTH_PASS` | — | Optional HTTP basic auth |

### TLS without a domain

- **Self‑signed** (`NP_TLS_SELFSIGNED=true`) — HTTPS on `:443` immediately, works with a
  bare IP; the browser warns once. Simplest for a private panel.
- **sslip.io / DuckDNS** — set `NP_TLS_DOMAIN=1-2-3-4.sslip.io` (resolves to your IP) and
  Let's Encrypt issues a valid cert. Needs ports 80/443 reachable.
- Or front it with **Tailscale / Cloudflare Tunnel** for valid HTTPS without opening ports.

## Endpoints

| Path | Description |
|---|---|
| `/` | The dashboard |
| `/api/summary` | One‑shot JSON snapshot |
| `/api/stream` | Server‑Sent Events: a fresh summary every poll interval |
| `/api/config` | Front‑end config (title, label, language, widget switches, public mode) |
| `/healthz` | Health check (no auth) |

## Build from source

```bash
go build -o nano-pulse .   # Go 1.26+
./nano-pulse               # serves on :8080
```

## Roadmap

Per‑block live confirmation feed via the node WebSocket · Telegram/Discord alert webhooks ·
Prometheus `/metrics` · delegators list · geo‑located peer map · multi‑node.

## License

MIT © [@jaumebosch](https://github.com/jaumebosch)
