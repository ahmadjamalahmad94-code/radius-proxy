# RADIUS Proxy — Deployment Guide

> **Security classification:** internal infrastructure — handle with care.
> This file documents how to deploy `radius-proxy` safely in production.

---

## Table of Contents

1. [Architecture overview](#architecture-overview)
2. [Required environment variables](#required-environment-variables)
3. [Ports and firewall rules](#ports-and-firewall-rules)
4. [Target RADIUS requirements](#target-radius-requirements)
5. [Accounting timeout mode](#accounting-timeout-mode)
6. [Strict response verification](#strict-response-verification)
7. [Fail-open CHR allowlist warning](#fail-open-chr-allowlist-warning)
8. [Running tests](#running-tests)
9. [Systemd install](#systemd-install)
10. [Log checks](#log-checks)

---

## Architecture overview

```
CHR Node(s)
  │  wg-mgmt tunnel only (API/telemetry — no data traffic)
  │  UDP 1812 / 1813 via WireGuard
  ▼
radius-proxy  (this service)
  │  Re-signs RADIUS packets: CHR secret → customer secret
  │  Routes by @realm from User-Name attribute
  │  UDP 1812 / 1813 to customer RADIUS VPS
  ▼
Customer RADIUS (FreeRADIUS / Cisco ISE / etc.)
  │  Returns Access-Accept / Access-Reject / Accounting-Response
  ▼
radius-proxy re-signs response: customer secret → CHR secret
  ▼
CHR Node receives authenticated response
```

**Key invariants:**
- CHR nodes only know the proxy address — never individual customer RADIUS IPs.
- `wg-mgmt` MUST NOT carry data traffic (no NAT, no default route, no forwarding).
- RADIUS ports **MUST NOT** be opened to the public internet; all CHR-to-proxy
  traffic travels inside a WireGuard tunnel.
- Private keys and RADIUS secrets are NEVER logged or returned to client apps.

---

## Required environment variables

Set these in `/etc/radius-proxy.env` (mode 0600, owned by the service user):

| Variable | Required | Default | Description |
|---|---|---|---|
| `PROXY_CHR_SECRET` | **yes** | `changeme-chr-secret` | Shared secret used by all CHR nodes when sending RADIUS to this proxy. Change before any production use. |
| `ADMIN_BASE_URL` | **yes** | `https://panel.hoberadius.com` | License panel base URL — used to pull routing table and send heartbeats. |
| `RADIUS_PROXY_SHARED_SECRET` | **yes** | *(empty)* | API token for authenticating with the license panel. |
| `PROXY_ENV` | **yes (prod)** | *(empty)* | Set to `production` to activate secure defaults (`STRICT_RESPONSE_VERIFY=true`). |
| `PROXY_LISTEN_HOST` | no | `0.0.0.0` | Bind address. Restrict to the WireGuard interface IP in production. |
| `PROXY_AUTH_PORT` | no | `1812` | UDP port for Access-Request / Access-Accept. |
| `PROXY_ACCT_PORT` | no | `1813` | UDP port for Accounting-Request / Accounting-Response. |
| `PROXY_FORWARD_TIMEOUT` | no | `10` | Seconds to wait for a response from the target RADIUS. |
| `PROXY_ROUTING_REFRESH` | no | `60` | Seconds between routing table refreshes from the license panel. |
| `PROXY_HEARTBEAT_INTERVAL` | no | `30` | Seconds between heartbeat pings to the license panel. |
| `PROXY_LOG_LEVEL` | no | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `PROXY_LOG_REALMS` | no | `true` | Set `false` in high-privacy environments to suppress realm names in logs. |
| `PROXY_FAIL_OPEN_CHR_ALLOWLIST` | no | `false` | **See [Fail-open warning](#fail-open-chr-allowlist-warning).** |
| `PROXY_ACCT_TIMEOUT_MODE` | no | `strict` | **See [Accounting timeout mode](#accounting-timeout-mode).** |
| `PROXY_STRICT_RESPONSE_VERIFY` | no | `true` when `PROXY_ENV=production` | **See [Strict response verification](#strict-response-verification).** |
| `PROXY_ID` | no | random hex | Stable identifier sent in heartbeats. Set explicitly for multi-instance setups. |

**Minimal production `.env` example:**

```env
PROXY_ENV=production
PROXY_CHR_SECRET=<long-random-string>
ADMIN_BASE_URL=https://panel.hoberadius.com
RADIUS_PROXY_SHARED_SECRET=<api-token-from-panel>
PROXY_LISTEN_HOST=10.10.0.2          # WireGuard interface IP
PROXY_ACCT_TIMEOUT_MODE=strict
# PROXY_STRICT_RESPONSE_VERIFY is true by default when PROXY_ENV=production
```

---

## Ports and firewall rules

### Open (inbound on the proxy host)

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 1812 | UDP | CHR nodes (via WireGuard) | RADIUS Access-Request |
| 1813 | UDP | CHR nodes (via WireGuard) | RADIUS Accounting-Request |

**These ports MUST be firewalled from the public internet.**
Only accept packets from the WireGuard interface (`wg-mgmt`), not from `eth0`.

Example (iptables):
```bash
# Allow RADIUS only from WireGuard interface
iptables -A INPUT -i wg-mgmt -p udp --dport 1812 -j ACCEPT
iptables -A INPUT -i wg-mgmt -p udp --dport 1813 -j ACCEPT
# Drop from all other interfaces
iptables -A INPUT -p udp --dport 1812 -j DROP
iptables -A INPUT -p udp --dport 1813 -j DROP
```

### Open (outbound from the proxy host)

| Port | Protocol | Destination | Purpose |
|---|---|---|---|
| 1812 | UDP | Customer RADIUS VPS | Forward Access-Request |
| 1813 | UDP | Customer RADIUS VPS | Forward Accounting-Request |
| 443 | TCP | License panel (`ADMIN_BASE_URL`) | Routing table + heartbeat API |

---

## Target RADIUS requirements

Each customer's RADIUS server (`RouteEntry.auth_addr` / `acct_addr`) must:

1. **Accept UDP on 1812 (auth) and 1813 (acct)** from the proxy host IP.
2. **Share a RADIUS secret** configured in the license panel as `RouteEntry.secret`.
   This secret is used by the proxy to re-sign packets before forwarding.
3. **Sign responses** with the same secret and the correct Response-Authenticator
   (RFC 2865 §3).  With `PROXY_STRICT_RESPONSE_VERIFY=true` (production default),
   any response that fails authenticator verification is dropped.
4. **Not expose RADIUS ports to the internet** — use a firewall allowlist limited
   to the proxy's outbound IP.

---

## Accounting timeout mode

Controlled by `PROXY_ACCT_TIMEOUT_MODE`.

| Value | Behaviour | When to use |
|---|---|---|
| `strict` *(default)* | Silent drop when target RADIUS doesn't respond within `PROXY_FORWARD_TIMEOUT`. CHR retransmits until its own timer expires. Accounting data is eventually re-sent. | Always (production default). No data fabrication. |
| `ack_on_timeout` | Send a fake `Accounting-Response (code 5)` to CHR. Stops retransmit storm immediately. **The accounting record for this request is LOST upstream.** | Only when CHR retransmit storms are a confirmed operational problem. |

> **⚠ WARNING — `ack_on_timeout`:**
> The fake ACK only tells the CHR "packet received."
> It does **NOT** prove that the target RADIUS ever received or stored the record.
> Accounting data for timed-out requests is **permanently lost** upstream.
> Each fake ACK is logged at `WARNING` level with the session identifier.

**Legacy aliases** (accepted for backward compatibility, but deprecated):
- `drop` → treated as `strict` (deprecation WARNING logged at startup)
- `fake_ack` → treated as `ack_on_timeout` (deprecation WARNING logged at startup)

---

## Strict response verification

Controlled by `PROXY_STRICT_RESPONSE_VERIFY`.

| Value | Behaviour |
|---|---|
| `true` | Drop any response from the target RADIUS whose `Response-Authenticator` does not match the RFC 2865 expected value. Prevents tampered, replayed, or corrupt packets from reaching CHR nodes. **Production default when `PROXY_ENV=production`.** |
| `false` | Log a `WARNING` and forward the response anyway. Useful in dev/CI when testing against non-compliant RADIUS implementations. |

**Production deployments MUST use `true`** (either via `PROXY_ENV=production` or
`PROXY_STRICT_RESPONSE_VERIFY=true`).

When a response is dropped in strict mode, the log entry looks like:
```
WARNING  proxy: Dropping response from realm 'client5':
         Response-Authenticator mismatch from target RADIUS
         (code=2 id=7) — packet dropped (PROXY_STRICT_RESPONSE_VERIFY=true)
```
The CHR will retransmit the request (normal RADIUS retry behaviour).

---

## Fail-open CHR allowlist warning

`PROXY_FAIL_OPEN_CHR_ALLOWLIST` defaults to `false`.

- **`false` (production):** If the CHR allowlist is empty (no CHR nodes loaded
  from the license panel yet), **all source IPs are rejected.**
  This is the secure default — if the proxy can't reach the panel on startup,
  it fails closed rather than accepting packets from unknown sources.

- **`true` (dev only):** Any source IP is accepted when the allowlist is empty.
  Set this only during initial bootstrap when you have no CHR nodes registered
  and need to test packet flow.

> **Never set `PROXY_FAIL_OPEN_CHR_ALLOWLIST=true` in production.**

---

## Running tests

```bash
cd radius-proxy/

# Run all tests (requires Python 3.10+)
python -m pytest tests/ -v

# Run only the hardening tests
python -m pytest tests/test_radius_packet.py -v -k "StrictVerify or Normalization"

# Run with coverage
python -m pytest tests/ --cov=radius_packet --cov=config --cov=proxy
```

All tests must pass before any production deployment.
The following test classes cover the hardening additions:

| Class | What it tests |
|---|---|
| `TestRebuildResponseStrictVerify` | `strict_verify=False` warns; `strict_verify=True` raises `RadiusError` |
| `TestAcctTimeoutModeNormalization` | `strict`/`ack_on_timeout` canonical; `drop`/`fake_ack` aliases with deprecation |

---

## Systemd install

Create `/etc/systemd/system/radius-proxy.service`:

```ini
[Unit]
Description=HobeRadius Central RADIUS Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=radius-proxy
Group=radius-proxy
WorkingDirectory=/opt/radius-proxy
EnvironmentFile=/etc/radius-proxy.env
ExecStart=/opt/radius-proxy/venv/bin/python main.py
Restart=on-failure
RestartSec=5
# Harden the process
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/radius-proxy
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable radius-proxy
systemctl start radius-proxy
systemctl status radius-proxy
```

---

## Log checks

**Verify the proxy is running cleanly:**

```bash
# Service status
journalctl -u radius-proxy -n 50 --no-pager

# Watch live (auth + accounting traffic)
journalctl -u radius-proxy -f

# Check for startup deprecation warnings (old env var values)
journalctl -u radius-proxy -b | grep -i deprecated

# Check for strict-mode drops (tampered responses from target RADIUS)
journalctl -u radius-proxy | grep "Dropping response"

# Check for fake ACKs (ack_on_timeout events — should be rare)
journalctl -u radius-proxy | grep "ack_on_timeout"

# Check for CHR allowlist rejects (unknown source IPs)
journalctl -u radius-proxy | grep "unknown CHR IP"
```

**Expected healthy startup log (production):**
```
INFO  proxy: Auth listener ready
INFO  proxy: Accounting listener ready
INFO  proxy: RADIUS Proxy started | auth=:1812 acct=:1813
INFO  routing_table: Loaded N routes from panel
```

**Red flags to investigate immediately:**
- `PROXY_FAIL_OPEN_CHR_ALLOWLIST=True in production` — fix env and restart
- Repeated `"Dropping response"` from a specific realm — target RADIUS misconfigured
- `"fake_ack"` in logs at high frequency — target RADIUS is down or unreachable
- `"Message-Authenticator mismatch"` — CHR secret misconfigured or packet tampering
