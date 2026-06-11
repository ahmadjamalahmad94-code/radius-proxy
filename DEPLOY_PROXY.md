# DEPLOY_PROXY.md — First Live Proxy Deployment Runbook

> **Target:** the owner's first production `radius-proxy` host.
> **Host:** `178.105.251.67` · DNS `proxy.hoberadius.com` (Cloudflare, **DNS-only/grey cloud** — WireGuard is UDP, it must NOT be proxied)
> **OS assumed:** fresh **Ubuntu 22.04** with root SSH. (Different distro? Adjust the `apt` lines and ufw; everything else is identical.)
> **Panel:** `https://hoberadius.com` (radius-module-admin)
> **First CHR:** `chr-vpn-1` — wg-data IP `10.98.0.11`, public IP `178.105.244.112`, wg-data listen 51821, dials the proxy at `proxy.hoberadius.com:51821`, expects allowed-address `10.98.0.1/32`.
> **Data plane:** proxy = `10.98.0.1/24`, CHRs = `10.98.0.x`. (Control plane wg-mgmt `10.99.0.x` is panel↔CHR and is **not** part of this runbook.)

Values **only the owner has** are marked like this: `🔑 OWNER-VALUE`.
There are exactly four: the two panel secrets, and the CHR's wg-data public key, plus your SSH access.

---

## Scope — what this proxy does, and what it explicitly does NOT

This service is **only** a UDP RADIUS relay + a small panel-facing control
client. It is NOT in the licensing or integration path.

**The proxy DOES:**
- Listen on UDP `1812` (Auth) and `1813` (Acct) on the wg-data interface
  (`10.98.0.1`), accept RADIUS from registered CHRs, re-sign with the per-
  customer secret, forward to the customer's RADIUS, re-sign the response
  with the CHR secret, return it.
- Speak HTTPS **outbound only** to the panel, on these endpoints exclusively
  (all under `/api/proxy/`):
  - `GET  /api/proxy/routing-table` — pull realms + CHR allowlist.
  - `POST /api/proxy/heartbeat` — uptime + stats.
  - `POST /api/proxy/telemetry` — per-node session/egress samples.
  - `POST /api/proxy/placement` — §2 placement feedback.
  - `GET  /api/proxy/placement-decision` — advisory read.
  - `POST /api/proxy/enforcement` — §1.4 enforcement outcomes.
  - All authenticated with the proxy's own `X-Proxy-Token` (HMAC-SHA256
    keyed with `RADIUS_PROXY_SHARED_SECRET`).
- Send RFC 5176 CoA (Disconnect / Change-of-Authorization) **outbound** to
  each CHR on UDP 3799 (over wg-data) for kill-old / move.

**The proxy DOES NOT (and MUST never):**
- Run any inbound HTTP listener. There is no HTTP server in this codebase
  (`grep -nE 'aiohttp|flask|fastapi|starlette|http\.server' *.py` → empty).
  The only sockets the proxy opens are the two UDP listeners above plus
  outbound UDP/HTTPS clients.
- Touch the **licensing-runtime** path. `radius-module` (the per-customer
  appliance) talks to the panel directly over HTTPS for `/api/license/*`
  and licensing checks. The proxy is not a hop.
- Touch the **integration** path (`/api/integration/*`). Integration calls
  go radius-module ↔ panel directly. The proxy doesn't see them, doesn't
  forward them, doesn't proxy them, doesn't observe them.
- Touch the **backup / bridge** path. Backups flow radius-module ↔ panel
  (or radius-module ↔ object storage) directly. The proxy is not involved.
- Hold any customer secret beyond what the panel publishes in
  `routes[].secret` (per-realm, fetched at refresh). It holds NO license
  keys, NO integration tokens, NO billing data.

> **Operational consequence.** A `403 Forbidden` on `/api/license/*` or
> `/api/integration/*` cannot have come from the proxy. The proxy is not a
> hop on those URLs. Investigate the radius-module ↔ panel path directly.

This is enforced by [`tests/test_proxy_not_in_license_path.py`](tests/test_proxy_not_in_license_path.py):
the source must contain zero references to `/api/license`, `/api/integration`,
or backup URLs, and every URL the proxy constructs at runtime must start
with `/api/proxy/`. If a future change violates this, CI fails.

---

## 0. Before you start — what you need in hand

| # | Value | Where it comes from |
|---|-------|---------------------|
| 1 | `🔑 RADIUS_PROXY_SHARED_SECRET` | The panel API token — panel page **«إعدادات البنية → وكيل RADIUS المركزي»**. Must be IDENTICAL on panel + proxy. |
| 2 | `🔑 PROXY_CHR_SECRET` | The fleet-wide RADIUS shared secret you generated on the same panel infra page (every CHR uses it toward the proxy). |
| 3 | `🔑 CHR wg-data PUBLIC key` | Read on the MikroTik (step 2.3 below). |
| 4 | Root SSH to `178.105.251.67` | — |

---

## 1. System prep

SSH in as root (`ssh root@178.105.251.67`), then:

```bash
apt update && apt -y upgrade
apt -y install wireguard-tools python3 python3-venv python3-pip git ufw
```

UFW is configured by an idempotent script shipped in the repo
(`systemd/setup-ufw.sh`) — re-running it is safe and recommended on every
deploy. It enforces the firewall invariants automatically; do NOT paste raw
`ufw` commands by hand for normal onboarding. After `git clone` in step 4.1,
or before it (the script has no other repo dependencies):

```bash
# One-time: fetch + run the UFW setup script. Same rules every host.
curl -fsSL https://raw.githubusercontent.com/ahmadjamalahmad94-code/radius-proxy/main/systemd/setup-ufw.sh \
    -o /usr/local/sbin/setup-ufw.sh
chmod +x /usr/local/sbin/setup-ufw.sh
bash /usr/local/sbin/setup-ufw.sh
```

(If you've already cloned the repo, just run
`bash /opt/hobe-radius-proxy/app/systemd/setup-ufw.sh` instead.)

What the script enforces (read it before approving — it is short):

| Rule | Why |
|---|---|
| `default deny incoming` / `default allow outgoing` | Fail-closed baseline. |
| `allow OpenSSH` **before** `enable` | Lockout prevention. |
| `allow 51821/udp` (public) | wg-data — CHRs dial us. |
| `allow in on wg-data from 10.98.0.0/24 to any port 1812 proto udp` | RADIUS auth — tunnel + CHR subnet only. |
| `allow in on wg-data from 10.98.0.0/24 to any port 1813 proto udp` | RADIUS acct — tunnel + CHR subnet only. |
| (no public 1812/1813 rule) | RADIUS is **never** reachable from the internet. |
| (no listen rule for 3799) | CoA is **outbound** from the proxy to each CHR. |

Override via env before running (rarely needed):
`PROXY_WG_DATA_IFACE`, `PROXY_WG_DATA_SUBNET`, `PROXY_WG_DATA_LISTEN`,
`PROXY_AUTH_PORT`, `PROXY_ACCT_PORT`.

Verify:

```bash
ufw status verbose
# expect: 22/tcp ALLOW, 51821/udp ALLOW,
#         1812/udp on wg-data from 10.98.0.0/24 ALLOW,
#         1813/udp on wg-data from 10.98.0.0/24 ALLOW,
#         default deny incoming
```

> ⚠️ **Cloud provider security group:** if the VPS provider has its own firewall
> (Hetzner Cloud Firewall, AWS SG, Oracle security list…), also open **UDP 51821**
> there. This is the #1 cause of "handshake never appears".
>
> 🔒 **Why this is automated.** Hand-pasted `ufw` lines drift across hosts and
> are easy to get wrong (e.g. opening 1812 publicly while debugging). The
> script is the source of truth: every proxy gets the same rules, idempotently.
> The script ALSO ensures 1812/1813 are scoped to the wg-data interface, so a
> mis-set `PROXY_LISTEN_HOST=0.0.0.0` still cannot expose RADIUS publicly.

Ubuntu 22.04 ships Python 3.10 — the proxy needs **3.10+**, so no extra Python work:

```bash
python3 --version    # expect Python 3.10.x or newer
```

---

## 2. WireGuard data-plane interface (`wg-data`)

### 2.1 Generate the proxy keypair

```bash
umask 077
mkdir -p /etc/wireguard
wg genkey | tee /etc/wireguard/wg-data.privkey | wg pubkey > /etc/wireguard/wg-data.pubkey
cat /etc/wireguard/wg-data.pubkey     # ← you will paste THIS into the panel (step 3)
```

### 2.2 Get the CHR's wg-data public key (`🔑 OWNER-VALUE` #3)

On the MikroTik (`chr-vpn-1`, e.g. via WinBox terminal or SSH):

```routeros
/interface wireguard print
```

Find the row whose `name=wg-data` and copy its **`public-key=`** value
(a 44-character base64 string ending in `=`). That is the CHR's wg-data public key.

### 2.3 Create `/etc/wireguard/wg-data.conf`

```bash
cat > /etc/wireguard/wg-data.conf <<'EOF'
[Interface]
# The proxy's wg-data identity
PrivateKey = __PASTE_CONTENTS_OF /etc/wireguard/wg-data.privkey__
Address    = 10.98.0.1/24
ListenPort = 51821

# ── chr-vpn-1 ─────────────────────────────────────────────
[Peer]
# 🔑 OWNER-VALUE: the CHR's wg-data PUBLIC key from step 2.2
PublicKey  = __CHR_VPN_1_WG_DATA_PUBLIC_KEY__
AllowedIPs = 10.98.0.11/32
# Endpoint is optional: chr-vpn-1 dials US (proxy.hoberadius.com:51821) with
# persistent-keepalive, so the proxy can stay passive. Uncomment to also
# initiate from this side:
# Endpoint = 178.105.244.112:51821
EOF

# Insert the real private key (avoids shell-history leakage):
sed -i "s|__PASTE_CONTENTS_OF /etc/wireguard/wg-data.privkey__|$(cat /etc/wireguard/wg-data.privkey)|" /etc/wireguard/wg-data.conf

chmod 600 /etc/wireguard/wg-data.conf
```

Now edit the file once more and replace `__CHR_VPN_1_WG_DATA_PUBLIC_KEY__` with the
key you copied in 2.2 (`nano /etc/wireguard/wg-data.conf`).

### 2.4 Bring it up + enable on boot

```bash
wg-quick up wg-data
systemctl enable wg-quick@wg-data
wg show wg-data
```

Within ~25 s (the CHR's keepalive) `wg show wg-data` should display the peer with a
`latest handshake:` line. Then prove the data path:

```bash
ping -c 3 10.98.0.11      # the CHR over the tunnel — must reply
```

### 2.5 Adding more CHRs later

One `[Peer]` block per CHR, appended to the same file — only the key + IP change:

```ini
# ── chr-vpn-2 ─────────────────────────────────────────────
[Peer]
PublicKey  = <chr-vpn-2 wg-data public key>
AllowedIPs = 10.98.0.12/32
```

Apply without dropping existing peers:

```bash
wg syncconf wg-data <(wg-quick strip wg-data)
```

(Each new CHR gets the next `10.98.0.x` and is also registered in the panel; the
panel's onboarding generates the CHR side automatically.)

---

## 3. Give the panel its two values

Open the panel: **«إعدادات البنية → وكيل RADIUS المركزي»** and enter:

| Panel field | Value |
|---|---|
| Proxy WireGuard public key | output of `cat /etc/wireguard/wg-data.pubkey` (step 2.1) |
| Proxy endpoint | `proxy.hoberadius.com:51821` |

While you're on that page, copy (or generate, if not done yet) the two secrets —
you need them in step 4:
- **`🔑 RADIUS_PROXY_SHARED_SECRET`** (panel ↔ proxy API token, keys the X-Proxy-Token HMAC)
- **`🔑 PROXY_CHR_SECRET`** (CHR ↔ proxy RADIUS shared secret, fleet-wide)

---

## 4. Deploy the radius-proxy app

### 4.1 Code + virtualenv

```bash
# Service user (no shell, no home login)
useradd --system --create-home --home-dir /opt/hobe-radius-proxy --shell /usr/sbin/nologin hobeproxy || true

git clone https://github.com/ahmadjamalahmad94-code/radius-proxy /opt/hobe-radius-proxy/app
cd /opt/hobe-radius-proxy/app
git checkout main

python3 -m venv /opt/hobe-radius-proxy/venv
/opt/hobe-radius-proxy/venv/bin/pip install --upgrade pip
/opt/hobe-radius-proxy/venv/bin/pip install -r requirements.txt   # installs: requests

chown -R hobeproxy:hobeproxy /opt/hobe-radius-proxy
mkdir -p /var/log/hobe-radius-proxy && chown hobeproxy:hobeproxy /var/log/hobe-radius-proxy
```

### 4.2 Environment file — `/etc/hobe-radius-proxy/env`

Every variable below is the **real name from `config.py`** (verified, not guessed).

```bash
mkdir -p /etc/hobe-radius-proxy
cat > /etc/hobe-radius-proxy/env <<'EOF'
# ════════ REQUIRED — the proxy refuses to start / fails closed without these ════════

# Production mode: turns on strict Response-Authenticator verification.
PROXY_ENV=production

# The licensing panel base URL. ALL fleet endpoints derive from this
# automatically: /api/proxy/routing-table, /heartbeat, /telemetry,
# /placement, /placement-decision, /enforcement.
ADMIN_BASE_URL=https://hoberadius.com

# 🔑 OWNER-VALUE #1 — panel API token (X-Proxy-Token HMAC key).
# MUST equal the panel's RADIUS_PROXY_SHARED_SECRET on the infra page.
RADIUS_PROXY_SHARED_SECRET=__PASTE_FROM_PANEL_INFRA_PAGE__

# 🔑 OWNER-VALUE #2 — RADIUS shared secret used by EVERY CHR toward this proxy.
# MUST equal the value generated on the panel infra page (the onboarding
# script writes the same value into each CHR's /radius config).
PROXY_CHR_SECRET=__PASTE_FROM_PANEL_INFRA_PAGE__

# Stable identity of this proxy (shown in panel heartbeats; placement reports).
PROXY_ID=proxy-01

# Bind RADIUS ONLY on the wg-data interface — never the public IP.
PROXY_LISTEN_HOST=10.98.0.1
# PROXY_AUTH_PORT=1812          # default
# PROXY_ACCT_PORT=1813          # default

# ════════ Node identity (telemetry/placement key by registry node NAME) ════════
# The proxy resolves CHR source-IP → node name from the panel routing-table
# (chr_nodes[].name). This static map is the explicit fallback — RECOMMENDED
# for first light. NOTE: the IP here is the address the proxy actually SEES
# as the RADIUS source = the CHR's wg-data IP (10.98.0.x), not its public IP.
PROXY_CHR_NODE_MAP=10.98.0.11=chr-vpn-1

# ════════ Fleet features (these are the defaults — listed for visibility) ════════
# PROXY_FLEET_TELEMETRY=true            # per-node samples → /api/proxy/telemetry
# PROXY_TELEMETRY_INTERVAL=30           # seconds (bounded 5..3600)
# PROXY_FLEET_PLACEMENT=true            # §2 placement feedback + decision read
# PROXY_PLACEMENT_DECISION_PROBE=true   # advisory decision read-path
# PROXY_FLEET_ENFORCEMENT=true          # CoA engine (kill-old/move/kick)
# PROXY_LIVE_APPLY_ALLOWED=true         # local guard; panel's live_apply_enabled
#                                       # flag still gates ALL enforcement —
#                                       # until the panel turns it ON, the proxy
#                                       # is ADVISORY-ONLY (sends no CoA).
# PROXY_COA_PORT=3799                   # port CoA is SENT TO on each CHR
#                                       # (outbound over wg-data; NOT a listen port)
# PROXY_COA_TIMEOUT=5
# PROXY_MOVE_COOLDOWN=120               # per-user move hysteresis (seconds)
# PROXY_MOVE_EVAL_INTERVAL=60           # rebalance/outage evaluation loop

# ════════ Behaviour (safe defaults — change only if you know why) ════════
# PROXY_ACCT_TIMEOUT_MODE=strict        # never fabricate accounting ACKs
# PROXY_STRICT_RESPONSE_VERIFY=true     # implied by PROXY_ENV=production
# PROXY_FAIL_OPEN_CHR_ALLOWLIST=false   # NEVER true in production
# PROXY_ROUTING_REFRESH=60
# PROXY_FORWARD_TIMEOUT=10
# PROXY_HEARTBEAT_INTERVAL=30
# PROXY_LOG_LEVEL=INFO                  # set DEBUG for first-light, then back
# PROXY_LOG_REALMS=true
EOF

chmod 600 /etc/hobe-radius-proxy/env
```

Now `nano /etc/hobe-radius-proxy/env` and replace the two `__PASTE_FROM_PANEL_INFRA_PAGE__`
placeholders with the real secrets. **Tip for first light:** set `PROXY_LOG_LEVEL=DEBUG`
now and revert to `INFO` after step 6 — DEBUG shows the per-packet and heartbeat lines.

**Where each value comes from — summary table:**

| Env var | Source |
|---|---|
| `ADMIN_BASE_URL` | fixed: `https://hoberadius.com` |
| `RADIUS_PROXY_SHARED_SECRET` | 🔑 panel «إعدادات البنية → وكيل RADIUS المركزي» — must match panel exactly |
| `PROXY_CHR_SECRET` | 🔑 same panel page — must match what onboarding wrote into the CHRs |
| `PROXY_ID` | you choose; keep stable (`proxy-01`) |
| `PROXY_LISTEN_HOST` | the wg-data address `10.98.0.1` (step 2) |
| `PROXY_CHR_NODE_MAP` | `wg-data-IP=registry-node-name` per CHR (`10.98.0.11=chr-vpn-1`) |
| telemetry/placement/enforcement endpoints | derived from `ADMIN_BASE_URL` automatically — only set `PROXY_TELEMETRY_ENDPOINT` / `PROXY_PLACEMENT_ENDPOINT` / `PROXY_PLACEMENT_DECISION_ENDPOINT` / `PROXY_ENFORCEMENT_ENDPOINT` if the panel ever moves them |
| everything else | safe defaults baked into `config.py` (bounded/validated at startup) |

---

## 5. Run it — systemd

```bash
cat > /etc/systemd/system/radius-proxy.service <<'EOF'
[Unit]
Description=HobeRadius Central RADIUS Proxy
After=network-online.target wg-quick@wg-data.service
Wants=network-online.target
Requires=wg-quick@wg-data.service

[Service]
Type=simple
User=hobeproxy
Group=hobeproxy
WorkingDirectory=/opt/hobe-radius-proxy/app
EnvironmentFile=/etc/hobe-radius-proxy/env
ExecStart=/opt/hobe-radius-proxy/venv/bin/python main.py
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/hobe-radius-proxy

StandardOutput=journal
StandardError=journal
SyslogIdentifier=radius-proxy

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now radius-proxy
systemctl status radius-proxy --no-pager
```

Logs:

```bash
journalctl -u radius-proxy -f          # live tail
journalctl -u radius-proxy -n 100      # last 100 lines
```

**Healthy startup looks like:**

```
HobeRadius Central RADIUS Proxy
  Admin URL : https://hoberadius.com
  Proxy ID  : proxy-01
  Auth port : 1812
  Acct port : 1813
Auth listener ready
Accounting listener ready
RADIUS Proxy started | auth=:1812 acct=:1813 | telemetry=on placement=on enforcement=on
Routing table refreshed: N realms, M CHR nodes
```

---

## 6. Verify first light

Run these in order — each has an exact expected result.

**6.1 — Tunnel handshake (both ends).**

```bash
# On the proxy:
wg show wg-data
#   peer: <chr key>
#   latest handshake: X seconds ago        ← MUST be present and recent (<2 min)
#   transfer: ... received, ... sent       ← both counters non-zero
```

```routeros
# On the CHR:
/interface wireguard peers print
#   the proxy peer row shows last-handshake=…s ago (refreshes every ~25s)
```

**6.2 — Data path.**

```bash
ping -c 3 10.98.0.11        # from proxy → CHR over the tunnel: 3/3 replies
ss -ulpn | grep -E '1812|1813'
#   UNCONN ... 10.98.0.1:1812 ... python    ← bound on the WG address, NOT 0.0.0.0
#   UNCONN ... 10.98.0.1:1813 ... python
```

**6.3 — Panel API path (routing table + heartbeat + telemetry).**

```bash
journalctl -u radius-proxy -n 200 | grep -E "Routing table refreshed|Heartbeat|telemetry"
```

- `Routing table refreshed: N realms, M CHR nodes` → the X-Proxy-Token works and the panel answered. **M ≥ 1** must include `chr-vpn-1`.
- With `PROXY_LOG_LEVEL=DEBUG`: `Heartbeat sent OK` every 30 s.
- Telemetry success is **silent by design** — what you must NOT see is
  `telemetry POST node=… failed` or `…rejected 401`. (Telemetry only POSTs once
  a CHR has live sessions to report, i.e. after the first real Accounting-Start.)

**6.4 — Panel dashboard.**
Open the fleet dashboard: `chr-vpn-1` should flip from **«تجهيز»** toward
**«نشطة»** once its telemetry/health data starts arriving (CHR metrics flow via
the panel's own wg-mgmt collector; the proxy's telemetry adds session/egress data
after the first connection).

**6.5 — First real login (end-to-end).**
Connect one test VPN user (`user@realm`) through `chr-vpn-1`:

```bash
journalctl -u radius-proxy -f
# DEBUG: ← Access-Request id=… from 10.98.0.11 user=test@client1
# DEBUG: → Access-Accept id=… to 10.98.0.11 (realm=client1)
```

and the panel's sessions view shows the placement (`chr-vpn-1`, the user's fixed IP).

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `wg show` has **no `latest handshake`** | UDP 51821 blocked (ufw or **provider security group**), wrong key on either side, or `proxy.hoberadius.com` not resolving to `178.105.251.67` / orange-clouded in Cloudflare | `ufw status`; check provider firewall; `dig +short proxy.hoberadius.com` must print `178.105.251.67` (set the record to **DNS-only**); re-compare both public keys (`cat /etc/wireguard/wg-data.pubkey` vs the panel, and the CHR's `public-key` vs your `[Peer]`) |
| Handshake OK but `ping 10.98.0.11` fails | `AllowedIPs` mismatch (proxy needs `10.98.0.11/32`; CHR needs `10.98.0.1/32`) or Address typo | fix `wg-data.conf` / CHR peer, `wg syncconf` |
| Log: `Packet from unknown CHR IP 10.98.0.11 — dropped` | The CHR's `wg_data_ip` is missing from the panel's routing-table response. The proxy ingests `chr_nodes[].wg_data_ip` into its allowlist on every refresh; if the field is empty/absent, the wg-data source IP won't match | check `GET /api/proxy/routing-table` (panel side): the offending node must publish `chr_nodes[].wg_data_ip="10.98.0.x"`. The proxy picks up the new value within `PROXY_ROUTING_REFRESH` (≤60 s) — no restart needed |
| Log: `CHR allowlist empty + fail_open=False: rejecting …` | Panel reachable but returned **zero CHR nodes** (none registered/active yet) | finish CHR registration in the panel; never "fix" with `PROXY_FAIL_OPEN_CHR_ALLOWLIST=true` in production |
| Log: `Message-Authenticator mismatch from 10.98.0.11 — dropped` or CHR shows RADIUS timeout | **`PROXY_CHR_SECRET` mismatch** between proxy env and the CHR's `/radius` secret | both must equal the panel infra page value; after editing env: `systemctl restart radius-proxy` |
| CHR says RADIUS **connection refused** | proxy not bound on wg-data (check `ss -ulpn`), wg-data down, or service not running | `systemctl status radius-proxy`, `wg show`, confirm `PROXY_LISTEN_HOST=10.98.0.1` |
| Log: `Failed to refresh routing table: 401` / telemetry/placement/enforcement `rejected 401` | **`RADIUS_PROXY_SHARED_SECRET` mismatch** with the panel, or clock skew beyond the panel's token TTL (60 s) | paste the exact panel value; `timedatectl` → enable NTP: `timedatectl set-ntp true` |
| `Failed to refresh routing table: …Connection…` | panel URL wrong/unreachable from this host | `curl -sI https://hoberadius.com` from the proxy; check `ADMIN_BASE_URL` |
| Enforcement never disconnects anyone | **By design**: the panel's `live_apply_enabled` flag is still off → proxy is advisory-only (log shows `ADVISORY … (no CoA)`) | flip live-apply in the panel when ready; the proxy picks it up on the next routing-table refresh (≤60 s) |
| CoA sent but no ACK (`coa: Disconnect … ok=False … err=timeout`) | CHR's CoA listener off or 3799 blocked on wg-data | on the CHR: `/radius incoming set accept=yes port=3799`; firewall must accept 3799 **on the wg-data interface** (the onboarding script does both) |
| Service exits at startup with config error | missing `ADMIN_BASE_URL` / `RADIUS_PROXY_SHARED_SECRET` | the proxy validates at boot and logs exactly which var is missing — fix `/etc/hobe-radius-proxy/env`, restart |

**Useful one-liners:**

```bash
systemctl restart radius-proxy && journalctl -u radius-proxy -f   # apply env change
journalctl -u radius-proxy -b | grep -iE "error|warn|mismatch|dropped|401"
wg show wg-data; ping -c1 10.98.0.11; ss -ulpn | grep 181
```

---

## Appendix — security invariants (do not break)

1. RADIUS (1812/1813) and CoA (3799) **never** traverse the public internet — wg-data only. The bind on `10.98.0.1` + UFW default-deny enforce this.
2. `PROXY_FAIL_OPEN_CHR_ALLOWLIST` stays `false` in production (fail-closed).
3. `PROXY_ENV=production` stays set (strict Response-Authenticator verification).
4. `/etc/hobe-radius-proxy/env` and `/etc/wireguard/*` stay `chmod 600` root-owned; secrets never go into shell history (the `sed` trick in 2.3) or logs (the proxy never logs them).
5. Enforcement is gated by the **panel's** `live_apply_enabled` — leave it off until you have verified 6.1–6.5, then enable it from the panel, watch `journalctl` for the first `coa: Disconnect … ok=True`.
