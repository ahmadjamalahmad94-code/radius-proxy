#!/usr/bin/env bash
# setup-ufw.sh — Idempotent UFW rules for the central radius-proxy host.
#
# Run once on every deploy (the systemd unit's ExecStartPre may also invoke
# it). Safe to re-run: ufw deduplicates identical allow rules.
#
# Invariants enforced (per RADIUS_PROXY_DEPLOYMENT.md / DEPLOY_PROXY.md):
#   1. SSH (OpenSSH) stays open before `ufw enable` to avoid lockout.
#   2. wg-data tunnel — UDP 51821 — open to the public internet (CHRs dial us).
#   3. RADIUS Auth/Acct (1812/1813) — open ONLY on the wg-data interface,
#      ONLY from CHR wg-data IPs (the 10.98.0.0/24 subnet). Never publicly.
#   4. CoA (3799) is OUTBOUND from the proxy to each CHR — no public listen.
#
# Run as root: bash setup-ufw.sh
#
set -euo pipefail

WG_IF="${PROXY_WG_DATA_IFACE:-wg-data}"
WG_SUBNET="${PROXY_WG_DATA_SUBNET:-10.98.0.0/24}"
WG_LISTEN_PORT="${PROXY_WG_DATA_LISTEN:-51821}"
AUTH_PORT="${PROXY_AUTH_PORT:-1812}"
ACCT_PORT="${PROXY_ACCT_PORT:-1813}"

# Customer RADIUS tunnel (design §4.2): wg-radius is the SECOND wireguard
# interface on the proxy host — customer RADIUS servers dial in to
# 51822/udp and live in 10.200.0.0/16. RADIUS is OUTBOUND from the proxy
# to each customer (proxy.py forwards to 10.200.<id>.2:1812/1813 inside
# the tunnel) — we do NOT add inbound RADIUS rules for this iface.
WG_RADIUS_LISTEN_PORT="${PROXY_WG_RADIUS_LISTEN:-51822}"

if ! command -v ufw >/dev/null 2>&1; then
    echo "setup-ufw: 'ufw' not installed — run: apt -y install ufw" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "setup-ufw: must run as root (try: sudo bash $0)" >&2
    exit 1
fi

echo "setup-ufw: applying rules — wg-iface=${WG_IF} subnet=${WG_SUBNET} wg-port=${WG_LISTEN_PORT}/udp wg-radius-port=${WG_RADIUS_LISTEN_PORT}/udp"

# ── 1. SSH first (lockout prevention) + default-deny baseline. ────────
ufw --force default deny incoming
ufw --force default allow outgoing
ufw allow OpenSSH

# ── 2. wg-data tunnel — publicly reachable so CHRs can hand-shake. ────
ufw allow "${WG_LISTEN_PORT}/udp" comment 'wg-data from CHRs'

# ── 2bis. wg-radius tunnel — publicly reachable so customer RADIUS dials in.
# RADIUS itself is NOT inbound here — the proxy DIALS OUT to each customer
# inside the tunnel (10.200.<id>.2:1812/1813). Crypto-key routing enforces
# that each customer only sees its own /32, so opening 51822 publicly is
# safe — without a registered pubkey the handshake fails.
ufw allow "${WG_RADIUS_LISTEN_PORT}/udp" comment 'wg-radius from customer RADIUS'

# ── 3. RADIUS — ONLY on wg-data, ONLY from CHR wg-data subnet. ────────
# These rules survive even if PROXY_LISTEN_HOST is mis-set to 0.0.0.0:
# UFW will still drop public RADIUS attempts because the public-facing
# allows above do NOT cover 1812/1813.
ufw allow in on "${WG_IF}" from "${WG_SUBNET}" \
    to any port "${AUTH_PORT}" proto udp \
    comment 'RADIUS auth from CHRs (wg-data only)'
ufw allow in on "${WG_IF}" from "${WG_SUBNET}" \
    to any port "${ACCT_PORT}" proto udp \
    comment 'RADIUS acct from CHRs (wg-data only)'

# ── 4. Explicit deny on public iface (belt-and-braces, no-op vs default). ─
# Kept commented because UFW default-deny already covers it; uncomment if
# auditors require an explicit rule.
# ufw deny in 1812/udp comment 'RADIUS auth never public'
# ufw deny in 1813/udp comment 'RADIUS acct never public'

# ── Enable + verify ───────────────────────────────────────────────────
ufw --force enable
ufw status verbose
echo "setup-ufw: done."
