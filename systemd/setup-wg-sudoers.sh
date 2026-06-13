#!/usr/bin/env bash
# setup-wg-sudoers.sh — Configure wg / wg-quick access for the radius-proxy
# service. ROBUST to whatever user the proxy actually runs as (auto-detected
# from the installed systemd unit, NOT hardcoded).
#
# Two modes (auto-detected; you don't pick):
#
#   ROOT mode  — the systemd unit's User= is empty/root (e.g. the live
#                proxy01 install: /opt/hoberadius/radius-proxy under
#                User=root). The proxy invokes /usr/bin/wg + /usr/bin/wg-quick
#                DIRECTLY; no sudoers grant needed (root can already do
#                anything). The script skips the sudoers + wrapper installs
#                and prints the env vars the operator should set.
#
#   SCOPED mode — the unit's User= is a real non-root account (e.g. the
#                 DEPLOY_PROXY.md walkthrough creates `hobeproxy`). The
#                 script installs a sudoers rule allowing ONLY:
#
#                   wg show <iface> dump | public-key
#                   wg set  <iface> peer * allowed-ips * | remove
#                   wg-quick save <iface>
#
#                 against {wg-data, wg-radius}, plus two tiny wrappers at
#                 /usr/local/sbin/hobe-wg{,-quick} that exec `sudo -n …`.
#                 The proxy is then configured with
#                 PROXY_WG_BIN=/usr/local/sbin/hobe-wg + likewise for
#                 wg-quick.
#
# Idempotent — safe to re-run on every deploy.
#
# Detection order (first non-empty wins):
#   1. systemctl show <unit> -p User --value  (for unit ∈
#      {radius-proxy.service, hobe-radius-proxy.service})
#   2. PROXY_SERVICE_USER env var
#   3. default: "root"
set -euo pipefail

# ── 0. Inputs that the operator can override ──────────────────────────
WG_BIN="${WG_BIN:-/usr/bin/wg}"
WG_QUICK_BIN="${WG_QUICK_BIN:-/usr/bin/wg-quick}"
WRAPPER="/usr/local/sbin/hobe-wg"
WG_QUICK_WRAPPER="/usr/local/sbin/hobe-wg-quick"
SUDOERS_FILE="/etc/sudoers.d/hobe-radius-proxy-wg"
STATE_DIR="/var/lib/hobe-radius-proxy"
UNIT_CANDIDATES=("radius-proxy.service" "hobe-radius-proxy.service")

# ── 1. Pre-flight ─────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "setup-wg-sudoers: must run as root (try: sudo bash $0)" >&2
    exit 1
fi
if ! command -v "$WG_BIN" >/dev/null 2>&1; then
    echo "setup-wg-sudoers: '$WG_BIN' not installed — run: apt -y install wireguard-tools" >&2
    exit 1
fi
if ! command -v "$WG_QUICK_BIN" >/dev/null 2>&1; then
    echo "setup-wg-sudoers: '$WG_QUICK_BIN' not installed — run: apt -y install wireguard-tools" >&2
    exit 1
fi

# ── 2. Auto-detect the proxy service user ────────────────────────────
# `systemctl show -p User --value` prints the User= value or empty
# (NOT "root" — systemd treats unset == root implicitly). Empty is
# what we want to surface as the root-mode signal.
detect_user() {
    if command -v systemctl >/dev/null 2>&1; then
        for unit in "${UNIT_CANDIDATES[@]}"; do
            local u
            u="$(systemctl show "$unit" -p User --value 2>/dev/null || true)"
            u="${u//[$'\r\n\t ']/}"
            if [[ -n "$u" ]]; then
                echo "$u"
                return 0
            fi
        done
    fi
    if [[ -n "${PROXY_SERVICE_USER:-}" ]]; then
        echo "$PROXY_SERVICE_USER"
        return 0
    fi
    echo "root"
}

SERVICE_USER="$(detect_user)"
echo "setup-wg-sudoers: detected proxy service user = '$SERVICE_USER'"

# ── 3. ROOT mode short-circuit ───────────────────────────────────────
if [[ "$SERVICE_USER" == "root" || -z "$SERVICE_USER" ]]; then
    cat <<EOF
setup-wg-sudoers: البروكسي يعمل بصلاحية root — لا حاجة لـsudoers؛ سيستخدم wg مباشرة.
setup-wg-sudoers: proxy runs as root — sudoers grant NOT needed; wg/wg-quick
                  invoked directly. No wrapper scripts installed.
EOF
    # Still create the state directory so the proxy can persist
    # /var/lib/hobe-radius-proxy/chr-secret.json + managed-peers.json +
    # coa-executed.json. Root owns it; the proxy runs as root so the
    # 0750 default is fine.
    install -d -m 0750 -o root -g root "$STATE_DIR"
    echo "setup-wg-sudoers: state dir $STATE_DIR ready (owner=root)."
    echo
    echo "setup-wg-sudoers: ADD THESE LINES TO /etc/hobe-radius-proxy/env"
    echo "                  (or leave the defaults — they already point at"
    echo "                  the in-PATH binaries):"
    echo
    echo "    PROXY_WG_BIN=$WG_BIN"
    echo "    PROXY_WG_QUICK_BIN=$WG_QUICK_BIN"
    echo
    echo "setup-wg-sudoers: then 'systemctl restart radius-proxy'."
    echo "setup-wg-sudoers: done."
    exit 0
fi

# ── 4. SCOPED mode — full sudoers install ────────────────────────────
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    cat >&2 <<EOF
setup-wg-sudoers: detected service user '$SERVICE_USER' does not exist.

  This can happen if a systemd unit declares User=$SERVICE_USER but the
  account was never created. Either:
    1. Create the account:
         useradd --system --create-home \\
                 --home-dir /opt/hobe-radius-proxy \\
                 --shell /usr/sbin/nologin '$SERVICE_USER'
    2. OR fix the systemd unit's User= to a different account that
       does exist.
    3. OR run THIS script with the right user explicitly:
         PROXY_SERVICE_USER=<existing-user> sudo -E bash $0
EOF
    exit 1
fi

# Scoped sudoers rule. Each pattern uses sudo's wildcards (NOT shell
# globs) — wildcards match any single argv token but cannot reach
# across spaces. So `wg set wg-data peer *` cannot be abused to inject
# extra `--` flags or run a different subcommand.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
# Installed by setup-wg-sudoers.sh — DO NOT EDIT.
# Grants the radius-proxy service user the minimum 'wg' / 'wg-quick'
# invocations required by the zero-touch peer sync reconcilers (both
# wg-data and wg-radius), plus:
#   - read-only \`wg show <iface> public-key\` for the heartbeat's
#     live proxy pubkey publish (chr-vpn-2 onboarding fix);
#   - \`wg-quick save <iface>\` so reconciler-added peers are written
#     to /etc/wireguard/<iface>.conf and survive a reboot.
# Nothing else.

# wg-data — CHR fleet plane.
Cmnd_Alias HOBE_WG_SHOW_DATA = $WG_BIN show wg-data dump, \\
                               $WG_BIN show wg-data public-key
Cmnd_Alias HOBE_WG_SET_DATA  = $WG_BIN set wg-data peer * allowed-ips *, \\
                               $WG_BIN set wg-data peer * remove
Cmnd_Alias HOBE_WG_SAVE_DATA = $WG_QUICK_BIN save wg-data

# wg-radius — customer RADIUS plane.
Cmnd_Alias HOBE_WG_SHOW_RADIUS = $WG_BIN show wg-radius dump, \\
                                 $WG_BIN show wg-radius public-key
Cmnd_Alias HOBE_WG_SET_RADIUS  = $WG_BIN set wg-radius peer * allowed-ips *, \\
                                 $WG_BIN set wg-radius peer * remove
Cmnd_Alias HOBE_WG_SAVE_RADIUS = $WG_QUICK_BIN save wg-radius

$SERVICE_USER ALL=(root) NOPASSWD: HOBE_WG_SHOW_DATA, HOBE_WG_SET_DATA, \\
                                   HOBE_WG_SAVE_DATA, \\
                                   HOBE_WG_SHOW_RADIUS, HOBE_WG_SET_RADIUS, \\
                                   HOBE_WG_SAVE_RADIUS
Defaults!HOBE_WG_SHOW_DATA,HOBE_WG_SET_DATA,HOBE_WG_SAVE_DATA,HOBE_WG_SHOW_RADIUS,HOBE_WG_SET_RADIUS,HOBE_WG_SAVE_RADIUS !requiretty
EOF

if ! visudo -c -f "$TMP" >/dev/null; then
    echo "setup-wg-sudoers: refusing to install — sudoers syntax check failed." >&2
    exit 1
fi
install -m 0440 -o root -g root "$TMP" "$SUDOERS_FILE"
echo "setup-wg-sudoers: installed $SUDOERS_FILE"

# ── 5. wg wrappers — tiny `sudo -n` shims ────────────────────────────
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
# Auto-generated by setup-wg-sudoers.sh. Forwards a constrained set of
# 'wg' invocations through sudo. The sudoers rule above pins which ones.
exec /usr/bin/sudo -n $WG_BIN "\$@"
EOF
chmod 0755 "$WRAPPER"
chown root:root "$WRAPPER"
echo "setup-wg-sudoers: installed $WRAPPER (proxy should set PROXY_WG_BIN=$WRAPPER)"

cat > "$WG_QUICK_WRAPPER" <<EOF
#!/usr/bin/env bash
# Auto-generated by setup-wg-sudoers.sh. Forwards 'wg-quick save'
# through sudo (the sudoers rule pins which sub-commands are allowed).
exec /usr/bin/sudo -n $WG_QUICK_BIN "\$@"
EOF
chmod 0755 "$WG_QUICK_WRAPPER"
chown root:root "$WG_QUICK_WRAPPER"
echo "setup-wg-sudoers: installed $WG_QUICK_WRAPPER (proxy should set PROXY_WG_QUICK_BIN=$WG_QUICK_WRAPPER)"

# ── 6. Smoke check (read-only). ──────────────────────────────────────
if sudo -u "$SERVICE_USER" "$WRAPPER" show wg-data dump >/dev/null 2>&1; then
    echo "setup-wg-sudoers: OK — $SERVICE_USER can invoke 'wg show wg-data dump'."
else
    echo "setup-wg-sudoers: WARNING — $SERVICE_USER could not run 'wg show wg-data dump'." >&2
    echo "  This is normal if wg-data isn't up yet; rerun after 'wg-quick up wg-data'." >&2
fi

# ── 7. State directory owned by the scoped user. ─────────────────────
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
echo "setup-wg-sudoers: state dir $STATE_DIR ready (owner=$SERVICE_USER)."

echo "setup-wg-sudoers: done."
