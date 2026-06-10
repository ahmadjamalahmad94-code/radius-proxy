"""تهيئة وكيل RADIUS المركزي — مقروءة من متغيرات البيئة."""
from __future__ import annotations

import logging
import os
import secrets

_LOG = logging.getLogger(__name__)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, ""))
    except (TypeError, ValueError):
        return default


def _env_int_bounded(key: str, default: int, lo: int, hi: int) -> int:
    """_env_int clamped to [lo, hi] — a typo'd env var (0, negative, or huge)
    must never produce a non-blocking socket, a div-by-zero window, a busy
    loop, or an unbounded retry storm (P10 hardening)."""
    value = _env_int(key, default)
    if value < lo or value > hi:
        _LOG.warning(
            "%s=%r out of bounds [%d, %d] — clamped to %d",
            key, value, lo, hi, min(max(value, lo), hi),
        )
    return min(max(value, lo), hi)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def _parse_node_map(raw: str) -> dict[str, str]:
    """Parse a ``ip=name,ip=name`` CHR-IP → registry-node-name override map.

    Used as a static fallback for telemetry/placement node identity until the
    panel's routing-table API carries the node name (see contract gap).
    """
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        ip, name = pair.split("=", 1)
        ip, name = ip.strip(), name.strip()
        if ip and name:
            out[ip] = name
    return out


def _normalize_acct_timeout_mode(raw: str) -> str:
    """Normalize PROXY_ACCT_TIMEOUT_MODE to its canonical form.

    Canonical names:
      "strict"         — Silent drop on timeout.  CHR retransmits until its
                         own timer expires; data is eventually re-sent.
                         Fail-safe default; no data fabrication.

      "ack_on_timeout" — Send a fake Accounting-Response (code 5) to CHR.
                         Stops CHR retransmit storm immediately. The accounting
                         record for this request IS LOST upstream — the fake
                         ACK only acknowledges the CHR node; it does NOT prove
                         that the target RADIUS server ever received or stored
                         the record. Use only when retransmit storms outweigh
                         the risk of missing individual accounting records.

    Legacy aliases (deprecated, still accepted for backward compatibility):
      "drop"     → "strict"          (behaviour unchanged)
      "fake_ack" → "ack_on_timeout"  (behaviour unchanged)

    Unknown values fall back to "strict" with a WARNING.
    """
    m = raw.strip().lower()
    if m == "drop":
        _LOG.warning(
            "PROXY_ACCT_TIMEOUT_MODE='drop' is deprecated; "
            "use 'strict' instead (behaviour unchanged)"
        )
        return "strict"
    if m == "fake_ack":
        _LOG.warning(
            "PROXY_ACCT_TIMEOUT_MODE='fake_ack' is deprecated; "
            "use 'ack_on_timeout' instead (behaviour unchanged). "
            "Note: ack_on_timeout only acknowledges the CHR node — "
            "it does NOT prove target accounting persistence."
        )
        return "ack_on_timeout"
    if m in ("strict", "ack_on_timeout"):
        return m
    _LOG.warning(
        "Unknown PROXY_ACCT_TIMEOUT_MODE=%r — defaulting to 'strict'", raw
    )
    return "strict"


class Config:
    # ── Admin panel connection ────────────────────────────────────────────
    ADMIN_BASE_URL = _env("ADMIN_BASE_URL", "https://panel.hoberadius.com")
    PROXY_SHARED_SECRET = _env("RADIUS_PROXY_SHARED_SECRET")

    # ── RADIUS listener ───────────────────────────────────────────────────
    # Default: listen on 0.0.0.0. Set to specific IP to restrict.
    LISTEN_HOST = _env("PROXY_LISTEN_HOST", "0.0.0.0")
    RADIUS_AUTH_PORT = _env_int("PROXY_AUTH_PORT", 1812)
    RADIUS_ACCT_PORT = _env_int("PROXY_ACCT_PORT", 1813)

    # Shared secret for CHR nodes → Proxy (same secret for all CHRs in MVP).
    # Each CHR uses this secret when sending RADIUS to the proxy.
    CHR_SHARED_SECRET = _env("PROXY_CHR_SECRET", "changeme-chr-secret")

    # ── Routing table refresh ─────────────────────────────────────────────
    ROUTING_REFRESH_SECONDS = _env_int("PROXY_ROUTING_REFRESH", 60)

    # ── Timeouts ──────────────────────────────────────────────────────────
    FORWARD_TIMEOUT_SECONDS = _env_int("PROXY_FORWARD_TIMEOUT", 10)
    HEARTBEAT_INTERVAL_SECONDS = _env_int("PROXY_HEARTBEAT_INTERVAL", 30)

    # ── Logging ───────────────────────────────────────────────────────────
    LOG_LEVEL = _env("PROXY_LOG_LEVEL", "INFO")
    # Log username realm lookups (disable in high-privacy environments)
    LOG_REALM_LOOKUPS = _env_bool("PROXY_LOG_REALMS", True)

    PROXY_ID = _env("PROXY_ID", f"proxy-{secrets.token_hex(4)}")

    # ── Environment ───────────────────────────────────────────────────────
    # Set PROXY_ENV=production (or "prod") to activate production defaults
    # for security-sensitive settings.
    PROXY_ENV = _env("PROXY_ENV", "")

    # ── Security ──────────────────────────────────────────────────────────
    # When False (default, production): if the CHR allowlist is empty
    # (no CHR nodes loaded from admin yet), ALL source IPs are REJECTED.
    # Set to True only in development / initial bootstrap when you have no
    # CHR nodes registered yet and need to test packet flow without them.
    FAIL_OPEN_CHR_ALLOWLIST = _env_bool("PROXY_FAIL_OPEN_CHR_ALLOWLIST", False)

    # ── Accounting timeout behavior ───────────────────────────────────────
    # What to do when the target RADIUS does not respond to an
    # Accounting-Request within FORWARD_TIMEOUT_SECONDS.
    #
    # Canonical names (use these):
    #
    #   "strict"         — Silent drop.  CHR retransmits until its own timer
    #                      expires; data is eventually re-sent upstream.
    #                      Safe default; no data fabrication.
    #
    #   "ack_on_timeout" — Send a fake Accounting-Response (code 5) to CHR.
    #                      Stops CHR retransmit storm immediately. IMPORTANT:
    #                      the accounting record for this request is LOST
    #                      upstream — the fake ACK only acknowledges the CHR;
    #                      it does NOT prove target accounting persistence.
    #                      Each fake ACK is logged at WARNING level.
    #
    # Legacy aliases (deprecated, still accepted):
    #   "drop"     → "strict"          (behaviour unchanged)
    #   "fake_ack" → "ack_on_timeout"  (behaviour unchanged)
    #
    # Default: "strict" — fail safe, no data fabrication.
    ACCT_TIMEOUT_MODE = _normalize_acct_timeout_mode(
        _env("PROXY_ACCT_TIMEOUT_MODE", "strict")
    )

    # ── Response-Authenticator strict verification ────────────────────────
    # Controls how rebuild_response() reacts to a Response-Authenticator
    # mismatch from the target RADIUS server:
    #
    #   True  (production default when PROXY_ENV=production) —
    #         Drop the response.  Any response whose Response-Authenticator
    #         does not match the RFC 2865 expected value is silently discarded.
    #         This prevents forwarding tampered, replayed, or corrupt packets
    #         to CHR nodes.
    #
    #   False (development default) —
    #         Warn only; forward the response anyway.  Useful when testing
    #         against non-compliant RADIUS servers or in CI environments where
    #         the target RADIUS may not sign responses correctly.
    #
    # Override with PROXY_STRICT_RESPONSE_VERIFY=true|false explicitly;
    # production deployments SHOULD set this to true.
    STRICT_RESPONSE_VERIFY = _env_bool(
        "PROXY_STRICT_RESPONSE_VERIFY",
        _env("PROXY_ENV", "").lower() in ("production", "prod"),
    )

    # ── CHR Fleet: telemetry + placement (Phase 4) ────────────────────────
    # All proxy → panel fleet calls reuse the X-Proxy-Token HMAC scheme keyed
    # with RADIUS_PROXY_SHARED_SECRET (PROXY_SHARED_SECRET) — the proxy↔panel
    # secret, NOT the per-CHR RADIUS secret. Endpoints/identity/secret come from
    # config/env (never hardcoded).

    # Telemetry (per-node samples → POST /api/proxy/telemetry, contract §1)
    FLEET_TELEMETRY_ENABLED = _env_bool("PROXY_FLEET_TELEMETRY", True)
    FLEET_TELEMETRY_ENDPOINT = _env("PROXY_TELEMETRY_ENDPOINT", "") or (
        ADMIN_BASE_URL.rstrip("/") + "/api/proxy/telemetry"
    )
    FLEET_TELEMETRY_INTERVAL = _env_int_bounded("PROXY_TELEMETRY_INTERVAL", 30, 5, 3600)
    FLEET_TELEMETRY_TIMEOUT = _env_int_bounded("PROXY_TELEMETRY_TIMEOUT", 10, 1, 60)
    FLEET_TELEMETRY_MAX_RETRIES = _env_int_bounded("PROXY_TELEMETRY_MAX_RETRIES", 3, 1, 6)
    try:
        FLEET_TELEMETRY_BACKOFF_BASE = float(
            _env("PROXY_TELEMETRY_BACKOFF_BASE", "0.5") or "0.5"
        )
    except ValueError:
        FLEET_TELEMETRY_BACKOFF_BASE = 0.5
    FLEET_AGENT_VERSION = _env("PROXY_AGENT_VERSION", "1.0.0")

    # Placement (feedback write → /api/proxy/placement §2;
    #            decision read → /api/proxy/placement-decision, PROPOSED)
    FLEET_PLACEMENT_ENABLED = _env_bool("PROXY_FLEET_PLACEMENT", True)
    FLEET_PLACEMENT_REPORT_ENDPOINT = _env("PROXY_PLACEMENT_ENDPOINT", "") or (
        ADMIN_BASE_URL.rstrip("/") + "/api/proxy/placement"
    )
    FLEET_PLACEMENT_DECISION_ENDPOINT = _env(
        "PROXY_PLACEMENT_DECISION_ENDPOINT", ""
    ) or (ADMIN_BASE_URL.rstrip("/") + "/api/proxy/placement-decision")
    # Read-path decision probe (advisory, log-only in Phase 4).
    FLEET_PLACEMENT_DECISION_PROBE = _env_bool("PROXY_PLACEMENT_DECISION_PROBE", True)
    FLEET_PLACEMENT_DECISION_TTL = _env_int_bounded("PROXY_PLACEMENT_DECISION_TTL", 30, 1, 3600)
    FLEET_PLACEMENT_TIMEOUT = _env_int_bounded("PROXY_PLACEMENT_TIMEOUT", 10, 1, 60)

    # Static CHR-IP → registry node-name map (fallback until routing-table API
    # carries node names). Format: "203.0.113.11=chr-exit-01,203.0.113.12=chr-exit-02"
    FLEET_CHR_NODE_MAP = _parse_node_map(_env("PROXY_CHR_NODE_MAP", ""))

    # ── CHR Fleet: live enforcement / CoA (Phase 7) ───────────────────────
    # Local master switch for the enforcement engine. When False the engine is
    # not even constructed (no kill-old / no moves). Default ON, but enforcement
    # still only ACTS when the PANEL live-apply flag is also enabled (below).
    FLEET_ENFORCEMENT_ENABLED = _env_bool("PROXY_FLEET_ENFORCEMENT", True)

    # SAFETY GUARD — the panel's authoritative live-apply flag is read from the
    # routing-table response (RoutingTable.live_apply()). This LOCAL override is
    # a hard floor: effective_live_apply = panel_flag AND this. Default True
    # (let the panel decide); set False to hard-disable enforcement locally
    # regardless of the panel. Either way the safe default is ADVISORY (the
    # panel flag defaults False when absent/unreachable).
    FLEET_LIVE_APPLY_ALLOWED = _env_bool("PROXY_LIVE_APPLY_ALLOWED", True)

    # CoA / RFC 5176 sender. Bounds (P10): port must be valid; timeout 0 would
    # make the UDP socket non-blocking (instant failure) → min 1s; retries
    # capped so a mass failover can't turn into a retransmit storm.
    FLEET_COA_PORT = _env_int_bounded("PROXY_COA_PORT", 3799, 1, 65535)
    FLEET_COA_TIMEOUT = _env_int_bounded("PROXY_COA_TIMEOUT", 5, 1, 30)
    FLEET_COA_MAX_RETRIES = _env_int_bounded("PROXY_COA_MAX_RETRIES", 2, 0, 5)
    try:
        FLEET_COA_BACKOFF_BASE = float(_env("PROXY_COA_BACKOFF_BASE", "0.5") or "0.5")
    except ValueError:
        FLEET_COA_BACKOFF_BASE = 0.5
    if not (0.0 <= FLEET_COA_BACKOFF_BASE <= 10.0):
        FLEET_COA_BACKOFF_BASE = 0.5

    # Per-user move cooldown (hysteresis) seconds — prevents ping-ponging.
    # 0 disables the gate (allowed but discouraged); cap prevents a fat-finger
    # value from freezing rebalancing for days.
    FLEET_MOVE_COOLDOWN = _env_int_bounded("PROXY_MOVE_COOLDOWN", 120, 0, 86400)
    # How often the rebalance/outage move-evaluation loop runs. Min 5s so a
    # typo can't busy-loop the evaluator.
    FLEET_MOVE_EVAL_INTERVAL = _env_int_bounded("PROXY_MOVE_EVAL_INTERVAL", 60, 5, 3600)

    # Enforcement-outcome ingest (FROZEN §1.4: actions single_session_kill/
    # move/kick, results applied|failed only; moves also mirror via §2).
    FLEET_ENFORCEMENT_ENDPOINT = _env("PROXY_ENFORCEMENT_ENDPOINT", "") or (
        ADMIN_BASE_URL.rstrip("/") + "/api/proxy/enforcement"
    )
    FLEET_ENFORCEMENT_TIMEOUT = _env_int_bounded("PROXY_ENFORCEMENT_TIMEOUT", 10, 1, 60)
    FLEET_ENFORCEMENT_MAX_RETRIES = _env_int_bounded("PROXY_ENFORCEMENT_MAX_RETRIES", 2, 0, 5)
    try:
        FLEET_ENFORCEMENT_BACKOFF_BASE = float(
            _env("PROXY_ENFORCEMENT_BACKOFF_BASE", "0.5") or "0.5"
        )
    except ValueError:
        FLEET_ENFORCEMENT_BACKOFF_BASE = 0.5
    if not (0.0 <= FLEET_ENFORCEMENT_BACKOFF_BASE <= 10.0):
        FLEET_ENFORCEMENT_BACKOFF_BASE = 0.5
