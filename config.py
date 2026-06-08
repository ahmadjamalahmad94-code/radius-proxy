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


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


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
