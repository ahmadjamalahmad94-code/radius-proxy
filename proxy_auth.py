"""Shared X-Proxy-Token authentication helper for proxy → panel calls.

CHR Fleet — Phase 4 (P4-T7).

Centralises the HMAC token scheme that the proxy already uses toward the
licensing panel (see ``routing_table.RoutingTable._make_token``). Reused
verbatim by the telemetry emitter and the placement hook so all proxy → panel
endpoints authenticate identically and stay in lock-step with the frozen
contract (radius-module-admin ``docs/contracts/fleet_api.md`` §0):

    X-Proxy-Token: <timestamp>:<nonce>:<hmac>
      timestamp  integer unix seconds
      nonce      random hex, unique within the panel's TTL window (replay-safe)
      hmac       HMAC_SHA256(key=RADIUS_PROXY_SHARED_SECRET,
                             msg=f"{timestamp}:{nonce}").hexdigest()
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional


def make_proxy_token(
    secret: str,
    *,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
) -> str:
    """Build a ``<ts>:<nonce>:<hmac>`` proxy token.

    Args:
        secret:  RADIUS_PROXY_SHARED_SECRET (proxy ↔ panel shared key).
        ts:      Override the unix timestamp (testing); defaults to now.
        nonce:   Override the nonce (testing); defaults to a random hex string.

    Returns:
        The token string, or "" when ``secret`` is empty (panel will deny).
    """
    if not secret:
        return ""
    ts = int(time.time()) if ts is None else ts
    nonce = secrets.token_hex(8) if nonce is None else nonce
    message = f"{ts}:{nonce}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{sig}"


def proxy_token_headers(secret: str) -> dict[str, str]:
    """Return request headers carrying a fresh X-Proxy-Token + JSON content type."""
    return {
        "X-Proxy-Token": make_proxy_token(secret),
        "Content-Type": "application/json",
    }
