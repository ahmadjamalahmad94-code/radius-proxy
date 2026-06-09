"""Session placement reporter for the central RADIUS proxy.

CHR Fleet — Phase 1 STUB (P1-T3).  Bodies are filled in Phase 4 (P4-T6).

Responsibility (per docs/chr_fleet/01_ARCHITECTURE.md §1.3.1 and
docs/chr_fleet/04_FIXED_IP_AND_SESSIONS.md §4.6):
    On every Accounting-Start / Stop / Interim, report *which CHR a session
    actually landed on* to the panel at ``POST /api/proxy/placement``.  This is
    the ground-truth feed for the panel's ``sessions`` table, the single-session
    / kill-old-session guard, and per-user → CHR placement.

Contract:
    Endpoint : POST {ADMIN_BASE_URL}/api/proxy/placement
    Auth     : X-Proxy-Token = "<ts>:<nonce>:<HMAC-SHA256(secret, 'ts:nonce')>"
               (secret = RADIUS_PROXY_SHARED_SECRET).
    Body     : {
                 "event": "start" | "stop" | "interim",
                 "username": "bob@client5",
                 "realm": "client5",
                 "chr_public_ip": "203.0.113.11",
                 "framed_ip": "10.77.0.42",        # RADIUS Framed-IP-Address (attr 8)
                 "acct_session_id": "8f2c...",     # Acct-Session-Id (attr 44)
                 "nas_ip": "203.0.113.11",         # NAS-IP-Address (attr 4), optional
                 "ts": 1733740800
               }

Phase-4 implementers: fill the method bodies; keep the public signatures stable
— the panel side (radius-module-admin: routes_placement.py / placement_ingest.py)
is built against this contract.
"""
from __future__ import annotations

from typing import Optional

import radius_packet as rp


class PlacementHook:
    """Posts session→CHR placement events to the panel on accounting activity."""

    def __init__(
        self,
        admin_base_url: str,
        shared_secret: str,
        timeout: float = 10.0,
    ) -> None:
        """Configure the placement hook.

        Args:
            admin_base_url:  License panel base URL (Config.ADMIN_BASE_URL).
            shared_secret:   RADIUS_PROXY_SHARED_SECRET — keys the X-Proxy-Token.
            timeout:         HTTP timeout for the POST.
        """
        raise NotImplementedError("Phase 4 (P4-T6): PlacementHook.__init__")

    def report(
        self,
        *,
        event: str,
        username: str,
        realm: str,
        chr_public_ip: str,
        framed_ip: str,
        acct_session_id: str,
        nas_ip: Optional[str] = None,
        ts: Optional[int] = None,
    ) -> bool:
        """Report a single placement event to the panel.

        Args:
            event:           "start", "stop", or "interim".
            username:        Full RADIUS identity (user@realm), lowercased.
            realm:           Resolved realm.
            chr_public_ip:   The CHR that handled this session.
            framed_ip:       The fixed Framed-IP-Address assigned by RADIUS.
            acct_session_id: RADIUS Acct-Session-Id.
            nas_ip:          NAS-IP-Address of the CHR (optional).
            ts:              Unix timestamp of the event (defaults to now).

        Returns:
            True on a successful (ok=true) POST, False otherwise.
        """
        raise NotImplementedError("Phase 4 (P4-T6): PlacementHook.report")

    def report_from_packet(
        self,
        pkt: rp.RadiusPacket,
        chr_public_ip: str,
    ) -> bool:
        """Extract placement fields from a parsed Accounting-Request and report.

        Pulls User-Name (attr 1), Framed-IP-Address (attr 8), Acct-Session-Id
        (attr 44), Acct-Status-Type (attr 40 → event), and NAS-IP-Address
        (attr 4) from ``pkt``, then delegates to :meth:`report`.

        Args:
            pkt:            Parsed Accounting-Request packet.
            chr_public_ip:  Source CHR IP (from the UDP datagram address).

        Returns:
            True on a successful POST, False otherwise.
        """
        raise NotImplementedError("Phase 4 (P4-T6): PlacementHook.report_from_packet")

    def _headers(self) -> dict[str, str]:
        """Build the X-Proxy-Token authentication header (mirrors RoutingTable)."""
        raise NotImplementedError("Phase 4 (P4-T6): PlacementHook._headers")
