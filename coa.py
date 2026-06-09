"""RADIUS CoA / Disconnect sender (RFC 5176) for the central RADIUS proxy.

CHR Fleet — Phase 1 STUB (P1-T3).  Bodies are filled in Phase 7 (P7-T1).

Responsibility (per docs/chr_fleet/07_CONTROL_PLANE.md §7.1/§7.3/§7.4 and
docs/chr_fleet/04_FIXED_IP_AND_SESSIONS.md §4.4):
    Build and send RFC 5176 Disconnect-Request / CoA-Request packets to a CHR's
    CoA port (default 3799) over the wg-data tunnel, to kill an old session
    ("kill-old-session") or force-move a user.  The proxy is the natural origin
    because it already holds the CHR shared secret and sits on the WireGuard
    network with line-of-sight to the CHRs.

Trigger:
    The panel asks the proxy via ``POST /api/proxy/coa`` (handler wired in
    Phase 7 P7-T2):
        { "action": "disconnect",          # or "coa"
          "realm": "client5",
          "acct_session_id": "8f2c...",
          "username": "bob@client5",
          "chr_public_ip": "203.0.113.11",
          "idempotency_key": "ks-8f2c..." }
    and expects back:
        { "ok": true,  "code": 41 }        # Disconnect-ACK
        { "ok": false, "code": 42 }        # Disconnect-NAK
      (or a timeout when the target CHR is down — handled by the caller).

Session identification (RFC 5176 §3):
    Disconnect/CoA requests carry Acct-Session-Id (44) + User-Name (1) +
    NAS-IP-Address (4) of the target CHR.  Packets are signed with the CHR
    shared secret (the same secret the CHR uses toward the proxy); the
    Request-Authenticator is computed per RFC 5176 §2.3.

Phase-7 implementers: fill the method bodies; keep the public signatures stable
— the panel side (radius-module-admin: coa_client.py) is built against the
HTTP contract above, and proxy.py / main.py (P7-T2) wire this sender in.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

import radius_packet as rp

# ── RFC 5176 packet codes (reference constants, no behaviour) ──────────
CODE_DISCONNECT_REQUEST = 40
CODE_DISCONNECT_ACK     = 41
CODE_DISCONNECT_NAK     = 42
CODE_COA_REQUEST        = 43
CODE_COA_ACK            = 44
CODE_COA_NAK            = 45

# Default CoA listener port on the CHR (RouterOS /radius incoming).
DEFAULT_COA_PORT = 3799


@dataclass
class CoaResult:
    """Outcome of a CoA / Disconnect exchange.

    Attributes:
        ok:    True on ACK (Disconnect-ACK / CoA-ACK), False on NAK / failure.
        code:  RADIUS response code (41/42/44/45), or None on timeout.
        error: Human-readable error when the exchange failed/timed out.
    """

    ok: bool
    code: Optional[int] = None
    error: Optional[str] = None


class CoaSender:
    """Builds and sends RFC 5176 Disconnect / CoA requests to CHR nodes."""

    def __init__(
        self,
        chr_secret: str,
        coa_port: int = DEFAULT_COA_PORT,
        timeout: float = 5.0,
    ) -> None:
        """Configure the sender.

        Args:
            chr_secret:  Shared secret used toward CHRs (Config.CHR_SHARED_SECRET).
            coa_port:    UDP CoA port on the CHR (default 3799).
            timeout:     Seconds to wait for the ACK/NAK response.
        """
        raise NotImplementedError("Phase 7 (P7-T1): CoaSender.__init__")

    def disconnect(
        self,
        *,
        chr_ip: str,
        username: str,
        acct_session_id: str,
        nas_ip: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CoaResult:
        """Send a Disconnect-Request (code 40) to terminate a session.

        Used for kill-old-session and for evacuating a user during rebalance /
        forced failover.

        Args:
            chr_ip:           Target CHR IP (CoA sent to chr_ip:coa_port).
            username:         RADIUS User-Name (attr 1) of the session.
            acct_session_id:  Acct-Session-Id (attr 44) of the session to kill.
            nas_ip:           NAS-IP-Address (attr 4) of the CHR (optional).
            idempotency_key:  Replay-safe key; a repeat returns the prior result.

        Returns:
            A :class:`CoaResult` (ok+code on ACK/NAK, error on timeout/failure).
        """
        raise NotImplementedError("Phase 7 (P7-T1): CoaSender.disconnect")

    def change_authorization(
        self,
        *,
        chr_ip: str,
        username: str,
        acct_session_id: str,
        attributes: list[tuple[int, bytes]],
        nas_ip: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CoaResult:
        """Send a CoA-Request (code 43) to change a live session's attributes.

        Args:
            chr_ip:           Target CHR IP.
            username:         RADIUS User-Name (attr 1) of the session.
            acct_session_id:  Acct-Session-Id (attr 44) of the session.
            attributes:       (type, value) attribute pairs to apply.
            nas_ip:           NAS-IP-Address (attr 4) of the CHR (optional).
            idempotency_key:  Replay-safe key.

        Returns:
            A :class:`CoaResult`.
        """
        raise NotImplementedError("Phase 7 (P7-T1): CoaSender.change_authorization")

    def _build_request(
        self,
        code: int,
        identifier: int,
        attributes: list[tuple[int, bytes]],
    ) -> bytes:
        """Build a signed RFC 5176 request packet.

        Computes the Request-Authenticator over Code+ID+Length+16 zero bytes+
        Attributes+secret (RFC 5176 §2.3), then patches it in. Adds a
        Message-Authenticator when required.

        Args:
            code:        CODE_DISCONNECT_REQUEST or CODE_COA_REQUEST.
            identifier:  RADIUS packet identifier.
            attributes:  Session-identification + optional CoA attributes.

        Returns:
            The fully built, signed packet bytes.
        """
        raise NotImplementedError("Phase 7 (P7-T1): CoaSender._build_request")

    def _send(self, packet: bytes, addr: tuple[str, int]) -> Optional[rp.RadiusPacket]:
        """Send a CoA/Disconnect packet over UDP and wait for the response.

        Args:
            packet:  Built request bytes.
            addr:    (chr_ip, coa_port) target address.

        Returns:
            The parsed ACK/NAK response packet, or None on timeout.
        """
        raise NotImplementedError("Phase 7 (P7-T1): CoaSender._send")
