"""RADIUS CoA / Disconnect sender (RFC 5176) for the central RADIUS proxy.

CHR Fleet — Phase 7 (P7-T1): real enforcement layer.

Builds and sends RFC 5176 Disconnect-Request / CoA-Request packets to a CHR's
CoA port (default 3799) over the wg-data tunnel, to kill an old session
("kill-old-session", doc 04 §4.4) or force-move a user (doc 04 §4.5 / doc 05
§5.6). The proxy is the natural origin: it holds the CHR shared secret and sits
on the WireGuard network with line-of-sight to the CHRs.

RFC 5176 mechanics:
    - Disconnect-Request = code 40 → Disconnect-ACK 41 / Disconnect-NAK 42.
    - CoA-Request        = code 43 → CoA-ACK 44 / CoA-NAK 45.
    - Request-Authenticator (§2.3) = MD5(Code+ID+Length+16 zero octets+Attrs+
      secret) — identical construction to an Accounting-Request authenticator,
      so we reuse ``radius_packet.accounting_request_authenticator``.
    - Response-Authenticator = MD5(Code+ID+Length+RequestAuth+Attrs+secret),
      verified with ``radius_packet.verify_response_authenticator``.
    - Session identification (doc 04 §4.4.3): Acct-Session-Id (44) + User-Name
      (1) + NAS-IP-Address (4) of the target CHR.
    - Signed with the CHR shared secret (the same secret the CHR uses toward the
      proxy); RouterOS ``/radius incoming accept=yes`` honours it.

Resilience: timeouts are retried with exponential backoff; nothing raises out of
the public methods — they return a :class:`CoaResult`. ``_send`` uses a blocking
UDP socket and is meant to run off the event loop (in a worker thread).
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

import radius_packet as rp

log = logging.getLogger(__name__)

# ── RFC 5176 packet codes ──────────────────────────────────────────────
CODE_DISCONNECT_REQUEST = 40
CODE_DISCONNECT_ACK     = 41
CODE_DISCONNECT_NAK     = 42
CODE_COA_REQUEST        = 43
CODE_COA_ACK            = 44
CODE_COA_NAK            = 45

_ACK_FOR = {CODE_DISCONNECT_REQUEST: CODE_DISCONNECT_ACK,
            CODE_COA_REQUEST: CODE_COA_ACK}
_NAK_FOR = {CODE_DISCONNECT_REQUEST: CODE_DISCONNECT_NAK,
            CODE_COA_REQUEST: CODE_COA_NAK}

# Default CoA listener port on the CHR (RouterOS /radius incoming).
DEFAULT_COA_PORT = 3799


@dataclass
class CoaResult:
    """Outcome of a CoA / Disconnect exchange.

    Attributes:
        ok:    True on ACK (Disconnect-ACK / CoA-ACK), False on NAK / failure.
        code:  RADIUS response code (41/42/44/45), or None on timeout.
        error: Human-readable error when the exchange failed/timed out.
        attempts: How many request transmissions were made.
    """

    ok: bool
    code: Optional[int] = None
    error: Optional[str] = None
    attempts: int = 0


class CoaSender:
    """Builds and sends RFC 5176 Disconnect / CoA requests to CHR nodes."""

    def __init__(
        self,
        chr_secret: str,
        coa_port: int = DEFAULT_COA_PORT,
        timeout: float = 5.0,
        max_retries: int = 2,
        backoff_base: float = 0.5,
    ) -> None:
        """Configure the sender.

        Args:
            chr_secret:   Shared secret used toward CHRs (Config.CHR_SHARED_SECRET).
            coa_port:     UDP CoA port on the CHR (default 3799).
            timeout:      Seconds to wait for the ACK/NAK response per attempt.
            max_retries:  Extra retransmits on timeout (>=0); total tries = 1+n.
            backoff_base: Exponential backoff base seconds between retries.
        """
        self._secret = chr_secret
        self._port = coa_port
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._backoff_base = backoff_base
        self._ident = 0
        self._lock = threading.Lock()
        self._idem: dict[str, CoaResult] = {}

    # ── public API ────────────────────────────────────────────────────
    def disconnect(
        self,
        *,
        chr_ip: str,
        username: str,
        acct_session_id: str,
        nas_ip: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CoaResult:
        """Send a Disconnect-Request (code 40) to terminate a session."""
        attrs = self._session_attrs(username, acct_session_id, nas_ip)
        return self._exchange(
            CODE_DISCONNECT_REQUEST, chr_ip, attrs, idempotency_key
        )

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
        """Send a CoA-Request (code 43) to change a live session's attributes."""
        attrs = self._session_attrs(username, acct_session_id, nas_ip)
        attrs.extend(attributes or [])
        return self._exchange(
            CODE_COA_REQUEST, chr_ip, attrs, idempotency_key
        )

    # ── internals ─────────────────────────────────────────────────────
    @staticmethod
    def _session_attrs(
        username: str, acct_session_id: str, nas_ip: Optional[str]
    ) -> list[tuple[int, bytes]]:
        """Build the RFC 5176 §3 session-identification attribute set."""
        attrs: list[tuple[int, bytes]] = []
        if username:
            attrs.append((rp.ATTR_USER_NAME, username.encode("utf-8")))
        if acct_session_id:
            attrs.append((rp.ATTR_ACCT_SESSION_ID, acct_session_id.encode("utf-8")))
        if nas_ip:
            try:
                attrs.append((rp.ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip)))
            except OSError:
                log.debug("coa: bad nas_ip %r — omitting NAS-IP-Address", nas_ip)
        return attrs

    def _next_ident(self) -> int:
        with self._lock:
            self._ident = (self._ident + 1) & 0xFF
            return self._ident

    def _build_request(
        self,
        code: int,
        identifier: int,
        attributes: list[tuple[int, bytes]],
    ) -> tuple[bytes, bytes]:
        """Build a signed RFC 5176 request packet.

        Returns:
            (packet_bytes, request_authenticator) — the authenticator is needed
            to verify the response.
        """
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in attributes
        )
        length = rp.HEADER_SIZE + len(attrs_bytes)
        # RFC 5176 §2.3 Request Authenticator == Accounting-Request style.
        authenticator = rp.accounting_request_authenticator(
            code, identifier, length, attrs_bytes, self._secret
        )
        packet = (
            struct.pack("!BBH", code, identifier, length)
            + authenticator
            + attrs_bytes
        )
        return packet, authenticator

    def _exchange(
        self,
        code: int,
        chr_ip: str,
        attributes: list[tuple[int, bytes]],
        idempotency_key: Optional[str],
    ) -> CoaResult:
        """Build → send (with retry/backoff) → validate. Never raises."""
        if idempotency_key:
            with self._lock:
                cached = self._idem.get(idempotency_key)
            if cached is not None:
                log.debug("coa: idempotent replay key=%s → %s", idempotency_key, cached)
                return cached

        identifier = self._next_ident()
        try:
            packet, req_auth = self._build_request(code, identifier, attributes)
        except Exception as exc:  # pragma: no cover - defensive
            return CoaResult(ok=False, error=f"build_failed: {exc}")

        addr = (chr_ip, self._port)
        result = CoaResult(ok=False, error="timeout")
        for attempt in range(self._max_retries + 1):
            result.attempts = attempt + 1
            resp = self._send(packet, addr)
            if resp is not None:
                result = self._classify(code, resp, req_auth, attempt + 1)
                break
            if attempt < self._max_retries:
                time.sleep(self._backoff_base * (2 ** attempt))

        if idempotency_key and (result.ok or result.code is not None):
            with self._lock:
                if len(self._idem) > 4096:        # bound memory
                    self._idem.clear()
                self._idem[idempotency_key] = result
        log.info(
            "coa: %s chr=%s ok=%s code=%s attempts=%d%s",
            "Disconnect" if code == CODE_DISCONNECT_REQUEST else "CoA",
            chr_ip, result.ok, result.code, result.attempts,
            f" err={result.error}" if result.error else "",
        )
        return result

    def _classify(
        self, req_code: int, resp: rp.RadiusPacket, req_auth: bytes, attempts: int
    ) -> CoaResult:
        """Validate a response packet's authenticator and map ACK/NAK → CoaResult."""
        if not rp.verify_response_authenticator(resp, req_auth, self._secret):
            return CoaResult(ok=False, code=resp.code, attempts=attempts,
                             error="response_authenticator_mismatch")
        if resp.code == _ACK_FOR.get(req_code):
            return CoaResult(ok=True, code=resp.code, attempts=attempts)
        if resp.code == _NAK_FOR.get(req_code):
            return CoaResult(ok=False, code=resp.code, attempts=attempts, error="nak")
        return CoaResult(ok=False, code=resp.code, attempts=attempts,
                         error=f"unexpected_code_{resp.code}")

    def _send(self, packet: bytes, addr: tuple[str, int]) -> Optional[rp.RadiusPacket]:
        """Send a CoA/Disconnect packet over UDP and wait for the response.

        Returns the parsed ACK/NAK response packet, or None on timeout/error.
        Blocking — run off the event loop.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self._timeout)
        try:
            sock.sendto(packet, addr)
            data, _ = sock.recvfrom(4096)
            return rp.parse(data)
        except (socket.timeout, OSError, rp.RadiusError) as exc:
            log.debug("coa: no/invalid response from %s: %s", addr, exc)
            return None
        finally:
            sock.close()
