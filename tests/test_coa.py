"""Unit tests for coa.py (CHR Fleet Phase 7 — RFC 5176 CoA/Disconnect sender).

Covers, against a REAL mock UDP CoA server (loopback socket):
  1. Disconnect-Request packet built correctly: code 40, RFC 5176 §2.3
     Request-Authenticator, session-identification attrs (User-Name 1,
     Acct-Session-Id 44, NAS-IP-Address 4).
  2. ACK → ok=True, code=41; NAK → ok=False, code=42.
  3. Response-Authenticator verified — a forged response is rejected.
  4. Timeout → retry with backoff → CoaResult(ok=False, error="timeout").
  5. CoA-Request (code 43) carries extra attributes.
  6. Idempotency: same key returns the cached result without resending.
  7. Nothing raises out of the public API.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import coa
import radius_packet as rp

SECRET = "chr-secret-test"


class MockCoaServer:
    """Minimal RFC 5176 responder on 127.0.0.1:<ephemeral>.

    mode: "ack" | "nak" | "silent" | "forge" (bad response authenticator)
    Records every request it receives (parsed) in .requests.
    """

    def __init__(self, mode: str = "ack", secret: str = SECRET):
        self.mode = mode
        self.secret = secret
        self.requests: list[rp.RadiusPacket] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(5.0)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._stop = False

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        self._sock.close()

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            try:
                pkt = rp.parse(data)
            except rp.RadiusError:
                continue
            self.requests.append(pkt)
            if self.mode == "silent":
                continue
            ack_code = {40: 41, 43: 44}.get(pkt.code, 41)
            nak_code = {40: 42, 43: 45}.get(pkt.code, 42)
            code = ack_code if self.mode in ("ack", "forge") else nak_code
            attrs_bytes = b""
            length = rp.HEADER_SIZE + len(attrs_bytes)
            req_auth = pkt.authenticator if self.mode != "forge" else b"\x00" * 16
            auth = rp.response_authenticator(
                code, pkt.identifier, length, req_auth, attrs_bytes, self.secret
            )
            resp = struct.pack("!BBH", code, pkt.identifier, length) + auth
            try:
                self._sock.sendto(resp, addr)
            except OSError:
                return


def _sender(port: int, **kw) -> coa.CoaSender:
    defaults = dict(chr_secret=SECRET, coa_port=port, timeout=1.0,
                    max_retries=1, backoff_base=0.05)
    defaults.update(kw)
    return coa.CoaSender(**defaults)


# ── 1. packet construction ────────────────────────────────────────────
def test_disconnect_packet_built_correctly():
    with MockCoaServer("ack") as srv:
        s = _sender(srv.port)
        res = s.disconnect(chr_ip="127.0.0.1", username="bob@client5",
                           acct_session_id="8f2c01", nas_ip="203.0.113.11")
        assert res.ok is True
    assert len(srv.requests) == 1
    req = srv.requests[0]
    assert req.code == coa.CODE_DISCONNECT_REQUEST           # 40
    # Session-identification attrs (doc 04 §4.4.3)
    assert req.get_attr(rp.ATTR_USER_NAME) == b"bob@client5"
    assert req.get_attr(rp.ATTR_ACCT_SESSION_ID) == b"8f2c01"
    assert req.get_attr(rp.ATTR_NAS_IP_ADDRESS) == socket.inet_aton("203.0.113.11")
    # RFC 5176 §2.3 Request-Authenticator: MD5 over code+id+len+zeros+attrs+secret
    attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in req.attributes)
    expected = rp.accounting_request_authenticator(
        req.code, req.identifier, rp.HEADER_SIZE + len(attrs_bytes),
        attrs_bytes, SECRET,
    )
    assert req.authenticator == expected


# ── 2. ACK / NAK handling ─────────────────────────────────────────────
def test_ack_result():
    with MockCoaServer("ack") as srv:
        res = _sender(srv.port).disconnect(
            chr_ip="127.0.0.1", username="u", acct_session_id="s1")
    assert res.ok is True and res.code == coa.CODE_DISCONNECT_ACK     # 41


def test_nak_result():
    with MockCoaServer("nak") as srv:
        res = _sender(srv.port).disconnect(
            chr_ip="127.0.0.1", username="u", acct_session_id="s1")
    assert res.ok is False and res.code == coa.CODE_DISCONNECT_NAK    # 42
    assert res.error == "nak"


# ── 3. forged response rejected ───────────────────────────────────────
def test_forged_response_authenticator_rejected():
    with MockCoaServer("forge") as srv:
        res = _sender(srv.port).disconnect(
            chr_ip="127.0.0.1", username="u", acct_session_id="s1")
    assert res.ok is False
    assert res.error == "response_authenticator_mismatch"


# ── 4. timeout + retry/backoff ────────────────────────────────────────
def test_timeout_retries_then_fails():
    with MockCoaServer("silent") as srv:
        s = _sender(srv.port, timeout=0.2, max_retries=2, backoff_base=0.01)
        res = s.disconnect(chr_ip="127.0.0.1", username="u", acct_session_id="s1")
    assert res.ok is False and res.code is None
    assert res.error == "timeout"
    assert res.attempts == 3                       # 1 + 2 retries
    assert len(srv.requests) == 3                  # actually retransmitted


def test_unreachable_host_swallowed():
    # Port 1 on loopback: nothing listening → timeout, no exception.
    s = _sender(1, timeout=0.2, max_retries=0)
    res = s.disconnect(chr_ip="127.0.0.1", username="u", acct_session_id="s1")
    assert res.ok is False and res.error == "timeout"


# ── 5. CoA-Request with attributes ────────────────────────────────────
def test_coa_request_with_attributes():
    with MockCoaServer("ack") as srv:
        s = _sender(srv.port)
        res = s.change_authorization(
            chr_ip="127.0.0.1", username="bob@client5", acct_session_id="s1",
            attributes=[(rp.ATTR_FRAMED_IP_ADDRESS, socket.inet_aton("10.77.0.42"))],
        )
    assert res.ok is True and res.code == coa.CODE_COA_ACK            # 44
    req = srv.requests[0]
    assert req.code == coa.CODE_COA_REQUEST                           # 43
    assert req.get_attr(rp.ATTR_FRAMED_IP_ADDRESS) == socket.inet_aton("10.77.0.42")


# ── 6. idempotency ────────────────────────────────────────────────────
def test_idempotency_key_returns_cached_result():
    with MockCoaServer("ack") as srv:
        s = _sender(srv.port)
        r1 = s.disconnect(chr_ip="127.0.0.1", username="u",
                          acct_session_id="s1", idempotency_key="k1")
        r2 = s.disconnect(chr_ip="127.0.0.1", username="u",
                          acct_session_id="s1", idempotency_key="k1")
    assert r1.ok and r2.ok
    assert r2 is r1                                # cached object returned
    assert len(srv.requests) == 1                  # NOT resent
