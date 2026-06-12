"""Tests for §6.2 — per-realm proxy↔customer route-secret rotation grace.

The proxy converges on a new route secret via the routing-table refresh
(≤60 s by design). The customer's FreeRADIUS converges via the bridge
heartbeat (≤300 s by design). For the ~240 s gap between them, the
proxy holds NEW + the customer still has OLD — if the proxy forwards
signed with NEW, the customer drops the request and the proxy sees a
TIMEOUT. With §6.2 dual-accept, the proxy retries once with the PREVIOUS
secret; the response is verified and re-signed back to the CHR with the
secret that actually round-tripped.

These tests pin:
  * RoutingTable.refresh preserves previous_secret across refreshes when
    the panel publishes a rotated secret.
  * The grace window expires after route_secret_grace_seconds.
  * proxy._handle retries ONCE on timeout when the realm is in grace,
    and never when there is no rotation (so steady-state latency is
    unchanged).
  * The response is verified with the secret that worked upstream AND
    re-signed back to the CHR with the secret the CHR used.
"""
from __future__ import annotations

import asyncio
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import proxy as proxymod
import radius_packet as rp
import routing_table as rtmod


CHR_SECRET = "chr-fleet-secret"
PROXY_TOKEN = "proxy-panel-token"
WG_DATA_IP = "10.98.0.11"


def _mock_panel(body: dict):
    class _Resp:
        status_code = 200

        @staticmethod
        def raise_for_status() -> None:
            pass

        @staticmethod
        def json() -> dict:
            return body

    return mock.patch.object(rtmod.requests, "get", return_value=_Resp())


def _payload(realm_secret: str) -> dict:
    return {
        "ok": True,
        "chr_shared_secret": CHR_SECRET,
        "routes": [
            {
                "realm": "client5", "customer_id": 5,
                "target_ip": "10.200.5.2", "auth_port": 1812, "acct_port": 1813,
                "secret": realm_secret,
            }
        ],
        "chr_nodes": [
            {"name": "chr-vpn-1", "wg_data_ip": WG_DATA_IP,
             "public_ip": "203.0.113.1", "status": "active"},
        ],
    }


def _build_routing(tmp_path: str, grace: int = 600) -> rtmod.RoutingTable:
    return rtmod.RoutingTable(
        "https://panel.example", PROXY_TOKEN,
        chr_secret_state_path=os.path.join(str(tmp_path), "chr-secret.json"),
        route_secret_grace_seconds=grace,
    )


def _access_request(user: str, secret: str, identifier: int = 7) -> bytes:
    auth = rp.request_authenticator()
    attrs = [(1, user.encode()), (80, b"\x00" * 16)]
    pkt = bytearray(rp.build(rp.CODE_ACCESS_REQUEST, identifier, auth, attrs))
    rp.recompute_message_authenticator(pkt, secret)
    return bytes(pkt)


def _customer_response(req: bytes, secret: str, code: int = rp.CODE_ACCESS_REJECT) -> bytes:
    """Upstream customer RADIUS reply signed with `secret`. The proxy
    will verify with `secret` and re-sign for the CHR."""
    fwd = rp.parse(req)
    attrs_bytes = b""
    length = rp.HEADER_SIZE + len(attrs_bytes)
    auth = rp.response_authenticator(
        code, fwd.identifier, length, fwd.authenticator, attrs_bytes, secret,
    )
    return struct.pack("!BBH", code, fwd.identifier, length) + auth


# ── 1. Refresh preserves previous_secret on rotation ─────────────────


def test_refresh_preserves_previous_when_secret_rotates(tmp_path):
    rt = _build_routing(str(tmp_path))
    with _mock_panel(_payload("first-secret")):
        rt.refresh()
    entry1 = rt.lookup("client5")
    assert entry1 and entry1.secret == "first-secret"
    assert entry1.previous_secret == ""

    # Rotation
    with _mock_panel(_payload("second-secret")):
        rt.refresh()
    entry2 = rt.lookup("client5")
    assert entry2.secret == "second-secret"
    assert entry2.previous_secret == "first-secret"
    # And the proxy-side accessor returns the grace value.
    assert rt.route_previous_secret_in_grace("client5") == "first-secret"


def test_refresh_carries_previous_across_unchanged_refreshes(tmp_path):
    """Once a rotation has been observed, repeated identical refreshes
    must keep the previous_secret + rotated_at intact (so the proxy
    keeps the grace window through normal refresh ticks until the
    customer converges OR the window expires)."""
    rt = _build_routing(str(tmp_path))
    with _mock_panel(_payload("s1")):
        rt.refresh()
    with _mock_panel(_payload("s2")):
        rt.refresh()
    rotated_at = rt.lookup("client5").secret_rotated_at
    # Now several identical refreshes
    for _ in range(3):
        with _mock_panel(_payload("s2")):
            rt.refresh()
    entry = rt.lookup("client5")
    assert entry.previous_secret == "s1"
    assert entry.secret_rotated_at == rotated_at   # unchanged
    assert rt.route_previous_secret_in_grace("client5") == "s1"


def test_route_previous_secret_expires_after_grace(tmp_path):
    rt = _build_routing(str(tmp_path), grace=600)
    with _mock_panel(_payload("old")):
        rt.refresh()
    with _mock_panel(_payload("new")):
        rt.refresh()
    assert rt.route_previous_secret_in_grace("client5") == "old"

    # Fast-forward past grace
    entry = rt.lookup("client5")
    entry.secret_rotated_at = time.time() - 700
    assert rt.route_previous_secret_in_grace("client5") is None


def test_route_previous_secret_none_for_unknown_realm(tmp_path):
    rt = _build_routing(str(tmp_path))
    assert rt.route_previous_secret_in_grace("does-not-exist") is None


def test_route_previous_secret_none_when_no_rotation(tmp_path):
    rt = _build_routing(str(tmp_path))
    with _mock_panel(_payload("only-one")):
        rt.refresh()
    assert rt.route_previous_secret_in_grace("client5") is None


# ── 2. proxy._handle retries on timeout within grace ─────────────────


def _proto_with_routing(tmp_path: str) -> tuple[proxymod.RadiusProxyProtocol, asyncio.AbstractEventLoop, rtmod.RoutingTable]:
    rt = _build_routing(str(tmp_path))
    with _mock_panel(_payload("first")):
        rt.refresh()
    loop = asyncio.new_event_loop()
    proto = proxymod.RadiusProxyProtocol(
        rt, CHR_SECRET, loop,
        forward_timeout=1, is_accounting=False,
        strict_response_verify=True,
    )
    sent: list[tuple[bytes, tuple]] = []
    proto._transport = type("T", (), {"sendto": lambda _s, d, a: sent.append((d, a))})()
    proto._sent = sent  # type: ignore[attr-defined]
    return proto, loop, rt


def test_retry_with_previous_secret_succeeds_during_grace(tmp_path):
    """Owner's #4 invariant: NO RADIUS drops during route-secret
    rotation. After the panel rotates the realm secret, the proxy
    holds NEW + the customer holds OLD for ~240 s. A forward signed
    with NEW times out; the proxy must retry once with OLD and the
    request round-trips."""
    proto, loop, rt = _proto_with_routing(str(tmp_path))
    try:
        # Rotate
        with _mock_panel(_payload("second")):
            rt.refresh()
        assert rt.route_previous_secret_in_grace("client5") == "first"

        forwards: list[bytes] = []
        attempt = {"n": 0}

        async def _fake_forward(packet: bytes, target: tuple) -> "bytes | None":
            forwards.append(packet)
            attempt["n"] += 1
            assert target == ("10.200.5.2", 1812)
            # First call (signed with NEW=second): the customer is on
            # OLD and silently drops → simulate a timeout.
            if attempt["n"] == 1:
                return None
            # Second call (signed with OLD=first): customer accepts and
            # replies signed with OLD.
            return _customer_response(packet, "first")

        proto._forward = _fake_forward
        # CHR signs with CHR_SECRET (steady-state on the CHR side; only
        # the proxy↔customer secret is rotating).
        req = _access_request("ghost@client5", CHR_SECRET, identifier=42)
        loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))

        # Exactly TWO forwards: first with NEW (timeout), then with OLD.
        assert attempt["n"] == 2
        assert forwards[0] != forwards[1]              # different signatures

        # One Access-Reject delivered back to CHR, signed with CHR secret.
        sent = proto._sent  # type: ignore[attr-defined]
        assert len(sent) == 1
        resp = rp.parse(sent[0][0])
        assert resp.code == rp.CODE_ACCESS_REJECT
        # Response-Authenticator must verify with CHR_SECRET.
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in resp.attributes
        )
        expected = rp.response_authenticator(
            rp.CODE_ACCESS_REJECT, resp.identifier,
            rp.HEADER_SIZE + len(attrs_bytes),
            rp.parse(req).authenticator, attrs_bytes, CHR_SECRET,
        )
        assert resp.authenticator == expected
    finally:
        loop.close()


def test_no_retry_outside_grace(tmp_path):
    """Once the grace window closes, the proxy MUST NOT retry — that
    way a genuinely-broken upstream surfaces as a single timeout (the
    operator sees the problem) instead of being masked by silent retries."""
    proto, loop, rt = _proto_with_routing(str(tmp_path))
    try:
        with _mock_panel(_payload("second")):
            rt.refresh()
        # Force grace expiry
        rt.lookup("client5").secret_rotated_at = time.time() - 9999
        assert rt.route_previous_secret_in_grace("client5") is None

        attempts = {"n": 0}

        async def _fake_forward(_packet, _target):
            attempts["n"] += 1
            return None                                # always timeout

        proto._forward = _fake_forward
        req = _access_request("ghost@client5", CHR_SECRET)
        loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))
        assert attempts["n"] == 1                       # NO retry
    finally:
        loop.close()


def test_no_retry_when_no_rotation_steady_state_latency(tmp_path):
    """Steady-state: no rotation, one forward. No retry latency for the
    99.x% case where the secret hasn't changed."""
    proto, loop, rt = _proto_with_routing(str(tmp_path))
    try:
        # No rotation; previous_secret remains empty.
        assert rt.route_previous_secret_in_grace("client5") is None
        attempts = {"n": 0}

        async def _fake_forward(_packet, _target):
            attempts["n"] += 1
            return None

        proto._forward = _fake_forward
        req = _access_request("ghost@client5", CHR_SECRET)
        loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))
        assert attempts["n"] == 1
    finally:
        loop.close()


def test_retry_only_on_timeout_not_on_first_success(tmp_path):
    """If the first forward succeeds (the more common case during
    rotation: the customer ALREADY converged), there must be no retry."""
    proto, loop, rt = _proto_with_routing(str(tmp_path))
    try:
        with _mock_panel(_payload("second")):
            rt.refresh()
        attempts = {"n": 0}

        async def _fake_forward(packet, _target):
            attempts["n"] += 1
            # First (and only) call: customer accepts, signed with NEW.
            return _customer_response(packet, "second")

        proto._forward = _fake_forward
        req = _access_request("ghost@client5", CHR_SECRET)
        loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))
        assert attempts["n"] == 1                       # only first attempt
    finally:
        loop.close()


def test_response_verified_with_secret_that_worked_upstream(tmp_path):
    """When the retry with PREVIOUS succeeds, the response is signed
    with PREVIOUS by the customer and the proxy must verify it with
    PREVIOUS (not current). Strict mode is on, so a wrong verify would
    drop the response and the test would fail to deliver Access-Reject."""
    proto, loop, rt = _proto_with_routing(str(tmp_path))
    try:
        with _mock_panel(_payload("second")):
            rt.refresh()

        async def _fake_forward(packet, _target):
            # On every call, the customer responds with PREVIOUS-signed
            # data (simulating an upstream that hasn't converged yet).
            # First attempt: timeout. Second: response.
            _fake_forward.n = getattr(_fake_forward, "n", 0) + 1
            if _fake_forward.n == 1:
                return None
            return _customer_response(packet, "first")

        proto._forward = _fake_forward
        req = _access_request("ghost@client5", CHR_SECRET)
        loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))
        sent = proto._sent  # type: ignore[attr-defined]
        # The response MUST be delivered (proves verify with PREVIOUS worked).
        assert len(sent) == 1
        resp = rp.parse(sent[0][0])
        assert resp.code == rp.CODE_ACCESS_REJECT
    finally:
        loop.close()
