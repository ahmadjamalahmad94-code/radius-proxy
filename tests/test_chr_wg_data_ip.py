"""Regression tests for the panel ↔ proxy frozen field ``chr_nodes[].wg_data_ip``.

LIVE FAILURE this guards against:

    tcpdump:  10.98.0.11.59123 > 10.98.0.1.1812: RADIUS Access-Request …
    proxy log: WARNING  proxy: Packet from unknown CHR IP 10.98.0.11 — dropped

Root cause was in ``RoutingTable.refresh()``: it only read
``chr_nodes[].public_ip`` (the CHR's PUBLIC v4) into the allowlist, while the
proxy actually sees the CHR's **wg-data** address (10.98.0.x) as the RADIUS
source over the WireGuard tunnel. The two never matched → drop.

These tests pin the fix: the allowlist must contain every ``wg_data_ip``
published by the panel, and a packet from that address must be PROCESSED
(forwarded → reject), not dropped.
"""
from __future__ import annotations

import asyncio
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import proxy as proxymod
import radius_packet as rp
import routing_table as rtmod


CHR_SECRET = "chr-fleet-secret"
CUSTOMER_SECRET = "customer-radius-secret"
PROXY_SECRET = "proxy-panel-secret"

# The actual live numbers from the incident.
WG_DATA_IP = "10.98.0.11"
PUBLIC_IP = "178.105.244.112"


# ── 1. refresh() ingests chr_nodes[].wg_data_ip into the allowlist ────


def _routing_table() -> rtmod.RoutingTable:
    return rtmod.RoutingTable("https://panel.example", PROXY_SECRET)


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


def test_refresh_ingests_wg_data_ip_into_allowlist():
    """The exact live failure: panel publishes wg_data_ip=10.98.0.11; proxy must
    recognize a packet from that source as a KNOWN CHR (no drop)."""
    rt = _routing_table()
    payload = {
        "ok": True,
        "routes": [],
        "chr_nodes": [
            {
                "name": "chr-vpn-1",
                "public_ip": PUBLIC_IP,
                "wg_data_ip": WG_DATA_IP,
                "status": "active",
            }
        ],
    }
    with _mock_panel(payload):
        assert rt.refresh() is True

    # The wg-data source IP is now in the allowlist — packet would be PROCESSED.
    assert rt.is_allowed_chr(WG_DATA_IP) is True
    # Legacy public_ip stays accepted (panel may still send it, e.g. for
    # public-facing tooling) — set semantics dedupe; both map to the node.
    assert rt.is_allowed_chr(PUBLIC_IP) is True
    # Node-name resolution works for EITHER address (telemetry/placement
    # currently key by source IP → name).
    assert rt.node_name_for(WG_DATA_IP) == "chr-vpn-1"
    assert rt.node_name_for(PUBLIC_IP) == "chr-vpn-1"


def test_refresh_tolerates_legacy_only_entries():
    """Backwards compatibility: a node entry with ONLY public_ip (pre-fleet
    panel response) still populates the allowlist as before."""
    rt = _routing_table()
    payload = {
        "ok": True,
        "routes": [],
        "chr_nodes": [{"name": "legacy", "public_ip": "203.0.113.7"}],
    }
    with _mock_panel(payload):
        assert rt.refresh() is True
    assert rt.is_allowed_chr("203.0.113.7") is True
    assert rt.is_allowed_chr(WG_DATA_IP) is False  # not published → not allowed


def test_refresh_tolerates_wg_data_ip_only_entries():
    """Forward compatibility: a fleet-only entry with ONLY wg_data_ip still
    enters the allowlist (the panel may drop public_ip once the migration
    completes — the proxy must not regress)."""
    rt = _routing_table()
    payload = {
        "ok": True,
        "routes": [],
        "chr_nodes": [
            {"name": "chr-vpn-2", "wg_data_ip": "10.98.0.12", "status": "active"}
        ],
    }
    with _mock_panel(payload):
        assert rt.refresh() is True
    assert rt.is_allowed_chr("10.98.0.12") is True
    assert rt.node_name_for("10.98.0.12") == "chr-vpn-2"


def test_refresh_dedupes_overlap_and_picks_up_new_nodes_without_restart():
    """Refresh #1: one node. Refresh #2: two nodes (the panel agent published
    a new wg_data_ip). The proxy must recognize the new IP WITHOUT a restart,
    which is exactly what the routing-table maintenance loop does in prod."""
    rt = _routing_table()
    first = {
        "ok": True,
        "routes": [],
        "chr_nodes": [
            {"name": "chr-vpn-1", "public_ip": PUBLIC_IP, "wg_data_ip": WG_DATA_IP},
        ],
    }
    with _mock_panel(first):
        assert rt.refresh() is True
    assert rt.is_allowed_chr(WG_DATA_IP) is True
    assert rt.is_allowed_chr("10.98.0.12") is False

    second = {
        "ok": True,
        "routes": [],
        "chr_nodes": [
            {"name": "chr-vpn-1", "public_ip": PUBLIC_IP, "wg_data_ip": WG_DATA_IP},
            {"name": "chr-vpn-2", "wg_data_ip": "10.98.0.12", "status": "active"},
        ],
    }
    with _mock_panel(second):
        assert rt.refresh() is True
    assert rt.is_allowed_chr(WG_DATA_IP) is True       # still there
    assert rt.is_allowed_chr("10.98.0.12") is True     # now recognized too


# ── 2. End-to-end: known CHR + unknown user → Access-Reject (forwarded) ─


def _access_request(user: str, identifier: int = 7) -> bytes:
    """Build an Access-Request from a CHR, signed with CHR_SECRET. The
    proxy will re-sign it for the target RADIUS using CUSTOMER_SECRET."""
    auth = rp.request_authenticator()
    attrs = [(1, user.encode())]  # User-Name
    return rp.build(rp.CODE_ACCESS_REQUEST, identifier, auth, attrs)


def _customer_access_reject(req: bytes) -> bytes:
    """The upstream RADIUS replies Access-Reject signed with CUSTOMER_SECRET.

    The proxy will then verify this with CUSTOMER_SECRET and re-sign for the
    CHR with CHR_SECRET before returning it.
    """
    fwd = rp.parse(req)
    attrs_bytes = b""
    length = rp.HEADER_SIZE + len(attrs_bytes)
    auth = rp.response_authenticator(
        rp.CODE_ACCESS_REJECT, fwd.identifier, length,
        fwd.authenticator, attrs_bytes, CUSTOMER_SECRET,
    )
    return struct.pack("!BBH", rp.CODE_ACCESS_REJECT, fwd.identifier, length) + auth


def _routing_with_realm() -> rtmod.RoutingTable:
    rt = _routing_table()
    payload = {
        "ok": True,
        "routes": [
            {
                "realm": "client5", "customer_id": 1,
                "target_ip": "10.20.30.40", "auth_port": 1812, "acct_port": 1813,
                "secret": CUSTOMER_SECRET,
            }
        ],
        "chr_nodes": [
            {
                "name": "chr-vpn-1",
                "public_ip": PUBLIC_IP, "wg_data_ip": WG_DATA_IP,
                "status": "active",
            }
        ],
    }
    with _mock_panel(payload):
        assert rt.refresh() is True
    return rt


def test_known_chr_unknown_user_forwarded_to_reject_not_dropped(caplog):
    """The acceptance check: an Access-Request from wg-data 10.98.0.11
    (the live failing source) for an unknown user must reach the upstream
    RADIUS, get an Access-Reject back, be re-signed, and be DELIVERED to the
    CHR. No "unknown CHR IP … dropped" log line."""
    rt = _routing_with_realm()
    loop = asyncio.new_event_loop()
    try:
        sent: list[tuple[bytes, tuple]] = []

        class _Transport:
            def sendto(self, data, addr):
                sent.append((data, addr))

        proto = proxymod.RadiusProxyProtocol(
            rt, CHR_SECRET, loop,
            forward_timeout=1, is_accounting=False,
            acct_timeout_mode="strict", strict_response_verify=True,
        )
        proto._transport = _Transport()

        req = _access_request("ghost@client5")

        async def _fake_forward(packet: bytes, target: tuple) -> bytes:
            # Confirm forwarding went to the customer's RADIUS.
            assert target == ("10.20.30.40", 1812)
            return _customer_access_reject(packet)

        proto._forward = _fake_forward

        with caplog.at_level("WARNING", logger="proxy"):
            loop.run_until_complete(proto._handle(req, (WG_DATA_IP, 45000)))

        # ── Acceptance ───────────────────────────────────────────────
        # No "unknown CHR IP" drop.
        assert not any(
            "unknown CHR IP" in rec.getMessage() for rec in caplog.records
        ), [rec.getMessage() for rec in caplog.records]

        # The proxy delivered an Access-Reject back to the CHR (code 3),
        # with the same identifier, signed with CHR_SECRET.
        assert len(sent) == 1
        data, addr = sent[0]
        assert addr == (WG_DATA_IP, 45000)
        resp = rp.parse(data)
        assert resp.code == rp.CODE_ACCESS_REJECT
        assert resp.identifier == rp.parse(req).identifier
        # Response-Authenticator must verify with the CHR secret (proves
        # the re-sign on the way OUT happened correctly).
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


def test_unknown_chr_source_still_dropped(caplog):
    """The fix must not weaken security: a packet from an IP NOT in the
    panel's chr_nodes (neither public_ip nor wg_data_ip) is still rejected."""
    rt = _routing_with_realm()
    loop = asyncio.new_event_loop()
    try:
        proto = proxymod.RadiusProxyProtocol(
            rt, CHR_SECRET, loop, is_accounting=False,
        )
        proto._transport = type("T", (), {"sendto": lambda *a, **k: None})()
        req = _access_request("ghost@client5")
        with caplog.at_level("WARNING", logger="proxy"):
            loop.run_until_complete(proto._handle(req, ("10.98.0.99", 45000)))
        assert any(
            "unknown CHR IP 10.98.0.99" in rec.getMessage()
            for rec in caplog.records
        )
    finally:
        loop.close()
