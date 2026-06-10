"""P10 integration test — the full proxy-side enforce loop, end to end.

Drives REAL components wired by proxy._build_fleet_components (no stubs except
the panel HTTP layer and the CHR):

    Acct-Start packet → RadiusProxyProtocol._handle
        → TelemetryEmitter counts the session (flush → POST §1 payload)
        → PlacementHook reports §2 placement (run_in_executor)
        → EnforcementEngine tracks the session
    same user, second CHR → kill-old via REAL CoaSender → RFC 5176
        Disconnect on the wire → mock UDP CoA server ACKs
        → outcome POSTed to the mock panel enforcement ingest (§1.4)
    brain decision says move + movable → evaluate_moves → CoA → §1.4 + §2
    live-apply OFF → advisory-only: ZERO CoA packets, ZERO enforcement POSTs.

The "panel" is a recording fake patched over requests.post/get (all fleet
modules share the one requests module). The "CHR" is tests.test_coa.
MockCoaServer — a real loopback UDP socket speaking RFC 5176.
"""
from __future__ import annotations

import asyncio
import os
import struct
import sys
import time as _time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import pytest

import proxy as proxymod
import radius_packet as rp
import routing_table as rtmod
from tests.test_coa import MockCoaServer

SECRET_CHR = "chr-secret-test"          # must match MockCoaServer's default
OLD_CHR_IP = "127.0.0.1"                # where the mock CoA server listens
NEW_CHR_IP = "127.0.0.3"                # second CHR (loopback alias, no server)


# ── fake panel (records every HTTP call the fleet modules make) ───────
class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"ok": True}

    def json(self):
        return self._body

    @staticmethod
    def raise_for_status():
        pass


class FakePanel:
    def __init__(self, decision: str | None = None):
        self.decision = decision
        self.posts: list[tuple[str, dict, dict]] = []   # (url, json, headers)
        self.gets: list[str] = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append((url, json, headers or {}))
        return _Resp(200, {"ok": True})

    def get(self, url, params=None, headers=None, timeout=None):
        self.gets.append(url)
        if "placement-decision" in url:
            top = [{"node": self.decision, "score": 0.9}] if self.decision else []
            return _Resp(200, {"ok": True, "decision": self.decision, "top_n": top})
        return _Resp(200, {"ok": True, "routes": [], "chr_nodes": []})

    def posts_to(self, fragment: str) -> list[dict]:
        return [body for (url, body, _h) in self.posts if fragment in url]

    def all_headers(self) -> list[dict]:
        return [h for (_u, _b, h) in self.posts]


def _cfg(coa_port: int):
    class Cfg:
        ADMIN_BASE_URL = "https://panel.example"
        PROXY_SHARED_SECRET = "proxy-secret"
        CHR_SHARED_SECRET = SECRET_CHR
        PROXY_ID = "proxy-itest"
        FORWARD_TIMEOUT_SECONDS = 10
        ACCT_TIMEOUT_MODE = "strict"
        STRICT_RESPONSE_VERIFY = True
        FLEET_TELEMETRY_ENABLED = True
        FLEET_TELEMETRY_ENDPOINT = "https://panel.example/api/proxy/telemetry"
        FLEET_TELEMETRY_INTERVAL = 30
        FLEET_TELEMETRY_TIMEOUT = 5
        FLEET_TELEMETRY_MAX_RETRIES = 1
        FLEET_TELEMETRY_BACKOFF_BASE = 0.01
        FLEET_AGENT_VERSION = "1.0.0"
        FLEET_PLACEMENT_ENABLED = True
        FLEET_PLACEMENT_REPORT_ENDPOINT = "https://panel.example/api/proxy/placement"
        FLEET_PLACEMENT_DECISION_ENDPOINT = "https://panel.example/api/proxy/placement-decision"
        FLEET_PLACEMENT_DECISION_PROBE = True
        FLEET_PLACEMENT_DECISION_TTL = 30
        FLEET_PLACEMENT_TIMEOUT = 5
        FLEET_ENFORCEMENT_ENABLED = True
        FLEET_LIVE_APPLY_ALLOWED = True
        FLEET_COA_PORT = coa_port
        FLEET_COA_TIMEOUT = 1
        FLEET_COA_MAX_RETRIES = 0
        FLEET_COA_BACKOFF_BASE = 0.01
        FLEET_MOVE_COOLDOWN = 120
        FLEET_MOVE_EVAL_INTERVAL = 60
        FLEET_ENFORCEMENT_ENDPOINT = "https://panel.example/api/proxy/enforcement"
        # Fast + zero-retry so executor threads finish INSIDE the mock-patch
        # scope (a retry sleeping past it would hit the real network).
        FLEET_ENFORCEMENT_TIMEOUT = 5
        FLEET_ENFORCEMENT_MAX_RETRIES = 0
        FLEET_ENFORCEMENT_BACKOFF_BASE = 0.01
    return Cfg


def _routing(live_apply: bool) -> rtmod.RoutingTable:
    rt = rtmod.RoutingTable("https://panel.example", "proxy-secret")
    rt._allowed_chr_ips = {OLD_CHR_IP, NEW_CHR_IP}
    rt._chr_node_names = {OLD_CHR_IP: "chr-old", NEW_CHR_IP: "chr-new"}
    rt._node_status = {"chr-old": "active", "chr-new": "active"}
    rt._live_apply = live_apply
    rt._movable_users = {"bob@client5"}
    rt._routes = {
        "client5": rtmod.RouteEntry(
            realm="client5", customer_id=1, target_ip="127.0.0.1",
            auth_port=65334, acct_port=65335, secret="customer-secret",
        )
    }
    rt._last_refresh = _time.time()        # ensure_fresh stays off HTTP
    return rt


def _acct_start(user: str, sid: str) -> bytes:
    attrs = [
        (1, user.encode()),                                  # User-Name
        (40, struct.pack("!I", 1)),                          # Acct-Status-Type Start
        (44, sid.encode()),                                  # Acct-Session-Id
        (8, bytes([10, 77, 0, 42])),                         # Framed-IP-Address
    ]
    return rp.build(rp.CODE_ACCOUNTING_REQUEST, 7, b"\x00" * 16, attrs)


async def _drive(proto, packets: list[tuple[bytes, str]]):
    """Feed packets through the real _handle (forwarding stubbed to timeout)."""
    async def _no_forward(_packet, _target):
        return None                       # upstream RADIUS "timeout" — strict drop

    proto._forward = _no_forward
    for data, src in packets:
        await proto._handle(data, (src, 45000))


async def _wait_for(cond, timeout=4.0):
    """Await an executor-side condition without blocking the loop."""
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        if cond():
            return True
        await asyncio.sleep(0.02)
    return False


def _build(live_apply: bool, coa_port: int, decision: str | None):
    cfg = _cfg(coa_port)
    rt = _routing(live_apply)
    telemetry, placement, enforcement = proxymod._build_fleet_components(cfg, rt)
    loop = asyncio.new_event_loop()
    proto = proxymod.RadiusProxyProtocol(
        rt, cfg.CHR_SHARED_SECRET, loop, is_accounting=True,
        telemetry=telemetry, placement=placement, decision_probe=False,
        enforcement=enforcement,
    )
    return cfg, rt, proto, telemetry, placement, enforcement, loop


# ── scenario 1: live-apply ON — single-session kill via real CoA ──────
def test_live_loop_single_session_kill_and_telemetry():
    panel = FakePanel()
    with MockCoaServer("ack") as srv, \
         mock.patch("requests.post", side_effect=panel.post), \
         mock.patch("requests.get", side_effect=panel.get):
        cfg, rt, proto, telemetry, placement, enforcement, loop = _build(
            live_apply=True, coa_port=srv.port, decision=None)
        asyncio.set_event_loop(loop)
        try:
            # First Acct-Start; wait until the executor hook tracked it (the
            # two hooks run in worker threads — ordering must be pinned).
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-OLD"), OLD_CHR_IP),
            ]))
            assert loop.run_until_complete(_wait_for(
                lambda: (s := enforcement._tracker.get("bob@client5"))
                and s.chr_ip == OLD_CHR_IP))
            # Same user reconnects on the second CHR → kill-old fires.
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-NEW"), NEW_CHR_IP),
            ]))
            # kill-old runs in the executor → CoA must hit the mock CHR.
            assert loop.run_until_complete(
                _wait_for(lambda: len(srv.requests) >= 1))
            # …and the outcome must be POSTed to the panel ingest.
            assert loop.run_until_complete(_wait_for(
                lambda: len(panel.posts_to("/api/proxy/enforcement")) >= 1))
        finally:
            loop.close()

        # RFC 5176 Disconnect for the OLD session on the OLD CHR.
        req = srv.requests[0]
        assert req.code == 40
        assert req.get_attr(44) == b"SID-OLD"
        assert req.get_attr(1) == b"bob@client5"

        # §1.4 enforcement outcome: frozen vocabulary + applied.
        enf_posts = panel.posts_to("/api/proxy/enforcement")
        assert enf_posts[0]["action"] == "single_session_kill"
        assert enf_posts[0]["result"] == "applied"
        assert enf_posts[0]["node"] == "chr-old"
        assert enf_posts[0]["user"] == "bob@client5"
        assert enf_posts[0]["acct_session_id"] == "SID-OLD"

        # §2 placement feedback for both Acct-Starts (reason=new).
        pl_posts = panel.posts_to("/api/proxy/placement")
        nodes = [p["placements"][0]["node"] for p in pl_posts]
        assert "chr-old" in nodes and "chr-new" in nodes

        # Telemetry observed both nodes; flush emits §1 payloads to the panel.
        assert telemetry.flush() is True
        tel_posts = panel.posts_to("/api/proxy/telemetry")
        tel_nodes = {p["node"]: p for p in tel_posts}
        assert {"chr-old", "chr-new"} <= set(tel_nodes)
        assert tel_nodes["chr-new"]["metrics"]["active_sessions"] == 1
        assert tel_nodes["chr-new"]["sampled_at"].endswith("Z")

        # EVERY panel call carried an X-Proxy-Token.
        for headers in panel.all_headers():
            assert headers.get("X-Proxy-Token", "").count(":") == 2


# ── scenario 2: live-apply ON — placement move via real CoA ───────────
def test_live_loop_move_with_decision_and_movable():
    panel = FakePanel(decision="chr-target")        # brain wants bob elsewhere
    with MockCoaServer("ack") as srv, \
         mock.patch("requests.post", side_effect=panel.post), \
         mock.patch("requests.get", side_effect=panel.get):
        cfg, rt, proto, telemetry, placement, enforcement, loop = _build(
            live_apply=True, coa_port=srv.port, decision="chr-target")
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-1"), OLD_CHR_IP),
            ]))
            assert loop.run_until_complete(_wait_for(
                lambda: enforcement._tracker.get("bob@client5") is not None))
            # The brain decision is consumed inside evaluate_moves (read path),
            # the user is movable → enforced disconnect on the current CHR.
            outcomes = enforcement.evaluate_moves(now=_time.time())
        finally:
            loop.close()

        move = [o for o in outcomes if o.action == "move"][0]
        assert move.reason == "rebalance" and move.result == "applied"
        assert move.intended_node == "chr-target"
        assert len(srv.requests) == 1 and srv.requests[0].get_attr(44) == b"SID-1"

        enf_posts = panel.posts_to("/api/proxy/enforcement")
        assert enf_posts[0]["action"] == "move"
        assert enf_posts[0]["node"] == "chr-target"          # destination
        assert enf_posts[0]["previous_node"] == "chr-old"    # source
        # §2 mirror: pending until the user reconnects.
        pl_moves = [p for p in panel.posts_to("/api/proxy/placement")
                    if p["placements"][0]["reason"] == "rebalance"]
        assert pl_moves and pl_moves[0]["placements"][0]["result"] == "pending"


# ── scenario 3: live-apply OFF — advisory only, zero side effects ─────
def test_advisory_loop_sends_nothing():
    panel = FakePanel(decision="chr-target")
    with MockCoaServer("ack") as srv, \
         mock.patch("requests.post", side_effect=panel.post), \
         mock.patch("requests.get", side_effect=panel.get):
        cfg, rt, proto, telemetry, placement, enforcement, loop = _build(
            live_apply=False, coa_port=srv.port, decision="chr-target")
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-OLD"), OLD_CHR_IP),
            ]))
            assert loop.run_until_complete(_wait_for(
                lambda: (s := enforcement._tracker.get("bob@client5"))
                and s.chr_ip == OLD_CHR_IP))
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-NEW"), NEW_CHR_IP),
            ]))
            assert loop.run_until_complete(_wait_for(
                lambda: (s := enforcement._tracker.get("bob@client5"))
                and s.chr_ip == NEW_CHR_IP))
            outcomes = enforcement.evaluate_moves(now=_time.time())
            loop.run_until_complete(asyncio.sleep(0.3))
        finally:
            loop.close()

        # Advisory outcomes computed (intent visible) …
        advisory = [o for o in outcomes if o.result == "advisory"]
        assert advisory and advisory[0].advisory is True
        # … but ZERO CoA packets and ZERO enforcement ingests.
        assert srv.requests == []
        assert panel.posts_to("/api/proxy/enforcement") == []
        # §2 'new' placement feedback (observability) still flows — that path
        # is Phase-4 read/report, independent of enforcement.
        assert panel.posts_to("/api/proxy/placement")  # non-empty


# ── panel down: enforce loop must not raise, falls back safe ──────────
def test_panel_down_never_breaks_radius_handling():
    import requests as _requests

    def _down_post(*a, **k):
        raise _requests.ConnectionError("panel down")

    def _down_get(*a, **k):
        raise _requests.ConnectionError("panel down")

    with MockCoaServer("ack") as srv, \
         mock.patch("requests.post", side_effect=_down_post), \
         mock.patch("requests.get", side_effect=_down_get):
        cfg, rt, proto, telemetry, placement, enforcement, loop = _build(
            live_apply=True, coa_port=srv.port, decision=None)
        asyncio.set_event_loop(loop)
        try:
            # Both packets handled without any exception escaping _handle.
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-OLD"), OLD_CHR_IP),
            ]))
            assert loop.run_until_complete(_wait_for(
                lambda: (s := enforcement._tracker.get("bob@client5"))
                and s.chr_ip == OLD_CHR_IP))
            loop.run_until_complete(_drive(proto, [
                (_acct_start("bob@client5", "SID-NEW"), NEW_CHR_IP),
            ]))
            # Kill-old still enforced (CoA is socket-level, panel-independent);
            # only the REPORT is lost (swallowed).
            assert loop.run_until_complete(
                _wait_for(lambda: len(srv.requests) >= 1))
            outcomes = enforcement.evaluate_moves(now=_time.time())  # no raise
            assert telemetry.flush() is False                        # swallowed
            # Drain executor threads before the requests mock exits, so no
            # in-flight retry can escape to the real network.
            loop.run_until_complete(asyncio.sleep(0.3))
        finally:
            loop.close()
