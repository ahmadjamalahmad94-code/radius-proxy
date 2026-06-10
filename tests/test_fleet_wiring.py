"""Smoke tests: proxy boots clean with the Phase-4/Phase-7 fleet hooks wired.

Confirms _build_fleet_components constructs real objects from Config (telemetry,
placement, enforcement), that the RoutingTable node-name resolver +
local-candidate + live-apply/status/movable accessors work, and that the
RadiusProxyProtocol accepts the hooks.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy as proxymod
import routing_table as rtmod
import telemetry as tel
import placement_hook as ph
import enforcement as enf


class _Cfg:
    ADMIN_BASE_URL = "https://panel.example"
    PROXY_SHARED_SECRET = "proxy-secret"
    CHR_SHARED_SECRET = "chr-secret"
    PROXY_ID = "proxy-test"
    FORWARD_TIMEOUT_SECONDS = 10
    ACCT_TIMEOUT_MODE = "strict"
    STRICT_RESPONSE_VERIFY = True
    FLEET_TELEMETRY_ENABLED = True
    FLEET_TELEMETRY_ENDPOINT = "https://panel.example/api/proxy/telemetry"
    FLEET_TELEMETRY_INTERVAL = 30
    FLEET_TELEMETRY_TIMEOUT = 10
    FLEET_TELEMETRY_MAX_RETRIES = 3
    FLEET_TELEMETRY_BACKOFF_BASE = 0.5
    FLEET_AGENT_VERSION = "1.0.0"
    FLEET_PLACEMENT_ENABLED = True
    FLEET_PLACEMENT_REPORT_ENDPOINT = "https://panel.example/api/proxy/placement"
    FLEET_PLACEMENT_DECISION_ENDPOINT = "https://panel.example/api/proxy/placement-decision"
    FLEET_PLACEMENT_DECISION_PROBE = True
    FLEET_PLACEMENT_DECISION_TTL = 30
    FLEET_PLACEMENT_TIMEOUT = 10
    # Phase 7
    FLEET_ENFORCEMENT_ENABLED = True
    FLEET_LIVE_APPLY_ALLOWED = True
    FLEET_COA_PORT = 3799
    FLEET_COA_TIMEOUT = 5
    FLEET_COA_MAX_RETRIES = 2
    FLEET_COA_BACKOFF_BASE = 0.5
    FLEET_MOVE_COOLDOWN = 120
    FLEET_MOVE_EVAL_INTERVAL = 60
    FLEET_ENFORCEMENT_ENDPOINT = "https://panel.example/api/proxy/enforcement"


def _routing():
    return rtmod.RoutingTable(
        "https://panel.example", "proxy-secret",
        static_node_map={"203.0.113.11": "chr-exit-01"},
    )


def test_build_fleet_components_returns_objects():
    t, p, e = proxymod._build_fleet_components(_Cfg, _routing())
    assert isinstance(t, tel.TelemetryEmitter)
    assert isinstance(p, ph.PlacementHook)
    assert isinstance(e, enf.EnforcementEngine)


def test_components_disabled_via_config():
    class Off(_Cfg):
        FLEET_TELEMETRY_ENABLED = False
        FLEET_PLACEMENT_ENABLED = False
        FLEET_ENFORCEMENT_ENABLED = False
    t, p, e = proxymod._build_fleet_components(Off, _routing())
    assert t is None and p is None and e is None


def test_routing_node_resolver_and_candidates():
    rt = _routing()
    # static map resolves; allowlist drives local candidates
    rt._allowed_chr_ips = {"203.0.113.11", "203.0.113.12"}
    assert rt.node_name_for("203.0.113.11") == "chr-exit-01"
    assert rt.node_name_for("203.0.113.12") is None        # unmapped → caller falls back
    cands = rt.local_node_candidates()
    assert "chr-exit-01" in cands and "203.0.113.12" in cands


def test_routing_phase7_accessors_default_safe():
    rt = _routing()
    # Defaults before/without panel data: advisory + no status + nobody movable.
    assert rt.live_apply() is False
    assert rt.has_node_status() is False
    assert rt.is_node_healthy("chr-exit-01") is False      # unknown ⇒ not healthy
    assert rt.is_user_movable("bob@client5") is False
    # Simulate a refreshed table:
    rt._live_apply = True
    rt._node_status = {"chr-exit-01": "active", "chr-exit-02": "draining"}
    rt._movable_users = {"bob@client5"}
    assert rt.live_apply() is True
    assert rt.is_node_healthy("chr-exit-01") is True
    assert rt.is_node_healthy("chr-exit-02") is False
    assert rt.is_user_movable("BOB@client5") is True        # case-insensitive


def test_engine_effective_live_apply_panel_and_local():
    """effective live-apply = panel flag AND local override."""
    rt = _routing()
    _, _, e = proxymod._build_fleet_components(_Cfg, rt)
    assert e._live_apply() is False        # panel default False
    rt._live_apply = True
    assert e._live_apply() is True         # panel on + local allowed

    class LocalOff(_Cfg):
        FLEET_LIVE_APPLY_ALLOWED = False
    rt2 = _routing()
    rt2._live_apply = True
    _, _, e2 = proxymod._build_fleet_components(LocalOff, rt2)
    assert e2._live_apply() is False       # local override hard-blocks


def test_engine_node_healthy_gated_on_status_presence():
    rt = _routing()
    _, _, e = proxymod._build_fleet_components(_Cfg, rt)
    # No status from panel ⇒ everything "healthy" ⇒ no forced moves.
    assert e._node_healthy("chr-exit-99") is True
    rt._node_status = {"chr-exit-01": "active"}
    assert e._node_healthy("chr-exit-01") is True
    assert e._node_healthy("chr-exit-99") is False         # known-status world: unknown ⇒ down


def test_protocol_accepts_hooks():
    loop = asyncio.new_event_loop()
    try:
        rt = _routing()
        t, p, e = proxymod._build_fleet_components(_Cfg, rt)
        proto = proxymod.RadiusProxyProtocol(
            rt, "chr-secret", loop,
            is_accounting=True, telemetry=t, placement=p, decision_probe=True,
            enforcement=e,
        )
        assert proto._telemetry is t and proto._placement is p
        assert proto._enforcement is e
    finally:
        loop.close()
