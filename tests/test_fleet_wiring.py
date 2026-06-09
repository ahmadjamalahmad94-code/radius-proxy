"""Smoke tests: proxy boots clean with the Phase-4 fleet hooks wired.

Confirms _build_fleet_components constructs real objects from Config, that the
RoutingTable node-name resolver + local-candidate provider work, and that the
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


def _routing():
    return rtmod.RoutingTable(
        "https://panel.example", "proxy-secret",
        static_node_map={"203.0.113.11": "chr-exit-01"},
    )


def test_build_fleet_components_returns_objects():
    t, p = proxymod._build_fleet_components(_Cfg, _routing())
    assert isinstance(t, tel.TelemetryEmitter)
    assert isinstance(p, ph.PlacementHook)


def test_components_disabled_via_config():
    class Off(_Cfg):
        FLEET_TELEMETRY_ENABLED = False
        FLEET_PLACEMENT_ENABLED = False
    t, p = proxymod._build_fleet_components(Off, _routing())
    assert t is None and p is None


def test_routing_node_resolver_and_candidates():
    rt = _routing()
    # static map resolves; allowlist drives local candidates
    rt._allowed_chr_ips = {"203.0.113.11", "203.0.113.12"}
    assert rt.node_name_for("203.0.113.11") == "chr-exit-01"
    assert rt.node_name_for("203.0.113.12") is None        # unmapped → caller falls back
    cands = rt.local_node_candidates()
    assert "chr-exit-01" in cands and "203.0.113.12" in cands


def test_protocol_accepts_hooks():
    loop = asyncio.new_event_loop()
    try:
        rt = _routing()
        t, p = proxymod._build_fleet_components(_Cfg, rt)
        proto = proxymod.RadiusProxyProtocol(
            rt, "chr-secret", loop,
            is_accounting=True, telemetry=t, placement=p, decision_probe=True,
        )
        assert proto._telemetry is t and proto._placement is p
    finally:
        loop.close()
