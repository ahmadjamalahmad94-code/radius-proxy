"""P10 hardening tests — config bounds + the refresh() crash-path regression.

1. _env_int_bounded clamps out-of-range env values (a typo can't produce a
   non-blocking socket, busy loop, or retry storm).
2. REGRESSION (real bug found in the P10 review): RoutingTable.refresh() is
   reached from lookup() in the RADIUS packet hot path. A panel that answers
   HTTP 200 with malformed JSON or wrong-typed fields used to raise
   ValueError/TypeError OUT of refresh() and kill the packet task. It must
   swallow, return False, and keep the previous table.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import config as cfgmod
import routing_table as rtmod


# ── 1. config bounds ──────────────────────────────────────────────────
def test_env_int_bounded_clamps():
    with mock.patch.dict(os.environ, {"X_TEST_KNOB": "0"}):
        assert cfgmod._env_int_bounded("X_TEST_KNOB", 5, 1, 30) == 1     # low
    with mock.patch.dict(os.environ, {"X_TEST_KNOB": "-7"}):
        assert cfgmod._env_int_bounded("X_TEST_KNOB", 5, 1, 30) == 1
    with mock.patch.dict(os.environ, {"X_TEST_KNOB": "99999"}):
        assert cfgmod._env_int_bounded("X_TEST_KNOB", 5, 1, 30) == 30    # high
    with mock.patch.dict(os.environ, {"X_TEST_KNOB": "garbage"}):
        assert cfgmod._env_int_bounded("X_TEST_KNOB", 5, 1, 30) == 5     # default
    with mock.patch.dict(os.environ, {"X_TEST_KNOB": "12"}):
        assert cfgmod._env_int_bounded("X_TEST_KNOB", 5, 1, 30) == 12    # in range


def test_phase7_knobs_have_sane_values():
    c = cfgmod.Config
    assert 1 <= c.FLEET_COA_PORT <= 65535
    assert 1 <= c.FLEET_COA_TIMEOUT <= 30
    assert 0 <= c.FLEET_COA_MAX_RETRIES <= 5
    assert 0.0 <= c.FLEET_COA_BACKOFF_BASE <= 10.0
    assert 0 <= c.FLEET_MOVE_COOLDOWN <= 86400
    assert 5 <= c.FLEET_MOVE_EVAL_INTERVAL <= 3600
    assert 5 <= c.FLEET_TELEMETRY_INTERVAL <= 3600
    assert 1 <= c.FLEET_TELEMETRY_TIMEOUT <= 60
    assert 1 <= c.FLEET_TELEMETRY_MAX_RETRIES <= 6
    assert 1 <= c.FLEET_PLACEMENT_DECISION_TTL <= 3600
    assert 1 <= c.FLEET_PLACEMENT_TIMEOUT <= 60
    assert 1 <= c.FLEET_ENFORCEMENT_TIMEOUT <= 60
    assert 0 <= c.FLEET_ENFORCEMENT_MAX_RETRIES <= 5
    assert 0.0 <= c.FLEET_ENFORCEMENT_BACKOFF_BASE <= 10.0
    # Endpoints resolved, never empty.
    for ep in (c.FLEET_TELEMETRY_ENDPOINT, c.FLEET_PLACEMENT_REPORT_ENDPOINT,
               c.FLEET_PLACEMENT_DECISION_ENDPOINT, c.FLEET_ENFORCEMENT_ENDPOINT):
        assert ep.startswith("http")


# ── 2. refresh() crash-path regression ────────────────────────────────
def _table_with_route() -> rtmod.RoutingTable:
    rt = rtmod.RoutingTable("https://panel.example", "s")
    rt._routes = {"client5": rtmod.RouteEntry(
        realm="client5", customer_id=1, target_ip="10.0.0.9",
        auth_port=1812, acct_port=1813, secret="x")}
    rt._allowed_chr_ips = {"203.0.113.11"}
    return rt


def test_refresh_swallows_malformed_json():
    rt = _table_with_route()

    class _Bad:
        status_code = 200
        @staticmethod
        def raise_for_status():
            pass
        @staticmethod
        def json():
            raise ValueError("not json")

    with mock.patch.object(rtmod.requests, "get", return_value=_Bad()):
        assert rt.refresh() is False          # swallowed, no raise
    # Previous table stays in effect (stale-but-valid beats crash).
    assert rt._routes["client5"].target_ip == "10.0.0.9"
    assert rt.is_allowed_chr("203.0.113.11") is True


def test_refresh_swallows_wrong_typed_fields():
    rt = _table_with_route()
    data = {"ok": True,
            "routes": [{"realm": "client9", "customer_id": "NaN",
                        "target_ip": "10.0.0.1"}],
            "chr_nodes": []}

    class _Resp:
        status_code = 200
        @staticmethod
        def raise_for_status():
            pass
        @staticmethod
        def json():
            return data

    with mock.patch.object(rtmod.requests, "get", return_value=_Resp()):
        assert rt.refresh() is False          # int("NaN") swallowed
    assert "client5" in rt._routes            # old table intact


def test_lookup_survives_bad_panel_response():
    """End check: the hot path (lookup → ensure_fresh → refresh) never raises."""
    rt = _table_with_route()
    rt._last_refresh = 0                      # force a refresh on lookup

    class _Bad:
        status_code = 200
        @staticmethod
        def raise_for_status():
            pass
        @staticmethod
        def json():
            raise ValueError("boom")

    with mock.patch.object(rtmod.requests, "get", return_value=_Bad()):
        entry = rt.lookup("client5")          # must not raise
    assert entry is not None and entry.realm == "client5"
