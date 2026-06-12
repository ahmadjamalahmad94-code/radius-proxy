"""Tests for §4.2 — customer-RADIUS peer reconciler (wg-radius).

Mirrors ``tests/test_wg_peer_sync.py`` (the proven wg-data reconciler) but
points at:
  * Panel endpoint: ``GET /api/proxy/radius-peers``
  * JSON top-level key: ``radius_peers`` (NOT ``peers`` — distinct contract)
  * WireGuard interface: ``wg-radius`` (NOT ``wg-data``)
  * State file: ``managed-radius-peers.json``
  * Subnet: ``10.200.0.0/16`` per design §1; entries are ``/32`` host routes

The class is the SAME (parametrized) ``WgPeerSync`` — these tests guard
that the parametrization actually shifted the contract to the new
endpoint + JSON key + interface, and that the safety model carried over.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy as proxymod
import wg_peer_sync as wps


# Realistic-shaped wg pubkeys (same constraint chars as wg-data tests).
PK_C5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PK_C9 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
PK_C12 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCY="


class _Resp:
    def __init__(self, status: int = 200, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


def _http_ok(body):
    def _get(url, headers=None, timeout=None):
        # Pin the contract URL — the parametrization must actually take effect.
        assert url.endswith("/api/proxy/radius-peers"), url
        assert headers and "X-Proxy-Token" in headers
        return _Resp(200, body)
    return _get


class _Runner:
    """Same shape as the wg-data test runner but pins the interface name."""

    def __init__(self, iface: str = "wg-radius"):
        self.calls: list[list[str]] = []
        self._iface = iface
        self._actual: list[str] = []
        self._show_rc = 0
        self._set_rc = 0
        self._set_err = ""

    def set_actual(self, pubkeys: list[str]):
        self._actual = list(pubkeys)

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.calls.append(list(argv))
        # The reconciler must NEVER target the wrong iface — that would
        # mean parametrization broke and we'd be rewriting wg-data peers
        # from a radius-peers payload, which is catastrophic.
        if "wg-data" in argv:
            return 1, "", "WRONG INTERFACE — would corrupt wg-data peer set"
        if "show" in argv:
            if self._show_rc != 0:
                return self._show_rc, "", "show failed"
            lines = ["PRIVKEY\tPUBKEY\t51822\toff"]
            for pk in self._actual:
                lines.append("\t".join([
                    pk, "(none)", "(none)", "10.200.0.x/32",
                    "0", "0", "0", "off",
                ]))
            return 0, "\n".join(lines) + "\n", ""
        if "set" in argv:
            if self._set_rc != 0:
                return self._set_rc, "", self._set_err
            pk = argv[argv.index("peer") + 1]
            if "remove" in argv:
                if pk in self._actual:
                    self._actual.remove(pk)
            elif pk and pk not in self._actual:
                self._actual.append(pk)
            return 0, "", ""
        return 0, "", ""


def _new_sync(http_get, runner, *, tmp_path):
    return wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        endpoint_path="/api/proxy/radius-peers",
        peers_json_key="radius_peers",
        interface="wg-radius",
        state_path=os.path.join(tmp_path, "managed-radius-peers.json"),
        log_prefix="wg radius sync",
        runner=runner,
        http_get=http_get,
    )


def _payload(peers):
    """The frozen panel contract for radius-peers — top-level
    ``radius_peers`` (NOT ``peers``)."""
    return {"ok": True, "radius_peers": peers}


# ── 1. Contract fields routed correctly ───────────────────────────────


def test_endpoint_url_is_api_proxy_radius_peers(tmp_path):
    sync = _new_sync(_http_ok(_payload([])), _Runner(), tmp_path=str(tmp_path))
    assert sync._url.endswith("/api/proxy/radius-peers"), sync._url
    assert sync._peers_key == "radius_peers"
    assert sync._iface == "wg-radius"


def test_fetch_reads_radius_peers_key_not_peers(tmp_path):
    """Critical contract guard: if we accidentally read the wg-data key
    `peers`, the radius reconciler would silently keep producing zero
    desired peers and never converge."""
    # A payload that has BOTH keys — only `radius_peers` is correct here.
    body = {
        "ok": True,
        "peers": [{
            "name": "WRONG", "public_key": PK_C12,
            "allowed_ips": ["10.98.0.99/32"],
        }],
        "radius_peers": [{
            "name": "client5", "public_key": PK_C5,
            "allowed_ips": ["10.200.5.2/32"],
        }],
    }
    sync = _new_sync(_http_ok(body), _Runner(), tmp_path=str(tmp_path))
    peers, _skipped, err = sync._fetch_desired()
    assert err is None
    pubkeys = {p.public_key for p in peers}
    assert pubkeys == {PK_C5}                    # the radius_peers entry
    assert PK_C12 not in pubkeys                  # NOT the wg-data 'peers' one


def test_bad_json_error_message_mentions_the_radius_peers_key(tmp_path):
    body = {"ok": True, "radius_peers": "not-a-list"}
    sync = _new_sync(_http_ok(body), _Runner(), tmp_path=str(tmp_path))
    _peers, _skipped, err = sync._fetch_desired()
    assert err and "radius_peers" in err


# ── 2. Reconcile: adds, idempotent, stale removal, unprivileged ──────


def test_reconcile_adds_missing_customer_peer(tmp_path):
    runner = _Runner()                              # actual = {} at start
    body = _payload([
        {"name": "client5-radius", "public_key": PK_C5,
         "allowed_ips": ["10.200.5.2/32"]},
    ])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.mode == "apply"
    assert res.added == [PK_C5]
    assert any(
        "set" in c and PK_C5 in c and "10.200.5.2/32" in c and "wg-radius" in c
        for c in runner.calls
    ), runner.calls


def test_reconcile_is_idempotent(tmp_path):
    runner = _Runner()
    body = _payload([
        {"name": "client5-radius", "public_key": PK_C5,
         "allowed_ips": ["10.200.5.2/32"]},
    ])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    sync.reconcile()
    n_set_after_first = sum("set" in c for c in runner.calls)
    sync.reconcile()
    n_set_after_second = sum("set" in c for c in runner.calls)
    assert n_set_after_first == n_set_after_second


def test_reconcile_removes_stale_managed_customer(tmp_path):
    """Customer 9 was previously provisioned (wg-radius peer added by
    the proxy and persisted to managed-radius-peers.json) but is now
    disabled in the panel. It must be removed; customer 5 stays."""
    runner = _Runner()
    runner.set_actual([PK_C5, PK_C9])
    state_path = os.path.join(str(tmp_path), "managed-radius-peers.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"managed_pubkeys": [PK_C5, PK_C9]}, f)

    body = _payload([
        {"name": "client5-radius", "public_key": PK_C5,
         "allowed_ips": ["10.200.5.2/32"]},
    ])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.removed == [PK_C9]
    assert any("remove" in c and PK_C9 in c for c in runner.calls), runner.calls


def test_reconcile_never_touches_unmanaged_peer(tmp_path):
    """The operator may have manually `wg set wg-radius peer …` for
    staging. The reconciler MUST NOT remove peers it didn't add."""
    runner = _Runner()
    runner.set_actual([PK_C5, PK_C12])              # PK_C12 = operator's
    state_path = os.path.join(str(tmp_path), "managed-radius-peers.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"managed_pubkeys": [PK_C5]}, f)

    body = _payload([
        {"name": "client5-radius", "public_key": PK_C5,
         "allowed_ips": ["10.200.5.2/32"]},
    ])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.removed == []
    assert not any("remove" in c and PK_C12 in c for c in runner.calls)


def test_reconcile_degrades_to_dry_run_unprivileged(tmp_path):
    runner = _Runner()
    runner._set_rc = 126
    runner._set_err = "Operation not permitted"
    body = _payload([
        {"name": "client5-radius", "public_key": PK_C5,
         "allowed_ips": ["10.200.5.2/32"]},
    ])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.mode == "dry-run"
    assert res.added == [PK_C5]                    # logged as would-do
    assert res.error is None                        # NO exception


def test_reconcile_safe_swallows_any_inner_crash(tmp_path):
    sync = _new_sync(_http_ok(_payload([])), _Runner(), tmp_path=str(tmp_path))
    sync.reconcile = lambda: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[assignment]
    assert sync.reconcile_safe() is None             # NO exception escapes


# ── 3. The proxy builder + boot wiring ────────────────────────────────


class _CfgRadius:
    """Test config that enables ONLY the wg-radius reconciler (so the
    boot-check is focused — fleet hooks tested elsewhere)."""
    ADMIN_BASE_URL = "https://panel.example"
    PROXY_SHARED_SECRET = "proxy-token"
    PROXY_ID = "proxy-test"
    # wg-data side
    FLEET_WG_PEER_SYNC_ENABLED = False
    FLEET_WG_INTERFACE = "wg-data"
    FLEET_WG_STATE_PATH = "/tmp/managed-peers.json"
    FLEET_WG_BIN = "wg"
    FLEET_WG_APPLY_MODE = "auto"
    FLEET_WG_PEER_SYNC_TIMEOUT = 10
    # wg-radius side (under test)
    FLEET_WG_RADIUS_SYNC_ENABLED = True
    FLEET_WG_RADIUS_SYNC_ENDPOINT_PATH = "/api/proxy/radius-peers"
    FLEET_WG_RADIUS_INTERFACE = "wg-radius"
    FLEET_WG_RADIUS_STATE_PATH = "/tmp/managed-radius-peers.json"
    FLEET_WG_RADIUS_SYNC_INTERVAL = 60
    FLEET_WG_RADIUS_SYNC_TIMEOUT = 10


def test_build_wg_radius_sync_returns_correctly_parametrized_instance():
    sync = proxymod._build_wg_radius_sync(_CfgRadius)
    assert sync is not None
    assert sync._url.endswith("/api/proxy/radius-peers")
    assert sync._peers_key == "radius_peers"
    assert sync._iface == "wg-radius"
    assert sync._log_prefix == "wg radius sync"


def test_build_returns_none_when_disabled():
    class Off(_CfgRadius):
        FLEET_WG_RADIUS_SYNC_ENABLED = False
    assert proxymod._build_wg_radius_sync(Off) is None
