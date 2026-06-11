"""Tests for the zero-touch wg-data peer sync (proxy side).

Covers:
  * Fetch + parse: the frozen panel contract ``GET /api/proxy/wg-peers``.
  * Validation: malformed pubkeys, allowed_ips, default route / wide prefix
    are skipped (not passed to ``wg``).
  * Reconcile: adds missing peers; removes ONLY managed-and-stale peers;
    NEVER touches operator-added peers; idempotent (no ``wg set`` calls
    when the actual set already matches the desired set).
  * Safe-by-default: when ``wg`` is unprivileged / missing, reconcile
    DEGRADES to dry-run — logs would-do, returns a ReconcileResult,
    never raises. Heartbeat + routing-table loops keep working.
  * Catch-all wrapper: reconcile_safe() returns None on any internal
    crash rather than escaping into the asyncio loop.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wg_peer_sync as wps


# ── Fixtures ──────────────────────────────────────────────────────────

# Two real-shaped (but synthetic) WireGuard public keys. They satisfy the
# strict regex (44 chars, ends with the constrained value-encoding byte =).
PK1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PK2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
PK3 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCY="


class _Resp:
    def __init__(self, status: int = 200, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _http_ok(body):
    def _get(_url, headers=None, timeout=None):
        # The reconciler MUST present an X-Proxy-Token (covered separately;
        # here we just check it's not empty for a non-empty secret).
        assert headers and "X-Proxy-Token" in headers
        return _Resp(200, body)
    return _get


def _http_status(code: int):
    def _get(_url, headers=None, timeout=None):
        return _Resp(code, {"error": "x"})
    return _get


class _Runner:
    """Pluggable subprocess runner. Records every argv. Replies based on
    pre-loaded handlers keyed by argv tuple-prefix."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self._show_actual: list[str] = []      # pubkeys present on iface
        self._show_rc = 0
        self._set_rc = 0
        self._set_err = ""

    def set_actual_peers(self, pubkeys: list[str]):
        self._show_actual = list(pubkeys)

    def make_show_fail(self, rc: int = 1, err: str = "permission denied"):
        self._show_rc = rc
        self._show_err = err

    def make_set_fail(self, rc: int = 126, err: str = "permission denied"):
        self._set_rc = rc
        self._set_err = err

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.calls.append(list(argv))
        if "show" in argv:
            if self._show_rc != 0:
                return self._show_rc, "", getattr(self, "_show_err", "err")
            # ``wg show <iface> dump`` first line = iface, then one line/peer.
            lines = ["PRIVKEY\tPUBKEY\t51821\toff"]
            for pk in self._show_actual:
                lines.append("\t".join([pk, "(none)", "(none)", "10.98.0.x/32",
                                        "0", "0", "0", "off"]))
            return 0, "\n".join(lines) + "\n", ""
        if "set" in argv:
            if self._set_rc != 0:
                return self._set_rc, "", self._set_err
            # On apply we update our notion of what's on the wire so
            # subsequent show calls reflect the change.
            try:
                pk = argv[argv.index("peer") + 1]
            except (ValueError, IndexError):
                pk = ""
            if "remove" in argv:
                if pk in self._show_actual:
                    self._show_actual.remove(pk)
            else:
                if pk and pk not in self._show_actual:
                    self._show_actual.append(pk)
            return 0, "", ""
        return 0, "", ""


def _state_file(tmp_path: str) -> str:
    return os.path.join(tmp_path, "managed-peers.json")


def _payload(peers):
    return {"peers": peers}


def _peer(name, pk, ips, endpoint=None):
    return {"name": name, "public_key": pk, "allowed_ips": ips, "endpoint": endpoint}


def _new_sync(http_get, runner, *, tmp_path, apply_mode="auto"):
    return wps.WgPeerSync(
        "https://panel.example", "proxy-secret",
        state_path=_state_file(tmp_path),
        apply_mode=apply_mode,
        http_get=http_get,
        runner=runner,
    )


# ── 1. Validation primitives ──────────────────────────────────────────


def test_pubkey_validation_rejects_obvious_garbage():
    assert wps._valid_pubkey(PK1) is True
    assert wps._valid_pubkey("too-short") is False
    assert wps._valid_pubkey("A" * 43 + "?") is False      # bad char
    # 43rd char must be in the constrained value-encoding set.
    bad_trailing = "A" * 42 + "Z" + "="                    # 'Z' not allowed there
    assert wps._valid_pubkey(bad_trailing) is False


def test_allowed_ip_validation_blocks_default_route_and_wide_prefix():
    assert wps._valid_allowed_ip("10.98.0.11/32") is True
    assert wps._valid_allowed_ip("10.98.0.0/24") is True
    assert wps._valid_allowed_ip("0.0.0.0/0") is False     # default route
    assert wps._valid_allowed_ip("10.0.0.0/8") is False    # too wide (< /24)
    assert wps._valid_allowed_ip("10.98.0.11") is False    # no prefix
    assert wps._valid_allowed_ip("not-an-ip/32") is False
    assert wps._valid_allowed_ip("999.0.0.1/32") is False
    assert wps._valid_allowed_ip("10.98.0.11/33") is False


# ── 2. Fetch + parse the contract response ────────────────────────────


def test_fetch_parses_valid_payload(tmp_path):
    body = _payload([
        _peer("chr-vpn-1", PK1, ["10.98.0.11/32"]),
        _peer("chr-vpn-2", PK2, ["10.98.0.12/32"], endpoint=None),
    ])
    sync = _new_sync(_http_ok(body), _Runner(), tmp_path=str(tmp_path))
    peers, skipped, err = sync._fetch_desired()
    assert err is None
    assert skipped == []
    pubkeys = {p.public_key for p in peers}
    assert pubkeys == {PK1, PK2}
    by_pk = {p.public_key: p for p in peers}
    assert by_pk[PK1].name == "chr-vpn-1"
    assert by_pk[PK1].allowed_ips == ("10.98.0.11/32",)
    assert by_pk[PK1].endpoint is None


def test_fetch_skips_invalid_entries_keeps_valid(tmp_path):
    body = _payload([
        _peer("bad-pubkey", "not-a-real-key", ["10.98.0.11/32"]),
        _peer("bad-ip", PK1, ["0.0.0.0/0"]),
        _peer("good", PK2, ["10.98.0.12/32"]),
        _peer("empty-ips", PK3, []),
        "not-a-dict",                                       # outright junk
    ])
    sync = _new_sync(_http_ok(body), _Runner(), tmp_path=str(tmp_path))
    peers, skipped, err = sync._fetch_desired()
    assert err is None
    assert {p.public_key for p in peers} == {PK2}
    # Reasons must be human-readable for the operator inspecting logs.
    joined = ";".join(skipped)
    assert "invalid-pubkey" in joined
    assert "invalid-allowed-ip" in joined
    assert "no-allowed-ips" in joined


def test_fetch_handles_404_as_inert_not_error(tmp_path):
    sync = _new_sync(_http_status(404), _Runner(), tmp_path=str(tmp_path))
    peers, skipped, err = sync._fetch_desired()
    assert peers == set() and skipped == []
    assert err and "404" in err


def test_fetch_handles_network_error_without_raising(tmp_path):
    def _boom(*_a, **_k):
        import requests as _rq
        raise _rq.ConnectionError("panel unreachable")
    sync = _new_sync(_boom, _Runner(), tmp_path=str(tmp_path))
    peers, skipped, err = sync._fetch_desired()
    assert peers == set() and err and "panel unreachable" in err


# ── 3. Reconcile: idempotency, add, remove (managed only) ─────────────


def test_reconcile_adds_missing_peer(tmp_path):
    runner = _Runner()                                      # actual = {} initially
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.error is None
    assert res.mode == "apply"
    assert res.added == [PK1]
    assert res.removed == []
    # `wg set wg-data peer PK1 allowed-ips 10.98.0.11/32` was issued.
    assert any(
        "set" in c and PK1 in c and "10.98.0.11/32" in c
        for c in runner.calls
    ), runner.calls
    # And we persisted PK1 as managed.
    with open(_state_file(str(tmp_path)), encoding="utf-8") as f:
        assert PK1 in json.load(f)["managed_pubkeys"]


def test_reconcile_is_idempotent_when_in_sync(tmp_path):
    runner = _Runner()
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    # First pass: applies the add.
    first = sync.reconcile()
    assert first.added == [PK1] and first.mode == "apply"
    set_calls_after_first = sum("set" in c for c in runner.calls)

    # Second pass: identical desired + state → ZERO new `wg set` calls.
    second = sync.reconcile()
    assert second.added == [] and second.removed == []
    set_calls_after_second = sum("set" in c for c in runner.calls)
    assert set_calls_after_second == set_calls_after_first, (
        "reconcile must be idempotent — no `wg set` on a no-change pass"
    )


def test_reconcile_removes_stale_managed_peer(tmp_path):
    # Two peers actually on the interface; we (proxy) manage BOTH; the
    # panel now only wants PK1 → PK2 must be removed.
    runner = _Runner()
    runner.set_actual_peers([PK1, PK2])
    # Pre-seed the managed state file: we own both PK1 and PK2.
    state_path = _state_file(str(tmp_path))
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"managed_pubkeys": [PK1, PK2]}, f)

    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.removed == [PK2], res
    assert res.added == []
    # The exact remove command was issued.
    remove_call = next((c for c in runner.calls if "remove" in c and PK2 in c), None)
    assert remove_call is not None, runner.calls
    # State file no longer lists PK2.
    with open(state_path, encoding="utf-8") as f:
        assert PK2 not in json.load(f)["managed_pubkeys"]


def test_reconcile_never_touches_unmanaged_peers(tmp_path):
    """The operator added PK3 by hand (out-of-band). It's on the wire but
    NOT in our managed set. The panel only wants PK1. We must NOT remove
    PK3 — it's the operator's, not ours."""
    runner = _Runner()
    runner.set_actual_peers([PK1, PK3])                     # PK3 is operator's
    state_path = _state_file(str(tmp_path))
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"managed_pubkeys": [PK1]}, f)            # only PK1 ours

    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.added == [] and res.removed == [], res
    # No `wg set ... remove` for PK3.
    assert not any("remove" in c and PK3 in c for c in runner.calls), runner.calls


# ── 4. Safe-by-default: unprivileged → dry-run, never crash ───────────


def test_reconcile_falls_back_to_dry_run_on_set_permission_denied(tmp_path):
    runner = _Runner()
    runner.make_set_fail(rc=126, err="Operation not permitted")
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    # Add was attempted (so the recommendation logs once), then degraded:
    assert res.mode == "dry-run"
    assert res.added == [PK1], res                          # logged as would-do
    assert res.error is None                                # no crash
    # And the managed state was persisted anyway — the next pass with
    # privilege will not see this as a "new" peer endlessly.
    with open(_state_file(str(tmp_path)), encoding="utf-8") as f:
        assert PK1 in json.load(f)["managed_pubkeys"]


def test_reconcile_handles_wg_show_failure_as_advisory(tmp_path):
    """If we can't even READ the interface (wg show failed), we don't
    speculate about what's on the wire. Return mode=dry-run, error
    populated, NO `wg set` calls attempted."""
    runner = _Runner()
    runner.make_show_fail(rc=126, err="permission denied")
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.mode == "dry-run"
    assert "wg show" in (res.error or "")
    # Crucially: no `wg set` was attempted.
    assert not any("set" in c for c in runner.calls), runner.calls


def test_reconcile_handles_wg_not_installed(tmp_path):
    def _no_wg(_argv):
        return 127, "", "wg: not found"
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), _no_wg, tmp_path=str(tmp_path))
    res = sync.reconcile()
    assert res.mode == "dry-run"
    assert "not found" in (res.error or "")


def test_explicit_dry_run_mode_never_calls_wg_set(tmp_path):
    runner = _Runner()
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(
        _http_ok(body), runner, tmp_path=str(tmp_path), apply_mode="dry_run",
    )
    res = sync.reconcile()
    assert res.added == [PK1]
    assert res.mode == "dry-run"
    # No `wg set` was issued.
    assert not any("set" in c for c in runner.calls), runner.calls


# ── 5. Catch-all + disabled paths ─────────────────────────────────────


def test_reconcile_safe_returns_result_on_normal_path(tmp_path):
    runner = _Runner()
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    out = sync.reconcile_safe()
    assert out is not None and out.added == [PK1]


def test_reconcile_safe_swallows_unexpected_exception(tmp_path):
    runner = _Runner()
    body = _payload([_peer("chr-vpn-1", PK1, ["10.98.0.11/32"])])
    sync = _new_sync(_http_ok(body), runner, tmp_path=str(tmp_path))
    # Sabotage the inner reconcile to raise — reconcile_safe must NOT.
    def _boom():
        raise RuntimeError("simulated crash")
    sync.reconcile = _boom                                  # type: ignore[assignment]
    assert sync.reconcile_safe() is None                    # no exception escapes


def test_disabled_instance_is_a_noop(tmp_path):
    runner = _Runner()
    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-secret",
        state_path=_state_file(str(tmp_path)),
        enabled=False, runner=runner, http_get=_http_ok(_payload([])),
    )
    res = sync.reconcile()
    assert res.mode == "disabled"
    # No HTTP, no subprocess.
    assert runner.calls == []


# ── 6. Endpoint URL respects the contract ─────────────────────────────


def test_endpoint_is_under_api_proxy(tmp_path):
    sync = _new_sync(_http_ok(_payload([])), _Runner(), tmp_path=str(tmp_path))
    assert sync._url.endswith("/api/proxy/wg-peers"), sync._url
