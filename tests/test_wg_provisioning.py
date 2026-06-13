"""Tests for the chr-vpn-2 onboarding-incident fixes.

The incident: a new CHR (chr-vpn-2, wg-data 10.98.0.12,
pubkey ``uo9/RhCiRqumTOq0ensOOl2Os5rAfz4h0hxtkGCF9zQ=``) failed to
hand-shake with the proxy. Two root causes, both fixed here:

  1. The CHR script the panel rendered carried a STALE proxy wg-data
     pubkey (the panel's stored copy had drifted from the live key on
     the proxy box). The proxy now publishes its LIVE
     ``wg show wg-data public-key`` in every heartbeat as
     ``proxy_wg_data_pubkey`` so the panel can render every CHR
     script with the current key.

  2. The proxy's wg-peer reconciler ADDED the peer to runtime kernel
     state but never PERSISTED it — a reboot would drop it. The
     reconciler now runs ``wg-quick save <iface>`` after a successful
     add/remove so the peer set survives a reboot.

These tests pin:
  * heartbeat POST body carries ``proxy_wg_data_pubkey`` with the
    value the provider returns;
  * empty result when the helper fails (panel falls back to stored);
  * provider exception is swallowed (heartbeat never crashes);
  * persist_fn is called exactly once after a successful add/remove
    (not when nothing changed, not in dry-run, not when persist_fn is
    None);
  * persist_fn failures are swallowed — peers stay live in kernel;
  * the LIVE pubkey value is read via ``wg show <iface> public-key``;
  * cached provider returns the same value within the TTL window;
  * malformed wg output is rejected (empty string).
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import routing_table as rtmod
import wg_peer_sync as wps
import wg_provisioning as wgp


# ── 1. Live wg pubkey provider ────────────────────────────────────────


VALID_PUBKEY = "uo9/RhCiRqumTOq0ensOOl2Os5rAfz4h0hxtkGCF9zQ="


def test_read_iface_pubkey_returns_trimmed_value_on_success():
    def _runner(argv):
        assert argv == ["wg", "show", "wg-data", "public-key"]
        return 0, VALID_PUBKEY + "\n", ""
    assert wgp.read_iface_pubkey("wg-data", runner=_runner) == VALID_PUBKEY


def test_read_iface_pubkey_returns_empty_on_nonzero_exit():
    def _runner(_argv):
        return 1, "", "Unable to access interface: Operation not permitted"
    assert wgp.read_iface_pubkey("wg-data", runner=_runner) == ""


def test_read_iface_pubkey_returns_empty_on_malformed_output():
    def _runner(_argv):
        return 0, "this-is-not-a-44-char-base64-pubkey", ""
    assert wgp.read_iface_pubkey("wg-data", runner=_runner) == ""


def test_caching_pubkey_provider_caches_within_ttl():
    """Heartbeat fires every 30s; key changes ~never. The cache
    avoids fork-exec'ing every cycle."""
    calls = {"n": 0}

    def _runner(_argv):
        calls["n"] += 1
        return 0, VALID_PUBKEY + "\n", ""

    cache = wgp.CachingPubkeyProvider("wg-data", ttl_seconds=60, runner=_runner)
    assert cache() == VALID_PUBKEY
    assert cache() == VALID_PUBKEY
    assert cache() == VALID_PUBKEY
    assert calls["n"] == 1                          # subsequent reads hit cache


def test_caching_provider_does_not_cache_empty():
    """A transient failure must not pin us to '' — we want the
    NEXT heartbeat to retry."""
    state = {"fail": True}

    def _runner(_argv):
        if state["fail"]:
            return 1, "", "transient"
        return 0, VALID_PUBKEY + "\n", ""

    cache = wgp.CachingPubkeyProvider("wg-data", ttl_seconds=60, runner=_runner)
    assert cache() == ""
    state["fail"] = False
    assert cache() == VALID_PUBKEY                 # retried, picked it up


# ── 2. Heartbeat carries proxy_wg_data_pubkey ────────────────────────


def _routing(provider=None):
    return rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        proxy_wg_data_pubkey_provider=provider,
    )


def _capturing_post():
    posts: list[dict] = []

    class _OkResp:
        ok = True
        status_code = 200

    def _post(url, json=None, headers=None, timeout=None):
        posts.append({"url": url, "json": json, "headers": headers})
        return _OkResp()

    return posts, _post


def test_heartbeat_includes_live_proxy_wg_data_pubkey():
    posts, _post = _capturing_post()
    rt = _routing(provider=lambda: VALID_PUBKEY)
    with mock.patch.object(rtmod.requests, "post", side_effect=_post):
        rt.heartbeat("proxy-01", uptime=12.3)
    assert posts and posts[0]["json"]["proxy_wg_data_pubkey"] == VALID_PUBKEY


def test_heartbeat_proxy_pubkey_empty_when_no_provider():
    """Backwards compat: if no provider is wired (e.g. dev / a test
    instance), the field is still present but empty — the panel sees
    'no signal' and keeps its stored copy."""
    posts, _post = _capturing_post()
    rt = _routing(provider=None)
    with mock.patch.object(rtmod.requests, "post", side_effect=_post):
        rt.heartbeat("proxy-01", uptime=1.0)
    assert posts[0]["json"]["proxy_wg_data_pubkey"] == ""


def test_heartbeat_proxy_pubkey_empty_when_provider_returns_empty():
    """Unprivileged proxy / iface absent → provider returns ''. The
    panel falls back to its stored Setting; the heartbeat itself is
    perfectly healthy."""
    posts, _post = _capturing_post()
    rt = _routing(provider=lambda: "")
    with mock.patch.object(rtmod.requests, "post", side_effect=_post):
        rt.heartbeat("proxy-01", uptime=1.0)
    assert posts[0]["json"]["proxy_wg_data_pubkey"] == ""


def test_heartbeat_swallows_provider_exception():
    """A bug in the provider must NEVER kill the heartbeat — the
    operator would see the proxy 'go down' on the panel for an
    unrelated reason."""
    posts, _post = _capturing_post()

    def _boom():
        raise RuntimeError("simulated bug")

    rt = _routing(provider=_boom)
    with mock.patch.object(rtmod.requests, "post", side_effect=_post):
        rt.heartbeat("proxy-01", uptime=1.0)        # must not raise
    assert posts and posts[0]["json"]["proxy_wg_data_pubkey"] == ""


# ── 3. wg_peer_sync calls persist_fn on actual changes ───────────────


PK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


class _Runner:
    """Same shape as the wg-data test runner — adds a peer to
    in-memory state on a `wg set ... peer ... allowed-ips ...`."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self._actual: list[str] = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        if "show" in argv:
            lines = ["PRIVKEY\tPUBKEY\t51821\toff"]
            for pk in self._actual:
                lines.append("\t".join([pk, "(none)", "(none)",
                                        "10.98.0.x/32", "0", "0", "0", "off"]))
            return 0, "\n".join(lines) + "\n", ""
        if "set" in argv:
            try:
                pk = argv[argv.index("peer") + 1]
            except (ValueError, IndexError):
                pk = ""
            if "remove" in argv:
                if pk in self._actual:
                    self._actual.remove(pk)
            elif pk and pk not in self._actual:
                self._actual.append(pk)
            return 0, "", ""
        return 0, "", ""


def _http_ok(body):
    class _R:
        status_code = 200

        def json(self):
            return body

    def _get(_url, headers=None, timeout=None):
        return _R()

    return _get


def _peer_payload(pubkey, ip):
    return {"ok": True, "peers": [{
        "name": "client", "public_key": pubkey,
        "allowed_ips": [f"{ip}/32"],
    }]}


def test_persist_fn_called_once_after_successful_add(tmp_path):
    runner = _Runner()
    persist_calls = {"n": 0}

    def _persist():
        persist_calls["n"] += 1
        return True

    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        state_path=os.path.join(str(tmp_path), "managed-peers.json"),
        runner=runner,
        http_get=_http_ok(_peer_payload(PK, "10.98.0.12")),
        persist_fn=_persist,
    )
    res = sync.reconcile()
    assert res.added == [PK] and res.mode == "apply"
    assert persist_calls["n"] == 1                  # persisted after add


def test_persist_fn_not_called_when_no_change(tmp_path):
    """Idempotent reconcile must NOT persist — `wg-quick save` is a
    real disk write; doing it every 60s when nothing changed wastes
    I/O and risks racing with operator edits to /etc/wireguard/."""
    runner = _Runner()
    persist_calls = {"n": 0}

    def _persist():
        persist_calls["n"] += 1
        return True

    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        state_path=os.path.join(str(tmp_path), "managed-peers.json"),
        runner=runner,
        http_get=_http_ok(_peer_payload(PK, "10.98.0.12")),
        persist_fn=_persist,
    )
    sync.reconcile()                                 # adds + persists
    sync.reconcile()                                 # no change → no persist
    sync.reconcile()                                 # still no change
    assert persist_calls["n"] == 1                  # ONCE total


def test_persist_fn_not_called_when_disabled(tmp_path):
    runner = _Runner()
    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        state_path=os.path.join(str(tmp_path), "managed-peers.json"),
        runner=runner,
        http_get=_http_ok(_peer_payload(PK, "10.98.0.12")),
        persist_fn=None,                            # explicit disable
    )
    res = sync.reconcile()
    assert res.added == [PK]                        # add still happened
    # No exception, no persist call. (Counter implicit: persist_fn=None.)


def test_persist_fn_not_called_in_dry_run(tmp_path):
    """Persisting in dry-run would clobber /etc/wireguard/<iface>.conf
    with zero peers (we never actually applied anything to runtime
    state). Skip the save in dry-run."""
    runner = _Runner()
    persist_calls = {"n": 0}

    def _persist():
        persist_calls["n"] += 1
        return True

    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        state_path=os.path.join(str(tmp_path), "managed-peers.json"),
        apply_mode="dry_run",                       # never call `wg set`
        runner=runner,
        http_get=_http_ok(_peer_payload(PK, "10.98.0.12")),
        persist_fn=_persist,
    )
    res = sync.reconcile()
    assert res.mode == "dry-run" and res.added == [PK]
    assert persist_calls["n"] == 0                  # NOT persisted


def test_persist_fn_failure_does_not_break_reconcile(tmp_path):
    """If `wg-quick save` fails (rare — sudoers misconfig, conf-file
    permission), we still want the peer LIVE in the kernel; the next
    reboot will lose it but a follow-up reconcile cycle re-adds it.
    Reconcile must succeed; reconcile_safe must not see an exception."""
    runner = _Runner()

    def _persist():
        return False                                # silently failed

    sync = wps.WgPeerSync(
        "https://panel.example", "proxy-token",
        state_path=os.path.join(str(tmp_path), "managed-peers.json"),
        runner=runner,
        http_get=_http_ok(_peer_payload(PK, "10.98.0.12")),
        persist_fn=_persist,
    )
    res = sync.reconcile_safe()
    assert res is not None
    assert res.added == [PK]


# ── 4. persist_iface helper around `wg-quick save` ───────────────────


def test_persist_iface_success():
    captured = {"argv": None}

    def _runner(argv):
        captured["argv"] = argv
        return 0, "", ""

    assert wgp.persist_iface("wg-data", runner=_runner) is True
    assert captured["argv"] == ["wg-quick", "save", "wg-data"]


def test_persist_iface_failure_returns_false_does_not_raise():
    def _runner(_argv):
        return 126, "", "permission denied"
    assert wgp.persist_iface("wg-data", runner=_runner) is False


def test_persist_iface_handles_missing_wg_quick():
    def _runner(_argv):
        return 127, "", "wg-quick: not found"
    assert wgp.persist_iface("wg-data", runner=_runner) is False
