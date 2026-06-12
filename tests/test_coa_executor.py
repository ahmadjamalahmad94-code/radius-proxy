"""Tests for the panel-queued CoA / Disconnect executor.

The contract (panel-authoritative, frozen 2026-06-12):

  Pull — ``GET /api/proxy/routing-table`` → new top-level array:
    "pending_coa": [
      { "id": "<uuid>", "realm": "<realm>", "action": "disconnect",
        "target_node_id": <int|null>, "reason": "panel:chr-move" }
    ]

  Push — ``POST /api/proxy/coa-result`` (X-Proxy-Token, same scheme as
    the routing-table fetch) with
    { "id": "<uuid>",
      "status": "done" | "failed",
      "detail": "<free-form>",
      "coa_code": <int|null>        # 41 = Disconnect-ACK, 42 = NAK
    }

These tests pin:
  * pending_coa entry → REAL RFC 5176 Disconnect-Request packet on the
    wire to the right CHR:3799, signed with the panel-canonical
    chr_shared_secret read PER PACKET from the routing-table.
  * ACK path: status "done", coa_code 41, POSTed with X-Proxy-Token.
  * NAK path: status "failed", coa_code 42.
  * Timeout path: status "failed", coa_code null, detail mentions
    "timeout".
  * Dedup: the same id seen twice in pending_coa yields ONE packet on
    the wire and ONE POST.
  * Unreachable CHR: no exception escapes — failed result reported.
  * No pending_coa: a clean no-op.
  * Missing realm-targets: status "done" with detail
    "no_active_sessions_for_realm" so the panel cleanly dequeues.
  * Result-POST URL stays under /api/proxy/.
  * The CHR shared secret is never logged.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import pytest

import coa as coamod
import coa_executor as coaex
import radius_packet as rp
import routing_table as rtmod
from tests.test_coa import MockCoaServer, SECRET as MOCK_SECRET


# ── helpers ───────────────────────────────────────────────────────────


REALM = "client5"
USER = f"bob@{REALM}"
SID = "8f2c01"
CHR_IP = "127.0.0.1"      # the MockCoaServer binds here


def _routing_with_secret(tmp_path: str, secret: str = MOCK_SECRET) -> rtmod.RoutingTable:
    """Build a RoutingTable that already has the panel-canonical CHR
    secret installed (skipping the routing-table HTTP path for speed)."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=os.path.join(tmp_path, "chr-secret.json"),
    )
    # Adopt directly so chr_secret() returns the value MockCoaServer uses.
    rt._adopt_chr_secret(secret)
    return rt


def _seed_pending(rt: rtmod.RoutingTable, entries: list[dict]) -> None:
    """Drop a list straight into the in-memory pending_coa snapshot —
    same shape the panel publishes on /api/proxy/routing-table."""
    rt._pending_coa = list(entries)


def _make_executor(
    tmp_path: str,
    *,
    targets,
    routing,
    coa_port: int,
    posts: list[dict],
    post_status: int = 200,
):
    """Build a CoaExecutor wired to a recording fake panel POST."""

    def _http_post(url, json=None, headers=None, timeout=None):
        posts.append({"url": url, "json": json, "headers": headers})

        class _R:
            status_code = post_status

        return _R()

    return coaex.CoaExecutor(
        routing=routing,
        targets_provider=lambda realm, _node_id: list(targets.get(realm, [])),
        result_endpoint="https://panel.example/api/proxy/coa-result",
        shared_secret="proxy-token",
        coa_port=coa_port,
        coa_timeout=1.0,
        coa_max_retries=0,
        coa_backoff_base=0.05,
        result_timeout=2.0,
        state_path=os.path.join(tmp_path, "coa-executed.json"),
        http_post=_http_post,
    )


def _entry(cid: str, realm: str = REALM, action: str = "disconnect",
           target_node_id=None):
    return {
        "id": cid, "realm": realm, "action": action,
        "target_node_id": target_node_id, "reason": "panel:chr-move",
    }


# ── 1. ACK path: real wire, signed packet, done/41 ───────────────────


def test_pending_coa_yields_real_disconnect_packet_and_done_status(tmp_path, caplog):
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-A")])

    with MockCoaServer("ack") as srv:
        posts: list[dict] = []
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        with caplog.at_level("INFO"):
            results = ex.tick_safe()

        # Exactly one Disconnect-Request hit the mock CHR.
        assert len(srv.requests) == 1
        pkt = srv.requests[0]
        assert pkt.code == coamod.CODE_DISCONNECT_REQUEST       # 40
        # Session-identifying attrs (RFC 5176 §3 / doc 04 §4.4.3).
        assert pkt.get_attr(rp.ATTR_USER_NAME) == USER.encode()
        assert pkt.get_attr(rp.ATTR_ACCT_SESSION_ID) == SID.encode()
        assert pkt.get_attr(rp.ATTR_NAS_IP_ADDRESS) == socket.inet_aton(CHR_IP)
        # Request-Authenticator was constructed with the panel-canonical
        # chr_shared_secret read PER PACKET via routing.chr_secret().
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in pkt.attributes
        )
        expected_auth = rp.accounting_request_authenticator(
            pkt.code, pkt.identifier, rp.HEADER_SIZE + len(attrs_bytes),
            attrs_bytes, MOCK_SECRET,
        )
        assert pkt.authenticator == expected_auth

    # Outcome the executor returned to the loop AND POSTed to the panel.
    assert results == [{
        "id": "uid-A", "status": "done",
        "detail": f"acked_by_chr={CHR_IP}",
        "coa_code": coamod.CODE_DISCONNECT_ACK,                  # 41
    }]
    # POST to the panel: shape, URL, X-Proxy-Token.
    assert len(posts) == 1
    post = posts[0]
    assert post["url"].endswith("/api/proxy/coa-result")
    assert post["headers"].get("X-Proxy-Token", "").count(":") == 2
    assert post["json"] == results[0]
    # And: the secret is NOT in any log line.
    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert MOCK_SECRET not in joined


# ── 2. NAK and timeout paths ─────────────────────────────────────────


def test_nak_yields_failed_with_coa_code_42(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-NAK")])
    with MockCoaServer("nak") as srv:
        posts: list[dict] = []
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results = ex.tick_safe()
    assert results[0]["status"] == "failed"
    assert results[0]["coa_code"] == coamod.CODE_DISCONNECT_NAK  # 42
    assert "nak" in results[0]["detail"]
    assert posts[0]["json"] == results[0]


def test_timeout_yields_failed_with_no_code(tmp_path):
    """Silent server — the sender times out, the executor reports
    failed with detail mentioning timeout."""
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-TO")])
    with MockCoaServer("silent") as srv:
        posts: list[dict] = []
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results = ex.tick_safe()
    assert results[0]["status"] == "failed"
    assert results[0]["coa_code"] is None
    assert "timeout" in results[0]["detail"]


# ── 3. Dedup ─────────────────────────────────────────────────────────


def test_same_id_seen_twice_fires_only_one_packet(tmp_path):
    """If the panel re-publishes the same id (before its own dequeue
    propagates, or across a proxy restart), the executor must NOT
    re-fire the disconnect — exactly one packet on the wire, exactly
    one POST."""
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-DUP"), _entry("uid-DUP")])
    with MockCoaServer("ack") as srv:
        posts: list[dict] = []
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        first = ex.tick_safe()

        # Second tick — same id in the panel's queue. ZERO new packets.
        _seed_pending(rt, [_entry("uid-DUP")])
        second = ex.tick_safe()

    assert len(srv.requests) == 1                                # only one wire send
    assert len(first) == 1 and first[0]["id"] == "uid-DUP"
    assert second == []                                          # nothing this tick
    assert len(posts) == 1                                       # only one POST
    # And the executed-id was persisted (survives a fresh executor).
    ex2 = _make_executor(
        str(tmp_path),
        targets={REALM: [(CHR_IP, USER, SID)]},
        routing=rt, coa_port=srv.port, posts=posts,
    )
    assert ex2.already_executed("uid-DUP")


def test_dedup_survives_restart_via_state_file(tmp_path):
    """Persist + reload: a fresh executor pointed at the same state
    file must NOT re-fire ids that the previous instance handled."""
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-A")])
    with MockCoaServer("ack") as srv:
        posts: list[dict] = []
        ex1 = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        ex1.tick_safe()
        assert len(srv.requests) == 1

        # Restart. Same panel queue. Same state path.
        ex2 = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results2 = ex2.tick_safe()

    assert results2 == []                                        # already executed
    assert len(srv.requests) == 1                                # no extra wire send


# ── 4. Unreachable CHR — failed, NOT crash ───────────────────────────


def test_unreachable_chr_reported_as_failed_not_crash(tmp_path):
    """Target the loopback port 1 — there is no server. The sender
    times out (or refused); the executor must report failed without
    raising, and the next tick keeps running cleanly."""
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-DOWN")])

    posts: list[dict] = []
    ex = _make_executor(
        str(tmp_path),
        targets={REALM: [(CHR_IP, USER, SID)]},
        routing=rt, coa_port=1, posts=posts,                     # nothing listens
    )
    results = ex.tick_safe()
    assert len(results) == 1
    assert results[0]["status"] == "failed"
    assert "uid-DOWN" == results[0]["id"]
    assert posts[0]["json"]["status"] == "failed"


# ── 5. No pending_coa → clean no-op ──────────────────────────────────


def test_no_pending_coa_is_a_clean_noop(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    # No _seed_pending() call — empty list.
    posts: list[dict] = []
    with MockCoaServer("ack") as srv:
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results = ex.tick_safe()
        assert results == []
        assert posts == []
        assert srv.requests == []


# ── 6. Missing realm-targets → done/no_active_sessions ───────────────


def test_no_targets_yields_done_with_no_active_sessions(tmp_path):
    """If the panel queues a Disconnect for a realm with no live
    session here, the intent is already satisfied — report done so
    the panel cleanly dequeues."""
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-X")])
    posts: list[dict] = []
    with MockCoaServer("ack") as srv:
        ex = _make_executor(
            str(tmp_path),
            targets={},                                            # no live sessions
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results = ex.tick_safe()
        assert srv.requests == []                                  # NO wire send
    assert results == [{
        "id": "uid-X", "status": "done",
        "detail": "no_active_sessions_for_realm",
        "coa_code": None,
    }]
    assert posts[0]["json"] == results[0]


# ── 7. Malformed entries — never crash ───────────────────────────────


def test_malformed_entries_are_dropped_during_refresh_not_during_tick(tmp_path):
    """Refresh-side hardening: pending_coa entries without an id (the
    proxy's primary dedup key) are silently dropped at parse time."""
    rt = _routing_with_secret(str(tmp_path))
    # Simulate a malformed refresh response by going through the real
    # refresh path with a payload that mixes good + bad entries.
    body = {
        "ok": True,
        "routes": [],
        "chr_nodes": [],
        "pending_coa": [
            {"id": "good-uid", "realm": REALM, "action": "disconnect"},
            "not-a-dict",                                          # junk
            {"realm": REALM, "action": "disconnect"},              # no id
            {"id": "", "realm": REALM, "action": "disconnect"},    # blank id
        ],
    }

    class _Resp:
        status_code = 200
        @staticmethod
        def raise_for_status():
            pass
        @staticmethod
        def json():
            return body

    with mock.patch.object(rtmod.requests, "get", return_value=_Resp()):
        assert rt.refresh() is True
    assert [e.get("id") for e in rt.pending_coa()] == ["good-uid"]


def test_unsupported_action_yields_failed(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-CoA", action="change_authorization")])
    posts: list[dict] = []
    with MockCoaServer("ack") as srv:
        ex = _make_executor(
            str(tmp_path),
            targets={REALM: [(CHR_IP, USER, SID)]},
            routing=rt, coa_port=srv.port, posts=posts,
        )
        results = ex.tick_safe()
        assert srv.requests == []                                  # no wire send
    assert results[0]["status"] == "failed"
    assert "unsupported_action" in results[0]["detail"]


# ── 8. Result URL stays under /api/proxy/ (license-path guard) ───────


def test_result_endpoint_is_under_api_proxy(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    ex = coaex.CoaExecutor(
        routing=rt,
        targets_provider=lambda *_a: [],
        result_endpoint="https://panel.example/api/proxy/coa-result",
        shared_secret="t",
        state_path=os.path.join(str(tmp_path), "coa-executed.json"),
    )
    assert ex._result_endpoint.endswith("/api/proxy/coa-result")
    assert "/api/integration" not in ex._result_endpoint
    assert "/api/license" not in ex._result_endpoint


# ── 9. Disabled executor — total no-op ───────────────────────────────


def test_disabled_executor_does_nothing(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-Z")])
    posts: list[dict] = []
    with MockCoaServer("ack") as srv:
        ex = coaex.CoaExecutor(
            routing=rt,
            targets_provider=lambda *_a: [(CHR_IP, USER, SID)],
            result_endpoint="https://panel.example/api/proxy/coa-result",
            shared_secret="t",
            coa_port=srv.port,
            state_path=os.path.join(str(tmp_path), "coa-executed.json"),
            http_post=lambda *a, **k: posts.append({"a": a, "k": k}) or type("R", (), {"status_code": 200})(),
            enabled=False,
        )
        assert ex.tick_safe() == []
    assert srv.requests == []
    assert posts == []


# ── 10. State-file bounding (FIFO trim) ──────────────────────────────


def test_executed_id_state_is_bounded_fifo(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    posts: list[dict] = []
    with MockCoaServer("ack") as srv:
        ex = coaex.CoaExecutor(
            routing=rt,
            targets_provider=lambda *_a: [(CHR_IP, USER, SID)],
            result_endpoint="https://panel.example/api/proxy/coa-result",
            shared_secret="t",
            coa_port=srv.port,
            coa_timeout=1.0, coa_max_retries=0, coa_backoff_base=0.01,
            state_path=os.path.join(str(tmp_path), "coa-executed.json"),
            max_executed_ids=4,                                    # tiny bound
            http_post=lambda *a, **k: posts.append({}) or type("R", (), {"status_code": 200})(),
        )
        for i in range(7):
            _seed_pending(rt, [_entry(f"uid-{i}")])
            ex.tick_safe()
        # Only the last 4 ids should be tracked; the first three should
        # have been evicted from the executed set + the on-disk state.
        with open(ex._state_path, encoding="utf-8") as f:
            stored = json.load(f)["ids"]
        assert stored == ["uid-3", "uid-4", "uid-5", "uid-6"]
        # Sanity: an early id re-sent NOW would re-fire (it was evicted).
        srv_calls_before = len(srv.requests)
        _seed_pending(rt, [_entry("uid-0")])
        ex.tick_safe()
        assert len(srv.requests) == srv_calls_before + 1


# ── 11. POST failure must not crash the tick ─────────────────────────


def test_post_failure_does_not_crash_tick(tmp_path):
    rt = _routing_with_secret(str(tmp_path))
    _seed_pending(rt, [_entry("uid-POST-FAIL")])

    import requests as _rq
    def _exploding_post(*_a, **_k):
        raise _rq.ConnectionError("panel unreachable")

    with MockCoaServer("ack") as srv:
        ex = coaex.CoaExecutor(
            routing=rt,
            targets_provider=lambda *_a: [(CHR_IP, USER, SID)],
            result_endpoint="https://panel.example/api/proxy/coa-result",
            shared_secret="t",
            coa_port=srv.port,
            coa_timeout=1.0, coa_max_retries=0, coa_backoff_base=0.01,
            state_path=os.path.join(str(tmp_path), "coa-executed.json"),
            http_post=_exploding_post,
        )
        results = ex.tick_safe()                                   # no exception escapes
        assert len(srv.requests) == 1                              # Disconnect still fired
    assert results[0]["status"] == "done"
    # And the id was still marked executed (so we don't double-fire next tick).
    assert ex.already_executed("uid-POST-FAIL")
