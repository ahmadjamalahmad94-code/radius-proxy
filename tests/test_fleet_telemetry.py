"""Unit tests for telemetry.py (CHR Fleet Phase 4 — proxy telemetry emitter).

Covers:
  1. Payload shape matches the FROZEN contract (§1): node / sampled_at / metrics
     / agent_version, ISO-8601 Z timestamp, node-name resolution.
  2. active_sessions counting from Accounting Start/Stop.
  3. egress_gbps derived from octet deltas over the flush window.
  4. Retry/backoff: transient failures retried with exponential backoff.
  5. Failure is swallowed — flush never raises and returns False.
  6. Node-name fallback to IP when unresolved (still emits).
  7. Disabled emitter is a no-op.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import pytest

import radius_packet as rp
import telemetry as tel


# ── helpers ───────────────────────────────────────────────────────────
def _acct_packet(status: int, sid: str, in_oct: int = 0, out_oct: int = 0,
                 ident: int = 7) -> rp.RadiusPacket:
    attrs: list[tuple[int, bytes]] = [
        (tel._ATTR_ACCT_STATUS_TYPE, struct.pack("!I", status)),
        (tel._ATTR_ACCT_SESSION_ID, sid.encode()),
    ]
    if in_oct:
        attrs.append((tel._ATTR_ACCT_INPUT_OCTETS, struct.pack("!I", in_oct)))
    if out_oct:
        attrs.append((tel._ATTR_ACCT_OUTPUT_OCTETS, struct.pack("!I", out_oct)))
    raw = rp.build(rp.CODE_ACCOUNTING_REQUEST, ident, b"\x00" * 16, attrs)
    return rp.parse(raw)


def _emitter(**kw):
    defaults = dict(
        endpoint="https://panel.example/api/proxy/telemetry",
        shared_secret="proxy-secret",
        node_resolver=lambda ip: {"203.0.113.11": "chr-exit-01"}.get(ip),
        interval=30,
        max_retries=3,
        backoff_base=0.01,
    )
    defaults.update(kw)
    return tel.TelemetryEmitter(**defaults)


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"ok": True}

    def json(self):
        return self._body


# ── 1. payload shape vs contract ──────────────────────────────────────
def test_payload_matches_contract_shape():
    em = _emitter()
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "203.0.113.11")
    payloads = em.build_payloads()
    assert len(payloads) == 1
    p = payloads[0]
    assert set(p.keys()) == {"node", "sampled_at", "metrics", "agent_version"}
    assert p["node"] == "chr-exit-01"                 # resolved registry NAME
    assert p["sampled_at"].endswith("Z") and "T" in p["sampled_at"]
    assert p["agent_version"] == "1.0.0"
    assert p["metrics"]["active_sessions"] == 1
    assert "egress_gbps" in p["metrics"]


# ── 2. active_sessions counting ───────────────────────────────────────
def test_active_sessions_start_stop():
    em = _emitter()
    ip = "203.0.113.11"
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), ip)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s2"), ip)
    assert em.build_payloads()[0]["metrics"]["active_sessions"] == 2
    em.record_from_accounting(_acct_packet(tel._ACCT_STOP, "s1", out_oct=100), ip)
    assert em.build_payloads()[0]["metrics"]["active_sessions"] == 1


# ── 3. egress_gbps from octet deltas ──────────────────────────────────
def test_egress_gbps_from_octets():
    em = _emitter(interval=10)
    ip = "203.0.113.11"
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), ip)
    # 1 GB downloaded over a 10s window → 1e9 bytes *8 /10 /1e9 = 0.8 Gbps
    em.record_from_accounting(
        _acct_packet(tel._ACCT_INTERIM, "s1", out_oct=1_000_000_000), ip
    )
    gbps = em.build_payloads(interval=10)[0]["metrics"]["egress_gbps"]
    assert gbps == pytest.approx(0.8, rel=1e-6)


# ── 4. retry/backoff ──────────────────────────────────────────────────
def test_retry_then_success_with_backoff():
    em = _emitter(max_retries=3, backoff_base=0.5)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "203.0.113.11")
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise tel.requests.ConnectionError("boom")
        return _Resp(200, {"ok": True})

    with mock.patch.object(tel.requests, "post", side_effect=flaky), \
         mock.patch.object(tel.time, "sleep") as sleep:
        ok = em.flush()
    assert ok is True
    assert calls["n"] == 3
    # exponential backoff: base*2**0, base*2**1 between the 3 attempts
    assert [c.args[0] for c in sleep.call_args_list] == [0.5, 1.0]


# ── 5. failure swallowed ──────────────────────────────────────────────
def test_flush_swallows_failure_and_returns_false():
    em = _emitter(max_retries=2, backoff_base=0.0)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "203.0.113.11")
    with mock.patch.object(tel.requests, "post",
                           side_effect=tel.requests.ConnectionError("down")), \
         mock.patch.object(tel.time, "sleep"):
        ok = em.flush()                # must not raise
    assert ok is False


def test_4xx_not_retried():
    em = _emitter(max_retries=5, backoff_base=0.0)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "203.0.113.11")
    with mock.patch.object(tel.requests, "post",
                           return_value=_Resp(404, {"ok": False, "error": "unknown_node"})) as post, \
         mock.patch.object(tel.time, "sleep"):
        ok = em.flush()
    assert ok is False
    assert post.call_count == 1        # unknown_node won't fix on retry


# ── 6. node-name fallback to IP ───────────────────────────────────────
def test_unresolved_node_falls_back_to_ip():
    em = _emitter(node_resolver=lambda ip: None)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "198.51.100.9")
    assert em.build_payloads()[0]["node"] == "198.51.100.9"


# ── 7. disabled no-op ─────────────────────────────────────────────────
def test_disabled_emitter_is_noop():
    em = _emitter(enabled=False)
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), "203.0.113.11")
    assert em.build_payloads() == []
    with mock.patch.object(tel.requests, "post") as post:
        assert em.flush() is True
    post.assert_not_called()


def test_flush_marks_window_only_on_success():
    em = _emitter(interval=10)
    ip = "203.0.113.11"
    em.record_from_accounting(_acct_packet(tel._ACCT_START, "s1"), ip)
    em.record_from_accounting(
        _acct_packet(tel._ACCT_INTERIM, "s1", out_oct=1_000_000_000), ip)
    with mock.patch.object(tel.requests, "post", return_value=_Resp(200)):
        assert em.flush(interval=10) is True
    # after a successful flush the rate window resets → next egress 0
    assert em.build_payloads(interval=10)[0]["metrics"]["egress_gbps"] == 0.0
