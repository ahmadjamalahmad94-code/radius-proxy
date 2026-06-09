"""Unit tests for placement_hook.py (CHR Fleet Phase 4 — proxy placement hook).

Covers:
  1. Feedback report (§2 write) builds the contract payload and posts it.
  2. Report failure is swallowed (returns False, never raises).
  3. report_from_accounting only fires on Accounting-Start.
  4. Decision read path: panel answers → source="panel".
  5. Decision fallback when panel unreachable → keep current node, log-only.
  6. Decision fallback to local candidates when no current node.
  7. Decision cache: second call within TTL does not hit HTTP.
  8. Read path NEVER enforces (never posts to the report endpoint).
  9. Disabled decision probe is a no-op.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import radius_packet as rp
import placement_hook as ph


def _hook(**kw):
    defaults = dict(
        report_endpoint="https://panel.example/api/proxy/placement",
        decision_endpoint="https://panel.example/api/proxy/placement-decision",
        shared_secret="proxy-secret",
        proxy_id="proxy-01",
        node_resolver=lambda ip: {"203.0.113.11": "chr-exit-01"}.get(ip),
        local_candidates_provider=lambda: ["chr-exit-09"],
        decision_cache_ttl=30,
    )
    defaults.update(kw)
    return ph.PlacementHook(**defaults)


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"ok": True}

    def json(self):
        return self._body


def _acct_start(sid="s1", user="bob@client5"):
    attrs = [
        (ph._ATTR_ACCT_STATUS_TYPE, struct.pack("!I", ph._ACCT_START)),
        (ph._ATTR_ACCT_SESSION_ID, sid.encode()),
        (rp.ATTR_USER_NAME, user.encode()),
    ]
    return rp.parse(rp.build(rp.CODE_ACCOUNTING_REQUEST, 7, b"\x00" * 16, attrs))


# ── 1. feedback report payload ────────────────────────────────────────
def test_report_builds_contract_payload():
    hook = _hook()
    with mock.patch.object(ph.requests, "post",
                           return_value=_Resp(200, {"ok": True})) as post:
        ok = hook.report(session_id="a1", realm="client5", node="chr-exit-02",
                         username="bob@client5")
    assert ok is True
    body = post.call_args.kwargs["json"]
    assert body["proxy_id"] == "proxy-01"
    assert body["reported_at"].endswith("Z")
    assert len(body["placements"]) == 1
    pl = body["placements"][0]
    assert pl["session_id"] == "a1"
    assert pl["realm"] == "client5"
    assert pl["node"] == "chr-exit-02"
    assert pl["reason"] == "new"
    assert pl["result"] == "applied"
    # X-Proxy-Token present
    assert "X-Proxy-Token" in post.call_args.kwargs["headers"]


# ── 2. report failure swallowed ───────────────────────────────────────
def test_report_swallows_failure():
    hook = _hook()
    with mock.patch.object(ph.requests, "post",
                           side_effect=ph.requests.ConnectionError("down")):
        assert hook.report(session_id="a1", realm="r", node="n") is False


# ── 3. report_from_accounting only on Start ───────────────────────────
def test_report_from_accounting_only_start():
    hook = _hook()
    with mock.patch.object(hook, "report", return_value=True) as rep:
        assert hook.report_from_accounting(_acct_start("s1"), "203.0.113.11") is True
    rep.assert_called_once()
    assert rep.call_args.kwargs["node"] == "chr-exit-01"   # resolved
    assert rep.call_args.kwargs["realm"] == "client5"

    # a Stop packet must NOT be reported as a placement
    stop = rp.parse(rp.build(rp.CODE_ACCOUNTING_REQUEST, 8, b"\x00" * 16, [
        (ph._ATTR_ACCT_STATUS_TYPE, struct.pack("!I", ph._ACCT_STOP)),
        (ph._ATTR_ACCT_SESSION_ID, b"s1"),
    ]))
    with mock.patch.object(hook, "report") as rep2:
        assert hook.report_from_accounting(stop, "203.0.113.11") is False
    rep2.assert_not_called()


# ── 4. decision read path — panel answers ─────────────────────────────
def test_resolve_decision_from_panel():
    hook = _hook()
    body = {"ok": True, "decision": "chr-exit-05", "top_n": ["chr-exit-05", "chr-exit-02"]}
    with mock.patch.object(ph.requests, "get", return_value=_Resp(200, body)) as get:
        dec = hook.resolve_decision("client5", current_node="chr-exit-01", now=1000.0)
    assert dec.source == "panel"
    assert dec.intended_node == "chr-exit-05"
    assert dec.panel_reachable is True
    assert dec.candidates == ["chr-exit-05", "chr-exit-02"]
    assert get.call_args.kwargs["params"]["realm"] == "client5"


# ── 5. fallback: panel unreachable → keep current ─────────────────────
def test_resolve_decision_fallback_current_node():
    hook = _hook()
    with mock.patch.object(ph.requests, "get",
                           side_effect=ph.requests.ConnectionError("down")):
        dec = hook.resolve_decision("client5", current_node="chr-exit-01", now=1000.0)
    assert dec.panel_reachable is False
    assert dec.source == "fallback_current"
    assert dec.intended_node == "chr-exit-01"          # safe: stay put


# ── 6. fallback to local candidates ───────────────────────────────────
def test_resolve_decision_fallback_local_candidates():
    hook = _hook(local_candidates_provider=lambda: ["chr-exit-09", "chr-exit-08"])
    with mock.patch.object(ph.requests, "get",
                           side_effect=ph.requests.Timeout("t")):
        dec = hook.resolve_decision("client5", now=1000.0)   # no current_node
    assert dec.source == "fallback_local"
    assert dec.intended_node == "chr-exit-09"


def test_resolve_decision_no_candidates():
    hook = _hook(local_candidates_provider=lambda: [])
    with mock.patch.object(ph.requests, "get",
                           side_effect=ph.requests.ConnectionError("down")):
        dec = hook.resolve_decision("client5", now=1000.0)
    assert dec.source == "none"
    assert dec.intended_node is None


# ── 7. decision cache within TTL ──────────────────────────────────────
def test_resolve_decision_cache():
    hook = _hook(decision_cache_ttl=30)
    body = {"ok": True, "decision": "chr-exit-05", "top_n": ["chr-exit-05"]}
    with mock.patch.object(ph.requests, "get", return_value=_Resp(200, body)) as get:
        hook.resolve_decision("client5", now=1000.0)
        hook.resolve_decision("client5", now=1010.0)        # within TTL → cached
    assert get.call_count == 1
    with mock.patch.object(ph.requests, "get", return_value=_Resp(200, body)) as get2:
        hook.resolve_decision("client5", now=1031.0)        # TTL expired → refetch
    assert get2.call_count == 1


# ── 8. read path never enforces ───────────────────────────────────────
def test_resolve_decision_never_posts():
    hook = _hook()
    with mock.patch.object(ph.requests, "get",
                           return_value=_Resp(200, {"ok": True, "decision": "n"})), \
         mock.patch.object(ph.requests, "post") as post:
        hook.resolve_decision("client5", current_node="chr-exit-01", now=1.0)
    post.assert_not_called()           # NO disconnect / report / enforcement


# ── 9. disabled decision probe ────────────────────────────────────────
def test_disabled_decision_probe_noop():
    hook = _hook(enabled_decision=False)
    with mock.patch.object(ph.requests, "get") as get:
        dec = hook.resolve_decision("client5", current_node="x", now=1.0)
    get.assert_not_called()
    assert dec.source == "none"
