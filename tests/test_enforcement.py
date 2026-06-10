"""Unit tests for enforcement.py (CHR Fleet Phase 7 — live apply engine).

Covers the required behavior matrix:
  1. SINGLE-SESSION: Acct-Start for a user already active on ANOTHER CHR →
     Disconnect sent to the OLD CHR (kill-old). Same-CHR reconnect → no kill.
  2. FORCED ON OUTAGE: node down → move enforced even for movable=false.
  3. OPT-IN: movable=false BLOCKS a cost/CPU rebalance move (skipped).
  4. HYSTERESIS: should_move cooldown prevents ping-pong (second move skipped).
  5. SAFETY GUARD: live-apply disabled → ADVISORY only (intended action computed
     + logged, NO CoA sent).
  6. REPORTING: outcome POSTed {proxy_id, node, user, action, result, reason,
     ts, ...} with X-Proxy-Token; §2 placement report for moves; failures
     swallowed + retried with backoff.
  7. RESILIENCE: malformed packets / CoA failures never raise.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import enforcement as enf
import radius_packet as rp
from coa import CoaResult
from placement_hook import PlacementDecision


# ── fakes ─────────────────────────────────────────────────────────────
class FakeCoa:
    def __init__(self, result: CoaResult | None = None):
        self.result = result or CoaResult(ok=True, code=41, attempts=1)
        self.calls: list[dict] = []

    def disconnect(self, **kw):
        self.calls.append(kw)
        return self.result


class FakeReporter:
    def __init__(self):
        self.outcomes: list[enf.EnforcementOutcome] = []

    def report(self, outcome, *, ts=None):
        self.outcomes.append(outcome)
        return True


class FakePlacement:
    """resolve_decision returns a configured intent; report records §2 calls."""

    def __init__(self, intended: str | None = None):
        self.intended = intended
        self.reports: list[dict] = []

    def resolve_decision(self, realm, *, session_id=None, current_node=None, now=None):
        return PlacementDecision(
            realm=realm, intended_node=self.intended,
            source="panel", panel_reachable=True,
        )

    def report(self, **kw):
        self.reports.append(kw)
        return True


def _acct(status: int, user: str, sid: str, framed: str = "") -> rp.RadiusPacket:
    attrs = [
        (1, user.encode()),                                   # User-Name
        (40, struct.pack("!I", status)),                      # Acct-Status-Type
        (44, sid.encode()),                                   # Acct-Session-Id
    ]
    if framed:
        attrs.append((8, bytes(int(x) for x in framed.split("."))))
    return rp.parse(rp.build(rp.CODE_ACCOUNTING_REQUEST, 9, b"\x00" * 16, attrs))


def _engine(
    *,
    live=True, coa=None, placement=None, reporter=None,
    healthy=None, movable=None, cooldown=120.0,
):
    return enf.EnforcementEngine(
        coa=coa if coa is not None else FakeCoa(),
        tracker=enf.SessionTracker(),
        reporter=reporter if reporter is not None else FakeReporter(),
        placement=placement,
        node_resolver=lambda ip: {"10.0.0.1": "chr-a", "10.0.0.2": "chr-b"}.get(ip),
        live_apply_provider=lambda: live,
        node_healthy_provider=healthy,
        movable_resolver=movable,
        move_cooldown=cooldown,
    )


# ── 1. single active session ──────────────────────────────────────────
def test_kill_old_on_reconnect_other_chr():
    coa = FakeCoa()
    eng = _engine(coa=coa)
    # Session up on CHR-A …
    out1 = eng.on_accounting(_acct(1, "bob@client5", "OLD", "10.77.0.42"), "10.0.0.1")
    assert out1.action == "none" and coa.calls == []
    # … then the SAME user starts on CHR-B → kill the OLD session on CHR-A.
    out2 = eng.on_accounting(_acct(1, "bob@client5", "NEW", "10.77.0.42"), "10.0.0.2")
    assert out2.action == "kill_old" and out2.result == "applied"
    assert out2.enforced is True and out2.coa_code == 41
    assert len(coa.calls) == 1
    call = coa.calls[0]
    assert call["chr_ip"] == "10.0.0.1"                       # the OLD CHR
    assert call["acct_session_id"] == "OLD"                   # the OLD session
    assert call["username"] == "bob@client5"
    # tracker now holds only the NEW session
    cur = eng._tracker.get("bob@client5")
    assert cur and cur.acct_session_id == "NEW" and cur.chr_ip == "10.0.0.2"


def test_no_kill_on_same_chr_reconnect():
    coa = FakeCoa()
    eng = _engine(coa=coa)
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    out = eng.on_accounting(_acct(1, "bob@client5", "S2"), "10.0.0.1")
    assert out.action == "none" and coa.calls == []


def test_acct_stop_untracks():
    eng = _engine()
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    eng.on_accounting(_acct(2, "bob@client5", "S1"), "10.0.0.1")
    assert eng._tracker.get("bob@client5") is None


# ── 2. forced on outage overrides movable=false ───────────────────────
def test_forced_move_on_outage_overrides_movable_false():
    coa = FakeCoa()
    eng = _engine(
        coa=coa,
        placement=FakePlacement(intended="chr-b"),
        healthy=lambda name: name != "chr-a",     # chr-a is DOWN
        movable=lambda u: False,                  # nobody opted in
    )
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")   # on chr-a
    outs = eng.evaluate_moves(now=1000.0)
    move = [o for o in outs if o.action == "move"][0]
    assert move.reason == "failover"
    assert move.result == "applied"               # FORCED despite movable=false
    assert len(coa.calls) == 1 and coa.calls[0]["chr_ip"] == "10.0.0.1"


def test_forced_move_applied_even_when_dead_chr_never_acks():
    # Old CHR is down → CoA times out; eviction still stands (doc 04 §4.4.4).
    coa = FakeCoa(CoaResult(ok=False, code=None, error="timeout", attempts=3))
    eng = _engine(coa=coa, healthy=lambda n: False, movable=lambda u: False)
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    outs = eng.evaluate_moves(now=1000.0)
    move = [o for o in outs if o.action == "move"][0]
    assert move.result == "applied" and "node down" in move.detail


# ── 3. movable=false blocks a rebalance move ──────────────────────────
def test_movable_false_blocks_rebalance():
    coa = FakeCoa()
    eng = _engine(
        coa=coa,
        placement=FakePlacement(intended="chr-b"),  # brain wants a move
        healthy=lambda name: True,                  # NO outage → rebalance path
        movable=lambda u: False,                    # not opted in
    )
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    outs = eng.evaluate_moves(now=1000.0)
    move = [o for o in outs if o.action == "move"][0]
    assert move.result == "skipped"
    assert "not movable" in move.detail
    assert coa.calls == []                          # nothing sent


def test_movable_true_allows_rebalance():
    coa = FakeCoa()
    eng = _engine(
        coa=coa,
        placement=FakePlacement(intended="chr-b"),
        healthy=lambda name: True,
        movable=lambda u: True,
    )
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    outs = eng.evaluate_moves(now=1000.0)
    move = [o for o in outs if o.action == "move"][0]
    assert move.reason == "rebalance" and move.result == "applied"
    assert len(coa.calls) == 1


def test_no_move_when_brain_agrees_with_current_node():
    coa = FakeCoa()
    eng = _engine(coa=coa, placement=FakePlacement(intended="chr-a"),
                  healthy=lambda n: True, movable=lambda u: True)
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")   # on chr-a
    outs = eng.evaluate_moves(now=1000.0)
    assert all(o.action == "none" for o in outs) and coa.calls == []


# ── 4. hysteresis / cooldown ──────────────────────────────────────────
def test_cooldown_prevents_ping_pong():
    coa = FakeCoa()
    eng = _engine(
        coa=coa, placement=FakePlacement(intended="chr-b"),
        healthy=lambda n: True, movable=lambda u: True, cooldown=120.0,
    )
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    first = eng.evaluate_moves(now=1000.0)
    assert [o for o in first if o.action == "move"][0].result == "applied"
    # User reconnects (lands back on chr-a within the cooldown window) …
    eng.on_accounting(_acct(1, "bob@client5", "S2"), "10.0.0.1")
    second = eng.evaluate_moves(now=1060.0)        # only 60s later
    move2 = [o for o in second if o.action == "move"][0]
    assert move2.result == "skipped" and "cooldown" in move2.detail
    assert len(coa.calls) == 1                     # no second disconnect
    # After the cooldown expires the move is allowed again.
    third = eng.evaluate_moves(now=1121.0)
    assert [o for o in third if o.action == "move"][0].result == "applied"


def test_should_move_gate():
    eng = _engine(cooldown=120.0)
    assert eng.should_move("u", now=100.0) is True
    eng._mark_moved("u", now=100.0)
    assert eng.should_move("u", now=150.0) is False
    assert eng.should_move("u", now=221.0) is True


# ── 5. live-apply safety guard ────────────────────────────────────────
def test_advisory_only_when_live_apply_disabled():
    coa = FakeCoa()
    rep = FakeReporter()
    eng = _engine(coa=coa, reporter=rep, live=False)
    eng.on_accounting(_acct(1, "bob@client5", "OLD"), "10.0.0.1")
    out = eng.on_accounting(_acct(1, "bob@client5", "NEW"), "10.0.0.2")
    # Intended action computed + logged, NOTHING sent.
    assert out.action == "kill_old"
    assert out.advisory is True and out.result == "advisory"
    assert out.enforced is False
    assert coa.calls == []                         # no CoA traffic at all


def test_live_apply_provider_failure_defaults_safe():
    def boom() -> bool:
        raise RuntimeError("panel gone")
    coa = FakeCoa()
    eng = enf.EnforcementEngine(
        coa=coa, tracker=enf.SessionTracker(), reporter=FakeReporter(),
        live_apply_provider=boom,
    )
    eng.on_accounting(_acct(1, "u@r", "A"), "10.0.0.1")
    out = eng.on_accounting(_acct(1, "u@r", "B"), "10.0.0.2")
    assert out.result == "advisory" and coa.calls == []


# ── 6. reporting ──────────────────────────────────────────────────────
def test_reporter_payload_shape_and_auth():
    rep = enf.EnforcementReporter(
        endpoint="https://panel.example/api/proxy/enforcement",
        shared_secret="proxy-secret", proxy_id="proxy-01",
        max_retries=0,
    )
    out = enf.EnforcementOutcome(
        action="kill_old", username="bob@client5", reason="manual",
        target_node="chr-a", intended_node="", enforced=True,
        result="applied", coa_code=41, detail="",
    )

    class _Resp:
        status_code = 200
        @staticmethod
        def json():
            return {"ok": True}

    with mock.patch.object(enf.requests, "post", return_value=_Resp()) as post:
        assert rep.report(out, ts=1733740800.0) is True
    body = post.call_args.kwargs["json"]
    assert body == {
        "proxy_id": "proxy-01", "node": "chr-a", "user": "bob@client5",
        "action": "kill_old", "result": "applied", "reason": "manual",
        "intended_node": "", "coa_code": 41, "detail": "",
        "ts": "2024-12-09T10:40:00Z",
    }
    assert "X-Proxy-Token" in post.call_args.kwargs["headers"]


def test_reporter_retries_with_backoff_and_swallows():
    rep = enf.EnforcementReporter(
        endpoint="https://panel.example/api/proxy/enforcement",
        shared_secret="s", proxy_id="p", max_retries=2, backoff_base=0.5,
    )
    out = enf.EnforcementOutcome(action="move", username="u")
    with mock.patch.object(enf.requests, "post",
                           side_effect=enf.requests.ConnectionError("down")) as post, \
         mock.patch.object(enf.time, "sleep") as sleep:
        assert rep.report(out) is False            # swallowed, no raise
    assert post.call_count == 3                    # 1 + 2 retries
    assert [c.args[0] for c in sleep.call_args_list] == [0.5, 1.0]


def test_move_also_reports_via_section2_placement():
    placement = FakePlacement(intended="chr-b")
    eng = _engine(placement=placement, healthy=lambda n: True,
                  movable=lambda u: True)
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    eng.evaluate_moves(now=1000.0)
    assert len(placement.reports) == 1
    sec2 = placement.reports[0]
    assert sec2["reason"] == "rebalance"
    assert sec2["result"] == "pending"             # realised after reconnect
    assert sec2["previous_node"] == "chr-a"
    assert sec2["node"] == "chr-b"


def test_kill_old_outcome_reported():
    rep = FakeReporter()
    eng = _engine(reporter=rep)
    eng.on_accounting(_acct(1, "bob@client5", "OLD"), "10.0.0.1")
    eng.on_accounting(_acct(1, "bob@client5", "NEW"), "10.0.0.2")
    assert len(rep.outcomes) == 1
    assert rep.outcomes[0].action == "kill_old"
    assert rep.outcomes[0].target_node == "chr-a"


# ── 7. resilience ─────────────────────────────────────────────────────
def test_malformed_accounting_never_raises():
    eng = _engine()
    bad = rp.parse(rp.build(rp.CODE_ACCOUNTING_REQUEST, 1, b"\x00" * 16, []))
    out = eng.on_accounting(bad, "10.0.0.1")       # no user/status attrs
    assert out.action == "none"


def test_coa_failure_on_rebalance_is_failed_not_crash():
    coa = FakeCoa(CoaResult(ok=False, code=42, error="nak", attempts=1))
    eng = _engine(coa=coa, placement=FakePlacement(intended="chr-b"),
                  healthy=lambda n: True, movable=lambda u: True)
    eng.on_accounting(_acct(1, "bob@client5", "S1"), "10.0.0.1")
    outs = eng.evaluate_moves(now=1000.0)
    move = [o for o in outs if o.action == "move"][0]
    assert move.result == "failed" and move.coa_code == 42
    # failed move does NOT consume the cooldown → retried next cycle
    assert eng.should_move("bob@client5", now=1001.0) is True
