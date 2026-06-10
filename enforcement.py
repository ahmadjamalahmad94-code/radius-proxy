"""Live enforcement engine for the central RADIUS proxy.

CHR Fleet — Phase 7 (P7): turns advisory placement into real action via CoA.

Responsibilities (docs 04 §4.4–4.5, 05 §5.6):
  1. SINGLE ACTIVE SESSION — on a new Accounting-Start for a user already active
     on ANOTHER CHR, disconnect the OLD CHR (kill-old-session) so the fixed
     private IP is never live on two CHRs at once (invariant G2). Always enforced
     (correctness), subject only to the live-apply guard.
  2. PLACEMENT ENFORCEMENT — consume the brain's decision (PlacementHook.
     resolve_decision). Move a user by disconnecting their current CHR so the
     client re-resolves the front door and RADIUS lands them on the chosen node.
       • CPU/cost REBALANCE moves respect the per-user ``movable`` opt-in.
       • On a CHR/provider OUTAGE the move is FORCED for everyone, ignoring the
         flag (G3 > opt-in).
       • Local hysteresis/cooldown (``should_move``) prevents ping-ponging.
  3. SAFETY GUARD — only actually send CoA when the panel's LIVE-APPLY flag is
     enabled (fetched from the routing-table). Otherwise ADVISORY-only: compute
     and log the intended action, send nothing.
  4. REPORT every action + CoA outcome to the panel (enforcement-outcome ingest,
     X-Proxy-Token auth) and, for moves, via the frozen §2 placement ingest.

Resilience: nothing here raises into RADIUS handling; CoA/report failures are
logged, retried with backoff, and swallowed.
"""
from __future__ import annotations

import datetime
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests

import radius_packet as rp
from coa import CoaSender, CoaResult
from proxy_auth import proxy_token_headers

log = logging.getLogger(__name__)

_ATTR_ACCT_STATUS_TYPE = 40
_ATTR_ACCT_SESSION_ID  = 44
_ACCT_START = 1
_ACCT_STOP  = 2

# Reasons (align with contract §2 placement `reason` vocabulary).
REASON_SINGLE_SESSION = "manual"      # kill-old is a correctness action
REASON_REBALANCE      = "rebalance"
REASON_FAILOVER       = "failover"


def _now_iso(ts: Optional[float] = None) -> str:
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          if ts is not None else datetime.datetime.now(datetime.timezone.utc))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ActiveSession:
    username: str
    realm: str
    node_name: str
    chr_ip: str
    acct_session_id: str
    framed_ip: str = ""
    nas_ip: Optional[str] = None
    started_at: float = 0.0


@dataclass
class EnforcementOutcome:
    """Result of one enforcement evaluation (always produced, for logging/report)."""

    action: str                       # "kill_old" | "move" | "none"
    username: str
    reason: str = ""
    target_node: str = ""             # the node we acted ON (disconnected)
    intended_node: str = ""           # where the user should end up (move)
    enforced: bool = False            # did we actually send CoA?
    advisory: bool = False            # blocked by live-apply guard?
    result: str = "skipped"           # applied | rejected | failed | advisory | skipped
    coa_code: Optional[int] = None
    detail: str = ""


class SessionTracker:
    """Fleet-wide active-session map keyed by username (thread-safe).

    The proxy is the only component that sees every CHR's Accounting, so it is
    the natural place to detect "same user active on two CHRs".
    """

    def __init__(self) -> None:
        self._by_user: dict[str, ActiveSession] = {}
        self._lock = threading.Lock()

    def on_start(self, sess: ActiveSession) -> Optional[ActiveSession]:
        """Register a new session. Returns the PRIOR session iff it was on a
        DIFFERENT CHR (i.e. the one that must be killed); else None."""
        with self._lock:
            prev = self._by_user.get(sess.username)
            self._by_user[sess.username] = sess
            if prev and prev.chr_ip != sess.chr_ip:
                return prev
            return None

    def on_stop(self, username: str, acct_session_id: str) -> None:
        with self._lock:
            cur = self._by_user.get(username)
            if cur and (not acct_session_id or cur.acct_session_id == acct_session_id):
                self._by_user.pop(username, None)

    def remove(self, username: str) -> None:
        with self._lock:
            self._by_user.pop(username, None)

    def get(self, username: str) -> Optional[ActiveSession]:
        with self._lock:
            return self._by_user.get(username)

    def snapshot(self) -> list[ActiveSession]:
        with self._lock:
            return list(self._by_user.values())


class EnforcementReporter:
    """POSTs enforcement actions + CoA outcomes to the panel. Never raises.

    CONTRACT GAP: no enforcement-outcome ingest endpoint is frozen yet (contract
    §3 says outcomes "flow back via §2 placement ingest"). We therefore POST a
    clear, self-describing payload to a configurable endpoint AND (for moves) the
    engine also emits the frozen §2 placement record. Reconcile the endpoint
    shape with the panel team.
    """

    def __init__(
        self,
        endpoint: str,
        shared_secret: str,
        proxy_id: str,
        *,
        timeout: float = 10.0,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        enabled: bool = True,
    ) -> None:
        self._endpoint = endpoint
        self._secret = shared_secret
        self._proxy_id = proxy_id
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._backoff_base = backoff_base
        self._enabled = enabled

    def report(self, outcome: EnforcementOutcome, *, ts: Optional[float] = None) -> bool:
        """POST {proxy_id, node, user, action, result, reason, ts, ...}."""
        if not self._enabled or not self._endpoint:
            return False
        payload = {
            "proxy_id": self._proxy_id,
            "node": outcome.target_node,
            "user": outcome.username,
            "action": outcome.action,
            "result": outcome.result,
            "reason": outcome.reason,
            "intended_node": outcome.intended_node,
            "coa_code": outcome.coa_code,
            "detail": outcome.detail,
            "ts": _now_iso(ts),
        }
        last: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = requests.post(
                    self._endpoint, json=payload,
                    headers=proxy_token_headers(self._secret), timeout=self._timeout,
                )
                if resp.status_code == 200 and resp.json().get("ok"):
                    return True
                if 400 <= resp.status_code < 500:
                    log.warning("enforcement report rejected %s — not retrying",
                                resp.status_code)
                    return False
                last = RuntimeError(f"HTTP {resp.status_code}")
            except (requests.RequestException, ValueError) as exc:
                last = exc
            if attempt < self._max_retries:
                time.sleep(self._backoff_base * (2 ** attempt))
        log.warning("enforcement report failed (swallowed): %s", last)
        return False


class EnforcementEngine:
    """Orchestrates kill-old-session + placement moves over CoA, guard-gated."""

    def __init__(
        self,
        coa: CoaSender,
        tracker: SessionTracker,
        reporter: EnforcementReporter,
        *,
        placement=None,                               # PlacementHook (resolve + §2)
        node_resolver: Optional[Callable[[str], Optional[str]]] = None,
        live_apply_provider: Callable[[], bool] = lambda: False,
        node_healthy_provider: Optional[Callable[[str], bool]] = None,
        movable_resolver: Optional[Callable[[str], Optional[bool]]] = None,
        move_cooldown: float = 120.0,
    ) -> None:
        """
        Args:
            coa:                   Real CoaSender.
            tracker:               Fleet-wide SessionTracker.
            reporter:              EnforcementReporter (panel outcome ingest).
            placement:             PlacementHook — resolve_decision (brain) + §2.
            node_resolver:         CHR IP → registry node name.
            live_apply_provider:   Returns the panel's effective LIVE-APPLY flag.
                                   When False → advisory-only (send nothing).
            node_healthy_provider: node name → is it healthy/active? Used to
                                   detect OUTAGE (forced move). None ⇒ assume
                                   healthy (no forced moves without a signal).
            movable_resolver:      username → movable flag (opt-in). None/unknown
                                   ⇒ treated as NOT movable (safe; rebalance moves
                                   are opt-in).
            move_cooldown:         Per-user seconds between enforced moves
                                   (hysteresis — prevents ping-ponging).
        """
        self._coa = coa
        self._tracker = tracker
        self._reporter = reporter
        self._placement = placement
        self._node_resolver = node_resolver
        self._live_apply = live_apply_provider
        self._node_healthy = node_healthy_provider
        self._movable = movable_resolver
        self._cooldown = move_cooldown
        self._last_move: dict[str, float] = {}
        self._lock = threading.Lock()

    # ── helpers ───────────────────────────────────────────────────────
    def _resolve_node(self, chr_ip: str) -> str:
        if self._node_resolver:
            try:
                return self._node_resolver(chr_ip) or chr_ip
            except Exception:
                return chr_ip
        return chr_ip

    def should_move(self, username: str, now: Optional[float] = None) -> bool:
        """Hysteresis gate: False if the user was moved within ``move_cooldown``."""
        clock = now if now is not None else time.time()
        with self._lock:
            last = self._last_move.get(username)
        return last is None or (clock - last) >= self._cooldown

    def _mark_moved(self, username: str, now: Optional[float] = None) -> None:
        clock = now if now is not None else time.time()
        with self._lock:
            self._last_move[username] = clock

    def _is_movable(self, username: str) -> bool:
        if self._movable is None:
            return False
        try:
            return bool(self._movable(username))
        except Exception:
            return False

    # ── (1) single active session: kill-old on Acct-Start ─────────────
    def on_accounting_start(
        self, pkt: rp.RadiusPacket, chr_ip: str, now: Optional[float] = None
    ) -> EnforcementOutcome:
        """Detect a reconnect on a different CHR and disconnect the OLD session."""
        try:
            status = pkt.get_attr(_ATTR_ACCT_STATUS_TYPE)
            status_val = int.from_bytes(status[:4], "big") if status and len(status) >= 4 else 0
            username = pkt.username
            if status_val != _ACCT_START or not username:
                return EnforcementOutcome(action="none", username=username or "")
            sid_raw = pkt.get_attr(_ATTR_ACCT_SESSION_ID)
            sid = sid_raw.decode("utf-8", "replace") if sid_raw else ""
            fip = pkt.get_attr(rp.ATTR_FRAMED_IP_ADDRESS)
            framed = ".".join(str(b) for b in fip[:4]) if fip and len(fip) >= 4 else ""
            new = ActiveSession(
                username=username, realm=pkt.realm,
                node_name=self._resolve_node(chr_ip), chr_ip=chr_ip,
                acct_session_id=sid, framed_ip=framed, nas_ip=chr_ip,
                started_at=now if now is not None else time.time(),
            )
            old = self._tracker.on_start(new)
            if old is None:
                return EnforcementOutcome(action="none", username=username)
            # User is now live on a different CHR → kill the OLD session.
            return self._disconnect(
                old, reason=REASON_SINGLE_SESSION, action="kill_old",
                forced=True, now=now,
            )
        except Exception as exc:  # never break accounting handling
            log.debug("enforcement.on_accounting_start ignored error: %s", exc)
            return EnforcementOutcome(action="none", username="")

    def on_accounting_stop(self, pkt: rp.RadiusPacket) -> None:
        try:
            sid_raw = pkt.get_attr(_ATTR_ACCT_SESSION_ID)
            sid = sid_raw.decode("utf-8", "replace") if sid_raw else ""
            self._tracker.on_stop(pkt.username, sid)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("enforcement.on_accounting_stop ignored error: %s", exc)

    def on_accounting(
        self, pkt: rp.RadiusPacket, chr_ip: str, now: Optional[float] = None
    ) -> EnforcementOutcome:
        """Single accounting entry point: dispatch Start (kill-old) / Stop (untrack)."""
        try:
            status = pkt.get_attr(_ATTR_ACCT_STATUS_TYPE)
            status_val = int.from_bytes(status[:4], "big") if status and len(status) >= 4 else 0
            if status_val == _ACCT_START:
                return self.on_accounting_start(pkt, chr_ip, now)
            if status_val == _ACCT_STOP:
                self.on_accounting_stop(pkt)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("enforcement.on_accounting ignored error: %s", exc)
        return EnforcementOutcome(action="none", username="")

    # ── (2) placement enforcement: rebalance vs forced failover ───────
    def evaluate_moves(self, now: Optional[float] = None) -> list[EnforcementOutcome]:
        """Scan active sessions; enforce forced (outage) + opt-in (rebalance) moves."""
        clock = now if now is not None else time.time()
        outcomes: list[EnforcementOutcome] = []
        for sess in self._tracker.snapshot():
            try:
                outcomes.append(self._evaluate_one(sess, clock))
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("evaluate_moves ignored error for %s: %s", sess.username, exc)
        return outcomes

    def _node_is_down(self, node_name: str) -> bool:
        if self._node_healthy is None:
            return False
        try:
            return not self._node_healthy(node_name)
        except Exception:
            return False

    def _evaluate_one(self, sess: ActiveSession, now: float) -> EnforcementOutcome:
        forced = self._node_is_down(sess.node_name)        # OUTAGE → forced
        intended = ""
        if self._placement is not None:
            try:
                dec = self._placement.resolve_decision(
                    sess.realm, session_id=sess.acct_session_id,
                    current_node=sess.node_name, now=now,
                )
                intended = dec.intended_node or ""
            except Exception:
                intended = ""

        if forced:
            return self.enforce_move(
                sess, intended_node=intended or "<any-healthy>",
                reason=REASON_FAILOVER, forced=True, now=now,
            )

        # Rebalance: only when the brain points elsewhere (better node exists).
        if intended and intended != sess.node_name:
            if not self._is_movable(sess.username):
                log.info("move SKIPPED (movable=false) user=%s %s→%s",
                         sess.username, sess.node_name, intended)
                return EnforcementOutcome(
                    action="move", username=sess.username, reason=REASON_REBALANCE,
                    target_node=sess.node_name, intended_node=intended,
                    result="skipped", detail="user not movable (opt-in)",
                )
            return self.enforce_move(
                sess, intended_node=intended, reason=REASON_REBALANCE,
                forced=False, now=now,
            )
        return EnforcementOutcome(action="none", username=sess.username)

    def enforce_move(
        self,
        sess: ActiveSession,
        *,
        intended_node: str,
        reason: str,
        forced: bool,
        now: Optional[float] = None,
    ) -> EnforcementOutcome:
        """Move a user by disconnecting their current CHR (guard + cooldown gated)."""
        clock = now if now is not None else time.time()
        if not forced and not self._is_movable(sess.username):
            return EnforcementOutcome(
                action="move", username=sess.username, reason=reason,
                target_node=sess.node_name, intended_node=intended_node,
                result="skipped", detail="user not movable (opt-in)",
            )
        if not self.should_move(sess.username, clock):
            return EnforcementOutcome(
                action="move", username=sess.username, reason=reason,
                target_node=sess.node_name, intended_node=intended_node,
                result="skipped", detail="cooldown (hysteresis)",
            )
        return self._disconnect(
            sess, reason=reason, action="move", forced=forced,
            intended_node=intended_node, now=clock,
        )

    # ── shared disconnect path (guard + CoA + report) ─────────────────
    def _disconnect(
        self,
        sess: ActiveSession,
        *,
        reason: str,
        action: str,
        forced: bool,
        intended_node: str = "",
        now: Optional[float] = None,
    ) -> EnforcementOutcome:
        clock = now if now is not None else time.time()
        out = EnforcementOutcome(
            action=action, username=sess.username, reason=reason,
            target_node=sess.node_name, intended_node=intended_node,
        )

        # SAFETY GUARD — advisory-only unless the panel enabled live-apply.
        try:
            live = bool(self._live_apply())
        except Exception:
            live = False
        if not live:
            out.advisory = True
            out.result = "advisory"
            out.detail = "live-apply disabled — advisory only (no CoA sent)"
            log.info(
                "ADVISORY %s user=%s node=%s reason=%s intended=%s (no CoA)",
                action, sess.username, sess.node_name, reason, intended_node,
            )
            return out  # send nothing

        # ENFORCE — send the RFC 5176 Disconnect to the target CHR.
        res: CoaResult = self._coa.disconnect(
            chr_ip=sess.chr_ip, username=sess.username,
            acct_session_id=sess.acct_session_id, nas_ip=sess.nas_ip,
            idempotency_key=f"{sess.username}:{sess.acct_session_id}:{action}",
        )
        out.enforced = True
        out.coa_code = res.code
        if res.ok:
            out.result = "applied"
        elif forced:
            # Outage: the old CHR may be dead and never ACK — eviction still
            # stands (its tunnels are gone). Treat as applied (doc 04 §4.4.4).
            out.result = "applied"
            out.detail = f"forced; coa not acked ({res.error}) — node down, session gone"
        else:
            out.result = "failed"
            out.detail = res.error or "coa failed"

        if out.result == "applied":
            self._mark_moved(sess.username, clock)
            if action == "move":
                # The old session is gone; user will reconnect elsewhere.
                self._tracker.remove(sess.username)

        self._report(out, sess, clock)
        return out

    def _report(self, out: EnforcementOutcome, sess: ActiveSession, clock: float) -> None:
        """Report the outcome: enforcement ingest (always) + §2 placement (moves)."""
        try:
            self._reporter.report(out, ts=clock)
        except Exception as exc:  # pragma: no cover - reporter already guards
            log.debug("enforcement report error (ignored): %s", exc)
        # Frozen §2 channel for moves: realised placement is pending until the
        # user reconnects (then the natural Acct-Start reports reason='new').
        if out.action == "move" and self._placement is not None and out.enforced:
            try:
                self._placement.report(
                    session_id=sess.acct_session_id, realm=sess.realm,
                    node=out.intended_node or sess.node_name,
                    username=sess.username, previous_node=sess.node_name,
                    reason=out.reason,
                    result="pending" if out.result == "applied" else "rejected",
                    detail=out.detail,
                )
            except Exception as exc:  # pragma: no cover
                log.debug("placement §2 report error (ignored): %s", exc)
