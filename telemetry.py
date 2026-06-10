"""Per-node telemetry emitter for the central RADIUS proxy.

CHR Fleet — Phase 4 (P4-T5 / P4-T7 integrator).

Responsibility:
    Collect the per-CHR-node metrics the proxy can actually observe from the
    RADIUS traffic flowing through it, and periodically POST one health/load
    sample **per node** to the panel at ``POST /api/proxy/telemetry``. Feeds
    ``fleet.health`` (state machine) and ``fleet.brain`` (scoring).

Source of truth = the FROZEN panel contract
``radius-module-admin/docs/contracts/fleet_api.md`` §1 (NOT the original Phase-1
stub docstring, which predates the freeze). The request shape is:

    {
      "node": "chr-exit-01",                 # registry node NAME (unique)
      "sampled_at": "2026-06-09T19:40:00Z",  # ISO-8601 UTC Z
      "metrics": { ... see below ... },
      "agent_version": "1.0.0"
    }

What the PROXY can observe (and therefore emits):
    - active_sessions  — live session count per node, tracked from Accounting
                         Start/Stop (gauge). STRONGLY recommended by the contract.
    - egress_gbps      — instantaneous node throughput, derived from the delta of
                         Acct-Input/Output-Octets (+Gigawords) over the flush
                         interval. Coarse (updated at interim/stop cadence).

What the proxy DOES NOT emit (omitted ⇒ contract treats as neutral, no penalty):
    - cpu_util, mem_util, uptime_seconds  — not observable from RADIUS; supplied
      by the panel's own control-plane collector (P4-T2 metrics_collector).
    - session_capacity                    — lives in the registry; the panel knows it.
    - egress_gb_period                    — period/billing accounting is panel-
      authoritative (control-plane interface counters); the proxy intentionally
      omits it to avoid double-counting against the cost cap.

Auth: X-Proxy-Token keyed with RADIUS_PROXY_SHARED_SECRET (proxy ↔ panel), via
``proxy_auth`` — this is the proxy→panel channel, NOT the per-CHR RADIUS secret.

Resilience: emit failures NEVER propagate. ``flush`` retries with exponential
backoff and always returns a bool; ``observe_*`` never raise. ``flush`` performs
blocking I/O (``requests`` + backoff sleeps) and is meant to be run off the event
loop via ``loop.run_in_executor`` (wired in ``proxy.run_proxy``).
"""
from __future__ import annotations

import datetime
import logging
import threading
import time
from typing import Callable, Optional

import requests

import radius_packet as rp
from proxy_auth import proxy_token_headers

log = logging.getLogger(__name__)

# ── Accounting attribute numbers (RFC 2866) not all in radius_packet ──
_ATTR_ACCT_STATUS_TYPE   = 40
_ATTR_ACCT_INPUT_OCTETS  = 42
_ATTR_ACCT_OUTPUT_OCTETS = 43
_ATTR_ACCT_SESSION_ID    = 44
_ATTR_ACCT_INPUT_GIGAWORDS  = 52
_ATTR_ACCT_OUTPUT_GIGAWORDS = 53

# Acct-Status-Type values
_ACCT_START   = 1
_ACCT_STOP    = 2
_ACCT_INTERIM = 3

_GIGAWORD = 1 << 32  # 2**32


def _now_iso(dt: Optional[datetime.datetime] = None) -> str:
    """ISO-8601 UTC timestamp with a trailing Z (contract format)."""
    dt = dt or datetime.datetime.now(datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _u32(value: Optional[bytes]) -> int:
    """Decode a 4-byte unsigned RADIUS integer attribute (0 if absent/short)."""
    if not value or len(value) < 4:
        return 0
    return int.from_bytes(value[:4], "big")


class _NodeCounters:
    """Mutable per-node accumulator (guarded by TelemetryEmitter's lock)."""

    __slots__ = ("active_sessions", "session_octets", "cum_octets",
                 "octets_at_last_flush", "last_seen")

    def __init__(self) -> None:
        self.active_sessions: set[str] = set()          # live Acct-Session-Ids
        self.session_octets: dict[str, int] = {}        # last cumulative (in+out) per session
        self.cum_octets: int = 0                        # node running total (delta-summed)
        self.octets_at_last_flush: int = 0              # for rate over the flush window
        self.last_seen: float = 0.0


class TelemetryEmitter:
    """Collects proxy-observable per-node metrics and flushes them to the panel."""

    def __init__(
        self,
        endpoint: str,
        shared_secret: str,
        *,
        node_resolver: Optional[Callable[[str], Optional[str]]] = None,
        interval: int = 30,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        agent_version: str = "1.0.0",
        enabled: bool = True,
    ) -> None:
        """Configure the emitter.

        Args:
            endpoint:       Full telemetry URL (e.g. ``{ADMIN}/api/proxy/telemetry``).
            shared_secret:  RADIUS_PROXY_SHARED_SECRET — keys the X-Proxy-Token.
            node_resolver:  Maps a CHR source IP → registry node NAME. Returns
                            None when unknown; the emitter then falls back to the
                            IP string and logs (see contract gap in the report).
            interval:       Suggested seconds between flushes (used by the caller).
            timeout:        Per-request HTTP timeout.
            max_retries:    Attempts per node POST before giving up (>=1).
            backoff_base:   Exponential backoff base seconds (sleep = base*2**n).
            agent_version:  Reported in the payload for compat gating.
            enabled:        When False, all collection/flush is a no-op.
        """
        self._endpoint = endpoint
        self._secret = shared_secret
        self._resolver = node_resolver
        self.interval = interval
        self._timeout = timeout
        self._max_retries = max(1, max_retries)
        self._backoff_base = backoff_base
        self._agent_version = agent_version
        self._enabled = enabled
        self._nodes: dict[str, _NodeCounters] = {}      # keyed by CHR source IP
        self._lock = threading.Lock()

    # ── observation (hot path; must never raise) ──────────────────────
    def _node(self, chr_ip: str) -> _NodeCounters:
        nc = self._nodes.get(chr_ip)
        if nc is None:
            nc = _NodeCounters()
            self._nodes[chr_ip] = nc
        return nc

    def observe_session_start(self, chr_ip: str, acct_session_id: str) -> None:
        """Record a session coming up on ``chr_ip`` (Accounting-Start)."""
        if not self._enabled or not acct_session_id:
            return
        with self._lock:
            nc = self._node(chr_ip)
            nc.active_sessions.add(acct_session_id)
            nc.last_seen = time.time()

    def observe_session_stop(self, chr_ip: str, acct_session_id: str) -> None:
        """Record a session ending on ``chr_ip`` (Accounting-Stop)."""
        if not self._enabled or not acct_session_id:
            return
        with self._lock:
            nc = self._node(chr_ip)
            nc.active_sessions.discard(acct_session_id)
            nc.session_octets.pop(acct_session_id, None)
            nc.last_seen = time.time()

    def observe_octets(
        self, chr_ip: str, acct_session_id: str, total_octets: int
    ) -> None:
        """Fold a session's cumulative (in+out) octet total into node throughput.

        RADIUS reports per-session cumulative octets; we keep the last value seen
        per session and add only the positive delta to the node total (handles
        counter resets / out-of-order updates safely).
        """
        if not self._enabled or not acct_session_id:
            return
        with self._lock:
            nc = self._node(chr_ip)
            prev = nc.session_octets.get(acct_session_id, 0)
            delta = total_octets - prev
            if delta < 0:               # reset / reconnect — count from zero
                delta = total_octets
            nc.cum_octets += max(0, delta)
            nc.session_octets[acct_session_id] = total_octets
            nc.last_seen = time.time()

    def record_from_accounting(self, pkt: rp.RadiusPacket, chr_ip: str) -> None:
        """Update per-node metrics from a parsed Accounting-Request. Never raises."""
        if not self._enabled:
            return
        try:
            status = _u32(pkt.get_attr(_ATTR_ACCT_STATUS_TYPE))
            sid_raw = pkt.get_attr(_ATTR_ACCT_SESSION_ID)
            sid = sid_raw.decode("utf-8", "replace") if sid_raw else ""
            if not sid:
                return
            in_oct = _u32(pkt.get_attr(_ATTR_ACCT_INPUT_OCTETS))
            out_oct = _u32(pkt.get_attr(_ATTR_ACCT_OUTPUT_OCTETS))
            in_gw = _u32(pkt.get_attr(_ATTR_ACCT_INPUT_GIGAWORDS))
            out_gw = _u32(pkt.get_attr(_ATTR_ACCT_OUTPUT_GIGAWORDS))
            total = in_oct + out_oct + (in_gw + out_gw) * _GIGAWORD

            if status == _ACCT_START:
                self.observe_session_start(chr_ip, sid)
            elif status == _ACCT_STOP:
                self.observe_octets(chr_ip, sid, total)
                self.observe_session_stop(chr_ip, sid)
            else:  # interim-update (3) or others carrying octet counters
                self.observe_session_start(chr_ip, sid)  # ensure tracked
                self.observe_octets(chr_ip, sid, total)
        except Exception as exc:  # never let telemetry break packet handling
            log.debug("telemetry.record_from_accounting ignored error: %s", exc)

    # ── snapshot + emit ───────────────────────────────────────────────
    def _resolve_node(self, chr_ip: str) -> str:
        if self._resolver:
            try:
                name = self._resolver(chr_ip)
                if name:
                    return name
            except Exception:
                pass
        log.warning(
            "telemetry: no registry node name for CHR %s — emitting with IP as "
            "'node' (panel may reject as unknown_node). See contract gap.", chr_ip,
        )
        return chr_ip

    def build_payloads(
        self,
        now: Optional[datetime.datetime] = None,
        interval: Optional[float] = None,
    ) -> list[dict]:
        """Snapshot one telemetry payload per node (contract §1 shape).

        Args:
            now:       Sample timestamp (defaults to current UTC).
            interval:  Seconds over which to compute egress_gbps (defaults to
                       ``self.interval``).

        Returns:
            A list of JSON-serialisable payloads, one per observed node.
        """
        window = float(interval if interval is not None else self.interval)
        if window <= 0:        # zero/negative window would corrupt the rate
            window = 1.0
        ts = _now_iso(now)
        payloads: list[dict] = []
        with self._lock:
            for chr_ip, nc in self._nodes.items():
                delta_octets = max(0, nc.cum_octets - nc.octets_at_last_flush)
                egress_gbps = (delta_octets * 8.0) / window / 1e9
                metrics = {
                    "active_sessions": len(nc.active_sessions),
                    "egress_gbps": round(egress_gbps, 6),
                }
                payloads.append({
                    "node": self._resolve_node(chr_ip),
                    "sampled_at": ts,
                    "metrics": metrics,
                    "agent_version": self._agent_version,
                })
        return payloads

    def _mark_flushed(self) -> None:
        with self._lock:
            for nc in self._nodes.values():
                nc.octets_at_last_flush = nc.cum_octets

    def _post(self, payload: dict) -> bool:
        """POST a single payload with retry/backoff. Returns True on ok=true."""
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries):
            try:
                resp = requests.post(
                    self._endpoint,
                    json=payload,
                    headers=proxy_token_headers(self._secret),
                    timeout=self._timeout,
                )
                if resp.status_code == 200 and resp.json().get("ok"):
                    return True
                # 4xx (unknown_node/bad_request/unauthorized) won't fix on retry
                if 400 <= resp.status_code < 500:
                    log.warning(
                        "telemetry POST node=%s rejected %s — not retrying",
                        payload.get("node"), resp.status_code,
                    )
                    return False
                last_exc = RuntimeError(f"HTTP {resp.status_code}")
            except (requests.RequestException, ValueError) as exc:
                last_exc = exc
            if attempt < self._max_retries - 1:
                time.sleep(self._backoff_base * (2 ** attempt))
        log.warning(
            "telemetry POST node=%s failed after %d attempts: %s",
            payload.get("node"), self._max_retries, last_exc,
        )
        return False

    def flush(
        self,
        now: Optional[datetime.datetime] = None,
        interval: Optional[float] = None,
    ) -> bool:
        """Build + POST all node payloads. Resilient: never raises.

        Returns:
            True if every node payload was accepted (or there was nothing to
            send), False if any POST failed. Counters are NOT reset on failure
            (the rate window only advances after a successful flush cycle so the
            next attempt still reflects accumulated traffic).
        """
        if not self._enabled:
            return True
        try:
            payloads = self.build_payloads(now=now, interval=interval)
        except Exception as exc:
            log.error("telemetry.flush snapshot error (swallowed): %s", exc)
            return False
        if not payloads:
            return True
        all_ok = True
        for payload in payloads:
            try:
                if not self._post(payload):
                    all_ok = False
            except Exception as exc:  # defensive — _post already guards
                log.error("telemetry.flush post error (swallowed): %s", exc)
                all_ok = False
        if all_ok:
            self._mark_flushed()
        return all_ok
