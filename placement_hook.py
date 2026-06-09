"""Session placement hook for the central RADIUS proxy.

CHR Fleet — Phase 4 (P4-T6 / P4-T7 integrator).

Two responsibilities, both NON-enforcing in Phase 4 (no session is moved or torn
down here — that is Phase 7/8 CoA):

  1. FEEDBACK report (write) — on Accounting-Start, report where a session
     actually landed to the panel at ``POST /api/proxy/placement`` (frozen
     contract §2). This closes the loop so ``fleet.brain`` sees realised state.

  2. DECISION resolve (read) — query the panel for the *intended* best node for a
     realm/session, with a SAFE LOCAL FALLBACK when the panel is unreachable. The
     result is only resolved + LOGGED; nothing is enforced.

Source of truth = the FROZEN panel contract
``radius-module-admin/docs/contracts/fleet_api.md`` §2 (placement ingest). The
feedback request shape is:

    {
      "proxy_id": "proxy-01",
      "reported_at": "2026-06-09T19:40:05Z",
      "placements": [
        { "session_id": "a1b2c3", "realm": "client5", "username": "u@client5",
          "node": "chr-exit-02", "previous_node": null,
          "reason": "new", "result": "applied", "detail": "" }
      ]
    }
    reason  ∈ {new, rebalance, shed, failover, manual}
    result  ∈ {applied, rejected, pending}

CONTRACT GAP (see report): there is NO frozen *read* endpoint for the proxy to
ask "which node should this session go to". The decision resolver targets a
PROPOSED ``GET /api/proxy/placement-decision`` and degrades gracefully (local
fallback) until that endpoint is frozen, so nothing breaks meanwhile.

Auth: X-Proxy-Token keyed with RADIUS_PROXY_SHARED_SECRET via ``proxy_auth``.
Resilience: report/resolve never raise; failures are swallowed and logged.
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
from proxy_auth import proxy_token_headers

log = logging.getLogger(__name__)

_ATTR_ACCT_STATUS_TYPE = 40
_ATTR_ACCT_SESSION_ID  = 44
_ATTR_FRAMED_IP        = rp.ATTR_FRAMED_IP_ADDRESS  # 8
_ATTR_USER_NAME        = rp.ATTR_USER_NAME          # 1
_ACCT_START = 1
_ACCT_STOP  = 2


def _now_iso(dt: Optional[datetime.datetime] = None) -> str:
    dt = dt or datetime.datetime.now(datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class PlacementDecision:
    """Outcome of a READ-path placement-decision query (advisory, never enforced).

    Attributes:
        realm:           The realm the decision is for.
        intended_node:   Best node name the proxy *would* steer toward, or None.
        source:          Where the decision came from:
                         "panel" | "fallback_current" | "fallback_local" | "none".
        panel_reachable: True if the panel answered the query.
        candidates:      Node names considered (panel top-N or local set).
        detail:          Human-readable note (logged).
    """

    realm: str
    intended_node: Optional[str] = None
    source: str = "none"
    panel_reachable: bool = False
    candidates: list[str] = field(default_factory=list)
    detail: str = ""


class PlacementHook:
    """Reports realised placements (write) and resolves intended ones (read)."""

    def __init__(
        self,
        report_endpoint: str,
        decision_endpoint: str,
        shared_secret: str,
        proxy_id: str,
        *,
        node_resolver: Optional[Callable[[str], Optional[str]]] = None,
        local_candidates_provider: Optional[Callable[[], list[str]]] = None,
        timeout: float = 10.0,
        decision_cache_ttl: int = 30,
        enabled_report: bool = True,
        enabled_decision: bool = True,
    ) -> None:
        """Configure the placement hook.

        Args:
            report_endpoint:    ``{ADMIN}/api/proxy/placement`` (frozen §2, write).
            decision_endpoint:  ``{ADMIN}/api/proxy/placement-decision`` (proposed
                                read endpoint — see contract gap).
            shared_secret:      RADIUS_PROXY_SHARED_SECRET — keys X-Proxy-Token.
            proxy_id:           Stable proxy id (Config.PROXY_ID) for §2 payloads.
            node_resolver:      CHR source IP → registry node NAME (contract keys
                                placements by node name).
            local_candidates_provider:  Returns locally-known healthy node names
                                for the read-path fallback when the panel is down.
            timeout:            HTTP timeout for both calls.
            decision_cache_ttl: Seconds to cache a realm's decision (keeps the
                                read path off the auth hot path).
            enabled_report:     Master switch for the feedback write path.
            enabled_decision:   Master switch for the decision read path.
        """
        self._report_endpoint = report_endpoint
        self._decision_endpoint = decision_endpoint
        self._secret = shared_secret
        self._proxy_id = proxy_id
        self._resolver = node_resolver
        self._local_candidates = local_candidates_provider
        self._timeout = timeout
        self._cache_ttl = decision_cache_ttl
        self._enabled_report = enabled_report
        self._enabled_decision = enabled_decision
        self._decision_cache: dict[str, tuple[float, PlacementDecision]] = {}
        self._lock = threading.Lock()

    def _resolve_node(self, chr_ip: str) -> str:
        if self._resolver:
            try:
                name = self._resolver(chr_ip)
                if name:
                    return name
            except Exception:
                pass
        return chr_ip  # fall back to IP (logged once by telemetry resolver)

    # ── (1) FEEDBACK report — write path, frozen contract §2 ──────────
    def report(
        self,
        *,
        session_id: str,
        realm: str,
        node: str,
        username: Optional[str] = None,
        previous_node: Optional[str] = None,
        reason: str = "new",
        result: str = "applied",
        detail: str = "",
        reported_at: Optional[datetime.datetime] = None,
    ) -> bool:
        """POST a single realised placement to the panel (§2). Never raises.

        Returns:
            True on a successful (ok=true) ingest, False otherwise.
        """
        if not self._enabled_report:
            return False
        if not session_id or not realm or not node:
            log.debug("placement.report skipped — missing session_id/realm/node")
            return False
        payload = {
            "proxy_id": self._proxy_id,
            "reported_at": _now_iso(reported_at),
            "placements": [{
                "session_id": session_id,
                "realm": realm,
                "username": username or "",
                "node": node,
                "previous_node": previous_node,
                "reason": reason,
                "result": result,
                "detail": detail,
            }],
        }
        try:
            resp = requests.post(
                self._report_endpoint,
                json=payload,
                headers=proxy_token_headers(self._secret),
                timeout=self._timeout,
            )
            ok = resp.status_code == 200 and resp.json().get("ok")
            if not ok:
                log.warning(
                    "placement.report rejected node=%s session=%s status=%s",
                    node, session_id, resp.status_code,
                )
            return bool(ok)
        except (requests.RequestException, ValueError) as exc:
            log.warning("placement.report failed (swallowed): %s", exc)
            return False

    def report_from_accounting(self, pkt: rp.RadiusPacket, chr_ip: str) -> bool:
        """Report a placement from a parsed Accounting-Start packet. Never raises.

        Only Accounting-Start represents a *new placement* in contract §2; other
        status types are ignored here (session counting is telemetry's job).
        """
        if not self._enabled_report:
            return False
        try:
            from_attr = pkt.get_attr  # local alias
            status = from_attr(_ATTR_ACCT_STATUS_TYPE)
            status_val = int.from_bytes(status[:4], "big") if status and len(status) >= 4 else 0
            if status_val != _ACCT_START:
                return False
            sid_raw = from_attr(_ATTR_ACCT_SESSION_ID)
            sid = sid_raw.decode("utf-8", "replace") if sid_raw else ""
            username = pkt.username
            realm = pkt.realm
            node = self._resolve_node(chr_ip)
            return self.report(
                session_id=sid, realm=realm, node=node,
                username=username, reason="new", result="applied",
            )
        except Exception as exc:
            log.debug("placement.report_from_accounting ignored error: %s", exc)
            return False

    # ── (2) DECISION resolve — READ path, advisory + log-only ─────────
    def resolve_decision(
        self,
        realm: str,
        *,
        session_id: Optional[str] = None,
        current_node: Optional[str] = None,
        now: Optional[float] = None,
    ) -> PlacementDecision:
        """Resolve the intended best node for ``realm`` (read-only, never enforced).

        Queries the panel's (proposed) decision endpoint; on ANY failure falls
        back to a safe local choice and logs the intended decision. Results are
        cached per realm for ``decision_cache_ttl`` seconds.

        Returns:
            A :class:`PlacementDecision` (always — never raises). Phase 4 only
            logs it; Phase 7/8 will act on it.
        """
        if not self._enabled_decision:
            return PlacementDecision(realm=realm, source="none",
                                     detail="decision probe disabled")
        clock = now if now is not None else time.time()
        cached = self._cache_get(realm, clock)
        if cached is not None:
            return cached

        decision = self._query_panel(realm, session_id)
        if decision is None:
            decision = self._fallback(realm, current_node)
        self._cache_put(realm, clock, decision)

        log.info(
            "placement decision (advisory, not enforced) realm=%s intended=%s "
            "source=%s panel_reachable=%s%s",
            realm, decision.intended_node, decision.source,
            decision.panel_reachable,
            f" [{decision.detail}]" if decision.detail else "",
        )
        return decision

    def _query_panel(
        self, realm: str, session_id: Optional[str]
    ) -> Optional[PlacementDecision]:
        """GET the panel decision endpoint. Returns None on any failure."""
        params = {"realm": realm}
        if session_id:
            params["session_id"] = session_id
        try:
            resp = requests.get(
                self._decision_endpoint,
                params=params,
                headers=proxy_token_headers(self._secret),
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                log.debug("placement decision endpoint status %s", resp.status_code)
                return None
            data = resp.json()
            if not data.get("ok"):
                return None
            candidates = list(data.get("top_n") or [])
            intended = data.get("decision") or (candidates[0] if candidates else None)
            return PlacementDecision(
                realm=realm, intended_node=intended, source="panel",
                panel_reachable=True, candidates=candidates,
            )
        except (requests.RequestException, ValueError) as exc:
            log.debug("placement decision query failed (fallback): %s", exc)
            return None

    def _fallback(
        self, realm: str, current_node: Optional[str]
    ) -> PlacementDecision:
        """Safe local decision when the panel can't be reached."""
        if current_node:
            return PlacementDecision(
                realm=realm, intended_node=current_node,
                source="fallback_current", panel_reachable=False,
                candidates=[current_node],
                detail="panel unreachable — keep current node",
            )
        candidates: list[str] = []
        if self._local_candidates:
            try:
                candidates = list(self._local_candidates() or [])
            except Exception:
                candidates = []
        if candidates:
            return PlacementDecision(
                realm=realm, intended_node=candidates[0],
                source="fallback_local", panel_reachable=False,
                candidates=candidates,
                detail="panel unreachable — local healthy candidate",
            )
        return PlacementDecision(
            realm=realm, intended_node=None, source="none",
            panel_reachable=False,
            detail="panel unreachable — no local candidates",
        )

    # ── decision cache (thread-safe) ──────────────────────────────────
    def _cache_get(self, realm: str, clock: float) -> Optional[PlacementDecision]:
        with self._lock:
            entry = self._decision_cache.get(realm)
            if entry and (clock - entry[0]) < self._cache_ttl:
                return entry[1]
        return None

    def _cache_put(self, realm: str, clock: float, decision: PlacementDecision) -> None:
        with self._lock:
            self._decision_cache[realm] = (clock, decision)
