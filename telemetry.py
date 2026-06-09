"""Per-CHR / per-realm telemetry emitter for the central RADIUS proxy.

CHR Fleet — Phase 1 STUB (P1-T3).  Bodies are filled in Phase 4 (P4-T5).

Responsibility (per docs/chr_fleet/01_ARCHITECTURE.md §1.3.1 + §1.4.2):
    Aggregate per-CHR **and** per-realm RADIUS counters (accepts / rejects /
    errors / accounting events, last-seen) and periodically POST them to the
    licensing panel at ``POST /api/proxy/telemetry``.  This feed drives the
    panel's health loop and the scoring brain (docs/chr_fleet/05_LOAD_BALANCER_BRAIN.md).

Contract:
    Endpoint : POST {ADMIN_BASE_URL}/api/proxy/telemetry
    Auth     : X-Proxy-Token = "<ts>:<nonce>:<HMAC-SHA256(secret, 'ts:nonce')>"
               (same scheme as routing_table.RoutingTable; secret =
               RADIUS_PROXY_SHARED_SECRET).
    Body     : {
                 "proxy_id": "<proxy id>",
                 "ts": <unix seconds>,
                 "per_chr": [
                   {"chr_ip": "203.0.113.11", "requests_total": N,
                    "accepted": N, "rejected": N, "error": N,
                    "acct_starts": N, "acct_stops": N, "last_seen": <ts>}
                 ],
                 "per_realm": [
                   {"realm": "client5", "requests_total": N,
                    "accepted": N, "rejected": N, "error": N}
                 ]
               }

Phase-4 implementers: fill the method bodies; do not change the public
signatures — the panel side (radius-module-admin: routes_telemetry.py /
telemetry_ingest.py) is built against this contract.
"""
from __future__ import annotations

from typing import Optional


class TelemetryEmitter:
    """Accumulates RADIUS counters per CHR / per realm and flushes them to the panel.

    Lifecycle:
        1. The proxy calls :meth:`record_request` for every handled packet,
           tagging it with the source CHR IP and the resolved realm.
        2. A periodic task (the proxy maintenance loop) calls :meth:`flush`
           every ``interval`` seconds, which POSTs a snapshot and resets the
           in-memory counters.
    """

    def __init__(
        self,
        admin_base_url: str,
        shared_secret: str,
        proxy_id: str,
        interval: int = 30,
        timeout: float = 10.0,
    ) -> None:
        """Configure the emitter.

        Args:
            admin_base_url:  License panel base URL (Config.ADMIN_BASE_URL).
            shared_secret:   RADIUS_PROXY_SHARED_SECRET — keys the X-Proxy-Token.
            proxy_id:        Stable proxy identifier (Config.PROXY_ID).
            interval:        Seconds between flushes.
            timeout:         HTTP timeout for the POST.
        """
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter.__init__")

    def record_request(
        self,
        chr_ip: str,
        realm: str,
        *,
        accepted: bool,
        error: bool = False,
        is_accounting: bool = False,
    ) -> None:
        """Tally a single handled RADIUS request against its CHR and realm.

        Called from proxy._handle once the source CHR and realm are known.

        Args:
            chr_ip:         Source CHR public/identifier IP.
            realm:          Resolved realm (may be "" when routing failed).
            accepted:       True for Access-Accept outcomes.
            error:          True for malformed/auth/forwarding errors.
            is_accounting:  True for 1813 (accounting) traffic.
        """
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter.record_request")

    def record_accounting(
        self,
        chr_ip: str,
        realm: str,
        *,
        status_type: str,
    ) -> None:
        """Tally an accounting event (Start / Stop / Interim) per CHR and realm.

        Args:
            chr_ip:       Source CHR IP.
            realm:        Resolved realm.
            status_type:  One of "start", "stop", "interim".
        """
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter.record_accounting")

    def build_payload(self) -> dict:
        """Snapshot the current counters into the POST body (see module docstring).

        Returns:
            The JSON-serialisable telemetry payload.
        """
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter.build_payload")

    def flush(self) -> bool:
        """POST the accumulated telemetry to the panel and reset counters.

        Returns:
            True on a successful (ok=true) POST, False otherwise. On failure
            counters are retained for the next attempt.
        """
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter.flush")

    def _headers(self) -> dict[str, str]:
        """Build the X-Proxy-Token authentication header (mirrors RoutingTable)."""
        raise NotImplementedError("Phase 4 (P4-T5): TelemetryEmitter._headers")
