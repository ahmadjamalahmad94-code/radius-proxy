"""جدول التوجيه — يُجلَب من لوحة التراخيص ويُحدَّث دوريًا.

يستخدم requests (مزامن) لجلب المسارات من /api/proxy/routing-table.
التحقق من الهوية: X-Proxy-Token = timestamp:nonce:HMAC-SHA256.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

log = logging.getLogger(__name__)


@dataclass
class RouteEntry:
    realm: str
    customer_id: int
    target_ip: str
    auth_port: int
    acct_port: int
    secret: str
    allowed_chr_ips: list[str] = field(default_factory=list)

    @property
    def auth_addr(self) -> tuple[str, int]:
        return (self.target_ip, self.auth_port)

    @property
    def acct_addr(self) -> tuple[str, int]:
        return (self.target_ip, self.acct_port)

    def chr_is_allowed(self, chr_ip: str) -> bool:
        if not self.allowed_chr_ips:
            return True  # empty = all CHRs allowed
        return chr_ip in self.allowed_chr_ips


class RoutingTable:
    """Thread-safe routing table with periodic refresh from admin panel API."""

    def __init__(
        self,
        admin_base_url: str,
        shared_secret: str,
        refresh_interval: int = 60,
        fail_open_chr: bool = False,
        static_node_map: Optional[dict[str, str]] = None,
    ):
        self._url = admin_base_url.rstrip("/") + "/api/proxy/routing-table"
        self._chr_nodes_url = admin_base_url.rstrip("/") + "/api/proxy/chr-nodes"
        self._heartbeat_url = admin_base_url.rstrip("/") + "/api/proxy/heartbeat"
        self._secret = shared_secret
        self._interval = refresh_interval
        self._routes: dict[str, RouteEntry] = {}
        self._allowed_chr_ips: set[str] = set()
        # CHR public IP → registry node NAME (when the panel supplies it).
        # The fleet telemetry/placement layers key by node name; this is the
        # proxy's IP→name resolver. ``static_node_map`` is a config fallback
        # until the routing-table API carries names (see Phase-4 contract gap).
        self._chr_node_names: dict[str, str] = {}
        self._static_node_map: dict[str, str] = dict(static_node_map or {})
        # node NAME → status ("active"|"draining"|"disabled"|...). Drives the
        # Phase-7 outage signal (status != "active" ⇒ forced move).
        self._node_status: dict[str, str] = {}
        # Panel's authoritative LIVE-APPLY flag (Phase 7 safety guard). Default
        # False (advisory) when the panel doesn't send it / is unreachable.
        self._live_apply: bool = False
        # Per-user movable opt-in (Phase 7). Forward-compatible capture of a
        # top-level "movable_users" list in the routing-table response (contract
        # gap — not frozen yet). Usernames lowercased. Absent ⇒ empty ⇒ nobody
        # is movable (safe default: rebalance moves are opt-in).
        self._movable_users: set[str] = set()
        self._last_refresh: float = 0
        self._fail_open_chr = fail_open_chr
        self._stats = {
            "requests_total": 0,
            "requests_accepted": 0,
            "requests_rejected": 0,
            "requests_error": 0,
            "realms_not_found": set(),
        }

    def _make_token(self) -> str:
        ts = int(time.time())
        nonce = secrets.token_hex(8)
        message = f"{ts}:{nonce}".encode()
        sig = hmac.new(self._secret.encode(), message, hashlib.sha256).hexdigest()
        return f"{ts}:{nonce}:{sig}"

    def _headers(self) -> dict[str, str]:
        return {"X-Proxy-Token": self._make_token(), "Content-Type": "application/json"}

    def refresh(self) -> bool:
        """Fetch routing table from admin panel. Returns True on success."""
        try:
            resp = requests.get(self._url, headers=self._headers(), timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("ok"):
                log.error("Routing table fetch returned ok=false")
                return False

            routes: dict[str, RouteEntry] = {}
            for r in data.get("routes", []):
                realm = str(r.get("realm", "")).strip().lower()
                if not realm:
                    continue
                routes[realm] = RouteEntry(
                    realm=realm,
                    customer_id=int(r.get("customer_id", 0)),
                    target_ip=str(r.get("target_ip", "")),
                    auth_port=int(r.get("auth_port", 1812)),
                    acct_port=int(r.get("acct_port", 1813)),
                    secret=str(r.get("secret", "")),
                    allowed_chr_ips=list(r.get("allowed_chr_ips", [])),
                )

            chr_ips: set[str] = set()
            chr_names: dict[str, str] = {}
            node_status: dict[str, str] = {}
            for n in data.get("chr_nodes", []):
                ip = str(n.get("public_ip", "")).strip()
                name = str(n.get("name") or n.get("node") or "").strip()
                status = str(n.get("status") or "").strip().lower()
                if ip:
                    chr_ips.add(ip)
                    if name:
                        chr_names[ip] = name
                if name and status:
                    node_status[name] = status

            self._routes = routes
            self._allowed_chr_ips = chr_ips
            self._chr_node_names = chr_names
            self._node_status = node_status
            # LIVE-APPLY flag — additive, panel-authoritative. Accept either a
            # top-level "live_apply" or a nested config block. Default False.
            self._live_apply = bool(
                data.get("live_apply",
                         (data.get("config") or {}).get("live_apply", False))
            )
            # Per-user movable opt-in list — additive, forward-compatible
            # (contract gap: not frozen; absent ⇒ empty ⇒ nobody movable).
            self._movable_users = {
                str(u).strip().lower()
                for u in (data.get("movable_users") or [])
                if str(u).strip()
            }
            self._last_refresh = time.time()
            log.info("Routing table refreshed: %d realms, %d CHR nodes", len(routes), len(chr_ips))
            return True

        except requests.RequestException as exc:
            log.error("Failed to refresh routing table: %s", exc)
            return False

    def ensure_fresh(self) -> None:
        """Refresh if stale."""
        if time.time() - self._last_refresh > self._interval:
            self.refresh()

    def lookup(self, realm: str) -> Optional[RouteEntry]:
        self.ensure_fresh()
        entry = self._routes.get(realm.lower())
        if not entry:
            self._stats["realms_not_found"].add(realm)
        return entry

    def all_realms(self) -> list[str]:
        return list(self._routes.keys())

    def node_name_for(self, chr_ip: str) -> Optional[str]:
        """Resolve a CHR public IP → registry node NAME for fleet telemetry.

        Resolution order: name supplied by the routing-table API, then the
        static config map, else None (caller falls back to the IP and logs).
        """
        return self._chr_node_names.get(chr_ip) or self._static_node_map.get(chr_ip)

    def local_node_candidates(self) -> list[str]:
        """Best-effort local set of known CHR node names (placement read-path
        fallback only). The proxy has no health view — that is the panel's job —
        so this is purely a last-resort hint when the panel is unreachable."""
        out: list[str] = []
        for ip in self._allowed_chr_ips:
            out.append(self.node_name_for(ip) or ip)
        return out

    def live_apply(self) -> bool:
        """The panel's authoritative LIVE-APPLY flag (Phase 7 safety guard).

        Default False (advisory) when the panel doesn't expose it yet or the
        last refresh failed — enforcement stays safe until the panel opts in.
        """
        return self._live_apply

    def node_status(self, node_name: str) -> Optional[str]:
        """Lifecycle status for a registry node name, or None if unknown."""
        return self._node_status.get(node_name)

    def is_node_healthy(self, node_name: str) -> bool:
        """True iff the node is known and ``status == 'active'``.

        Used as the Phase-7 OUTAGE signal: a session whose CHR is not active
        (down/draining/disabled/unknown) is force-moved regardless of `movable`.
        Unknown nodes (absent from the table) are treated as NOT healthy so a
        removed/dead node triggers evacuation. If the panel sends no status at
        all, the engine's node_healthy_provider is left unset (no forced moves).
        """
        return self._node_status.get(node_name) == "active"

    def has_node_status(self) -> bool:
        """Whether the panel supplied any node status (gates forced-move logic)."""
        return bool(self._node_status)

    def is_user_movable(self, username: str) -> bool:
        """Per-user movable opt-in (Phase 7). Unknown users ⇒ NOT movable.

        Only consulted for CPU/cost rebalance moves; outage failover ignores it
        (forced for everyone — doc 04 §4.7, doc 05 §5.6.2).
        """
        return username.strip().lower() in self._movable_users

    def is_allowed_chr(self, ip: str) -> bool:
        """Check if this source IP is a known CHR node.

        When the allowlist is empty (no CHR nodes loaded from admin yet):
          - fail_open_chr=False (production default): REJECT all sources.
          - fail_open_chr=True  (dev mode): allow all sources.

        Set PROXY_FAIL_OPEN_CHR_ALLOWLIST=true only in development.
        In production this must be False (the default) to prevent
        unauthenticated sources from injecting RADIUS traffic.
        """
        if not self._allowed_chr_ips:
            if self._fail_open_chr:
                log.debug("CHR allowlist empty + fail_open=True: allowing %s", ip)
                return True
            log.warning(
                "CHR allowlist empty + fail_open=False: rejecting %s "
                "(set PROXY_FAIL_OPEN_CHR_ALLOWLIST=true for dev mode)",
                ip,
            )
            return False
        return ip in self._allowed_chr_ips

    def record_request(self, accepted: bool, error: bool = False) -> None:
        self._stats["requests_total"] += 1
        if error:
            self._stats["requests_error"] += 1
        elif accepted:
            self._stats["requests_accepted"] += 1
        else:
            self._stats["requests_rejected"] += 1

    def heartbeat(self, proxy_id: str, uptime: float) -> None:
        """Send heartbeat + stats to admin panel."""
        try:
            payload = {
                "proxy_id": proxy_id,
                "uptime_seconds": int(uptime),
                "routes_loaded": len(self._routes),
                "requests_total": self._stats["requests_total"],
                "requests_accepted": self._stats["requests_accepted"],
                "requests_rejected": self._stats["requests_rejected"],
                "requests_error": self._stats["requests_error"],
                "active_realms": list(self._routes.keys()),
                "realms_not_found": list(self._stats["realms_not_found"]),
            }
            resp = requests.post(self._heartbeat_url, json=payload, headers=self._headers(), timeout=10)
            if resp.ok:
                self._stats["realms_not_found"] = set()
                log.debug("Heartbeat sent OK")
            else:
                log.warning("Heartbeat returned %s", resp.status_code)
        except requests.RequestException as exc:
            log.warning("Heartbeat failed: %s", exc)
