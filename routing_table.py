"""جدول التوجيه — يُجلَب من لوحة التراخيص ويُحدَّث دوريًا.

يستخدم requests (مزامن) لجلب المسارات من /api/proxy/routing-table.
التحقق من الهوية: X-Proxy-Token = timestamp:nonce:HMAC-SHA256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

log = logging.getLogger(__name__)


# Default location for the 0600 state file that persists the CHR shared
# secret across restarts. Matches DEPLOY_PROXY.md / state-dir convention.
_DEFAULT_CHR_SECRET_STATE_PATH = "/var/lib/hobe-radius-proxy/chr-secret.json"
# Default rotation grace window for dual-accept. 24h gives the operator
# time to re-import all CHR scripts after the panel rotates the secret —
# during this window the proxy validates Message-Authenticator against
# BOTH current and previous, so no RADIUS packet is dropped.
_DEFAULT_CHR_SECRET_GRACE_SECONDS = 86400
# Default rotation grace window for the per-realm proxy↔customer route
# secret. The customer's FreeRADIUS converges via heartbeat (≤300s by
# design); the proxy converges via routing-table refresh (≤60s). During
# the gap the proxy may send the NEW secret while the customer still has
# the OLD — upstream silently drops, we see a TIMEOUT. With this grace,
# the proxy retries the forwarded request signed with the PREVIOUS secret
# so the customer accepts it. 600s = 5 min margin over the 300s
# convergence target.
_DEFAULT_ROUTE_SECRET_GRACE_SECONDS = 600


@dataclass
class RouteEntry:
    realm: str
    customer_id: int
    target_ip: str
    auth_port: int
    acct_port: int
    secret: str
    allowed_chr_ips: list[str] = field(default_factory=list)
    # §6.2 dual-accept (per-realm route secret rotation grace) — the
    # previous secret survives in-memory for one rotation window so the
    # proxy can transparently retry forwarded requests with the previous
    # value while the customer's FreeRADIUS still has the OLD secret.
    previous_secret: str = ""
    secret_rotated_at: float = 0.0

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
        *,
        bootstrap_chr_secret: str = "",
        chr_secret_state_path: Optional[str] = None,
        chr_secret_grace_seconds: int = _DEFAULT_CHR_SECRET_GRACE_SECONDS,
        route_secret_grace_seconds: int = _DEFAULT_ROUTE_SECRET_GRACE_SECONDS,
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

        # ── §6.1 CHR shared secret — panel-canonical, env demoted to bootstrap ─
        # The owner's manual-secret-matching pain came from two hand-managed
        # copies of CHR_SHARED_SECRET drifting (64-char panel vs 34-char env).
        # Eliminated by construction: the panel includes `chr_shared_secret`
        # in the authenticated routing-table response; the relay reads it
        # PER PACKET via chr_secret() / previous_chr_secret_in_grace(). The
        # bootstrap_chr_secret is the env value, used ONLY before the first
        # successful fetch (or when the panel didn't send the field).
        self._chr_secret_state_path = (
            chr_secret_state_path or _DEFAULT_CHR_SECRET_STATE_PATH
        )
        self._chr_secret_grace_seconds = int(chr_secret_grace_seconds)
        # §6.2 — per-realm route secret rotation grace (PROXY ↔ customer
        # RADIUS). Mirrors the chr-secret grace, but in-memory only — the
        # proxy converges in ≤60s and the customer in ≤300s, so a brief
        # in-memory previous is enough to bridge the gap.
        self._route_secret_grace_seconds = int(route_secret_grace_seconds)
        self._bootstrap_chr_secret = bootstrap_chr_secret or ""
        self._chr_secret_current: str = ""
        self._chr_secret_previous: str = ""
        self._chr_secret_rotated_at: float = 0.0
        # one-shot warning when the bootstrap env differs from the panel value
        self._chr_secret_env_warned = False
        # Load any persisted state FIRST (survives restart during a panel
        # outage), then fall back to the bootstrap env. The panel's next
        # refresh() takes over from there.
        self._load_chr_secret_state()
        if not self._chr_secret_current and self._bootstrap_chr_secret:
            self._chr_secret_current = self._bootstrap_chr_secret

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

            # §6.2 — capture the BEFORE state so we can detect per-realm
            # secret rotations and roll the previous_secret/rotated_at
            # forward into the new RouteEntry. Without this snapshot the
            # routes dict overwrite would lose rotation history and
            # silently break the forward-retry fallback below.
            old_routes_snapshot = self._routes
            now = time.time()
            routes: dict[str, RouteEntry] = {}
            for r in data.get("routes", []):
                realm = str(r.get("realm", "")).strip().lower()
                if not realm:
                    continue
                new_secret = str(r.get("secret", ""))
                old_entry = old_routes_snapshot.get(realm)
                prev_secret = ""
                rotated_at = 0.0
                if old_entry:
                    if (
                        new_secret
                        and old_entry.secret
                        and new_secret != old_entry.secret
                    ):
                        # Rotation detected: demote the old current to
                        # previous; open the per-realm grace window.
                        prev_secret = old_entry.secret
                        rotated_at = now
                        log.info(
                            "Route secret rotated for realm '%s' — "
                            "dual-accept window open for %d s.",
                            realm, self._route_secret_grace_seconds,
                        )
                    else:
                        # Secret unchanged for this realm: carry forward
                        # whatever previous/rotated_at we already had
                        # (still respecting the grace window on read).
                        prev_secret = old_entry.previous_secret
                        rotated_at = old_entry.secret_rotated_at
                routes[realm] = RouteEntry(
                    realm=realm,
                    customer_id=int(r.get("customer_id", 0)),
                    target_ip=str(r.get("target_ip", "")),
                    auth_port=int(r.get("auth_port", 1812)),
                    acct_port=int(r.get("acct_port", 1813)),
                    secret=new_secret,
                    allowed_chr_ips=list(r.get("allowed_chr_ips", [])),
                    previous_secret=prev_secret,
                    secret_rotated_at=rotated_at,
                )

            chr_ips: set[str] = set()
            chr_names: dict[str, str] = {}
            node_status: dict[str, str] = {}
            for n in data.get("chr_nodes", []):
                public_ip = str(n.get("public_ip", "")).strip()
                # FROZEN field (panel ↔ proxy contract): the CHR's wg-data
                # address — the source IP the proxy actually sees on UDP
                # 1812/1813 over wg-data. Without ingesting this the proxy
                # rejects every real packet with "Packet from unknown CHR
                # IP …" because public_ip never matches the tunnel source.
                wg_data_ip = str(n.get("wg_data_ip", "")).strip()
                name = str(n.get("name") or n.get("node") or "").strip()
                status = str(n.get("status") or "").strip().lower()
                # Both legacy (public-only) and fleet (wg_data_ip-bearing)
                # entries are accepted; set semantics dedupe overlap.
                for ip in (public_ip, wg_data_ip):
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
            # LIVE-APPLY flag — panel-authoritative, FROZEN field name
            # "live_apply_enabled" (contract §1.1). Default False (advisory)
            # when absent.
            self._live_apply = bool(data.get("live_apply_enabled", False))
            # Per-user movable opt-in list — FROZEN field "movable_users"
            # (lowercased usernames). Absent ⇒ empty ⇒ nobody movable.
            self._movable_users = {
                str(u).strip().lower()
                for u in (data.get("movable_users") or [])
                if str(u).strip()
            }
            # ── §6.1 CHR shared secret ingestion ──────────────────────────
            # Frozen field: data["chr_shared_secret"]. The owner's
            # manual-secret-matching pain is eliminated by construction —
            # the proxy's relay reads this value PER PACKET, so panel and
            # proxy can never drift again. Empty / absent ⇒ keep current
            # (don't poison state with an empty when the panel hasn't
            # configured the secret yet).
            panel_secret = str(data.get("chr_shared_secret") or "")
            if panel_secret:
                self._adopt_chr_secret(panel_secret)
            self._last_refresh = time.time()
            log.info("Routing table refreshed: %d realms, %d CHR nodes", len(routes), len(chr_ips))
            return True

        except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
            # ValueError/TypeError/KeyError: panel returned 200 with malformed
            # JSON or wrong-typed fields. refresh() is reached from lookup()
            # in the packet hot path (ensure_fresh) — it must NEVER raise, or
            # a bad panel response kills the RADIUS packet task (P10 review).
            # On failure the previous routing table stays in effect.
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

    # ── §6.1 CHR shared secret — panel-canonical, per-packet, dual-accept ──

    def chr_secret(self) -> str:
        """Currently effective CHR shared secret.

        Source of truth: the panel's authenticated routing-table response
        (``data["chr_shared_secret"]``), persisted to a 0600 state file so
        the proxy keeps relaying across restarts during a panel outage.
        Returns the bootstrap env value (``PROXY_CHR_SECRET``) only when
        the panel has not yet supplied one — once the panel ships a value,
        it permanently overrides.
        """
        return self._chr_secret_current

    def previous_chr_secret_in_grace(self) -> Optional[str]:
        """The pre-rotation secret while still inside the grace window.

        Returns ``None`` when there is no previous secret OR the rotation
        is older than ``chr_secret_grace_seconds``. The dual-accept logic
        in the protocol uses this to validate Message-Authenticator
        against BOTH secrets during rotation, so no RADIUS packet drops
        while CHRs re-import scripts.
        """
        if not self._chr_secret_previous:
            return None
        if (time.time() - self._chr_secret_rotated_at
                > self._chr_secret_grace_seconds):
            return None
        return self._chr_secret_previous

    def chr_secret_in_grace_remaining(self) -> int:
        """Seconds left in the dual-accept window (0 when not rotating)."""
        if not self._chr_secret_previous:
            return 0
        remaining = self._chr_secret_grace_seconds - int(
            time.time() - self._chr_secret_rotated_at,
        )
        return max(0, remaining)

    def route_previous_secret_in_grace(self, realm: str) -> Optional[str]:
        """Return the per-realm pre-rotation secret iff still in grace.

        §6.2 dual-accept: when the panel rotates a customer's route
        secret, the proxy adopts it within ≤60 s (next routing-table
        refresh) but the customer's FreeRADIUS only catches up after
        the next bridge heartbeat (≤300 s). In that ~240 s window the
        proxy's forwarded request — signed with the NEW secret — fails
        Request-Authenticator at the customer side and the customer
        silently drops it (the proxy sees a TIMEOUT). With this method
        the protocol can retry the forward signed with the PREVIOUS
        secret and the request goes through.

        Returns ``None`` when the realm is unknown, never rotated, or
        the rotation is older than the grace window.
        """
        entry = self._routes.get(realm.lower())
        if not entry or not entry.previous_secret:
            return None
        if (time.time() - entry.secret_rotated_at
                > self._route_secret_grace_seconds):
            return None
        return entry.previous_secret

    def chr_secret_fingerprint(self) -> str:
        """Non-reversible fingerprint of (current secret + allowed CHR set).

        Reported to the panel in heartbeats so the panel can detect drift
        (§6.4). NEVER logs the secret itself — only a 16-hex-char digest.
        """
        h = hashlib.sha256()
        h.update(self._chr_secret_current.encode())
        h.update(b"|")
        h.update("|".join(sorted(self._allowed_chr_ips)).encode())
        return h.hexdigest()[:16]

    def _adopt_chr_secret(self, panel_secret: str) -> None:
        """Install a new panel-published secret, demoting the current one
        to ``previous`` if it differs (starts the dual-accept window).
        Persists to the 0600 state file on every change. NEVER logs the
        secret value itself.
        """
        if panel_secret == self._chr_secret_current:
            # No-op: panel still publishing the value we already have.
            # One-shot env-deprecation warning still fires if env differs.
            self._maybe_warn_env_drift(panel_secret)
            return
        if self._chr_secret_current:
            self._chr_secret_previous = self._chr_secret_current
            self._chr_secret_rotated_at = time.time()
            log.info(
                "CHR shared secret rotated by panel — dual-accept window "
                "open for %d s (no RADIUS drops while CHRs re-import).",
                self._chr_secret_grace_seconds,
            )
        else:
            log.info("CHR shared secret loaded from panel (first acquisition).")
        self._chr_secret_current = panel_secret
        self._save_chr_secret_state()
        self._maybe_warn_env_drift(panel_secret)

    def _maybe_warn_env_drift(self, panel_secret: str) -> None:
        """ONE-shot warning when bootstrap env differs from panel value.
        The owner's incident was hand-managed env (34 chars) drifting from
        the panel (64 chars). With panel-canonical secrets this can never
        cause a RADIUS drop again — but we still flag it so the operator
        can clean up the stale env.
        """
        if (
            self._bootstrap_chr_secret
            and self._bootstrap_chr_secret != panel_secret
            and not self._chr_secret_env_warned
        ):
            log.warning(
                "PROXY_CHR_SECRET env value differs from the panel's "
                "authoritative chr_shared_secret — adopting the PANEL value "
                "(env is now bootstrap-only; remove it from /etc/hobe-"
                "radius-proxy/env to silence this warning). No RADIUS "
                "packets are at risk.",
            )
            self._chr_secret_env_warned = True

    def _load_chr_secret_state(self) -> None:
        """Best-effort load of the persisted CHR-secret state. Silent on
        first-run / unreadable / malformed — falls back to bootstrap env."""
        try:
            with open(self._chr_secret_state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        self._chr_secret_current = str(data.get("current") or "")
        self._chr_secret_previous = str(data.get("previous") or "")
        try:
            self._chr_secret_rotated_at = float(data.get("rotated_at_unix") or 0.0)
        except (TypeError, ValueError):
            self._chr_secret_rotated_at = 0.0

    def _save_chr_secret_state(self) -> None:
        """Persist (current, previous, rotated_at) atomically at 0600.

        Failure to persist is non-fatal: the relay keeps working with the
        in-memory state; the next refresh will retry. NEVER logs the
        secret values themselves.
        """
        try:
            parent = os.path.dirname(self._chr_secret_state_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self._chr_secret_state_path + ".tmp"
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({
                        "current": self._chr_secret_current,
                        "previous": self._chr_secret_previous,
                        "rotated_at_unix": self._chr_secret_rotated_at,
                    }, f)
            except Exception:
                # fdopen took ownership; if write blew up we still need to
                # remove the partial tmp file before re-raising.
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            os.replace(tmp, self._chr_secret_state_path)
            # `os.replace` preserves the mode set at open() time.
        except OSError as exc:
            log.warning(
                "CHR secret state save to %s failed: %s "
                "(relay continues; next refresh retries)",
                self._chr_secret_state_path, exc,
            )

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
                # §6.4 drift visibility: the panel compares this against
                # what it published and surfaces a single boolean per
                # party (سنخرى ✓ / بانتظار التقارب…). Non-reversible —
                # the secret itself never leaves the proxy.
                "config_fingerprint": self.chr_secret_fingerprint(),
                "chr_secret_grace_remaining_s": (
                    self.chr_secret_in_grace_remaining()
                ),
            }
            resp = requests.post(self._heartbeat_url, json=payload, headers=self._headers(), timeout=10)
            if resp.ok:
                self._stats["realms_not_found"] = set()
                log.debug("Heartbeat sent OK")
            else:
                log.warning("Heartbeat returned %s", resp.status_code)
        except (requests.RequestException, ValueError, TypeError) as exc:
            # Same never-raise rule as refresh(): heartbeat runs inside the
            # maintenance loop and must not kill it on a bad panel response.
            log.warning("Heartbeat failed: %s", exc)
