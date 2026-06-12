"""وكيل RADIUS المركزي — خادم UDP asyncio.

المنطق:
  1. يستمع على UDP 1812 (Auth) و 1813 (Acct) من عقد CHR.
  2. يحلّل الحزمة ويستخرج realm من User-Name (@realm).
  3. يبحث في جدول التوجيه (RoutingTable) عن الـ realm.
  4. يعيد توقيع الحزمة بسر العميل (re-sign).
  5. يُعيد توجيه الحزمة إلى RADIUS VPS العميل.
  6. يستلم الرد ويعيد توقيعه بسر CHR.
  7. يُعيد الرد إلى CHR.

الأمان:
  - يتحقق من Message-Authenticator إذا وُجد.
  - يتحقق من أن المصدر عقدة CHR معروفة.
  - لا يُسجَّل User-Password أو أسرار.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import struct
import time
from typing import Optional

import radius_packet as rp
from config import Config
from routing_table import RoutingTable
from telemetry import TelemetryEmitter
from placement_hook import PlacementHook
from coa import CoaSender
from coa_executor import CoaExecutor
from enforcement import EnforcementEngine, EnforcementReporter, SessionTracker
from wg_peer_sync import WgPeerSync

log = logging.getLogger(__name__)


class RadiusProxyProtocol(asyncio.DatagramProtocol):
    """معالج UDP للـ Auth (port 1812)."""

    def __init__(
        self,
        routing: RoutingTable,
        chr_secret: str,
        loop: asyncio.AbstractEventLoop,
        forward_timeout: float = 10.0,
        is_accounting: bool = False,
        acct_timeout_mode: str = "strict",
        strict_response_verify: bool = False,
        telemetry: "Optional[TelemetryEmitter]" = None,
        placement: "Optional[PlacementHook]" = None,
        decision_probe: bool = False,
        enforcement: "Optional[EnforcementEngine]" = None,
    ):
        self._routing = routing
        self._chr_secret = chr_secret
        self._loop = loop
        self._timeout = forward_timeout
        self._is_accounting = is_accounting
        self._acct_timeout_mode = acct_timeout_mode
        self._strict_response_verify = strict_response_verify
        # CHR Fleet (Phase 4): optional, non-enforcing observability hooks.
        # Always guarded so a fault here can never break RADIUS handling.
        self._telemetry = telemetry
        self._placement = placement
        self._decision_probe = decision_probe
        # CHR Fleet (Phase 7): enforcement engine — kill-old-session + moves
        # over CoA. Guard-gated (panel live-apply flag); same never-break rule.
        self._enforcement = enforcement
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        log.info(
            "%s listener ready",
            "Accounting" if self._is_accounting else "Auth",
        )

    def error_received(self, exc: Exception) -> None:
        log.error("UDP error: %s", exc)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._loop.create_task(self._handle(data, addr))

    def _validate_request_secret(self, raw: bytes) -> Optional[str]:
        """Validate inbound Message-Authenticator against current → previous
        (during the rotation grace window) → bootstrap env. Returns the
        secret that validated, or ``None`` if none did.

        Sourcing precedence (§6.1, owner's rule #1):
          1. ``routing.chr_secret()`` — the panel-canonical value from the
             authenticated routing-table, persisted across restarts.
          2. ``routing.previous_chr_secret_in_grace()`` — the pre-rotation
             secret while still inside the 24h dual-accept window, so
             CHRs that haven't re-imported scripts yet keep authenticating.
          3. ``self._chr_secret`` — the bootstrap ``PROXY_CHR_SECRET`` env
             value, used ONLY when the panel hasn't supplied one yet
             (before the first successful routing-table fetch).

        For packets WITHOUT a Message-Authenticator attribute,
        ``verify_message_authenticator`` returns True regardless of the
        secret — so for legacy non-MA Access-Requests current/bootstrap
        is returned (existing behavior preserved).

        Never logs any secret value.
        """
        current = self._routing.chr_secret() or self._chr_secret
        if rp.verify_message_authenticator(raw, current):
            return current
        previous = self._routing.previous_chr_secret_in_grace()
        if previous and rp.verify_message_authenticator(raw, previous):
            return previous
        return None

    async def _handle(self, data: bytes, addr: tuple) -> None:
        src_ip = addr[0]

        # 1. Validate source CHR
        if not self._routing.is_allowed_chr(src_ip):
            log.warning("Packet from unknown CHR IP %s — dropped", src_ip)
            self._routing.record_request(accepted=False, error=False)
            return

        # 2. Parse packet
        try:
            pkt = rp.parse(data)
        except rp.RadiusError as exc:
            log.warning("Malformed RADIUS packet from %s: %s", src_ip, exc)
            self._routing.record_request(accepted=False, error=True)
            return

        log.debug(
            "← %s id=%d from %s user=%s",
            pkt.code_name, pkt.identifier, src_ip,
            pkt.username if Config.LOG_REALM_LOOKUPS else "<hidden>",
        )

        # 3. Per-packet CHR shared secret + Message-Authenticator dual-accept.
        # §6.1 (THE HEADLINE): the secret is read PER PACKET from the
        # routing-table the panel publishes — never from a frozen env-bound
        # constructor value. During a rotation, dual-accept validates the
        # MA against current AND previous (within the 24h grace window) so
        # NO Access-Request is dropped while CHRs re-import scripts. The
        # response is then signed with whichever secret validated, so the
        # CHR can verify the Response-Authenticator against the one it
        # used to sign. This is the change that ends the owner's
        # manual-secret-matching pain forever.
        chr_secret = self._validate_request_secret(pkt.raw)
        if chr_secret is None:
            log.warning("Message-Authenticator mismatch from %s — dropped", src_ip)
            self._routing.record_request(accepted=False, error=True)
            return

        # 3b. CHR Fleet telemetry (accounting only). In-memory + fast: counts
        # live sessions and folds octet deltas per node. Fully guarded — a fault
        # here must never affect RADIUS handling.
        if self._is_accounting and self._telemetry is not None:
            try:
                self._telemetry.record_from_accounting(pkt, src_ip)
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("fleet telemetry hook error (ignored): %s", exc)

        # 3c. CHR Fleet enforcement (Phase 7): single-active-session guard.
        # On Acct-Start the engine tracks the session and — if the user is
        # already live on ANOTHER CHR — disconnects the OLD one (kill-old,
        # doc 04 §4.4) so the fixed IP is never live twice. The CoA send is
        # blocking (UDP + retry/backoff) → offloaded to a worker thread.
        # Guard-gated inside the engine (advisory when live-apply is off).
        if self._is_accounting and self._enforcement is not None:
            try:
                self._loop.run_in_executor(
                    None, self._enforcement.on_accounting, pkt, src_ip
                )
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("fleet enforcement hook error (ignored): %s", exc)

        # 4. Extract realm and look up route
        realm = pkt.realm
        if not realm:
            log.warning("No @realm in username '%s' from %s", pkt.username, src_ip)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr, chr_secret)
            return

        route = self._routing.lookup(realm)
        if not route:
            log.warning("Unknown realm '%s' from %s", realm, src_ip)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr, chr_secret)
            return

        # 4b. CHR Fleet placement (Phase 4): NON-enforcing observability,
        # offloaded off the event loop. Accounting-Start → report realised
        # placement (§2 write). Access-Request → advisory decision probe
        # (read path, log-only). Nothing is moved or disconnected here.
        if self._placement is not None:
            try:
                if self._is_accounting:
                    self._loop.run_in_executor(
                        None, self._placement.report_from_accounting, pkt, src_ip
                    )
                elif self._decision_probe:
                    node_name = self._routing.node_name_for(src_ip) or src_ip
                    self._loop.run_in_executor(
                        None,
                        functools.partial(
                            self._placement.resolve_decision,
                            realm, current_node=node_name,
                        ),
                    )
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("fleet placement hook error (ignored): %s", exc)

        if not route.chr_is_allowed(src_ip):
            log.warning("CHR %s not allowed for realm '%s'", src_ip, realm)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr, chr_secret)
            return

        if not route.secret:
            log.error("No secret configured for realm '%s'", realm)
            self._routing.record_request(accepted=False, error=True)
            return

        # 5. Re-sign packet for target RADIUS — use the secret that
        # validated this packet on the way in (current OR previous-in-grace).
        try:
            forwarded = rp.replace_secret_in_packet(pkt, chr_secret, route.secret)
        except Exception as exc:
            log.error("Failed to re-sign packet for realm '%s': %s", realm, exc)
            self._routing.record_request(accepted=False, error=True)
            return

        # Parse forwarded to get its authenticator for response verification.
        # For Access-Request the authenticator is unchanged (random nonce),
        # so fwd_auth == pkt.authenticator.
        # For Accounting-Request the authenticator IS recomputed with the new
        # secret, so fwd_auth != pkt.authenticator — the target RADIUS will
        # sign its response using fwd_auth and we must verify with it.
        try:
            fwd_auth = rp.parse(forwarded).authenticator
        except rp.RadiusError:
            fwd_auth = pkt.authenticator  # should never happen

        # 6. Forward to target RADIUS.
        target_addr = route.acct_addr if self._is_accounting else route.auth_addr
        response_data = await self._forward(forwarded, target_addr)

        # 6b. §6.2 — route-secret rotation grace.
        # The customer's FreeRADIUS converges on a new route secret via
        # bridge heartbeat (≤300 s by design) while the proxy converges via
        # routing-table refresh (≤60 s). In the gap, the upstream still has
        # the OLD secret and silently drops requests we signed with the
        # NEW secret. Detect that by way of a TIMEOUT, then RETRY ONCE
        # with the previous secret if the realm is still in grace. The
        # response (if any) is verified + re-signed back to CHR with the
        # secret that actually round-tripped — no drops at either end.
        # The retry is bounded: at most one extra forward per packet, and
        # only while a rotation is active for that specific realm.
        upstream_secret = route.secret
        if response_data is None and not self._is_accounting:
            prev_route_secret = self._routing.route_previous_secret_in_grace(realm)
            if prev_route_secret and prev_route_secret != route.secret:
                try:
                    forwarded_prev = rp.replace_secret_in_packet(
                        pkt, chr_secret, prev_route_secret,
                    )
                    fwd_auth_prev = rp.parse(forwarded_prev).authenticator
                except (rp.RadiusError, Exception) as exc:
                    log.warning(
                        "Route-secret retry: re-sign with previous failed "
                        "for realm '%s': %s",
                        realm, exc,
                    )
                else:
                    log.info(
                        "Route-secret retry: upstream timed out for realm "
                        "'%s' — retrying with previous secret (rotation "
                        "grace).",
                        realm,
                    )
                    retry_data = await self._forward(forwarded_prev, target_addr)
                    if retry_data is not None:
                        response_data = retry_data
                        upstream_secret = prev_route_secret
                        fwd_auth = fwd_auth_prev

        if response_data is None:
            log.warning(
                "No response from target RADIUS for realm '%s' (timeout) — mode=%s",
                realm, self._acct_timeout_mode if self._is_accounting else "n/a",
            )
            if self._is_accounting and self._acct_timeout_mode == "ack_on_timeout":
                # Send a fake Accounting-Response to prevent CHR retransmit storm.
                # WARNING: the accounting record is NOT saved upstream for this request.
                # ack_on_timeout only acknowledges the CHR node; it does NOT prove
                # target accounting persistence.
                await self._send_accounting_ack(pkt, addr, chr_secret)
            self._routing.record_request(accepted=False, error=True)
            return

        # 7. Parse and re-sign response for CHR.
        # We verify the upstream response with the SAME secret that
        # round-tripped (current OR previous, depending on §6.2 retry
        # above). We re-sign for the CHR with the secret that validated
        # the original request (current OR previous, depending on §6.1).
        # Both halves of the dual-accept window collapse to "use whichever
        # secret actually worked on the wire" — never drop a packet over
        # an in-flight rotation.
        try:
            resp_pkt = rp.parse(response_data)
            rebuilt = rp.rebuild_response(
                resp_pkt,
                request_auth=pkt.authenticator,             # original CHR authenticator
                old_secret=upstream_secret,
                new_secret=chr_secret,
                verify_auth=fwd_auth,                       # forwarded authenticator (differs for accounting)
                strict_verify=self._strict_response_verify, # drop on mismatch in production
            )
        except rp.RadiusError as exc:
            log.warning(
                "Dropping response from realm '%s': %s", realm, exc
            )
            self._routing.record_request(accepted=False, error=True)
            return
        except Exception as exc:
            log.error("Failed to rebuild response from realm '%s': %s", realm, exc)
            self._routing.record_request(accepted=False, error=True)
            return

        # 8. Send response to CHR
        if self._transport:
            self._transport.sendto(rebuilt, addr)

        accepted = resp_pkt.code == rp.CODE_ACCESS_ACCEPT
        self._routing.record_request(accepted=accepted)
        log.debug(
            "→ %s id=%d to %s (realm=%s)",
            resp_pkt.code_name, resp_pkt.identifier, src_ip, realm,
        )

    async def _forward(
        self, packet: bytes, target: tuple[str, int]
    ) -> Optional[bytes]:
        """Send packet to target and wait for response (UDP, one shot)."""
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bytes] = loop.create_future()

        class _OneShot(asyncio.DatagramProtocol):
            def datagram_received(self, data, _addr):
                if not future.done():
                    future.set_result(data)

            def error_received(self, exc):
                if not future.done():
                    future.set_exception(exc)

        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                _OneShot, remote_addr=target
            )
            transport.sendto(packet)
            return await asyncio.wait_for(future, timeout=self._timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            log.warning("Forward to %s:%d failed: %s", target[0], target[1], exc)
            return None
        finally:
            if transport:
                transport.close()

    async def _send_reject(
        self, pkt: rp.RadiusPacket, addr: tuple, chr_secret: str,
    ) -> None:
        """Send Access-Reject to CHR for requests we can't route.

        ``chr_secret`` is the secret that validated the original request
        (§6.1 dual-accept) — signing with anything else would cause the
        CHR to drop the Reject on Response-Authenticator mismatch.
        """
        if self._is_accounting:
            return  # Don't reject accounting packets — RFC says drop silently
        attrs_bytes = b""
        length = rp.HEADER_SIZE + len(attrs_bytes)
        auth = rp.response_authenticator(
            rp.CODE_ACCESS_REJECT, pkt.identifier, length,
            pkt.authenticator, attrs_bytes, chr_secret,
        )
        reject = struct.pack("!BBH", rp.CODE_ACCESS_REJECT, pkt.identifier, length) + auth
        if self._transport:
            self._transport.sendto(reject, addr)

    async def _send_accounting_ack(
        self, pkt: rp.RadiusPacket, addr: tuple, chr_secret: str,
    ) -> None:
        """Send a fake Accounting-Response (code 5) to CHR.

        Used only when PROXY_ACCT_TIMEOUT_MODE=fake_ack and the upstream
        target RADIUS timed out. Stops CHR from retransmitting endlessly.

        ``chr_secret`` is the secret that validated the incoming request
        (§6.1 dual-accept) so the CHR can verify Response-Authenticator.

        WARNING: The accounting record is NOT saved upstream for this packet.
        Each fake ACK is logged at WARNING level for auditability.
        """
        attrs_bytes = b""
        length = rp.HEADER_SIZE + len(attrs_bytes)
        auth = rp.response_authenticator(
            rp.CODE_ACCOUNTING_RESPONSE, pkt.identifier, length,
            pkt.authenticator, attrs_bytes, chr_secret,
        )
        ack = (
            struct.pack("!BBH", rp.CODE_ACCOUNTING_RESPONSE, pkt.identifier, length)
            + auth
        )
        if self._transport:
            self._transport.sendto(ack, addr)
        log.warning(
            "ack_on_timeout: sent Accounting-Response id=%d realm=%s "
            "— record NOT forwarded to target RADIUS (timeout); "
            "accounting persistence for this request is NOT guaranteed",
            pkt.identifier, pkt.realm,
        )


def _build_fleet_components(
    config: type, routing: RoutingTable
) -> "tuple[Optional[TelemetryEmitter], Optional[PlacementHook], Optional[EnforcementEngine]]":
    """Construct the Phase-4 telemetry/placement + Phase-7 enforcement from config.

    All resolve CHR-IP → registry node names via the routing table, and use the
    proxy↔panel shared secret for X-Proxy-Token auth. Returns None for a
    component when disabled by config.
    """
    telemetry: Optional[TelemetryEmitter] = None
    placement: Optional[PlacementHook] = None
    enforcement: Optional[EnforcementEngine] = None

    if getattr(config, "FLEET_TELEMETRY_ENABLED", False):
        telemetry = TelemetryEmitter(
            endpoint=config.FLEET_TELEMETRY_ENDPOINT,
            shared_secret=config.PROXY_SHARED_SECRET,
            node_resolver=routing.node_name_for,
            interval=config.FLEET_TELEMETRY_INTERVAL,
            timeout=config.FLEET_TELEMETRY_TIMEOUT,
            max_retries=config.FLEET_TELEMETRY_MAX_RETRIES,
            backoff_base=config.FLEET_TELEMETRY_BACKOFF_BASE,
            agent_version=config.FLEET_AGENT_VERSION,
            enabled=True,
        )

    if getattr(config, "FLEET_PLACEMENT_ENABLED", False):
        placement = PlacementHook(
            report_endpoint=config.FLEET_PLACEMENT_REPORT_ENDPOINT,
            decision_endpoint=config.FLEET_PLACEMENT_DECISION_ENDPOINT,
            shared_secret=config.PROXY_SHARED_SECRET,
            proxy_id=config.PROXY_ID,
            node_resolver=routing.node_name_for,
            local_candidates_provider=routing.local_node_candidates,
            timeout=config.FLEET_PLACEMENT_TIMEOUT,
            decision_cache_ttl=config.FLEET_PLACEMENT_DECISION_TTL,
            enabled_report=True,
            enabled_decision=config.FLEET_PLACEMENT_DECISION_PROBE,
        )

    if getattr(config, "FLEET_ENFORCEMENT_ENABLED", False):
        coa_sender = CoaSender(
            chr_secret=config.CHR_SHARED_SECRET,
            coa_port=config.FLEET_COA_PORT,
            timeout=config.FLEET_COA_TIMEOUT,
            max_retries=config.FLEET_COA_MAX_RETRIES,
            backoff_base=config.FLEET_COA_BACKOFF_BASE,
        )
        reporter = EnforcementReporter(
            endpoint=config.FLEET_ENFORCEMENT_ENDPOINT,
            shared_secret=config.PROXY_SHARED_SECRET,
            proxy_id=config.PROXY_ID,
            timeout=getattr(config, "FLEET_ENFORCEMENT_TIMEOUT", 10),
            max_retries=getattr(config, "FLEET_ENFORCEMENT_MAX_RETRIES", 2),
            backoff_base=getattr(config, "FLEET_ENFORCEMENT_BACKOFF_BASE", 0.5),
        )
        # SAFETY GUARD: effective live-apply = panel flag AND local override.
        # Panel flag defaults False when absent/unreachable → advisory-only.
        local_allowed = bool(getattr(config, "FLEET_LIVE_APPLY_ALLOWED", True))

        def _live_apply() -> bool:
            return local_allowed and routing.live_apply()

        # OUTAGE signal: only trust node status when the panel actually sends
        # it (otherwise no forced moves — never evacuate on missing data).
        def _node_healthy(name: str) -> bool:
            if not routing.has_node_status():
                return True  # no signal ⇒ assume healthy ⇒ no forced move
            return routing.is_node_healthy(name)

        enforcement = EnforcementEngine(
            coa=coa_sender,
            tracker=SessionTracker(),
            reporter=reporter,
            placement=placement,
            node_resolver=routing.node_name_for,
            live_apply_provider=_live_apply,
            node_healthy_provider=_node_healthy,
            movable_resolver=routing.is_user_movable,
            move_cooldown=config.FLEET_MOVE_COOLDOWN,
        )
    return telemetry, placement, enforcement


def _build_wg_peer_sync(config: type) -> "Optional[WgPeerSync]":
    """Construct the zero-touch fleet sync reconciler from config, or None
    when disabled. Kept separate from ``_build_fleet_components`` so the
    Phase-4/7 wiring test contract stays a 3-tuple."""
    if not getattr(config, "FLEET_WG_PEER_SYNC_ENABLED", False):
        return None
    return WgPeerSync(
        admin_base_url=config.ADMIN_BASE_URL,
        shared_secret=config.PROXY_SHARED_SECRET,
        interface=config.FLEET_WG_INTERFACE,
        state_path=config.FLEET_WG_STATE_PATH,
        wg_path=config.FLEET_WG_BIN,
        apply_mode=config.FLEET_WG_APPLY_MODE,
        timeout=config.FLEET_WG_PEER_SYNC_TIMEOUT,
        enabled=True,
    )


def _build_wg_radius_sync(config: type) -> "Optional[WgPeerSync]":
    """SECOND reconciler instance — applies customer-RADIUS peers to the
    NEW ``wg-radius`` interface (10.200.0.1/16, listen 51822) by consuming
    the panel's ``GET /api/proxy/radius-peers``. Same class, different
    endpoint + JSON key + interface + state file. Returns None when
    disabled. The asyncio loop runs both reconcilers as side-tasks; they
    are completely independent — wg-data outages never affect wg-radius
    and vice-versa.
    """
    if not getattr(config, "FLEET_WG_RADIUS_SYNC_ENABLED", False):
        return None
    return WgPeerSync(
        admin_base_url=config.ADMIN_BASE_URL,
        shared_secret=config.PROXY_SHARED_SECRET,
        interface=config.FLEET_WG_RADIUS_INTERFACE,
        state_path=config.FLEET_WG_RADIUS_STATE_PATH,
        wg_path=config.FLEET_WG_BIN,
        apply_mode=config.FLEET_WG_APPLY_MODE,
        timeout=config.FLEET_WG_RADIUS_SYNC_TIMEOUT,
        enabled=True,
        endpoint_path=config.FLEET_WG_RADIUS_SYNC_ENDPOINT_PATH,
        # FROZEN contract (cross-repo audit 2026-06-12): the panel's
        # /api/proxy/radius-peers response uses the top-level key `peers`
        # — deliberately matching the §1421c16 wg-peers shape. Per-peer
        # field names (`public_key`, `allowed_ips`, `name`, `endpoint`)
        # already match the WgPeerSync parser unchanged. The wg-data and
        # wg-radius reconcilers therefore BOTH read the default `peers`
        # — what disambiguates them is the endpoint_path + interface.
        peers_json_key="peers",
        log_prefix="wg radius sync",
    )


def _build_coa_executor(
    config: type, routing: RoutingTable,
    enforcement: "Optional[EnforcementEngine]",
) -> "Optional[CoaExecutor]":
    """Construct the panel-queued CoA / Disconnect executor.

    Returns None when disabled. The executor needs a way to map a realm
    (and optional ``target_node_id``) to live (chr_ip, username,
    acct_session_id) triples; production wires this through the
    enforcement engine's SessionTracker. When enforcement is off, the
    executor still runs — it will simply report ``no_active_sessions``
    for every realm (which is "done" with that detail string, so the
    panel cleanly dequeues).
    """
    if not getattr(config, "COA_EXECUTOR_ENABLED", False):
        return None
    # Best-effort session resolution. We deliberately avoid changing the
    # enforcement public API and reach into the engine's tracker — it's
    # already exposed for the Phase-7 integration tests, and the alternative
    # (a parallel SessionTracker fed off the same packet stream) would
    # double the bookkeeping. Falls back to "no targets" when enforcement
    # is disabled — callers see a clean 'done/no_active_sessions_for_realm'.
    tracker = getattr(enforcement, "_tracker", None) if enforcement else None

    def _targets_for(realm: str, _target_node_id):
        if tracker is None:
            return []
        out: list[tuple[str, str, str]] = []
        for sess in tracker.snapshot():
            # Filter by realm — usernames are user@realm in the proxy's
            # data model (the routing-table lookup uses the same split).
            uname = sess.username or ""
            if "@" not in uname:
                continue
            user_realm = uname.split("@", 1)[1].strip().lower()
            if user_realm != realm.strip().lower():
                continue
            out.append((sess.chr_ip, uname, sess.acct_session_id))
        return out

    return CoaExecutor(
        routing=routing,
        targets_provider=_targets_for,
        result_endpoint=config.COA_RESULT_ENDPOINT,
        shared_secret=config.PROXY_SHARED_SECRET,
        coa_port=config.FLEET_COA_PORT,
        coa_timeout=config.FLEET_COA_TIMEOUT,
        coa_max_retries=config.FLEET_COA_MAX_RETRIES,
        coa_backoff_base=config.FLEET_COA_BACKOFF_BASE,
        result_timeout=config.COA_RESULT_TIMEOUT,
        state_path=config.COA_EXECUTED_STATE_PATH,
        max_executed_ids=config.COA_EXECUTED_MAX_IDS,
        enabled=True,
    )


async def run_proxy(config: type, routing: RoutingTable) -> None:
    """Main proxy coroutine — runs Auth + Acct servers + heartbeat loop."""
    loop = asyncio.get_event_loop()
    start_time = time.time()

    telemetry, placement, enforcement = _build_fleet_components(config, routing)
    wg_peer_sync = _build_wg_peer_sync(config)
    wg_radius_sync = _build_wg_radius_sync(config)
    coa_executor = _build_coa_executor(config, routing, enforcement)
    decision_probe = bool(getattr(config, "FLEET_PLACEMENT_DECISION_PROBE", False))

    # Auth server (1812)
    auth_transport, _ = await loop.create_datagram_endpoint(
        lambda: RadiusProxyProtocol(
            routing, config.CHR_SHARED_SECRET, loop,
            forward_timeout=config.FORWARD_TIMEOUT_SECONDS,
            is_accounting=False,
            acct_timeout_mode=config.ACCT_TIMEOUT_MODE,
            strict_response_verify=config.STRICT_RESPONSE_VERIFY,
            telemetry=telemetry,
            placement=placement,
            decision_probe=decision_probe,
            enforcement=enforcement,
        ),
        local_addr=(config.LISTEN_HOST, config.RADIUS_AUTH_PORT),
    )

    # Accounting server (1813)
    acct_transport, _ = await loop.create_datagram_endpoint(
        lambda: RadiusProxyProtocol(
            routing, config.CHR_SHARED_SECRET, loop,
            forward_timeout=config.FORWARD_TIMEOUT_SECONDS,
            is_accounting=True,
            acct_timeout_mode=config.ACCT_TIMEOUT_MODE,
            strict_response_verify=config.STRICT_RESPONSE_VERIFY,
            telemetry=telemetry,
            placement=placement,
            decision_probe=decision_probe,
            enforcement=enforcement,
        ),
        local_addr=(config.LISTEN_HOST, config.RADIUS_ACCT_PORT),
    )

    log.info(
        "RADIUS Proxy started | auth=:%d acct=:%d | telemetry=%s placement=%s "
        "enforcement=%s wg_peer_sync=%s wg_radius_sync=%s coa_executor=%s",
        config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT,
        "on" if telemetry else "off", "on" if placement else "off",
        "on" if enforcement else "off",
        "on" if wg_peer_sync else "off",
        "on" if wg_radius_sync else "off",
        "on" if coa_executor else "off",
    )

    # Initial routing table load
    routing.refresh()

    # Heartbeat + refresh loop
    async def _maintenance_loop():
        while True:
            await asyncio.sleep(config.HEARTBEAT_INTERVAL_SECONDS)
            routing.heartbeat(config.PROXY_ID, time.time() - start_time)
            routing.ensure_fresh()
            # Drain panel-queued CoA/Disconnect commands picked up by
            # the just-completed routing-table refresh. Runs in a worker
            # thread because the inner UDP send + HTTPS POST are
            # blocking and would stall RADIUS packet I/O on the loop.
            # tick_safe() never raises into the executor scheduler.
            if coa_executor is not None:
                try:
                    await loop.run_in_executor(None, coa_executor.tick_safe)
                except Exception as exc:                          # pragma: no cover
                    log.debug("coa executor tick error (ignored): %s", exc)

    # Telemetry flush loop — runs the blocking POST (with retry/backoff) off the
    # event loop in a worker thread so backoff sleeps never stall packet I/O.
    async def _telemetry_loop():
        if telemetry is None:
            return
        interval = max(1, int(config.FLEET_TELEMETRY_INTERVAL))
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.run_in_executor(
                    None, functools.partial(telemetry.flush, interval=interval)
                )
            except Exception as exc:  # pragma: no cover - flush already guards
                log.debug("telemetry flush loop error (ignored): %s", exc)

    # Move-evaluation loop (Phase 7) — scans active sessions for forced
    # (outage) and opt-in (rebalance) moves. CoA sends are blocking → the
    # whole evaluation runs in a worker thread. Engine is guard-gated, so with
    # live-apply off this only logs advisory intentions.
    async def _enforcement_loop():
        if enforcement is None:
            return
        interval = max(5, int(getattr(config, "FLEET_MOVE_EVAL_INTERVAL", 60)))
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.run_in_executor(None, enforcement.evaluate_moves)
            except Exception as exc:  # pragma: no cover - engine already guards
                log.debug("enforcement eval loop error (ignored): %s", exc)

    # Zero-touch fleet sync — periodically reconcile the proxy's wg-data
    # peer set against the panel's published desired set. Both the HTTP
    # fetch AND `wg` invocations are blocking → run inside an executor.
    # The reconciler is internally guarded (reconcile_safe never raises),
    # so a panel outage or unprivileged proxy never affects heartbeat or
    # routing-table refresh.
    async def _wg_peer_sync_loop():
        if wg_peer_sync is None:
            return
        interval = max(
            10, int(getattr(config, "FLEET_WG_PEER_SYNC_INTERVAL", 60)),
        )
        # First pass shortly after startup so a newly-added CHR is picked
        # up faster than ``interval`` seconds. The maintenance loop already
        # waits the heartbeat interval before its first iteration, so
        # this brief lead time doesn't clash with the initial refresh.
        await asyncio.sleep(min(5, interval))
        while True:
            try:
                await loop.run_in_executor(None, wg_peer_sync.reconcile_safe)
            except Exception as exc:  # pragma: no cover - reconcile_safe guards
                log.debug("wg peer sync loop error (ignored): %s", exc)
            await asyncio.sleep(interval)

    # Customer RADIUS ↔ Proxy tunnel reconciler — same shape as the wg-data
    # loop above but driven by /api/proxy/radius-peers and acting on
    # wg-radius. Independent of the wg-data loop: a wg-data outage cannot
    # block customer onboarding and vice-versa.
    async def _wg_radius_sync_loop():
        if wg_radius_sync is None:
            return
        interval = max(
            10, int(getattr(config, "FLEET_WG_RADIUS_SYNC_INTERVAL", 60)),
        )
        await asyncio.sleep(min(5, interval))
        while True:
            try:
                await loop.run_in_executor(None, wg_radius_sync.reconcile_safe)
            except Exception as exc:  # pragma: no cover - reconcile_safe guards
                log.debug("wg radius sync loop error (ignored): %s", exc)
            await asyncio.sleep(interval)

    tasks = [asyncio.ensure_future(_maintenance_loop())]
    if telemetry is not None:
        tasks.append(asyncio.ensure_future(_telemetry_loop()))
    if enforcement is not None:
        tasks.append(asyncio.ensure_future(_enforcement_loop()))
    if wg_peer_sync is not None:
        tasks.append(asyncio.ensure_future(_wg_peer_sync_loop()))
    if wg_radius_sync is not None:
        tasks.append(asyncio.ensure_future(_wg_radius_sync_loop()))
    try:
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            t.cancel()
        auth_transport.close()
        acct_transport.close()
