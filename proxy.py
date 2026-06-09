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
import logging
import struct
import time
from typing import Optional

import radius_packet as rp
from config import Config
from routing_table import RoutingTable

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
    ):
        self._routing = routing
        self._chr_secret = chr_secret
        self._loop = loop
        self._timeout = forward_timeout
        self._is_accounting = is_accounting
        self._acct_timeout_mode = acct_timeout_mode
        self._strict_response_verify = strict_response_verify
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

        # 3. Verify Message-Authenticator (if present)
        if not rp.verify_message_authenticator(pkt.raw, self._chr_secret):
            log.warning("Message-Authenticator mismatch from %s — dropped", src_ip)
            self._routing.record_request(accepted=False, error=True)
            return

        # 4. Extract realm and look up route
        realm = pkt.realm
        if not realm:
            log.warning("No @realm in username '%s' from %s", pkt.username, src_ip)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr)
            return

        route = self._routing.lookup(realm)
        if not route:
            log.warning("Unknown realm '%s' from %s", realm, src_ip)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr)
            return

        if not route.chr_is_allowed(src_ip):
            log.warning("CHR %s not allowed for realm '%s'", src_ip, realm)
            self._routing.record_request(accepted=False, error=False)
            await self._send_reject(pkt, addr)
            return

        if not route.secret:
            log.error("No secret configured for realm '%s'", realm)
            self._routing.record_request(accepted=False, error=True)
            return

        # 5. Re-sign packet for target RADIUS
        try:
            forwarded = rp.replace_secret_in_packet(pkt, self._chr_secret, route.secret)
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

        # 6. Forward to target RADIUS
        target_addr = route.acct_addr if self._is_accounting else route.auth_addr
        response_data = await self._forward(forwarded, target_addr)

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
                await self._send_accounting_ack(pkt, addr)
            self._routing.record_request(accepted=False, error=True)
            return

        # 7. Parse and re-sign response for CHR
        try:
            resp_pkt = rp.parse(response_data)
            rebuilt = rp.rebuild_response(
                resp_pkt,
                request_auth=pkt.authenticator,             # original CHR authenticator
                old_secret=route.secret,
                new_secret=self._chr_secret,
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

    async def _send_reject(self, pkt: rp.RadiusPacket, addr: tuple) -> None:
        """Send Access-Reject to CHR for requests we can't route."""
        if self._is_accounting:
            return  # Don't reject accounting packets — RFC says drop silently
        attrs_bytes = b""
        length = rp.HEADER_SIZE + len(attrs_bytes)
        auth = rp.response_authenticator(
            rp.CODE_ACCESS_REJECT, pkt.identifier, length,
            pkt.authenticator, attrs_bytes, self._chr_secret,
        )
        reject = struct.pack("!BBH", rp.CODE_ACCESS_REJECT, pkt.identifier, length) + auth
        if self._transport:
            self._transport.sendto(reject, addr)

    async def _send_accounting_ack(
        self, pkt: rp.RadiusPacket, addr: tuple
    ) -> None:
        """Send a fake Accounting-Response (code 5) to CHR.

        Used only when PROXY_ACCT_TIMEOUT_MODE=fake_ack and the upstream
        target RADIUS timed out. Stops CHR from retransmitting endlessly.

        WARNING: The accounting record is NOT saved upstream for this packet.
        Each fake ACK is logged at WARNING level for auditability.
        """
        attrs_bytes = b""
        length = rp.HEADER_SIZE + len(attrs_bytes)
        auth = rp.response_authenticator(
            rp.CODE_ACCOUNTING_RESPONSE, pkt.identifier, length,
            pkt.authenticator, attrs_bytes, self._chr_secret,
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


async def run_proxy(config: type, routing: RoutingTable) -> None:
    """Main proxy coroutine — runs Auth + Acct servers + heartbeat loop."""
    loop = asyncio.get_event_loop()
    start_time = time.time()

    # Auth server (1812)
    auth_transport, _ = await loop.create_datagram_endpoint(
        lambda: RadiusProxyProtocol(
            routing, config.CHR_SHARED_SECRET, loop,
            forward_timeout=config.FORWARD_TIMEOUT_SECONDS,
            is_accounting=False,
            acct_timeout_mode=config.ACCT_TIMEOUT_MODE,
            strict_response_verify=config.STRICT_RESPONSE_VERIFY,
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
        ),
        local_addr=(config.LISTEN_HOST, config.RADIUS_ACCT_PORT),
    )

    log.info(
        "RADIUS Proxy started | auth=:%d acct=:%d",
        config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT,
    )

    # Initial routing table load
    routing.refresh()

    # Heartbeat + refresh loop
    async def _maintenance_loop():
        while True:
            await asyncio.sleep(config.HEARTBEAT_INTERVAL_SECONDS)
            routing.heartbeat(config.PROXY_ID, time.time() - start_time)
            routing.ensure_fresh()

    try:
        await _maintenance_loop()
    finally:
        auth_transport.close()
        acct_transport.close()
