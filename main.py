#!/usr/bin/env python3
"""نقطة دخول وكيل RADIUS المركزي.

الاستخدام:
    python main.py

متغيرات البيئة المطلوبة:
    ADMIN_BASE_URL           — عنوان لوحة التراخيص (مثال: https://panel.hoberadius.com)
    RADIUS_PROXY_SHARED_SECRET — سر مشترك بين الوكيل ولوحة التراخيص
    PROXY_CHR_SECRET         — السر المشترك بين عقد CHR والوكيل

متغيرات اختيارية:
    PROXY_LISTEN_HOST        — IP الاستماع (افتراضي: 0.0.0.0)
    PROXY_AUTH_PORT          — منفذ Auth (افتراضي: 1812)
    PROXY_ACCT_PORT          — منفذ Acct (افتراضي: 1813)
    PROXY_ROUTING_REFRESH    — دورة تحديث المسارات بالثواني (افتراضي: 60)
    PROXY_LOG_LEVEL          — مستوى التسجيل: DEBUG/INFO/WARNING (افتراضي: INFO)
    PROXY_ID                 — معرّف هذا الوكيل (يُولَّد تلقائيًا)
"""
import asyncio
import logging
import sys

# Allow running from this directory
import os
sys.path.insert(0, os.path.dirname(__file__))

from config import Config
from proxy import run_proxy
from routing_table import RoutingTable
from wg_provisioning import CachingPubkeyProvider


def _setup_logging(level: str) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def _check_config() -> None:
    errors = []
    if not Config.ADMIN_BASE_URL:
        errors.append("ADMIN_BASE_URL is not set")
    if not Config.PROXY_SHARED_SECRET:
        errors.append("RADIUS_PROXY_SHARED_SECRET is not set")
    if Config.CHR_SHARED_SECRET == "changeme-chr-secret":
        logging.warning("⚠️  Using default CHR shared secret — set PROXY_CHR_SECRET in production!")
    if errors:
        for e in errors:
            logging.critical("Config error: %s", e)
        sys.exit(1)


def main() -> None:
    _setup_logging(Config.LOG_LEVEL)
    log = logging.getLogger("main")

    _check_config()

    log.info("HobeRadius Central RADIUS Proxy")
    log.info("  Admin URL : %s", Config.ADMIN_BASE_URL)
    log.info("  Proxy ID  : %s", Config.PROXY_ID)
    log.info("  Auth port : %d", Config.RADIUS_AUTH_PORT)
    log.info("  Acct port : %d", Config.RADIUS_ACCT_PORT)
    log.info("  Refresh   : %ds", Config.ROUTING_REFRESH_SECONDS)

    # Live wg-data pubkey provider: publishes the proxy's CURRENT
    # `wg show wg-data public-key` value in every heartbeat so the
    # panel renders every CHR script with the right key. Cached for
    # PROXY_WG_PUBKEY_CACHE_TTL seconds — the key changes ~never; we
    # don't want to fork-exec on every 30s heartbeat. Empty result
    # (unprivileged / iface absent / wg missing) → heartbeat sends
    # "" and the panel falls back to its stored Setting.
    proxy_wg_data_pubkey = CachingPubkeyProvider(
        iface=Config.FLEET_WG_INTERFACE,
        wg_path=Config.FLEET_WG_BIN,
        ttl_seconds=Config.PROXY_WG_PUBKEY_CACHE_TTL,
    )

    routing = RoutingTable(
        admin_base_url=Config.ADMIN_BASE_URL,
        shared_secret=Config.PROXY_SHARED_SECRET,
        refresh_interval=Config.ROUTING_REFRESH_SECONDS,
        fail_open_chr=Config.FAIL_OPEN_CHR_ALLOWLIST,
        # §6.1 — env value becomes BOOTSTRAP-ONLY; the panel's
        # chr_shared_secret in /api/proxy/routing-table is the source of
        # truth on every refresh.
        bootstrap_chr_secret=Config.CHR_SHARED_SECRET,
        chr_secret_state_path=Config.CHR_SECRET_STATE_PATH,
        chr_secret_grace_seconds=Config.CHR_SECRET_GRACE_SECONDS,
        static_node_map=Config.FLEET_CHR_NODE_MAP,
        proxy_wg_data_pubkey_provider=proxy_wg_data_pubkey,
    )

    if Config.FAIL_OPEN_CHR_ALLOWLIST:
        log.warning(
            "⚠️  PROXY_FAIL_OPEN_CHR_ALLOWLIST=true — CHR allowlist is open. "
            "Only use this in development!"
        )

    try:
        asyncio.run(run_proxy(Config, routing))
    except KeyboardInterrupt:
        log.info("Proxy stopped by user.")
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
