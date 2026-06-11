"""Architectural guard: the proxy is NOT on the licensing/integration path.

Locks the contract documented in DEPLOY_PROXY.md (§ "Scope — what this proxy
does, and what it explicitly does NOT") so it cannot regress silently:

  * Proxy source contains ZERO references to ``/api/license``,
    ``/api/integration``, or backup URLs.
  * Every HTTP URL the proxy CONSTRUCTS at runtime sits under ``/api/proxy/``
    (no other namespace is reachable from a configured proxy).
  * Proxy code imports NO HTTP-server library (no aiohttp/Flask/FastAPI/
    Starlette/http.server). The proxy only opens UDP listeners + outbound
    HTTPS clients — never an inbound HTTP listener.

If you genuinely need to extend the proxy onto a new panel surface, add the
new ``/api/proxy/<thing>`` path to the allowlist below — do NOT add a
``/api/integration`` or ``/api/license`` path. Those belong to radius-module
↔ panel and must not transit the proxy.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

PROXY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROXY_ROOT))

import config as cfgmod
import enforcement as enf
import placement_hook as ph
import routing_table as rtmod
import telemetry as tel


# ── 1. Static grep: forbidden URL substrings nowhere in proxy source. ─

# Paths owned by other services that the proxy must NEVER speak.
FORBIDDEN_URL_FRAGMENTS = (
    "/api/license",
    "/api/integration",
    "/api/billing",
    "/api/backup",
    "/api/backups",
)

# Proxy source files (the runtime — not tests, not docs).
PROXY_SOURCES = sorted(
    p for p in PROXY_ROOT.glob("*.py") if p.name != "__init__.py"
)


def test_proxy_source_files_discovered():
    """Sanity: the glob actually finds the proxy modules, so a future rename
    can't silently turn the next test into a no-op."""
    names = {p.name for p in PROXY_SOURCES}
    # Spot-check the entry-point + the modules that construct outbound URLs.
    for required in ("main.py", "proxy.py", "config.py", "routing_table.py",
                     "telemetry.py", "placement_hook.py", "enforcement.py"):
        assert required in names, f"missing {required} in {names}"


def test_no_forbidden_url_fragments_in_proxy_source():
    """Hard line: not a single proxy .py mentions /api/license, /api/integration,
    /api/billing, or /api/backup(s). A diff that introduces one fails CI."""
    offenders: list[tuple[str, int, str, str]] = []
    for path in PROXY_SOURCES:
        text = path.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), 1):
            for fragment in FORBIDDEN_URL_FRAGMENTS:
                if fragment in line:
                    offenders.append((path.name, n, fragment, line.strip()))
    assert not offenders, (
        "Proxy source must not reference licensing/integration/backup URLs. "
        "These paths belong to radius-module ↔ panel, not the proxy. "
        f"Offenders: {offenders}"
    )


# ── 2. Runtime URL allowlist: every URL the proxy builds ⊂ /api/proxy/. ─

ALLOWED_PROXY_PATH_PREFIX = "/api/proxy/"


def _all_outbound_urls_from_config() -> list[tuple[str, str]]:
    """Enumerate every (label, url) the proxy will hit at runtime, given
    ``Config`` as evaluated from the environment + defaults.

    Mirrors what ``main.py``/``proxy._build_fleet_components`` actually wire
    up: a RoutingTable (3 URLs) plus the four fleet endpoints. Anything new
    that gets added must show up here AND start with /api/proxy/.
    """
    rt = rtmod.RoutingTable(
        cfgmod.Config.ADMIN_BASE_URL, cfgmod.Config.PROXY_SHARED_SECRET or "x",
    )
    urls = [
        ("routing_table.url", rt._url),
        ("routing_table.chr_nodes_url", rt._chr_nodes_url),
        ("routing_table.heartbeat_url", rt._heartbeat_url),
        ("config.telemetry_endpoint", cfgmod.Config.FLEET_TELEMETRY_ENDPOINT),
        ("config.placement_report_endpoint",
            cfgmod.Config.FLEET_PLACEMENT_REPORT_ENDPOINT),
        ("config.placement_decision_endpoint",
            cfgmod.Config.FLEET_PLACEMENT_DECISION_ENDPOINT),
        ("config.enforcement_endpoint",
            cfgmod.Config.FLEET_ENFORCEMENT_ENDPOINT),
    ]
    # And the actual attributes on the constructed fleet clients, in case a
    # future change builds a URL inside the constructor that diverges from
    # the Config value.
    telemetry = tel.TelemetryEmitter(
        endpoint=cfgmod.Config.FLEET_TELEMETRY_ENDPOINT,
        shared_secret="x", node_resolver=lambda _ip: None,
    )
    urls.append(("telemetry.endpoint", telemetry._endpoint))
    placement = ph.PlacementHook(
        report_endpoint=cfgmod.Config.FLEET_PLACEMENT_REPORT_ENDPOINT,
        decision_endpoint=cfgmod.Config.FLEET_PLACEMENT_DECISION_ENDPOINT,
        shared_secret="x", proxy_id="proxy-test",
        node_resolver=lambda _ip: None,
        local_candidates_provider=lambda: [],
    )
    urls.append(("placement.report_endpoint", placement._report_endpoint))
    urls.append(("placement.decision_endpoint", placement._decision_endpoint))
    reporter = enf.EnforcementReporter(
        endpoint=cfgmod.Config.FLEET_ENFORCEMENT_ENDPOINT,
        shared_secret="x", proxy_id="proxy-test",
    )
    urls.append(("enforcement.endpoint", reporter._endpoint))
    return urls


def _path_of(url: str) -> str:
    """Extract the path portion of an absolute HTTP(S) URL."""
    # We don't need urllib.parse for this — strip scheme://host.
    m = re.match(r"^https?://[^/]+(/.*)$", url)
    return m.group(1) if m else url


def test_every_constructed_outbound_url_is_under_api_proxy():
    """REAL assertion (not just prose): with Config evaluated from env +
    defaults, every URL the proxy will hit lives under /api/proxy/. If a
    future endpoint slips in under /api/integration, /api/license, or any
    other namespace, this test fails and points at the symbol that broke
    the rule."""
    violations = []
    for label, url in _all_outbound_urls_from_config():
        path = _path_of(url)
        if not path.startswith(ALLOWED_PROXY_PATH_PREFIX):
            violations.append((label, url, path))
        # Also reject the forbidden fragments outright (defense-in-depth in
        # case ADMIN_BASE_URL itself accidentally embeds one).
        for fragment in FORBIDDEN_URL_FRAGMENTS:
            if fragment in url:
                violations.append((label, url, f"contains {fragment!r}"))
    assert not violations, (
        f"Proxy constructed a URL outside {ALLOWED_PROXY_PATH_PREFIX!r}: "
        f"{violations}"
    )


# ── 3. No HTTP-server library is imported by any proxy module. ────────

# The proxy must not expose ANY inbound HTTP listener. The only sockets it
# opens are the two UDP RADIUS listeners + outbound clients (UDP CoA,
# HTTPS for /api/proxy/*). Any import of an HTTP-server framework would
# mean a new attack surface that doesn't belong here.
HTTP_SERVER_LIBRARY_PATTERNS = (
    # match `import foo` or `from foo[.bar] import ...`
    re.compile(r"^\s*(?:from|import)\s+aiohttp(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+flask(?:\.|\s|$)", re.IGNORECASE),
    re.compile(r"^\s*(?:from|import)\s+fastapi(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+starlette(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+uvicorn(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+hypercorn(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+http\.server(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+wsgiref(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+bottle(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+tornado(?:\.|\s|$)"),
    re.compile(r"^\s*(?:from|import)\s+sanic(?:\.|\s|$)"),
)


def test_no_http_server_library_imported_anywhere_in_proxy():
    """Defensive: a future PR cannot quietly add an HTTP listener to the
    proxy. The deployment guide promises the only inbound sockets are the
    UDP RADIUS ports; this test guards that promise at the import layer."""
    offenders: list[tuple[str, int, str]] = []
    for path in PROXY_SOURCES:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for pat in HTTP_SERVER_LIBRARY_PATTERNS:
                if pat.match(line):
                    offenders.append((path.name, n, line.strip()))
    assert not offenders, (
        "Proxy must not import any HTTP-server library. The proxy's only "
        "inbound sockets are the two UDP RADIUS listeners. "
        f"Offenders: {offenders}"
    )


# ── 4. requirements.txt sanity — no HTTP-server deps either. ──────────


def test_requirements_has_no_http_server_dependency():
    """A proxy that doesn't import an HTTP-server lib but still installs one
    is one accidental import away from a regression. Block at the dep layer
    too — the only network deps the proxy needs are an HTTPS client
    (requests) for outbound calls and asyncio (stdlib) for the UDP loops."""
    req_path = PROXY_ROOT / "requirements.txt"
    text = req_path.read_text(encoding="utf-8").lower()
    forbidden = ("aiohttp", "flask", "fastapi", "starlette", "uvicorn",
                 "hypercorn", "bottle", "tornado", "sanic")
    present = [name for name in forbidden if re.search(rf"^\s*{name}\b", text, re.MULTILINE)]
    assert not present, (
        f"requirements.txt installs an HTTP-server library ({present}); "
        "the proxy is UDP-listener-only and must not pull these in."
    )


# Marker so a stale glob (no files found) can't silently pass any test.
assert PROXY_SOURCES, "PROXY_SOURCES glob found no proxy modules"
_ = os  # keep os import referenced
