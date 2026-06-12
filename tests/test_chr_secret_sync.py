"""Tests for §6.1 — automatic CHR-shared-secret sync (panel-canonical) +
dual-accept rotation grace.

These tests pin the fix that permanently ends the owner's manual-secret-
matching pain (the 64-vs-34 incident in
``radius-module-admin/docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md`` §6.1):

  * The CHR shared secret is read PER PACKET from the authenticated
    routing-table the panel publishes — never from a frozen
    constructor-bound env value.
  * Precedence: PANEL value always wins. The ``PROXY_CHR_SECRET`` env is
    demoted to bootstrap-only, used solely before the first successful
    panel fetch (or when the panel hasn't supplied one).
  * Persistence: last-known panel secret persists to a 0600 state file
    so the proxy keeps relaying after a restart during a panel outage.
  * Dual-accept rotation: during a 24h grace window after rotation, the
    proxy validates Message-Authenticator against BOTH current and
    previous; the response is signed with whichever validated — so NO
    RADIUS packet drops while CHRs re-import scripts.
  * The secret value itself is never logged.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

import proxy as proxymod
import radius_packet as rp
import routing_table as rtmod


# ── helpers ───────────────────────────────────────────────────────────


def _state(tmp_path: str) -> str:
    return os.path.join(tmp_path, "chr-secret.json")


def _mock_panel(body: dict):
    class _Resp:
        status_code = 200

        @staticmethod
        def raise_for_status() -> None:
            pass

        @staticmethod
        def json() -> dict:
            return body

    return mock.patch.object(rtmod.requests, "get", return_value=_Resp())


def _payload(secret: str, *, with_routes=False) -> dict:
    """A frozen-shape routing-table payload that carries chr_shared_secret."""
    body: dict = {
        "ok": True,
        "routes": [],
        "chr_nodes": [{"name": "chr-1", "wg_data_ip": "10.98.0.11",
                       "public_ip": "203.0.113.1"}],
        "chr_shared_secret": secret,
    }
    if with_routes:
        body["routes"] = [{
            "realm": "client5", "customer_id": 5,
            "target_ip": "10.200.5.2", "auth_port": 1812, "acct_port": 1813,
            "secret": "customer-secret",
        }]
    return body


def _request_with_message_authenticator(
    user: str, secret: str, identifier: int = 7,
) -> bytes:
    """Build an Access-Request from a CHR including a valid Message-
    Authenticator signed with `secret`. Replicates what the CHR
    onboarding script wires up (`require_message_authenticator = yes`)."""
    auth = rp.request_authenticator()
    attrs = [
        (1, user.encode()),                  # User-Name
        (80, b"\x00" * 16),                  # Message-Authenticator placeholder
    ]
    pkt = bytearray(rp.build(rp.CODE_ACCESS_REQUEST, identifier, auth, attrs))
    rp.recompute_message_authenticator(pkt, secret)
    return bytes(pkt)


# ── 1. Panel value beats env — by construction ───────────────────────


def test_panel_secret_wins_over_env(tmp_path):
    """Owner's #1 rule: when the panel publishes a value, the proxy uses
    it. The env value is bootstrap-only and immediately demoted."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        bootstrap_chr_secret="env-bootstrap-secret",
        chr_secret_state_path=_state(str(tmp_path)),
    )
    # Before any refresh, env is the only thing we have.
    assert rt.chr_secret() == "env-bootstrap-secret"

    panel_secret = "panel-canonical-secret-XYZ"
    with _mock_panel(_payload(panel_secret)):
        assert rt.refresh() is True

    assert rt.chr_secret() == panel_secret


def test_env_demotion_warning_fires_exactly_once(tmp_path, caplog):
    """The deprecation warning must fire ONCE per process so the operator
    notices, but doesn't spam every refresh thereafter."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        bootstrap_chr_secret="env-stale-value",
        chr_secret_state_path=_state(str(tmp_path)),
    )
    panel_secret = "panel-different-value"

    with caplog.at_level("WARNING", logger="routing_table"):
        with _mock_panel(_payload(panel_secret)):
            rt.refresh()
            # ROOT INVARIANT: we adopt the PANEL value, not the env.
            assert rt.chr_secret() == panel_secret
            # Now refresh again — the panel still publishes the same
            # value, so we MUST NOT log a second warning.
            rt.refresh()
            rt.refresh()

    deprecation_lines = [
        rec.getMessage() for rec in caplog.records
        if "differs from the panel's" in rec.getMessage()
    ]
    assert len(deprecation_lines) == 1, deprecation_lines

    # And critically: the SECRET ITSELF is NEVER in any log line.
    for rec in caplog.records:
        msg = rec.getMessage()
        assert panel_secret not in msg
        assert "env-stale-value" not in msg


def test_empty_panel_field_does_not_clobber_existing(tmp_path):
    """A panel that hasn't configured the secret yet (chr_shared_secret
    field absent or empty) must NOT wipe our state — keep using whatever
    bootstrap/state we already have."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        bootstrap_chr_secret="env-bootstrap",
        chr_secret_state_path=_state(str(tmp_path)),
    )
    with _mock_panel({"ok": True, "routes": [], "chr_nodes": []}):
        rt.refresh()
    assert rt.chr_secret() == "env-bootstrap"   # untouched
    with _mock_panel({"ok": True, "routes": [], "chr_nodes": [],
                      "chr_shared_secret": ""}):
        rt.refresh()
    assert rt.chr_secret() == "env-bootstrap"   # still untouched


# ── 2. State file: 0600 + survives a restart ─────────────────────────


def test_secret_state_persists_across_routing_table_restart(tmp_path):
    """Owner's safety rule: a proxy restart while the panel is down must
    NOT drop RADIUS. The last-known panel secret is persisted in the
    0600 state file and re-loaded on instantiation."""
    state = _state(str(tmp_path))
    panel_secret = "long-strong-panel-secret-abcdef0123456789"

    rt1 = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=state,
    )
    with _mock_panel(_payload(panel_secret)):
        rt1.refresh()
    assert rt1.chr_secret() == panel_secret

    # State file must be 0600 (skip the mode-check on Windows because
    # POSIX permission bits are emulated; the value-persistence below
    # is what protects RADIUS on Linux production deploys).
    assert os.path.exists(state)
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(state).st_mode)
        assert mode == 0o600, oct(mode)

    # "Restart" — fresh RoutingTable instance pointed at the same state.
    rt2 = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=state,
    )
    assert rt2.chr_secret() == panel_secret


def test_state_file_is_pure_json_with_three_fields(tmp_path):
    """Schema check — the file content layout the rest of the system
    relies on (current / previous / rotated_at_unix)."""
    state = _state(str(tmp_path))
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=state,
    )
    with _mock_panel(_payload("first-secret")):
        rt.refresh()
    with open(state, encoding="utf-8") as f:
        data = json.load(f)
    assert set(data.keys()) == {"current", "previous", "rotated_at_unix"}
    assert data["current"] == "first-secret"
    assert data["previous"] == ""
    assert isinstance(data["rotated_at_unix"], (int, float))


# ── 3. Dual-accept rotation — current + previous inside grace ────────


def test_dual_accept_allows_previous_secret_within_grace(tmp_path):
    """The headline behavior: after a rotation, a CHR still using the OLD
    secret must keep authenticating until grace expires. No drops."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_grace_seconds=86400,
        chr_secret_state_path=_state(str(tmp_path)),
    )
    old_secret = "OLD-secret-on-CHR-not-yet-reimported"
    new_secret = "NEW-secret-just-rotated-on-panel"

    # Establish the old secret as current.
    with _mock_panel(_payload(old_secret)):
        rt.refresh()
    assert rt.chr_secret() == old_secret
    assert rt.previous_chr_secret_in_grace() is None

    # Rotate.
    with _mock_panel(_payload(new_secret)):
        rt.refresh()
    assert rt.chr_secret() == new_secret
    assert rt.previous_chr_secret_in_grace() == old_secret

    # A CHR still signing with the OLD secret can authenticate. The
    # proxy's validator must succeed against PREVIOUS (current would
    # fail because the CHR's MA is signed with the old key).
    raw_old = _request_with_message_authenticator("ghost@client5", old_secret)
    assert rp.verify_message_authenticator(raw_old, new_secret) is False
    assert rp.verify_message_authenticator(raw_old, old_secret) is True

    # And the brand-new CHR signs with the NEW secret — current matches.
    raw_new = _request_with_message_authenticator("ghost@client5", new_secret)
    assert rp.verify_message_authenticator(raw_new, new_secret) is True


def test_dual_accept_rejects_previous_after_grace_expires(tmp_path):
    """Once the 24h window closes, the previous secret stops being valid.
    A stuck-on-old-secret CHR will now fail Message-Authenticator — that
    is what surfaces the "you forgot to re-import scripts" condition."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_grace_seconds=86400,
        chr_secret_state_path=_state(str(tmp_path)),
    )
    with _mock_panel(_payload("old-1")):
        rt.refresh()
    with _mock_panel(_payload("new-2")):
        rt.refresh()
    assert rt.previous_chr_secret_in_grace() == "old-1"

    # Fast-forward past grace by mutating the rotation timestamp.
    rt._chr_secret_rotated_at = time.time() - 90_000   # > 86400s
    assert rt.previous_chr_secret_in_grace() is None


# ── 4. End-to-end: proxy._validate_request_secret picks the right one ─


def _routing_with_realm(tmp_path: str, current: str, previous: str = "",
                        grace: int = 86400) -> rtmod.RoutingTable:
    """Cook a routing table where current/previous are pre-loaded and
    a realm exists (so the proxy could forward if we let it)."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_grace_seconds=grace,
        chr_secret_state_path=_state(tmp_path),
    )
    # Establish current first.
    with _mock_panel(_payload(current, with_routes=True)):
        rt.refresh()
    if previous:
        with _mock_panel(_payload("rotated-once", with_routes=True)):
            rt.refresh()
        # Manually set previous to the asked value (simulates an earlier rotation
        # to `previous` then `current`).
        rt._chr_secret_previous = previous
        rt._chr_secret_current = current
        rt._chr_secret_rotated_at = time.time()
    # The allowlist was populated from the wg_data_ip in the payload.
    return rt


def test_proxy_validates_request_with_current_secret(tmp_path):
    """Steady-state: current secret validates the request, returned as-is."""
    rt = _routing_with_realm(str(tmp_path), current="curr-secret")
    proto = proxymod.RadiusProxyProtocol(
        rt, "env-bootstrap", asyncio.new_event_loop(),
        is_accounting=False,
    )
    raw = _request_with_message_authenticator("alice@client5", "curr-secret")
    assert proto._validate_request_secret(raw) == "curr-secret"
    proto._loop.close()


def test_proxy_validates_request_with_previous_secret_in_grace(tmp_path):
    """During rotation grace, a request signed with the OLD secret still
    authenticates. The validator returns the OLD secret so the rest of
    _handle re-signs / verifies with the secret the CHR is using."""
    rt = _routing_with_realm(
        str(tmp_path), current="new-secret", previous="old-secret",
    )
    proto = proxymod.RadiusProxyProtocol(
        rt, "env-bootstrap", asyncio.new_event_loop(),
        is_accounting=False,
    )
    raw_old_signed = _request_with_message_authenticator(
        "alice@client5", "old-secret",
    )
    assert proto._validate_request_secret(raw_old_signed) == "old-secret"
    proto._loop.close()


def test_proxy_rejects_request_signed_with_unrelated_secret(tmp_path):
    """A request signed with a secret unknown to the proxy must NOT
    validate against either current or previous — the validator
    returns None and the protocol drops the packet."""
    rt = _routing_with_realm(
        str(tmp_path), current="new-secret", previous="old-secret",
    )
    proto = proxymod.RadiusProxyProtocol(
        rt, "env-bootstrap", asyncio.new_event_loop(),
        is_accounting=False,
    )
    raw_unknown = _request_with_message_authenticator(
        "alice@client5", "totally-unrelated-secret",
    )
    assert proto._validate_request_secret(raw_unknown) is None
    proto._loop.close()


# ── 5. Re-sign uses the validating secret (no drops on CHR side) ─────


def _customer_access_reject(req: bytes, customer_secret: str) -> bytes:
    """Upstream customer RADIUS returns Access-Reject signed with
    CUSTOMER secret. The proxy will then verify with customer secret and
    re-sign for the CHR with the secret that validated the original
    request — which is the property under test."""
    import struct
    fwd = rp.parse(req)
    attrs_bytes = b""
    length = rp.HEADER_SIZE + len(attrs_bytes)
    auth = rp.response_authenticator(
        rp.CODE_ACCESS_REJECT, fwd.identifier, length,
        fwd.authenticator, attrs_bytes, customer_secret,
    )
    return struct.pack(
        "!BBH", rp.CODE_ACCESS_REJECT, fwd.identifier, length,
    ) + auth


def test_response_signed_with_validating_secret_during_rotation(tmp_path):
    """The end-to-end invariant: when a CHR-on-OLD-secret authenticates
    during grace, the proxy must re-sign the response with the OLD
    secret too. Anything else and the CHR drops the response on
    Response-Authenticator mismatch — which is the very thing dual-accept
    is supposed to prevent."""
    rt = _routing_with_realm(
        str(tmp_path), current="new-secret", previous="old-secret",
    )
    loop = asyncio.new_event_loop()
    try:
        sent: list[tuple[bytes, tuple]] = []

        class _Transport:
            def sendto(self, data, addr):
                sent.append((data, addr))

        proto = proxymod.RadiusProxyProtocol(
            rt, "env-bootstrap", loop,
            forward_timeout=1, is_accounting=False,
            strict_response_verify=True,
        )
        proto._transport = _Transport()

        async def _fake_forward(packet, _target):
            return _customer_access_reject(packet, "customer-secret")
        proto._forward = _fake_forward

        # CHR signs with OLD secret (it hasn't re-imported yet).
        req = _request_with_message_authenticator(
            "ghost@client5", "old-secret", identifier=42,
        )
        loop.run_until_complete(
            proto._handle(req, ("10.98.0.11", 45000)),
        )

        # The proxy sent exactly one Access-Reject back to the CHR.
        assert len(sent) == 1
        resp = rp.parse(sent[0][0])
        assert resp.code == rp.CODE_ACCESS_REJECT
        # The Response-Authenticator must be valid against the OLD secret
        # (the one the CHR will check with) — NOT the new one.
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in resp.attributes
        )
        old_expected = rp.response_authenticator(
            rp.CODE_ACCESS_REJECT, resp.identifier,
            rp.HEADER_SIZE + len(attrs_bytes),
            rp.parse(req).authenticator, attrs_bytes, "old-secret",
        )
        new_expected = rp.response_authenticator(
            rp.CODE_ACCESS_REJECT, resp.identifier,
            rp.HEADER_SIZE + len(attrs_bytes),
            rp.parse(req).authenticator, attrs_bytes, "new-secret",
        )
        assert resp.authenticator == old_expected
        assert resp.authenticator != new_expected
    finally:
        loop.close()


# ── 6. §6.4: heartbeat fingerprint is non-reversible + stable ────────


def test_heartbeat_fingerprint_present_and_does_not_reveal_secret(tmp_path):
    """The fingerprint is 16 hex chars (sha256 truncated). The full
    secret is never in it (one-way hash) — this is what the panel sees
    in /api/proxy/heartbeat for drift detection (§6.4)."""
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=_state(str(tmp_path)),
    )
    with _mock_panel(_payload("super-secret-no-leak")):
        rt.refresh()

    fp1 = rt.chr_secret_fingerprint()
    assert len(fp1) == 16
    int(fp1, 16)                                              # is hex
    assert "super-secret-no-leak" not in fp1

    # Same state → same fingerprint (idempotent).
    assert rt.chr_secret_fingerprint() == fp1

    # Rotate → fingerprint changes.
    with _mock_panel(_payload("rotated-again")):
        rt.refresh()
    fp2 = rt.chr_secret_fingerprint()
    assert fp2 != fp1


def test_heartbeat_payload_includes_fingerprint_and_grace_remaining(tmp_path):
    rt = rtmod.RoutingTable(
        "https://panel.example", "proxy-token",
        chr_secret_state_path=_state(str(tmp_path)),
    )
    with _mock_panel(_payload("first")):
        rt.refresh()

    captured: list[dict] = []

    class _OkResp:
        ok = True
        status_code = 200

    def _post(url, json=None, headers=None, timeout=None):
        captured.append({"url": url, "json": json, "headers": headers})
        return _OkResp()

    with mock.patch.object(rtmod.requests, "post", side_effect=_post):
        rt.heartbeat("proxy-test-01", uptime=12.3)

    assert captured, "heartbeat must POST"
    body = captured[0]["json"]
    assert isinstance(body["config_fingerprint"], str)
    assert len(body["config_fingerprint"]) == 16
    assert body["chr_secret_grace_remaining_s"] == 0      # no rotation yet
    # The secret itself must NOT leak into the heartbeat body.
    assert "first" not in json.dumps(body)
