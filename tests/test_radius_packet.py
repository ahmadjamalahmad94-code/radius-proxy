"""Unit tests for radius_packet.py — يجب أن تنجح قبل أي نشر في الإنتاج.

يغطّي:
  1. _replace_attr_value — الخلل الأصلي (User-Name قبل User-Password)
  2. replace_secret_in_packet — Access-Request + Accounting-Request
  3. rebuild_response — التحقق من الـ authenticator وإعادة حسابه
  4. تشفير/فك تشفير كلمة المرور (RFC 2865 §5.2)
  5. parse + build round-trip
  6. accounting_request_authenticator
  7. RouteEntry + RoutingTable.is_allowed_chr (fail-closed بالافتراضي)
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

# Allow running from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import radius_packet as rp

# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

CHR_SECRET    = "chr-secret-test"
TARGET_SECRET = "target-secret-test"
PASSWORD      = "p@ssw0rd"


def _build_access_request(
    username: str = "user@client1",
    password: str = PASSWORD,
    secret: str = CHR_SECRET,
    auth: bytes | None = None,
    ident: int = 42,
) -> tuple[bytes, bytes]:
    """Returns (raw_packet, request_authenticator)."""
    if auth is None:
        auth = rp.request_authenticator()
    enc = rp._encrypt_user_password(password.encode(), secret, auth)
    attrs = [
        (rp.ATTR_USER_NAME,     username.encode()),
        (rp.ATTR_USER_PASSWORD, enc),
        (rp.ATTR_NAS_IP_ADDRESS, b"\xc0\xa8\x01\x01"),
    ]
    return rp.build(rp.CODE_ACCESS_REQUEST, ident, auth, attrs), auth


def _build_access_request_pw_first(
    username: str = "user@client1",
    password: str = PASSWORD,
    secret: str = CHR_SECRET,
    ident: int = 7,
) -> tuple[bytes, bytes]:
    """Access-Request with User-Password BEFORE User-Name."""
    auth = rp.request_authenticator()
    enc = rp._encrypt_user_password(password.encode(), secret, auth)
    attrs = [
        (rp.ATTR_USER_PASSWORD, enc),              # password first
        (rp.ATTR_USER_NAME,     username.encode()),
        (rp.ATTR_NAS_IP_ADDRESS, b"\xc0\xa8\x02\x02"),
        (rp.ATTR_NAS_PORT,       struct.pack("!I", 1234)),
    ]
    return rp.build(rp.CODE_ACCESS_REQUEST, ident, auth, attrs), auth


def _build_accounting_request(
    username: str = "user@client1",
    secret: str = CHR_SECRET,
    ident: int = 10,
) -> bytes:
    """Build a valid Accounting-Request signed with ``secret``."""
    attrs = [
        (rp.ATTR_USER_NAME,        username.encode()),
        (rp.ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)),   # Acct-Start
        (rp.ATTR_ACCT_SESSION_ID,  b"sess-abc-001"),
        (rp.ATTR_NAS_IP_ADDRESS,   b"\xc0\xa8\x01\x01"),
    ]
    attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    length = rp.HEADER_SIZE + len(attrs_bytes)
    auth = rp.accounting_request_authenticator(
        rp.CODE_ACCOUNTING_REQUEST, ident, length, attrs_bytes, secret,
    )
    return rp.build(rp.CODE_ACCOUNTING_REQUEST, ident, auth, attrs)


def _build_access_response(
    code: int,
    ident: int,
    request_auth: bytes,
    secret: str,
    attrs: list | None = None,
) -> bytes:
    """Build a valid Access-Accept / Access-Reject response."""
    if attrs is None:
        attrs = []
    attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    length = rp.HEADER_SIZE + len(attrs_bytes)
    auth = rp.response_authenticator(code, ident, length, request_auth, attrs_bytes, secret)
    return struct.pack("!BBH", code, ident, length) + auth + attrs_bytes


# ─────────────────────────────────────────────────────────────────
# 1. _replace_attr_value
# ─────────────────────────────────────────────────────────────────

class TestReplaceAttrValue:
    """Issue 1 — the original code raised IndexError when User-Password
    was not the first attribute."""

    def test_user_name_before_password(self):
        """Normal Access-Request: User-Name(1) then User-Password(2)."""
        raw, auth = _build_access_request()
        pkt = rp.parse(raw)

        old_enc = pkt.get_attr(rp.ATTR_USER_PASSWORD)
        assert old_enc is not None

        new_enc = b"\xff" * 16  # arbitrary replacement
        result = rp._replace_attr_value(bytearray(raw), rp.ATTR_USER_PASSWORD, new_enc)
        rebuilt = rp.parse(bytes(result))

        # Password replaced
        assert rebuilt.get_attr(rp.ATTR_USER_PASSWORD) == new_enc
        # Username untouched
        assert rebuilt.get_attr(rp.ATTR_USER_NAME) == b"user@client1"
        # NAS-IP untouched
        assert rebuilt.get_attr(rp.ATTR_NAS_IP_ADDRESS) == b"\xc0\xa8\x01\x01"

    def test_password_first(self):
        """User-Password(2) before User-Name(1) — must also work."""
        raw, auth = _build_access_request_pw_first()
        pkt = rp.parse(raw)

        new_enc = b"\xab" * 16
        result = rp._replace_attr_value(bytearray(raw), rp.ATTR_USER_PASSWORD, new_enc)
        rebuilt = rp.parse(bytes(result))

        assert rebuilt.get_attr(rp.ATTR_USER_PASSWORD) == new_enc
        assert rebuilt.get_attr(rp.ATTR_USER_NAME) == b"user@client1"
        assert rebuilt.get_attr(rp.ATTR_NAS_IP_ADDRESS) == b"\xc0\xa8\x02\x02"
        assert rebuilt.get_attr(rp.ATTR_NAS_PORT) == struct.pack("!I", 1234)

    def test_multiple_attributes_after_password(self):
        """Several attributes following User-Password — all must be preserved."""
        auth = rp.request_authenticator()
        enc = rp._encrypt_user_password(PASSWORD.encode(), CHR_SECRET, auth)
        attrs = [
            (rp.ATTR_USER_NAME,          b"user@client1"),
            (rp.ATTR_USER_PASSWORD,      enc),
            (rp.ATTR_NAS_IP_ADDRESS,     b"\x0a\x00\x00\x01"),
            (rp.ATTR_NAS_PORT,           struct.pack("!I", 9999)),
            (rp.ATTR_CALLING_STATION_ID, b"00-11-22-33-44-55"),
            (rp.ATTR_NAS_IDENTIFIER,     b"nas-test"),
        ]
        raw = rp.build(rp.CODE_ACCESS_REQUEST, 1, auth, attrs)
        new_enc = b"\x12" * 16

        result = rp._replace_attr_value(bytearray(raw), rp.ATTR_USER_PASSWORD, new_enc)
        rebuilt = rp.parse(bytes(result))

        assert rebuilt.get_attr(rp.ATTR_USER_PASSWORD)      == new_enc
        assert rebuilt.get_attr(rp.ATTR_USER_NAME)          == b"user@client1"
        assert rebuilt.get_attr(rp.ATTR_NAS_IP_ADDRESS)     == b"\x0a\x00\x00\x01"
        assert rebuilt.get_attr(rp.ATTR_NAS_PORT)           == struct.pack("!I", 9999)
        assert rebuilt.get_attr(rp.ATTR_CALLING_STATION_ID) == b"00-11-22-33-44-55"
        assert rebuilt.get_attr(rp.ATTR_NAS_IDENTIFIER)     == b"nas-test"

    def test_replace_preserves_attribute_count(self):
        """Replacement must not add or remove attributes."""
        raw, _ = _build_access_request()
        result = rp._replace_attr_value(bytearray(raw), rp.ATTR_USER_PASSWORD, b"\x00" * 16)
        orig_attrs = rp._parse_attributes(raw)
        new_attrs  = rp._parse_attributes(bytes(result))
        assert len(orig_attrs) == len(new_attrs)

    def test_replace_nonexistent_attr_is_noop(self):
        """Replacing an attr that doesn't exist must return packet unchanged."""
        raw, _ = _build_access_request()
        result = rp._replace_attr_value(bytearray(raw), rp.ATTR_NAS_PORT, b"\x00\x00\x00\x01")
        # NAS-Port was not present — attrs length unchanged
        assert rp._parse_attributes(bytes(result)) == rp._parse_attributes(raw)


# ─────────────────────────────────────────────────────────────────
# 2. Password encryption / decryption (RFC 2865 §5.2)
# ─────────────────────────────────────────────────────────────────

class TestPasswordCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        auth = rp.request_authenticator()
        enc = rp._encrypt_user_password(PASSWORD.encode(), CHR_SECRET, auth)
        dec = rp._decrypt_user_password(enc, CHR_SECRET, auth)
        assert dec == PASSWORD.encode()

    def test_encrypt_different_secret_gives_different_ciphertext(self):
        auth = rp.request_authenticator()
        enc1 = rp._encrypt_user_password(PASSWORD.encode(), "secret-a", auth)
        enc2 = rp._encrypt_user_password(PASSWORD.encode(), "secret-b", auth)
        assert enc1 != enc2

    def test_encrypt_length_multiple_of_16(self):
        auth = rp.request_authenticator()
        for pw in [b"x", b"short", b"exactly16chars!!", b"seventeen_chars!!"]:
            enc = rp._encrypt_user_password(pw, CHR_SECRET, auth)
            assert len(enc) % 16 == 0

    def test_decrypt_with_wrong_secret_gives_garbage(self):
        auth = rp.request_authenticator()
        enc = rp._encrypt_user_password(PASSWORD.encode(), CHR_SECRET, auth)
        dec = rp._decrypt_user_password(enc, "wrong-secret", auth)
        assert dec != PASSWORD.encode()


# ─────────────────────────────────────────────────────────────────
# 3. replace_secret_in_packet — Access-Request
# ─────────────────────────────────────────────────────────────────

class TestReplaceSecretAccessRequest:
    def test_password_decryptable_with_new_secret(self):
        """After re-sign, password must decrypt correctly with new secret."""
        raw, auth = _build_access_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)

        new_enc = fwd_pkt.get_attr(rp.ATTR_USER_PASSWORD)
        assert new_enc is not None
        dec = rp._decrypt_user_password(new_enc, TARGET_SECRET, auth)
        assert dec == PASSWORD.encode()

    def test_password_not_decryptable_with_old_secret_after_resign(self):
        """Old secret must no longer decrypt the re-signed password."""
        raw, auth = _build_access_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)

        new_enc = fwd_pkt.get_attr(rp.ATTR_USER_PASSWORD)
        dec_wrong = rp._decrypt_user_password(new_enc, CHR_SECRET, auth)
        assert dec_wrong != PASSWORD.encode()

    def test_authenticator_unchanged_for_access_request(self):
        """Access-Request authenticator is random — must NOT be changed."""
        raw, auth = _build_access_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)
        assert fwd_pkt.authenticator == auth

    def test_username_preserved(self):
        raw, _ = _build_access_request(username="alice@realm1")
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)
        assert fwd_pkt.username == "alice@realm1"

    def test_password_first_resign_works(self):
        """Issue 1 regression: User-Name before User-Password must not raise."""
        raw, auth = _build_access_request_pw_first()
        pkt = rp.parse(raw)
        # Must not raise IndexError
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)
        new_enc = fwd_pkt.get_attr(rp.ATTR_USER_PASSWORD)
        dec = rp._decrypt_user_password(new_enc, TARGET_SECRET, auth)
        assert dec == PASSWORD.encode()


# ─────────────────────────────────────────────────────────────────
# 4. replace_secret_in_packet — Accounting-Request (Issue 2)
# ─────────────────────────────────────────────────────────────────

class TestReplaceSecretAccountingRequest:
    def _verify_acct_auth(self, raw: bytes, secret: str) -> bool:
        """Verify Accounting-Request authenticator for ``raw`` using ``secret``."""
        pkt = rp.parse(raw)
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in pkt.attributes
        )
        length = rp.HEADER_SIZE + len(attrs_bytes)
        expected = rp.accounting_request_authenticator(
            pkt.code, pkt.identifier, length, attrs_bytes, secret,
        )
        return pkt.authenticator == expected

    def test_original_acct_request_has_valid_chr_auth(self):
        raw = _build_accounting_request()
        assert self._verify_acct_auth(raw, CHR_SECRET)

    def test_acct_auth_changes_after_resign(self):
        """Issue 2: Accounting-Request authenticator MUST change when secret changes."""
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        original_auth = pkt.authenticator

        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)

        # Authenticator must have changed
        assert fwd_pkt.authenticator != original_auth

    def test_acct_auth_valid_with_target_secret_after_resign(self):
        """Forwarded Accounting-Request authenticator must be valid for target secret."""
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        assert self._verify_acct_auth(forwarded, TARGET_SECRET)

    def test_acct_auth_invalid_with_chr_secret_after_resign(self):
        """After re-sign, old CHR secret must NOT validate the new authenticator."""
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        assert not self._verify_acct_auth(forwarded, CHR_SECRET)

    def test_acct_request_attributes_preserved(self):
        """Accounting attributes (session ID, status type, etc.) must survive re-sign."""
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)

        assert fwd_pkt.get_attr(rp.ATTR_ACCT_SESSION_ID)  == b"sess-abc-001"
        assert fwd_pkt.get_attr(rp.ATTR_ACCT_STATUS_TYPE) == struct.pack("!I", 1)
        assert fwd_pkt.get_attr(rp.ATTR_USER_NAME)         == b"user@client1"

    def test_acct_request_code_unchanged(self):
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        forwarded = rp.replace_secret_in_packet(pkt, CHR_SECRET, TARGET_SECRET)
        assert rp.parse(forwarded).code == rp.CODE_ACCOUNTING_REQUEST

    def test_same_secret_resign_produces_same_auth(self):
        """Re-signing with the same secret must be idempotent."""
        raw = _build_accounting_request()
        pkt = rp.parse(raw)
        fwd = rp.replace_secret_in_packet(pkt, CHR_SECRET, CHR_SECRET)
        assert rp.parse(fwd).authenticator == pkt.authenticator


# ─────────────────────────────────────────────────────────────────
# 5. rebuild_response (Issue 5)
# ─────────────────────────────────────────────────────────────────

class TestRebuildResponse:
    def _make_response_and_rebuild(self, code=rp.CODE_ACCESS_ACCEPT):
        raw_req, req_auth = _build_access_request()
        req_pkt = rp.parse(raw_req)

        # Simulate what the target RADIUS would send (signed with target secret)
        raw_resp = _build_access_response(code, req_pkt.identifier, req_auth, TARGET_SECRET)
        resp_pkt = rp.parse(raw_resp)

        # Rebuild for CHR
        rebuilt = rp.rebuild_response(
            resp_pkt,
            request_auth=req_auth,
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
        )
        return rp.parse(rebuilt), req_auth

    def test_response_authenticator_valid_for_chr_secret(self):
        """Rebuilt response authenticator must be verifiable with CHR secret."""
        rebuilt_pkt, req_auth = self._make_response_and_rebuild()
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in rebuilt_pkt.attributes
        )
        length = rp.HEADER_SIZE + len(attrs_bytes)
        expected = rp.response_authenticator(
            rebuilt_pkt.code, rebuilt_pkt.identifier,
            length, req_auth, attrs_bytes, CHR_SECRET,
        )
        assert rebuilt_pkt.authenticator == expected

    def test_response_authenticator_invalid_for_target_secret(self):
        """CHR secret and target secret must produce different authenticators."""
        rebuilt_pkt, req_auth = self._make_response_and_rebuild()
        attrs_bytes = b"".join(
            bytes([t, len(v) + 2]) + v for t, v in rebuilt_pkt.attributes
        )
        length = rp.HEADER_SIZE + len(attrs_bytes)
        wrong = rp.response_authenticator(
            rebuilt_pkt.code, rebuilt_pkt.identifier,
            length, req_auth, attrs_bytes, TARGET_SECRET,
        )
        assert rebuilt_pkt.authenticator != wrong

    def test_rebuild_access_reject(self):
        rebuilt_pkt, _ = self._make_response_and_rebuild(rp.CODE_ACCESS_REJECT)
        assert rebuilt_pkt.code == rp.CODE_ACCESS_REJECT

    def test_rebuild_response_with_verify_auth(self):
        """verify_auth param: target response is verified with forwarded auth,
        but CHR response is computed with original request_auth."""
        raw_req, req_auth = _build_access_request()
        req_pkt = rp.parse(raw_req)

        # For Access-Request, fwd_auth == req_auth (auth not changed)
        fwd_auth = req_auth
        raw_resp = _build_access_response(
            rp.CODE_ACCESS_ACCEPT, req_pkt.identifier, fwd_auth, TARGET_SECRET,
        )
        resp_pkt = rp.parse(raw_resp)
        rebuilt = rp.rebuild_response(
            resp_pkt,
            request_auth=req_auth,
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            verify_auth=fwd_auth,
        )
        rebuilt_pkt = rp.parse(rebuilt)
        # Must be valid for CHR secret + original req_auth
        attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in rebuilt_pkt.attributes)
        length = rp.HEADER_SIZE + len(attrs_bytes)
        expected = rp.response_authenticator(
            rebuilt_pkt.code, rebuilt_pkt.identifier, length,
            req_auth, attrs_bytes, CHR_SECRET,
        )
        assert rebuilt_pkt.authenticator == expected

    def test_rebuild_response_accounting(self):
        """Accounting-Response: forwarded auth (A2) != original CHR auth (A1).
        CHR response must be computed with A1 + chr_secret."""
        acct_raw = _build_accounting_request()
        acct_pkt = rp.parse(acct_raw)
        original_auth = acct_pkt.authenticator   # A1

        # Re-sign for target (changes authenticator to A2)
        forwarded = rp.replace_secret_in_packet(acct_pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)
        fwd_auth = fwd_pkt.authenticator          # A2 — different from A1

        assert fwd_auth != original_auth          # sanity check

        # Target RADIUS sends Accounting-Response signed with A2 + target_secret
        attrs_bytes = b""
        length = rp.HEADER_SIZE
        target_resp_auth = rp.response_authenticator(
            rp.CODE_ACCOUNTING_RESPONSE, acct_pkt.identifier,
            length, fwd_auth, attrs_bytes, TARGET_SECRET,
        )
        raw_resp = struct.pack("!BBH", rp.CODE_ACCOUNTING_RESPONSE,
                               acct_pkt.identifier, length) + target_resp_auth

        resp_pkt = rp.parse(raw_resp)

        # Rebuild for CHR: must use A1 for CHR recomputation, A2 for verification
        rebuilt = rp.rebuild_response(
            resp_pkt,
            request_auth=original_auth,   # A1 — what CHR expects
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            verify_auth=fwd_auth,         # A2 — what target used to sign
        )
        rebuilt_pkt = rp.parse(rebuilt)

        # CHR verifies response with A1 + chr_secret
        expected_chr = rp.response_authenticator(
            rp.CODE_ACCOUNTING_RESPONSE, acct_pkt.identifier,
            rp.HEADER_SIZE, original_auth, b"", CHR_SECRET,
        )
        assert rebuilt_pkt.authenticator == expected_chr


# ─────────────────────────────────────────────────────────────────
# 6. parse + build round-trip
# ─────────────────────────────────────────────────────────────────

class TestParseAndBuild:
    def test_parse_access_request(self):
        raw, auth = _build_access_request()
        pkt = rp.parse(raw)
        assert pkt.code == rp.CODE_ACCESS_REQUEST
        assert pkt.authenticator == auth
        assert pkt.username == "user@client1"
        assert pkt.realm == "client1"

    def test_build_parse_roundtrip(self):
        auth = os.urandom(16)
        attrs = [
            (rp.ATTR_USER_NAME, b"bob@realm2"),
            (rp.ATTR_NAS_IP_ADDRESS, b"\x01\x02\x03\x04"),
        ]
        raw = rp.build(rp.CODE_ACCESS_REQUEST, 99, auth, attrs)
        pkt = rp.parse(raw)
        assert pkt.code == rp.CODE_ACCESS_REQUEST
        assert pkt.identifier == 99
        assert pkt.authenticator == auth
        assert pkt.get_attr(rp.ATTR_USER_NAME) == b"bob@realm2"

    def test_parse_rejects_short_packet(self):
        with pytest.raises(rp.RadiusError):
            rp.parse(b"\x01\x01\x00\x10")  # too short (16 < 20)

    def test_parse_rejects_truncated_packet(self):
        raw, _ = _build_access_request()
        with pytest.raises(rp.RadiusError):
            rp.parse(raw[:-5])  # truncated

    def test_realm_extraction_with_at(self):
        raw, _ = _build_access_request(username="john@example.com")
        pkt = rp.parse(raw)
        assert pkt.realm == "example.com"

    def test_realm_empty_without_at(self):
        raw, _ = _build_access_request(username="norealmuser")
        pkt = rp.parse(raw)
        assert pkt.realm == ""

    def test_realm_uses_last_at(self):
        """RFC: use rightmost @ (user@host@realm — realm is last)."""
        raw, _ = _build_access_request(username="user@host@myrealm")
        pkt = rp.parse(raw)
        assert pkt.realm == "myrealm"


# ─────────────────────────────────────────────────────────────────
# 7. accounting_request_authenticator
# ─────────────────────────────────────────────────────────────────

class TestAccountingRequestAuthenticator:
    def test_known_value(self):
        """Verify against a hand-computed value (RFC 2866 §3)."""
        code    = rp.CODE_ACCOUNTING_REQUEST
        ident   = 1
        attrs   = b"\x01\x08user"  # User-Name = "user"
        length  = rp.HEADER_SIZE + len(attrs)
        secret  = "testing123"
        result  = rp.accounting_request_authenticator(code, ident, length, attrs, secret)
        # Re-derive independently
        data = (
            bytes([code, ident])
            + struct.pack("!H", length)
            + b"\x00" * 16
            + attrs
            + secret.encode()
        )
        import hashlib
        expected = hashlib.md5(data).digest()
        assert result == expected

    def test_different_secret_different_auth(self):
        attrs  = b"\x01\x0auser@test"
        length = rp.HEADER_SIZE + len(attrs)
        a1 = rp.accounting_request_authenticator(4, 5, length, attrs, "secret-1")
        a2 = rp.accounting_request_authenticator(4, 5, length, attrs, "secret-2")
        assert a1 != a2

    def test_output_is_16_bytes(self):
        result = rp.accounting_request_authenticator(4, 1, 20, b"", "s")
        assert len(result) == 16


# ─────────────────────────────────────────────────────────────────
# 8. RoutingTable.is_allowed_chr (Issue 4)
# ─────────────────────────────────────────────────────────────────

class TestRoutingTableChrAllowlist:
    """Test the fail-closed / fail-open CHR allowlist behaviour."""

    def _make_routing(self, fail_open: bool):
        from routing_table import RoutingTable
        # Stub a RoutingTable without hitting the network
        rt = RoutingTable.__new__(RoutingTable)
        rt._allowed_chr_ips = set()
        rt._fail_open_chr   = fail_open
        rt._routes          = {}
        rt._last_refresh    = 0
        rt._stats           = {
            "requests_total": 0, "requests_accepted": 0,
            "requests_rejected": 0, "requests_error": 0,
            "realms_not_found": set(),
        }
        return rt

    def test_empty_allowlist_fail_closed_rejects_all(self):
        """Production default: empty allowlist → reject every source IP."""
        rt = self._make_routing(fail_open=False)
        assert rt.is_allowed_chr("1.2.3.4") is False
        assert rt.is_allowed_chr("10.0.0.1") is False

    def test_empty_allowlist_fail_open_allows_all(self):
        """Dev mode: empty allowlist + fail_open=True → allow any IP."""
        rt = self._make_routing(fail_open=True)
        assert rt.is_allowed_chr("1.2.3.4") is True

    def test_non_empty_allowlist_allows_known_ip(self):
        rt = self._make_routing(fail_open=False)
        rt._allowed_chr_ips = {"192.168.1.10", "10.0.0.5"}
        assert rt.is_allowed_chr("192.168.1.10") is True
        assert rt.is_allowed_chr("10.0.0.5") is True

    def test_non_empty_allowlist_rejects_unknown_ip(self):
        rt = self._make_routing(fail_open=False)
        rt._allowed_chr_ips = {"192.168.1.10"}
        assert rt.is_allowed_chr("9.9.9.9") is False

    def test_fail_open_flag_irrelevant_when_allowlist_populated(self):
        """Once IPs are loaded, fail_open has no effect."""
        for fail_open in (True, False):
            rt = self._make_routing(fail_open=fail_open)
            rt._allowed_chr_ips = {"10.10.10.1"}
            assert rt.is_allowed_chr("10.10.10.1") is True
            assert rt.is_allowed_chr("99.99.99.99") is False


# ─────────────────────────────────────────────────────────────────
# 9. Full forward pipeline smoke test
# ─────────────────────────────────────────────────────────────────

class TestForwardPipeline:
    """End-to-end simulation: CHR → Proxy → target RADIUS → CHR."""

    def test_access_request_full_pipeline(self):
        """Simulate a full Access-Accept round-trip."""
        # Step 1: CHR builds Access-Request
        raw_req, req_auth = _build_access_request()
        chr_pkt = rp.parse(raw_req)

        # Step 2: Proxy re-signs for target
        forwarded = rp.replace_secret_in_packet(chr_pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)

        # Verify password is correct for target secret
        enc = fwd_pkt.get_attr(rp.ATTR_USER_PASSWORD)
        assert rp._decrypt_user_password(enc, TARGET_SECRET, req_auth) == PASSWORD.encode()

        # Step 3: Target RADIUS responds (Access-Accept)
        raw_resp = _build_access_response(
            rp.CODE_ACCESS_ACCEPT, fwd_pkt.identifier, fwd_pkt.authenticator, TARGET_SECRET,
        )
        target_resp = rp.parse(raw_resp)

        # Step 4: Proxy rebuilds response for CHR
        rebuilt_raw = rp.rebuild_response(
            target_resp,
            request_auth=req_auth,                    # original CHR auth
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            verify_auth=fwd_pkt.authenticator,        # == req_auth for Access-Request
        )
        chr_resp = rp.parse(rebuilt_raw)

        # CHR verifies response authenticator
        assert rp.verify_response_authenticator(chr_resp, req_auth, CHR_SECRET)
        assert chr_resp.code == rp.CODE_ACCESS_ACCEPT

    def test_accounting_request_full_pipeline(self):
        """Simulate a full Accounting-Request round-trip with correct re-signing."""
        # Step 1: CHR sends Accounting-Request (A1)
        raw_acct = _build_accounting_request()
        chr_pkt = rp.parse(raw_acct)
        a1 = chr_pkt.authenticator

        # Step 2: Proxy re-signs (authenticator changes to A2)
        forwarded = rp.replace_secret_in_packet(chr_pkt, CHR_SECRET, TARGET_SECRET)
        fwd_pkt = rp.parse(forwarded)
        a2 = fwd_pkt.authenticator
        assert a1 != a2  # must have changed

        # Verify A2 is valid for target secret
        attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in fwd_pkt.attributes)
        length = rp.HEADER_SIZE + len(attrs_bytes)
        assert fwd_pkt.authenticator == rp.accounting_request_authenticator(
            rp.CODE_ACCOUNTING_REQUEST, fwd_pkt.identifier, length, attrs_bytes, TARGET_SECRET,
        )

        # Step 3: Target sends Accounting-Response (signed with A2)
        acct_resp_auth = rp.response_authenticator(
            rp.CODE_ACCOUNTING_RESPONSE, chr_pkt.identifier,
            rp.HEADER_SIZE, a2, b"", TARGET_SECRET,
        )
        raw_resp = (
            struct.pack("!BBH", rp.CODE_ACCOUNTING_RESPONSE, chr_pkt.identifier, rp.HEADER_SIZE)
            + acct_resp_auth
        )
        target_resp = rp.parse(raw_resp)

        # Step 4: Proxy rebuilds for CHR (must use A1 for CHR auth, A2 for verify)
        rebuilt_raw = rp.rebuild_response(
            target_resp,
            request_auth=a1,              # A1 — what CHR expects
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            verify_auth=a2,               # A2 — what target used
        )
        chr_resp = rp.parse(rebuilt_raw)

        # CHR verifies response using A1 + chr_secret
        assert rp.verify_response_authenticator(chr_resp, a1, CHR_SECRET)


# ─────────────────────────────────────────────────────────────────
# 10. rebuild_response strict_verify (PROXY_STRICT_RESPONSE_VERIFY)
# ─────────────────────────────────────────────────────────────────

class TestRebuildResponseStrictVerify:
    """Tests for the strict_verify parameter added in the hardening pass.

    Covers PROXY_STRICT_RESPONSE_VERIFY=true/false behaviour:
      - False (dev default): warn on mismatch, still return rebuilt bytes.
      - True  (prod default): raise RadiusError on mismatch — caller drops.
    """

    def _tampered_response(self):
        """Return a response packet whose authenticator is random garbage."""
        raw_req, req_auth = _build_access_request()
        req_pkt = rp.parse(raw_req)
        wrong_auth = os.urandom(16)
        raw_resp = (
            struct.pack("!BBH", rp.CODE_ACCESS_ACCEPT, req_pkt.identifier, rp.HEADER_SIZE)
            + wrong_auth
        )
        return rp.parse(raw_resp), req_auth

    def _valid_response(self):
        """Return a properly signed response + original request auth."""
        raw_req, req_auth = _build_access_request()
        req_pkt = rp.parse(raw_req)
        raw_resp = _build_access_response(
            rp.CODE_ACCESS_ACCEPT, req_pkt.identifier, req_auth, TARGET_SECRET,
        )
        return rp.parse(raw_resp), req_auth

    # ── strict_verify=False (lenient / dev) ──────────────────────────────

    def test_lenient_tampered_returns_bytes(self):
        """strict_verify=False (default): tampered response is forwarded."""
        resp_pkt, req_auth = self._tampered_response()
        result = rp.rebuild_response(
            resp_pkt,
            request_auth=req_auth,
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            strict_verify=False,
        )
        assert isinstance(result, bytes)
        assert len(result) >= rp.HEADER_SIZE

    def test_lenient_tampered_logs_warning(self, caplog):
        """strict_verify=False: a WARNING is logged on mismatch."""
        import logging
        resp_pkt, req_auth = self._tampered_response()
        with caplog.at_level(logging.WARNING, logger="radius_packet"):
            rp.rebuild_response(
                resp_pkt,
                request_auth=req_auth,
                old_secret=TARGET_SECRET,
                new_secret=CHR_SECRET,
                strict_verify=False,
            )
        assert any("mismatch" in m.lower() for m in caplog.messages), \
            "Expected a WARNING about authenticator mismatch"

    def test_default_strict_verify_is_false(self):
        """Omitting strict_verify must default to False (lenient)."""
        resp_pkt, req_auth = self._tampered_response()
        # Must NOT raise
        result = rp.rebuild_response(
            resp_pkt,
            request_auth=req_auth,
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
        )
        assert isinstance(result, bytes)

    # ── strict_verify=True (strict / production) ─────────────────────────

    def test_strict_tampered_raises_radius_error(self):
        """strict_verify=True: RadiusError raised on authenticator mismatch."""
        resp_pkt, req_auth = self._tampered_response()
        with pytest.raises(rp.RadiusError, match="[Mm]ismatch"):
            rp.rebuild_response(
                resp_pkt,
                request_auth=req_auth,
                old_secret=TARGET_SECRET,
                new_secret=CHR_SECRET,
                strict_verify=True,
            )

    def test_strict_valid_response_no_raise(self):
        """strict_verify=True: no exception when authenticator is correct."""
        resp_pkt, req_auth = self._valid_response()
        result = rp.rebuild_response(
            resp_pkt,
            request_auth=req_auth,
            old_secret=TARGET_SECRET,
            new_secret=CHR_SECRET,
            strict_verify=True,
        )
        assert isinstance(result, bytes)
        assert rp.verify_response_authenticator(rp.parse(result), req_auth, CHR_SECRET)

    def test_strict_error_message_contains_code_and_id(self):
        """RadiusError message must include packet code and identifier."""
        resp_pkt, req_auth = self._tampered_response()
        with pytest.raises(rp.RadiusError) as exc_info:
            rp.rebuild_response(
                resp_pkt,
                request_auth=req_auth,
                old_secret=TARGET_SECRET,
                new_secret=CHR_SECRET,
                strict_verify=True,
            )
        msg = str(exc_info.value)
        assert "code=" in msg or str(rp.CODE_ACCESS_ACCEPT) in msg


# ─────────────────────────────────────────────────────────────────
# 11. PROXY_ACCT_TIMEOUT_MODE normalization
# ─────────────────────────────────────────────────────────────────

class TestAcctTimeoutModeNormalization:
    """Tests for _normalize_acct_timeout_mode — covers canonical names
    and deprecated aliases (backward compatibility)."""

    @staticmethod
    def _normalize(raw: str) -> str:
        from config import _normalize_acct_timeout_mode
        return _normalize_acct_timeout_mode(raw)

    # Canonical names — must pass through unchanged
    def test_strict_canonical(self):
        assert self._normalize("strict") == "strict"

    def test_ack_on_timeout_canonical(self):
        assert self._normalize("ack_on_timeout") == "ack_on_timeout"

    # Deprecated aliases — must map to canonical equivalents
    def test_drop_maps_to_strict(self):
        """Legacy 'drop' → 'strict'."""
        assert self._normalize("drop") == "strict"

    def test_fake_ack_maps_to_ack_on_timeout(self):
        """Legacy 'fake_ack' → 'ack_on_timeout'."""
        assert self._normalize("fake_ack") == "ack_on_timeout"

    # Unknown values — safe default
    def test_unknown_value_defaults_to_strict(self):
        assert self._normalize("garbage") == "strict"
        assert self._normalize("") == "strict"

    # Case insensitivity
    def test_case_insensitive_canonical(self):
        assert self._normalize("STRICT") == "strict"
        assert self._normalize("ACK_ON_TIMEOUT") == "ack_on_timeout"

    def test_case_insensitive_aliases(self):
        assert self._normalize("DROP") == "strict"
        assert self._normalize("FAKE_ACK") == "ack_on_timeout"

    # Deprecated aliases emit a deprecation WARNING
    def test_drop_alias_logs_deprecation_warning(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="config"):
            self._normalize("drop")
        assert any("deprecated" in m.lower() for m in caplog.messages)

    def test_fake_ack_alias_logs_deprecation_warning_with_persistence_note(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="config"):
            self._normalize("fake_ack")
        assert any("deprecated" in m.lower() for m in caplog.messages)
        assert any("persistence" in m.lower() for m in caplog.messages)
