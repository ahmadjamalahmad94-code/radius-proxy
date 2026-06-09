"""تحليل وبناء حزم RADIUS (RFC 2865 / RFC 2866).

يُنفَّذ بدون مكتبات خارجية — المكتبة القياسية فقط.

بنية الحزمة:
  Code       (1 byte)
  Identifier (1 byte)
  Length     (2 bytes, big-endian, شامل 20 بايت الرأس)
  Authenticator (16 bytes)
  Attributes (متغير)

بنية كل Attribute:
  Type   (1 byte)
  Length (1 byte، شامل Type+Length)
  Value  (Length-2 bytes)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

_LOG = logging.getLogger(__name__)

# ── كودات الحزمة ───────────────────────────────────────────────────────
CODE_ACCESS_REQUEST      = 1
CODE_ACCESS_ACCEPT       = 2
CODE_ACCESS_REJECT       = 3
CODE_ACCOUNTING_REQUEST  = 4
CODE_ACCOUNTING_RESPONSE = 5
CODE_ACCESS_CHALLENGE    = 11

_CODE_NAMES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
}

# ── أنواع Attributes الأساسية ──────────────────────────────────────────
ATTR_USER_NAME             = 1
ATTR_USER_PASSWORD         = 2
ATTR_NAS_IP_ADDRESS        = 4
ATTR_NAS_PORT              = 5
ATTR_SERVICE_TYPE          = 6
ATTR_FRAMED_PROTOCOL       = 7
ATTR_FRAMED_IP_ADDRESS     = 8
ATTR_CALLING_STATION_ID    = 31
ATTR_NAS_IDENTIFIER        = 32
ATTR_ACCT_STATUS_TYPE      = 40
ATTR_ACCT_SESSION_ID       = 44
ATTR_MESSAGE_AUTHENTICATOR = 80

HEADER_SIZE = 20


class RadiusError(Exception):
    pass


@dataclass
class RadiusPacket:
    code: int
    identifier: int
    authenticator: bytes              # 16 bytes
    attributes: list[tuple[int, bytes]] = field(default_factory=list)
    raw: bytes = field(default=b"", repr=False)

    @property
    def code_name(self) -> str:
        return _CODE_NAMES.get(self.code, f"Code({self.code})")

    def get_attr(self, attr_type: int) -> Optional[bytes]:
        for t, v in self.attributes:
            if t == attr_type:
                return v
        return None

    def get_all_attrs(self, attr_type: int) -> list[bytes]:
        return [v for t, v in self.attributes if t == attr_type]

    @property
    def username(self) -> str:
        v = self.get_attr(ATTR_USER_NAME)
        return v.decode("utf-8", errors="replace") if v else ""

    @property
    def realm(self) -> str:
        """Extract realm from user@realm — returns '' if no @ present."""
        u = self.username
        idx = u.rfind("@")
        return u[idx + 1:].lower().strip() if idx >= 0 else ""


def parse(data: bytes) -> RadiusPacket:
    """Parse raw bytes into a RadiusPacket. Raises RadiusError on malformed data."""
    if len(data) < HEADER_SIZE:
        raise RadiusError(f"Packet too short: {len(data)} bytes")
    code, identifier, length = struct.unpack("!BBH", data[:4])
    if length < HEADER_SIZE or length > 4096:
        raise RadiusError(f"Invalid length field: {length}")
    if len(data) < length:
        raise RadiusError(f"Truncated packet: got {len(data)}, expected {length}")

    authenticator = data[4:20]
    attrs: list[tuple[int, bytes]] = []
    pos = HEADER_SIZE
    while pos < length:
        if pos + 2 > length:
            break
        attr_type = data[pos]
        attr_len = data[pos + 1]
        if attr_len < 2 or pos + attr_len > length:
            raise RadiusError(f"Malformed attribute at pos {pos}")
        value = data[pos + 2: pos + attr_len]
        attrs.append((attr_type, value))
        pos += attr_len

    return RadiusPacket(
        code=code,
        identifier=identifier,
        authenticator=authenticator,
        attributes=attrs,
        raw=data[:length],
    )


def build(code: int, identifier: int, authenticator: bytes,
          attributes: list[tuple[int, bytes]]) -> bytes:
    """Build a RADIUS packet from components."""
    attr_bytes = b"".join(
        bytes([t, len(v) + 2]) + v for t, v in attributes
    )
    length = HEADER_SIZE + len(attr_bytes)
    header = struct.pack("!BBH", code, identifier, length) + authenticator
    return header + attr_bytes


# ── Authenticator calculations ─────────────────────────────────────────

def request_authenticator() -> bytes:
    """Generate a random 16-byte Request-Authenticator (RFC 2865 §3)."""
    return os.urandom(16)


def response_authenticator(
    code: int,
    identifier: int,
    length: int,
    request_auth: bytes,
    attributes_bytes: bytes,
    secret: str,
) -> bytes:
    """Compute Response-Authenticator = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)."""
    data = (
        bytes([code])
        + bytes([identifier])
        + struct.pack("!H", length)
        + request_auth
        + attributes_bytes
        + secret.encode()
    )
    return hashlib.md5(data).digest()


def accounting_request_authenticator(
    code: int,
    identifier: int,
    length: int,
    attributes_bytes: bytes,
    secret: str,
) -> bytes:
    """Accounting-Request Authenticator = MD5(Code+ID+Length+16_zeros+Attrs+Secret)."""
    data = (
        bytes([code])
        + bytes([identifier])
        + struct.pack("!H", length)
        + b"\x00" * 16
        + attributes_bytes
        + secret.encode()
    )
    return hashlib.md5(data).digest()


def message_authenticator_value(
    packet_bytes: bytes,
    secret: str,
    msg_auth_offset: int,
) -> bytes:
    """Compute HMAC-MD5 Message-Authenticator (RFC 3579 §3.2).

    The HMAC is computed over the whole packet with the Message-Authenticator
    field set to 16 zero bytes.
    """
    zeroed = bytearray(packet_bytes)
    zeroed[msg_auth_offset: msg_auth_offset + 16] = b"\x00" * 16
    return hmac.new(secret.encode(), bytes(zeroed), hashlib.md5).digest()


def _find_message_authenticator_offset(packet_bytes: bytes) -> int:
    """Return byte offset of Message-Authenticator value field, or -1."""
    pos = HEADER_SIZE
    length = struct.unpack("!H", packet_bytes[2:4])[0]
    while pos < length:
        if pos + 2 > len(packet_bytes):
            break
        attr_type = packet_bytes[pos]
        attr_len = packet_bytes[pos + 1]
        if attr_len < 2:
            break
        if attr_type == ATTR_MESSAGE_AUTHENTICATOR:
            return pos + 2  # offset of the 16-byte value
        pos += attr_len
    return -1


def verify_message_authenticator(packet_bytes: bytes, secret: str) -> bool:
    """Verify Message-Authenticator if present. Returns True if valid or absent."""
    offset = _find_message_authenticator_offset(packet_bytes)
    if offset < 0:
        return True  # Not present — OK (optional in Access-Request)
    stored = packet_bytes[offset: offset + 16]
    expected = message_authenticator_value(packet_bytes, secret, offset)
    return hmac.compare_digest(stored, expected)


def recompute_message_authenticator(packet_bytes: bytearray, secret: str) -> None:
    """Re-compute and write Message-Authenticator in-place."""
    offset = _find_message_authenticator_offset(bytes(packet_bytes))
    if offset < 0:
        return
    new_val = message_authenticator_value(bytes(packet_bytes), secret, offset)
    packet_bytes[offset: offset + 16] = new_val


def verify_response_authenticator(
    response_pkt: RadiusPacket,
    request_auth: bytes,
    secret: str,
) -> bool:
    """Verify Response-Authenticator from a RADIUS response.

    RFC 2865 §3: ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)
    Returns True if correct, False otherwise.
    """
    attrs_bytes = b"".join(
        bytes([t, len(v) + 2]) + v for t, v in response_pkt.attributes
    )
    length = HEADER_SIZE + len(attrs_bytes)
    expected = response_authenticator(
        response_pkt.code, response_pkt.identifier,
        length, request_auth, attrs_bytes, secret,
    )
    return hmac.compare_digest(response_pkt.authenticator, expected)


def replace_secret_in_packet(
    pkt: RadiusPacket,
    old_secret: str,
    new_secret: str,
) -> bytes:
    """Re-sign a packet for forwarding: swap CHR secret → target secret.

    Handles:
    1. User-Password re-encryption (RFC 2865 §5.2) — Access-Request only.
    2. Accounting-Request Authenticator recomputation (RFC 2866 §3) — code 4.
    3. Message-Authenticator recalculation.

    Returns rebuilt packet bytes.

    Note: for Access-Request the Request-Authenticator is NOT changed
    (it's random, not keyed). For Accounting-Request it IS changed because
    it is keyed with the shared secret.
    """
    pkt_bytes = bytearray(pkt.raw)

    # 1. Re-encrypt User-Password if present (Access-Request only)
    password_enc = pkt.get_attr(ATTR_USER_PASSWORD)
    if password_enc:
        plaintext = _decrypt_user_password(password_enc, old_secret, pkt.authenticator)
        new_enc = _encrypt_user_password(plaintext, new_secret, pkt.authenticator)
        pkt_bytes = _replace_attr_value(pkt_bytes, ATTR_USER_PASSWORD, new_enc)

    # 2. Recompute Accounting-Request Authenticator for code 4 (RFC 2866 §3).
    #    The accounting authenticator is keyed with the secret, so it MUST
    #    be recomputed whenever the secret changes.
    if pkt.code == CODE_ACCOUNTING_REQUEST:
        attrs = _parse_attributes(bytes(pkt_bytes))
        attrs_bytes = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
        length = HEADER_SIZE + len(attrs_bytes)
        new_auth = accounting_request_authenticator(
            pkt.code, pkt.identifier, length, attrs_bytes, new_secret,
        )
        pkt_bytes = bytearray(
            struct.pack("!BBH", pkt.code, pkt.identifier, length)
            + new_auth
            + attrs_bytes
        )

    # 3. Recompute Message-Authenticator with new_secret
    recompute_message_authenticator(pkt_bytes, new_secret)

    return bytes(pkt_bytes)


def rebuild_response(
    response_pkt: RadiusPacket,
    request_auth: bytes,
    old_secret: str,
    new_secret: str,
    verify_auth: Optional[bytes] = None,
    strict_verify: bool = False,
) -> bytes:
    """Rebuild a response packet: swap target secret → CHR secret.

    Steps:
    1. Verify Response-Authenticator from target using ``verify_auth`` (or
       ``request_auth`` if not supplied).  Behaviour on mismatch is controlled
       by ``strict_verify``:
         - False (default / dev): log WARNING and forward anyway.
         - True  (production):    raise RadiusError — caller must drop packet.
       Callers must pass the *forwarded* request authenticator for accounting
       packets (which differs from the original CHR authenticator).
    2. Recompute Response-Authenticator using ``request_auth`` and ``new_secret``
       (what the CHR expects).
    3. Recompute Message-Authenticator with ``new_secret``.

    Args:
        response_pkt:   Parsed response from target RADIUS.
        request_auth:   Original request authenticator from CHR (used for
                        recomputing the response the CHR will verify).
        old_secret:     Target RADIUS shared secret (for verification).
        new_secret:     CHR shared secret (for recomputation).
        verify_auth:    Request authenticator that the target RADIUS used when
                        computing its response authenticator. Defaults to
                        ``request_auth``. Pass the forwarded authenticator here
                        for Accounting-Response packets.
        strict_verify:  When True, raise RadiusError on Response-Authenticator
                        mismatch instead of warning and forwarding. Set from
                        Config.STRICT_RESPONSE_VERIFY (production default: True).

    Raises:
        RadiusError: if ``strict_verify=True`` and the Response-Authenticator
                     does not match the expected value.
    """
    attrs_bytes = b"".join(
        bytes([t, len(v) + 2]) + v for t, v in response_pkt.attributes
    )
    length = HEADER_SIZE + len(attrs_bytes)

    # 1. Verify incoming response authenticator
    check_auth = verify_auth if verify_auth is not None else request_auth
    expected_old = response_authenticator(
        response_pkt.code, response_pkt.identifier,
        length, check_auth, attrs_bytes, old_secret,
    )
    if not hmac.compare_digest(response_pkt.authenticator, expected_old):
        if strict_verify:
            raise RadiusError(
                f"Response-Authenticator mismatch from target RADIUS "
                f"(code={response_pkt.code} id={response_pkt.identifier}) "
                "— packet dropped (PROXY_STRICT_RESPONSE_VERIFY=true)"
            )
        _LOG.warning(
            "Response-Authenticator mismatch from target "
            "(code=%d id=%d) — forwarding anyway (PROXY_STRICT_RESPONSE_VERIFY=false)",
            response_pkt.code, response_pkt.identifier,
        )

    # 2. Recompute Response-Authenticator for CHR
    new_auth = response_authenticator(
        response_pkt.code, response_pkt.identifier,
        length, request_auth, attrs_bytes, new_secret,
    )
    pkt_bytes = bytearray(
        struct.pack("!BBH", response_pkt.code, response_pkt.identifier, length)
        + new_auth
        + attrs_bytes
    )

    # 3. Recompute Message-Authenticator
    recompute_message_authenticator(pkt_bytes, new_secret)

    return bytes(pkt_bytes)


# ── Password en/decryption (RFC 2865 §5.2) ────────────────────────────

def _pad16(data: bytes) -> bytes:
    """Pad to multiple of 16 bytes."""
    r = len(data) % 16
    return data + b"\x00" * (16 - r if r else 0)


def _decrypt_user_password(ciphertext: bytes, secret: str, request_auth: bytes) -> bytes:
    result = bytearray()
    b = hashlib.md5(secret.encode() + request_auth).digest()
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i: i + 16]
        result.extend(x ^ y for x, y in zip(chunk, b))
        b = hashlib.md5(secret.encode() + chunk).digest()
    return bytes(result).rstrip(b"\x00")


def _encrypt_user_password(plaintext: bytes, secret: str, request_auth: bytes) -> bytes:
    padded = _pad16(plaintext)
    result = bytearray()
    b = hashlib.md5(secret.encode() + request_auth).digest()
    for i in range(0, len(padded), 16):
        chunk = padded[i: i + 16]
        xored = bytes(x ^ y for x, y in zip(chunk, b))
        result.extend(xored)
        b = hashlib.md5(secret.encode() + xored).digest()
    return bytes(result)


def _replace_attr_value(
    pkt_bytes: bytearray,
    attr_type: int,
    new_value: bytes,
) -> bytearray:
    """Replace the first occurrence of ``attr_type`` in the packet.

    Rebuilds the full attribute list — handles any position and any value
    length change correctly.  Previously this raised ``IndexError`` when
    User-Password was not the first attribute (e.g. after User-Name).
    """
    new_attrs: list[tuple[int, bytes]] = []
    replaced = False
    for at, av in _parse_attributes(bytes(pkt_bytes)):
        if at == attr_type and not replaced:
            new_attrs.append((at, new_value))
            replaced = True
        else:
            new_attrs.append((at, av))
    return bytearray(
        build(pkt_bytes[0], pkt_bytes[1], bytes(pkt_bytes[4:20]), new_attrs)
    )


def _parse_attributes(data: bytes) -> list[tuple[int, bytes]]:
    attrs = []
    pos = HEADER_SIZE
    length = struct.unpack("!H", data[2:4])[0]
    while pos < length:
        t = data[pos]
        l = data[pos + 1]
        if l < 2:
            break
        attrs.append((t, data[pos + 2: pos + l]))
        pos += l
    return attrs
