"""Unit tests for proxy_auth.py (CHR Fleet Phase 4 — shared X-Proxy-Token).

Confirms the token matches the FROZEN contract (§0) and the existing
RoutingTable scheme: <ts>:<nonce>:<HMAC-SHA256(secret, "ts:nonce")>.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy_auth


def test_token_format_and_hmac():
    token = proxy_auth.make_proxy_token("sekret", ts=1700000000, nonce="abcd1234")
    parts = token.split(":")
    assert len(parts) == 3
    ts, nonce, sig = parts
    assert ts == "1700000000"
    assert nonce == "abcd1234"
    expected = hmac.new(b"sekret", b"1700000000:abcd1234", hashlib.sha256).hexdigest()
    assert sig == expected


def test_empty_secret_yields_empty_token():
    assert proxy_auth.make_proxy_token("") == ""


def test_headers_include_token_and_content_type():
    h = proxy_auth.proxy_token_headers("sekret")
    assert h["Content-Type"] == "application/json"
    assert h["X-Proxy-Token"].count(":") == 2


def test_matches_routing_table_scheme():
    """proxy_auth must produce the same shape RoutingTable._make_token does."""
    import routing_table
    rt = routing_table.RoutingTable("https://panel.example", "sekret")
    a = rt._make_token().split(":")
    b = proxy_auth.make_proxy_token("sekret").split(":")
    assert len(a) == len(b) == 3
    # same hmac construction for a fixed (ts, nonce)
    token = proxy_auth.make_proxy_token("sekret", ts=42, nonce="ff")
    assert token.endswith(
        hmac.new(b"sekret", b"42:ff", hashlib.sha256).hexdigest()
    )
