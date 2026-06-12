"""Panel-queued CoA / Disconnect executor (proxy side).

A small consumer that bridges the gap between the panel's «CHR move /
public-IP change» feature and the CHR fleet on the wire. The proxy is
outbound-only — there is no inbound HTTP listener (see
``tests/test_proxy_not_in_license_path.py``), so the panel cannot push
commands. Instead, the panel publishes them in the EXISTING authenticated
``GET /api/proxy/routing-table`` response under a top-level
``pending_coa`` array; the proxy POLLS the table on every maintenance
tick and acts on whatever it finds.

CONTRACT (panel-authoritative, frozen 2026-06-12):

  Pull — ``GET /api/proxy/routing-table`` → adds
    {
      ...,
      "pending_coa": [
        { "id": "<uuid>", "realm": "<realm>", "action": "disconnect",
          "target_node_id": <int|null>, "reason": "panel:chr-move" }
      ]
    }

  Push — ``POST /api/proxy/coa-result`` (X-Proxy-Token, same scheme as
    /api/proxy/routing-table) with body
    {
      "id": "<uuid>",
      "status": "done" | "failed",
      "detail": "<free-form>",
      "coa_code": <int|null>     # 41 = Disconnect-ACK, 42 = Disconnect-NAK
    }

Invariants — and what these tests pin:
  * IDEMPOTENT BY ID: a command's ``id`` is recorded on completion in a
    0600 state file (``coa-executed.json``) and never re-fired even if
    the panel sends it again (e.g. before its own dequeue propagates).
  * SAFE-BY-DEFAULT: every unhappy path — unreachable CHR, network
    error to the panel, malformed entry — is caught and reported as
    ``status:"failed"`` with a human-readable ``detail``. The
    maintenance loop is never crashed.
  * SECRET ROTATION SAFE: the Disconnect packet is signed with the
    CURRENT panel-canonical CHR secret (§6.1 ``routing.chr_secret()``)
    at send time — never a constructor-frozen value — so a rotation
    that happens between two ticks just works.
  * NEVER OUTSIDE /api/proxy/: the result POST endpoint lives under
    /api/proxy/. The license-path guard test stays green.
  * NEVER LOGS THE SECRET, the panel token, or the CoA Request-
    Authenticator (which is a secret-derived MAC).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Callable, Optional

import requests

import coa as coamod
from proxy_auth import proxy_token_headers

log = logging.getLogger(__name__)


# A targets provider takes ``(realm, target_node_id)`` and returns a list
# of ``(chr_ip, username, acct_session_id)`` triples for the live sessions
# that the panel's Disconnect should reach. Production wires this to the
# enforcement engine's SessionTracker (filter by realm + best-effort
# by target_node_id). Tests inject a fake provider directly.
TargetsProvider = Callable[[str, Optional[int]], "list[tuple[str, str, str]]"]


_DEFAULT_STATE_PATH = "/var/lib/hobe-radius-proxy/coa-executed.json"
_DEFAULT_MAX_EXECUTED_IDS = 8192


class CoaExecutor:
    """Polls ``routing.pending_coa()`` each tick and dispatches each
    entry exactly once over RFC 5176 Disconnect, reporting the outcome
    to ``/api/proxy/coa-result``.

    The class is intentionally tiny — heavy lifting (UDP send + retry,
    Response-Authenticator verification) lives in ``coa.CoaSender``;
    realm → session resolution lives in the targets provider; and the
    panel HTTP plumbing reuses ``proxy_auth.proxy_token_headers``. This
    keeps the executor's test surface small and focused on the policy
    bits: dedup, never-raise, and the panel result shape.
    """

    def __init__(
        self,
        *,
        routing,                                            # RoutingTable
        targets_provider: TargetsProvider,
        result_endpoint: str,
        shared_secret: str,
        coa_port: int = coamod.DEFAULT_COA_PORT,
        coa_timeout: float = 5.0,
        coa_max_retries: int = 2,
        coa_backoff_base: float = 0.5,
        result_timeout: float = 10.0,
        state_path: str = _DEFAULT_STATE_PATH,
        max_executed_ids: int = _DEFAULT_MAX_EXECUTED_IDS,
        http_post: Optional[Callable] = None,
        sender_factory: Optional[Callable[[str], "coamod.CoaSender"]] = None,
        enabled: bool = True,
    ) -> None:
        self._routing = routing
        self._targets_provider = targets_provider
        self._result_endpoint = result_endpoint
        self._secret = shared_secret
        self._coa_port = coa_port
        self._coa_timeout = coa_timeout
        self._coa_max_retries = coa_max_retries
        self._coa_backoff_base = coa_backoff_base
        self._result_timeout = result_timeout
        self._state_path = state_path
        self._max_executed_ids = max(1, int(max_executed_ids))
        self._http_post = http_post or requests.post
        # Allow tests to inject a sender factory so they can hit a mock
        # CoA loopback server bound to an ephemeral port.
        self._sender_factory = sender_factory or self._default_sender
        self._enabled = enabled
        self._lock = threading.Lock()
        # FIFO of executed ids (ordered for bounded trimming) + a set
        # for O(1) lookup. Persisted across restarts so a panel that
        # double-publishes after a proxy restart still won't double-fire.
        self._executed_order: list[str] = []
        self._executed_set: set[str] = set()
        self._load_executed_state()

    # ── public entry point: called from proxy._maintenance_loop ───────

    def tick_safe(self) -> "list[dict]":
        """One reconcile pass — never raises. Returns the list of
        results that were POSTed (or attempted) this tick, in the order
        they were dispatched. Used by tests; production discards it.
        """
        if not self._enabled:
            return []
        try:
            return self.tick()
        except Exception as exc:                                  # pragma: no cover
            log.warning("coa-executor: tick crashed (swallowed): %s", exc)
            return []

    def tick(self) -> "list[dict]":
        results: list[dict] = []
        pending = self._routing.pending_coa() if self._routing else []
        if not pending:
            return results

        # Snapshot the secret ONCE per tick so all commands in this batch
        # are signed consistently even if the routing-table refreshes
        # asynchronously mid-tick (panel rotation grace handles drift on
        # the other side of the wire).
        chr_secret = self._chr_secret()

        for entry in pending:
            cid = str(entry.get("id") or "").strip()
            if not cid:
                continue
            with self._lock:
                if cid in self._executed_set:
                    log.debug("coa-executor: skipping already-executed id=%s", cid)
                    continue
            try:
                outcome = self._handle_one(entry, chr_secret)
            except Exception as exc:                              # pragma: no cover
                log.warning(
                    "coa-executor: handler crashed for id=%s (swallowed): %s",
                    cid, exc,
                )
                outcome = {
                    "id": cid, "status": "failed",
                    "detail": f"handler_crashed: {exc}",
                    "coa_code": None,
                }
            results.append(outcome)
            # Record + POST INSIDE the try/except so an error in either
            # step still leaves the executor in a consistent state.
            try:
                self._mark_executed(cid)
            except Exception as exc:                              # pragma: no cover
                log.warning("coa-executor: state mark failed for id=%s: %s", cid, exc)
            try:
                self._post_result(outcome)
            except Exception as exc:                              # pragma: no cover
                log.warning(
                    "coa-executor: result POST failed for id=%s (swallowed): %s",
                    cid, exc,
                )
        return results

    # ── per-entry handling ────────────────────────────────────────────

    def _handle_one(self, entry: dict, chr_secret: str) -> dict:
        cid = str(entry.get("id") or "").strip()
        action = str(entry.get("action") or "").strip().lower()
        realm = str(entry.get("realm") or "").strip().lower()
        target_node_id = entry.get("target_node_id")
        if not isinstance(target_node_id, int):
            target_node_id = None

        if action != "disconnect":
            # Unknown / unsupported action — mark as failed so the
            # panel can decide whether to alert; never silently succeed.
            return {
                "id": cid, "status": "failed",
                "detail": f"unsupported_action:{action!r}",
                "coa_code": None,
            }
        if not realm:
            return {
                "id": cid, "status": "failed",
                "detail": "missing_realm",
                "coa_code": None,
            }

        targets = []
        try:
            targets = list(self._targets_provider(realm, target_node_id))
        except Exception as exc:                                  # pragma: no cover
            log.warning(
                "coa-executor: targets_provider failed for realm=%s: %s",
                realm, exc,
            )
            return {
                "id": cid, "status": "failed",
                "detail": f"targets_provider_error: {exc}",
                "coa_code": None,
            }

        if not targets:
            # The panel asked us to disconnect a realm that has no live
            # session here — the intent (no live session on the affected
            # node) is already satisfied. Report 'done' so the panel
            # dequeues; record 'no_active_sessions_for_realm' in detail
            # so the operator can see what happened.
            return {
                "id": cid, "status": "done",
                "detail": "no_active_sessions_for_realm",
                "coa_code": None,
            }

        # Fan out: send a Disconnect-Request per target. First ACK wins;
        # if all fail, surface the LAST result (most recent CHR error).
        sender = self._sender_factory(chr_secret)
        last_result: Optional[coamod.CoaResult] = None
        last_chr_ip = ""
        ok_chr_ip = ""
        for chr_ip, username, acct_session_id in targets:
            try:
                result = sender.disconnect(
                    chr_ip=chr_ip,
                    username=username,
                    acct_session_id=acct_session_id,
                    nas_ip=chr_ip,
                )
            except Exception as exc:                              # pragma: no cover
                log.warning(
                    "coa-executor: sender.disconnect raised for chr=%s "
                    "(swallowed): %s",
                    chr_ip, exc,
                )
                result = coamod.CoaResult(
                    ok=False, code=None, error=f"sender_exception: {exc}",
                )
            last_result = result
            last_chr_ip = chr_ip
            if result.ok:
                ok_chr_ip = chr_ip
                break

        if last_result is None:                                   # defensive
            return {
                "id": cid, "status": "failed",
                "detail": "no_send_attempt",
                "coa_code": None,
            }

        if last_result.ok:
            return {
                "id": cid, "status": "done",
                "detail": f"acked_by_chr={ok_chr_ip}",
                "coa_code": last_result.code,
            }
        # Failure path — try to be useful in the detail.
        err = last_result.error or "unknown_error"
        return {
            "id": cid, "status": "failed",
            "detail": f"chr={last_chr_ip} {err}",
            "coa_code": last_result.code,
        }

    # ── helpers ───────────────────────────────────────────────────────

    def _chr_secret(self) -> str:
        """The current panel-canonical CHR shared secret (§6.1)."""
        if self._routing is None:
            return ""
        return self._routing.chr_secret() or ""

    def _default_sender(self, chr_secret: str) -> "coamod.CoaSender":
        return coamod.CoaSender(
            chr_secret=chr_secret,
            coa_port=self._coa_port,
            timeout=self._coa_timeout,
            max_retries=self._coa_max_retries,
            backoff_base=self._coa_backoff_base,
        )

    def _post_result(self, outcome: dict) -> None:
        """POST one outcome to the panel. Never raises."""
        try:
            resp = self._http_post(
                self._result_endpoint,
                json=outcome,
                headers=proxy_token_headers(self._secret),
                timeout=self._result_timeout,
            )
        except (requests.RequestException, ValueError) as exc:
            log.warning(
                "coa-executor: result POST for id=%s failed (network): %s",
                outcome.get("id"), exc,
            )
            return
        # Treat 2xx as success; 4xx/5xx as a warning (the panel will see
        # the next refresh of the routing-table tick from the absence of
        # `id` in pending_coa).
        status_code = getattr(resp, "status_code", 0)
        if not (200 <= status_code < 300):
            log.warning(
                "coa-executor: result POST for id=%s returned status=%s",
                outcome.get("id"), status_code,
            )

    # ── executed-id state file (idempotency across restarts) ──────────

    def _mark_executed(self, cid: str) -> None:
        with self._lock:
            if cid in self._executed_set:
                return
            self._executed_order.append(cid)
            self._executed_set.add(cid)
            # FIFO trim
            while len(self._executed_order) > self._max_executed_ids:
                old = self._executed_order.pop(0)
                self._executed_set.discard(old)
            self._save_executed_state_locked()

    def already_executed(self, cid: str) -> bool:
        """Public test hook: was this id recorded as executed?"""
        with self._lock:
            return cid in self._executed_set

    def _load_executed_state(self) -> None:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        raw = data.get("ids")
        if not isinstance(raw, list):
            return
        # Preserve order; drop duplicates; coerce to strings.
        seen: set[str] = set()
        order: list[str] = []
        for v in raw:
            s = str(v).strip()
            if s and s not in seen:
                seen.add(s)
                order.append(s)
        # Trim to bound
        if len(order) > self._max_executed_ids:
            order = order[-self._max_executed_ids:]
            seen = set(order)
        self._executed_order = order
        self._executed_set = seen

    def _save_executed_state_locked(self) -> None:
        """Persist (assumed lock is held). Failure is non-fatal — the
        in-memory set keeps the executor consistent until next save."""
        try:
            parent = os.path.dirname(self._state_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self._state_path + ".tmp"
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump({"ids": list(self._executed_order)}, f)
            except Exception:                                     # pragma: no cover
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            os.replace(tmp, self._state_path)
        except OSError as exc:
            log.warning(
                "coa-executor: state save to %s failed: %s "
                "(executor stays consistent in memory; next tick retries)",
                self._state_path, exc,
            )
