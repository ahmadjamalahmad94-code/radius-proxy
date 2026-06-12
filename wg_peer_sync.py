"""Zero-touch fleet sync — proxy side.

Reconciles the proxy host's ``wg-data`` WireGuard interface against the
panel-published desired peer set so onboarding a new CHR in the panel does
NOT require a human to SSH the proxy and run ``wg set wg-data peer ...``.

Contract — GET ``/api/proxy/wg-peers`` (authenticated with the existing
X-Proxy-Token, same client/secret as ``/api/proxy/routing-table``):

    {
      "peers": [
        { "name": "chr-vpn-1",
          "public_key": "<44-char base64 wg-data pubkey>",
          "allowed_ips": ["10.98.0.11/32"],
          "endpoint": null }
      ]
    }

Reconcile invariants:
  * The interface's PRIVATE key is never read or written by this module.
  * Only peers this module previously added are eligible for removal; peers
    placed by the operator out-of-band (a manual ``wg set ...``) are NEVER
    touched. The "managed" set is persisted in
    ``PROXY_WG_STATE_PATH`` (default ``/var/lib/hobe-radius-proxy/managed-peers.json``).
  * Every public_key + allowed_ips entry is validated before reaching
    ``wg``; malformed/oversized prefixes are skipped (and reported).
  * If the proxy lacks privileges to invoke ``wg`` (unprivileged + no
    sudoers + no CAP_NET_ADMIN), reconcile DEGRADES to dry-run: each
    intended change is logged at INFO ("would add/remove …") and the
    next reconcile retries. No exception escapes — the maintenance loop
    keeps heartbeat + routing-table healthy regardless.

See DEPLOY_PROXY.md § "Zero-touch fleet sync" for the one-time privileged
setup (a scoped sudoers rule for ``wg show wg-data`` + ``wg set wg-data
peer *`` only).
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests

from proxy_auth import proxy_token_headers

log = logging.getLogger(__name__)


# ── input validation ──────────────────────────────────────────────────

# WireGuard public keys are 32 raw bytes base64-encoded → 44 chars ending '='.
# The last value byte must encode 0 in the trailing 2 bits, so the 43rd char
# is restricted to the set {A,E,I,M,Q,U,Y,c,g,k,o,s,w,0,4,8}.
_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_CIDR_RE   = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")


def _valid_pubkey(s: str) -> bool:
    return bool(_PUBKEY_RE.match(s))


def _valid_allowed_ip(s: str) -> bool:
    m = _CIDR_RE.match(s)
    if not m:
        return False
    o1, o2, o3, o4, prefix = (int(x) for x in m.groups())
    if not all(0 <= o <= 255 for o in (o1, o2, o3, o4)):
        return False
    # Defense in depth: refuse the default route + any short prefix that
    # would widen the proxy's wg-data routing scope (the panel SHOULD only
    # ever publish /32 host routes per fleet contract).
    if (o1, o2, o3, o4) == (0, 0, 0, 0):
        return False
    if not (24 <= prefix <= 32):
        return False
    return True


# ── data classes ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class DesiredPeer:
    """One peer from the panel's ``/api/proxy/wg-peers`` response."""
    name: str
    public_key: str
    allowed_ips: tuple[str, ...]
    endpoint: Optional[str] = None


@dataclass
class ReconcileResult:
    """Summary of a reconcile pass — surfaced to logs + tests."""
    desired_count: int = 0
    actual_count: int = 0
    added: list[str] = field(default_factory=list)        # pubkeys
    removed: list[str] = field(default_factory=list)      # pubkeys
    skipped_invalid: list[str] = field(default_factory=list)
    mode: str = "apply"                                   # 'apply' | 'dry-run' | 'disabled'
    error: Optional[str] = None


# ── reconciler ────────────────────────────────────────────────────────


_Runner = Callable[[list[str]], "tuple[int, str, str]"]


def _subprocess_runner(argv: list[str]) -> tuple[int, str, str]:
    """Default runner: subprocess.run, never raises, returns (rc, out, err).

    A returncode of 126 means "permission denied", 127 means "command not
    found" — both are degraded states the reconciler interprets as "no
    privilege / no tool → dry-run, never crash".
    """
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=15, check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: timeout"
    except PermissionError as exc:
        return 126, "", str(exc)
    except OSError as exc:                                # pragma: no cover - defensive
        return 1, "", str(exc)


class WgPeerSync:
    """Periodic reconciler of the proxy host's wg-data peer set.

    The reconciler is the proxy's mechanism for zero-touch fleet sync. It
    runs in a side-task off the asyncio event loop (the subprocess + HTTP
    calls are blocking) and never raises into the loop.
    """

    def __init__(
        self,
        admin_base_url: str,
        shared_secret: str,
        *,
        interface: str = "wg-data",
        state_path: str = "/var/lib/hobe-radius-proxy/managed-peers.json",
        wg_path: str = "wg",
        apply_mode: str = "auto",     # 'auto' | 'apply' | 'dry_run'
        timeout: float = 10.0,
        enabled: bool = True,
        runner: Optional[_Runner] = None,
        http_get: Optional[Callable] = None,
        # Parametrized for the second instance (wg-radius) — defaults
        # preserve the original wg-data contract byte-for-byte.
        endpoint_path: str = "/api/proxy/wg-peers",
        peers_json_key: str = "peers",
        log_prefix: str = "wg peer sync",
    ) -> None:
        self._url = admin_base_url.rstrip("/") + endpoint_path
        self._peers_key = peers_json_key
        self._log_prefix = log_prefix
        self._secret = shared_secret
        self._iface = interface
        self._state_path = state_path
        self._wg = wg_path
        self._timeout = timeout
        self._enabled = enabled
        if apply_mode not in ("auto", "apply", "dry_run"):
            apply_mode = "auto"
        self._apply_mode = apply_mode
        self._runner = runner or _subprocess_runner
        self._http_get = http_get or requests.get
        # Lazy-loaded cache of pubkeys this proxy has previously written to
        # the interface — the only peers eligible for removal.
        self._managed: Optional[set[str]] = None
        # Throttle the "fix me" warning to once per process so a long-running
        # unprivileged proxy doesn't spam every cycle.
        self._priv_warning_logged = False
        # Throttle the "endpoint not exposed" notice the same way (panel may
        # be a version that doesn't expose /api/proxy/wg-peers yet).
        self._endpoint_404_logged = False

    # ── HTTP ──────────────────────────────────────────────────────────

    def _fetch_desired(self) -> "tuple[set[DesiredPeer], list[str], Optional[str]]":
        """Returns (peers, skipped, error). ``error`` is non-None when the
        panel was unreachable / answered an error — caller stays inert."""
        try:
            resp = self._http_get(
                self._url, headers=proxy_token_headers(self._secret),
                timeout=self._timeout,
            )
        except (requests.RequestException,) as exc:
            return set(), [], f"http error: {exc}"
        if resp.status_code == 404:
            return set(), [], "endpoint not exposed by panel (404)"
        if resp.status_code != 200:
            return set(), [], f"http {resp.status_code}"
        try:
            body = resp.json()
        except ValueError as exc:
            return set(), [], f"bad json: {exc}"
        if not isinstance(body, dict):
            return set(), [], "bad json: not an object"
        raw_peers = body.get(self._peers_key)
        if not isinstance(raw_peers, list):
            return set(), [], f"bad json: '{self._peers_key}' not a list"

        peers: set[DesiredPeer] = set()
        skipped: list[str] = []
        for entry in raw_peers:
            if not isinstance(entry, dict):
                skipped.append("not-an-object")
                continue
            pk = str(entry.get("public_key") or "").strip()
            name = str(entry.get("name") or "").strip() or (pk[:10] if pk else "?")
            ips_raw = entry.get("allowed_ips") or []
            endpoint = entry.get("endpoint")
            if not _valid_pubkey(pk):
                skipped.append(f"{name}:invalid-pubkey")
                continue
            if not isinstance(ips_raw, list) or not ips_raw:
                skipped.append(f"{name}:no-allowed-ips")
                continue
            ips: list[str] = []
            bad_ip: Optional[str] = None
            for ip in ips_raw:
                s = str(ip).strip()
                if not _valid_allowed_ip(s):
                    bad_ip = s
                    break
                ips.append(s)
            if bad_ip is not None:
                skipped.append(f"{name}:invalid-allowed-ip:{bad_ip}")
                continue
            peers.add(DesiredPeer(
                name=name, public_key=pk, allowed_ips=tuple(sorted(ips)),
                endpoint=str(endpoint) if endpoint else None,
            ))
        return peers, skipped, None

    # ── wg show ───────────────────────────────────────────────────────

    def _show_actual(self) -> "tuple[set[str], Optional[str]]":
        """Parse ``wg show <iface> dump``. Returns (pubkeys, error)."""
        rc, out, err = self._runner([self._wg, "show", self._iface, "dump"])
        if rc != 0:
            return set(), (err or "").strip() or f"rc={rc}"
        pubkeys: set[str] = set()
        # First line is the interface (private/public/listen/fwmark); each
        # subsequent line is a peer keyed by its public key.
        for n, line in enumerate(out.splitlines()):
            if n == 0:
                continue
            parts = line.split("\t")
            if not parts:
                continue
            pk = parts[0].strip()
            if _valid_pubkey(pk):
                pubkeys.add(pk)
        return pubkeys, None

    # ── managed state file ────────────────────────────────────────────

    def _load_managed(self) -> set[str]:
        if self._managed is not None:
            return self._managed
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._managed = {
                str(p).strip()
                for p in (data.get("managed_pubkeys") or [])
                if _valid_pubkey(str(p).strip())
            }
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            self._managed = set()
        return self._managed

    def _save_managed(self, pubkeys: set[str]) -> bool:
        try:
            parent = os.path.dirname(self._state_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"managed_pubkeys": sorted(pubkeys)}, f)
            os.replace(tmp, self._state_path)
            self._managed = set(pubkeys)
            return True
        except OSError as exc:
            log.warning(
                "%s: state save to %s failed: %s "
                "(reconcile still effective; next pass re-detects).",
                self._log_prefix, self._state_path, exc,
            )
            return False

    # ── reconcile ─────────────────────────────────────────────────────

    def _apply_peer(
        self, argv: list[str], result: ReconcileResult, *, op_log: str,
    ) -> bool:
        """Run a ``wg set`` op. Returns True on success.

        On any non-zero rc we log the operator-facing "install sudoers / cap"
        fix recommendation ONCE per process and downgrade the rest of this
        reconcile cycle to dry-run (the caller flips result.mode).
        """
        rc, _out, err = self._runner(argv)
        if rc == 0:
            log.info("%s: %s", self._log_prefix, op_log)
            return True
        fix_hint = (err or "").strip() or f"rc={rc}"
        if not self._priv_warning_logged:
            log.warning(
                "%s: `%s` failed (%s). Install the scoped sudoers "
                "rule (systemd/setup-wg-sudoers.sh) or run the proxy with "
                "CAP_NET_ADMIN to enable apply. Until then, falling back to "
                "dry-run — peer changes will be LOGGED but NOT applied.",
                self._log_prefix, " ".join(argv), fix_hint,
            )
            self._priv_warning_logged = True
        log.info("%s: DRY-RUN would %s", self._log_prefix, op_log)
        return False

    def reconcile(self) -> ReconcileResult:
        """One reconcile pass. Never raises. Returns a result summary."""
        result = ReconcileResult()
        if not self._enabled:
            result.mode = "disabled"
            return result

        desired, skipped, fetch_err = self._fetch_desired()
        result.skipped_invalid = skipped
        if fetch_err:
            result.error = fetch_err
            # 404 — panel hasn't shipped the endpoint yet: stay silent after
            # the first notice; the feature is opt-in on the panel side too.
            if fetch_err.startswith("endpoint not exposed"):
                if not self._endpoint_404_logged:
                    log.info(
                        "%s: %s — feature inert this cycle.",
                        self._log_prefix, fetch_err,
                    )
                    self._endpoint_404_logged = True
            else:
                log.warning("%s: fetch failed — %s", self._log_prefix, fetch_err)
            return result
        result.desired_count = len(desired)

        actual, show_err = self._show_actual()
        if show_err:
            # Can't read the interface — likely unprivileged or wg-data is
            # down. Stay safe: log advisory, do not touch state. The
            # heartbeat + routing-table loops keep working.
            result.mode = "dry-run"
            result.error = f"wg show {self._iface} failed: {show_err}"
            log.warning(
                "%s: %s — cannot reconcile (advisory only).",
                self._log_prefix, result.error,
            )
            return result
        result.actual_count = len(actual)

        managed = set(self._load_managed())
        desired_pks = {p.public_key for p in desired}

        to_add = [p for p in desired if p.public_key not in actual]
        # Stale = on-the-wire AND we own it AND no longer desired.
        # The (managed ∩ actual) part keeps us from touching peers added
        # manually by the operator — they were never in our managed set.
        to_remove = sorted(pk for pk in managed if pk in actual and pk not in desired_pks)

        # Decide initial mode. 'auto' tries apply unless explicitly dry_run.
        if self._apply_mode == "dry_run":
            mode_apply = False
        else:
            mode_apply = True

        new_managed = set(managed)

        for p in to_add:
            argv = [
                self._wg, "set", self._iface,
                "peer", p.public_key,
                "allowed-ips", ",".join(p.allowed_ips),
            ]
            op_log = f"add peer {p.name} ({','.join(p.allowed_ips)})"
            if mode_apply and self._apply_peer(argv, result, op_log=op_log):
                result.added.append(p.public_key)
                new_managed.add(p.public_key)
            else:
                # Either we were already in dry_run, or apply just failed —
                # downgrade and record the would-do.
                mode_apply = False
                result.added.append(p.public_key)
                new_managed.add(p.public_key)

        for pk in to_remove:
            argv = [
                self._wg, "set", self._iface,
                "peer", pk, "remove",
            ]
            op_log = f"remove peer {pk[:10]}…"
            if mode_apply and self._apply_peer(argv, result, op_log=op_log):
                result.removed.append(pk)
                new_managed.discard(pk)
            else:
                mode_apply = False
                result.removed.append(pk)
                new_managed.discard(pk)

        result.mode = "apply" if mode_apply else (
            "dry-run" if (to_add or to_remove) else result.mode
        )
        # Default mode for an empty reconcile: 'apply' (nothing to do, all
        # privileges trivially satisfied).
        if result.mode not in ("apply", "dry-run", "disabled"):
            result.mode = "apply"

        # Persist managed set whenever there were changes. We persist even
        # in dry-run because the next pass should not re-add the same peers
        # to the would-do list redundantly — they really ARE the peers we
        # intend to own.
        if to_add or to_remove:
            self._save_managed(new_managed)

        if not to_add and not to_remove:
            log.debug(
                "%s: in sync (%d peers, %d actual)",
                self._log_prefix, len(desired), len(actual),
            )
        return result

    def reconcile_safe(self) -> Optional[ReconcileResult]:
        """Wrapper used by the maintenance loop — guarantees no exception
        escapes into the asyncio task even if a future refactor introduces
        one. Returns None on internal crash (then logged)."""
        try:
            return self.reconcile()
        except Exception as exc:                          # pragma: no cover
            log.warning("%s: reconcile crashed (swallowed): %s", self._log_prefix, exc)
            return None
