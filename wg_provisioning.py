"""WireGuard provisioning helpers (proxy side).

Two tiny operations the proxy needs that didn't fit any existing module:

  1. ``read_iface_pubkey(iface, wg_path)`` — read the proxy's LIVE
     wg-data / wg-radius public key via ``wg show <iface> public-key``.
     The panel renders this key into every CHR script; if the panel's
     stored copy ever drifts from what is on the box (operator did
     ``wg genkey`` again, host rebuilt, key rotated…) every newly-
     onboarded CHR fails to hand-shake. To stop that class of bug by
     construction, the proxy publishes its live key in every heartbeat.

  2. ``persist_iface(iface, wg_quick_path)`` — write the current
     runtime peer set of an interface back to ``/etc/wireguard/<iface>.conf``
     via ``wg-quick save <iface>``. The wg-peer reconciler manipulates
     kernel state with ``wg set …``; without ``save``, every reboot
     wipes the peers and the operator has to manually re-add them.

Both are SAFE-BY-DEFAULT: a non-zero exit from ``wg`` / ``wg-quick``
(unprivileged / not installed / interface absent) is reported by return
value; nothing raises. The callers are in the maintenance path and
MUST keep RADIUS I/O going regardless of provisioning hiccups.

The same scoped sudoers rule installed by
``systemd/setup-wg-sudoers.sh`` covers the two new commands —
``wg show <iface> public-key`` is read-only and ``wg-quick save
<iface>`` only writes to ``/etc/wireguard/<iface>.conf``.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from typing import Callable, Optional

log = logging.getLogger(__name__)


# Systemd unit names the setup script / runtime should look at when
# auto-detecting which user the proxy runs as. Order = priority.
DEFAULT_PROXY_UNIT_CANDIDATES = (
    "radius-proxy.service",
    "hobe-radius-proxy.service",
)


# WireGuard public keys are 32 raw bytes base64-encoded → 44 chars
# ending '='. The 43rd char is constrained because the encoded value's
# last byte must encode 0 in the trailing 2 bits.
_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


def is_valid_pubkey(value: str) -> bool:
    return bool(_PUBKEY_RE.match(value))


def _run(argv: list[str], *, timeout: float = 8.0) -> "tuple[int, str, str]":
    """Run a subprocess. Never raises. (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
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


def read_iface_pubkey(
    iface: str,
    wg_path: str = "wg",
    *,
    runner=None,
) -> str:
    """Return the public key currently on the given wg interface.

    Empty string when the proxy can't read it for any reason —
    unprivileged, interface absent, wg-tools missing. The heartbeat
    consumer treats an empty value as "no live key to publish; let
    the panel keep its stored copy".
    """
    run = runner or _run
    rc, out, err = run([wg_path, "show", iface, "public-key"])
    if rc != 0:
        log.warning(
            "wg provisioning: read pubkey for %s failed (rc=%d) — "
            "panel will keep its stored value: %s",
            iface, rc, (err or "").strip(),
        )
        return ""
    pub = (out or "").strip()
    if not is_valid_pubkey(pub):
        log.warning(
            "wg provisioning: read pubkey for %s returned malformed "
            "value (len=%d) — ignoring",
            iface, len(pub),
        )
        return ""
    return pub


def persist_iface(
    iface: str,
    wg_quick_path: str = "wg-quick",
    *,
    runner=None,
) -> bool:
    """Persist the current runtime peer set of ``iface`` to
    ``/etc/wireguard/<iface>.conf`` via ``wg-quick save <iface>``.

    Returns True on success, False otherwise. A False return is
    reported at WARNING level once but never raises — the wg-peer
    reconciler has already updated the live kernel state; the only
    thing we lose by not persisting is reboot-survival.
    """
    run = runner or _run
    rc, _out, err = run([wg_quick_path, "save", iface])
    if rc != 0:
        log.warning(
            "wg provisioning: persist %s failed (rc=%d): %s — peers "
            "are LIVE in the kernel but will NOT survive reboot until "
            "the operator installs the scoped sudoers rule "
            "(systemd/setup-wg-sudoers.sh) or runs the proxy with "
            "CAP_NET_ADMIN",
            iface, rc, (err or "").strip(),
        )
        return False
    log.info("wg provisioning: persisted %s peer set to /etc/wireguard/%s.conf",
             iface, iface)
    return True


class CachingPubkeyProvider:
    """Thread-safe TTL cache around ``read_iface_pubkey``.

    The heartbeat fires every 30 s; the pubkey changes ~never. With a
    short TTL we keep the heartbeat cheap (no fork/exec when fresh)
    while still picking up an operator-side rotation within one cache
    window. Empty results are NOT cached so a transient failure
    doesn't pin us to an empty value.
    """

    def __init__(
        self,
        iface: str,
        wg_path: str = "wg",
        ttl_seconds: float = 60.0,
        *,
        runner=None,
    ) -> None:
        self._iface = iface
        self._wg_path = wg_path
        self._ttl = float(ttl_seconds)
        self._runner = runner
        self._lock = threading.Lock()
        self._value: str = ""
        self._fetched_at: float = 0.0

    def __call__(self) -> str:
        now = time.monotonic()
        with self._lock:
            if self._value and (now - self._fetched_at) < self._ttl:
                return self._value
        # Read outside the lock — subprocess can take a few ms.
        pub = read_iface_pubkey(self._iface, self._wg_path, runner=self._runner)
        with self._lock:
            if pub:
                self._value = pub
                self._fetched_at = now
        return pub


# ── Service-user / wg-binary detection (mirrors setup-wg-sudoers.sh) ──
#
# The setup script auto-detects which account the proxy actually runs
# as so the operator never has to manually create a `hobeproxy` user.
# These Python helpers exist mostly so the detection logic is
# unit-testable; production callers still drive everything from env
# vars (PROXY_WG_BIN / PROXY_WG_QUICK_BIN) which override these
# defaults.


def detect_proxy_service_user(
    *,
    systemctl_runner: Optional[Callable[[list[str]], "tuple[int, str, str]"]] = None,
    env_value: Optional[str] = None,
    unit_candidates: "tuple[str, ...]" = DEFAULT_PROXY_UNIT_CANDIDATES,
    default: str = "root",
) -> str:
    """Mirror of the bash detect_user() in setup-wg-sudoers.sh.

    Resolution order (first non-empty wins):
      1. ``systemctl show <unit> -p User --value`` for each unit in
         ``unit_candidates``. Empty result = systemd unit either does
         not exist OR declares no User= directive (which means systemd
         runs the service as root by convention).
      2. ``env_value`` (the operator's PROXY_SERVICE_USER env override).
      3. ``default`` ("root").

    Returning "root" is the signal to the bash script that we are in
    "ROOT mode" — skip the sudoers install entirely (root can call
    wg/wg-quick directly).

    ``systemctl_runner`` is a (rc, stdout, stderr) callable injected by
    tests so we can drive the detection without an actual systemd.
    """
    run = systemctl_runner or _run
    for unit in unit_candidates:
        rc, out, _err = run(["systemctl", "show", unit, "-p", "User", "--value"])
        if rc == 0:
            value = (out or "").strip().splitlines()[0].strip() if out else ""
            if value:
                return value
    if env_value:
        return env_value.strip()
    return default


def is_root_mode(service_user: str) -> bool:
    """True iff the service user is root (or empty — systemd default)."""
    u = (service_user or "").strip()
    return u == "" or u == "root"


def recommended_wg_bins(
    *,
    euid: Optional[int] = None,
    helper_present: Optional[bool] = None,
    helper_path: str = "/usr/local/sbin/hobe-wg",
    helper_quick_path: str = "/usr/local/sbin/hobe-wg-quick",
) -> "tuple[str, str]":
    """Pick sensible defaults for (PROXY_WG_BIN, PROXY_WG_QUICK_BIN)
    based on the current effective UID and whether the scoped wrappers
    are present on disk.

    The proxy itself does NOT call this in the hot path — the env vars
    win — but ``DEPLOY_PROXY.md`` references it as the recommended
    default so a deploy that doesn't customise env still does the
    right thing.

    Decision matrix:
        euid == 0          → /usr/bin/wg + /usr/bin/wg-quick (direct)
        euid != 0, helpers → /usr/local/sbin/hobe-wg{,-quick}
        euid != 0, no help → /usr/bin/wg + /usr/bin/wg-quick (will fail
                              at runtime — operator must install the
                              sudoers; we don't pretend otherwise).
    """
    if euid is None:
        try:
            euid = os.geteuid()                             # POSIX only
        except AttributeError:                              # pragma: no cover
            euid = 0                                        # Windows — assume "root"-like
    if euid == 0:
        return ("/usr/bin/wg", "/usr/bin/wg-quick")
    if helper_present is None:
        helper_present = (
            os.path.exists(helper_path) and os.path.exists(helper_quick_path)
        )
    if helper_present:
        return (helper_path, helper_quick_path)
    return ("/usr/bin/wg", "/usr/bin/wg-quick")
