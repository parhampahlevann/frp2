#!/usr/bin/env bash
# FRP v5.3: safe local manager for FRP 0.71.0.
# Requirements: Python >= 3.8, systemd Linux.
set -Eeuo pipefail

FRP_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$FRP_SOURCE" ]]; then
    export FRP_MANAGER_SOURCE="$(readlink -f -- "$FRP_SOURCE")"
else
    echo "ERROR: this script must be saved to a file and run directly - it cannot be piped into bash (curl ... | bash) or run via process substitution." >&2
    echo "It needs its own bytes on disk to install a trusted copy for the watchdog service." >&2
    echo "Fix: save it first, then run the saved file, e.g.:" >&2
    echo "  nano frp-manager.sh   # paste the script, save" >&2
    echo "  chmod +x frp-manager.sh" >&2
    echo "  sudo ./frp-manager.sh" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required. Install it first, e.g.: apt install -y python3" >&2
    exit 1
fi

exec python3 - "$@" <<'PYTHON'
import argparse
import base64
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

if sys.version_info < (3, 8):
    raise SystemExit("Python 3.8+ is required.")

try:
    import tomllib  # Python 3.11+; only needed to read legacy TOML configs
except ImportError:
    tomllib = None

VERSION = "0.71.0"
MANAGER_VERSION = "5.3"
PORT = 2087
DEFAULT_TOKEN = "123"
TOKEN = DEFAULT_TOKEN
MAX_POOL = 100    # local policy ceiling; frps enforces maxPoolCount per proxy

# Connection profiles.
#
# All four profiles use TCP as the FRP control transport. The critical transport
# difference is tcpMux:
#   mux on  -> multiple proxied flows share one TCP connection; lower socket and
#              connection-management overhead, but a bad shared path can affect
#              multiple flows together.
#   mux off -> each proxied flow uses its own transport connection; more sockets,
#              but unrelated flows are isolated from mux-level head-of-line blocking.
#
# FRP documents that application heartbeat is unnecessary when tcpMux is enabled.
# Therefore mux-on profiles explicitly disable both client/server application
# heartbeats and use tcpMuxKeepaliveInterval instead.
#
# poolCount is a pre-established connection pool per proxy. It primarily helps
# workloads with many short-lived connections; it is not a generic single-flow
# throughput multiplier.
#
# strikes = consecutive watchdog probe failures (1/minute) before a restart.
PROFILES = {
    "gaming": dict(
        # Deliberately no TCP mux: each proxied flow gets its own transport stream,
        # avoiding mux-level head-of-line blocking between unrelated flows.
        desc="latency/jitter oriented: TCP without mux, fast application heartbeat",
        proto="tcp", mux=False,
        mux_ka=None, tcp_ka=60,
        hb_iv=5, hb_to_c=15, hb_to_s=45,
        dial_to=10, pool=2, user_to=10, strikes=3,
    ),
    "balanced": dict(
        # General-purpose profile. Mux keepalive is the liveness mechanism.
        desc="general purpose: TCP mux, moderate keepalive, low connection overhead",
        proto="tcp", mux=True,
        mux_ka=30, tcp_ka=60,
        hb_iv=None, hb_to_c=None, hb_to_s=None,
        dial_to=10, pool=4, user_to=15, strikes=5,
    ),
    "streaming": dict(
        # Long-lived streams should not be discarded quickly because of transient
        # path problems. Pooling is intentionally modest: poolCount helps short
        # connection setup, not the throughput of one long-lived stream.
        desc="long-lived sessions: TCP mux, conservative reconnect sensitivity",
        proto="tcp", mux=True,
        mux_ka=30, tcp_ka=60,
        hb_iv=None, hb_to_c=None, hb_to_s=None,
        dial_to=15, pool=2, user_to=30, strikes=6,
    ),
    "speed": dict(
        # Larger pools are useful for many concurrent short connections; they do
        # not make a single TCP flow inherently faster.
        desc="high concurrency: TCP mux with a larger connection pool",
        proto="tcp", mux=True,
        mux_ka=20, tcp_ka=60,
        hb_iv=None, hb_to_c=None, hb_to_s=None,
        dial_to=10, pool=16, user_to=15, strikes=5,
    ),
}
DEFAULT_PROFILE = "balanced"
PROFILE_ALIASES = {
    # Kept only for upgrades from the previous manager, where this existed.
    "gaming-kcp": "gaming",
}

# Watchdog tuning
WD_GRACE = 120            # stay quiet this long after the service (re)starts
WD_BACKOFF = 600          # min seconds between watchdog restarts; doubles after each unsuccessful one
WD_BACKOFF_MAX = 6 * 3600
WD_HEALTHY_RESET = 1800   # continuous health needed before the backoff counter resets
MONO = time.monotonic     # same clock as systemd's *Monotonic timestamps (works in containers too)

ROOT = Path("/root/frp")
STATE = Path("/etc/frp-manager")
SELF = Path("/usr/local/libexec/frp-manager")
RUNTIME = Path("/run/frp-manager")

TAG = "# Managed by frp-manager-v5"


def say(text):
    print(text, flush=True)


def _exec(args, timeout, data):
    return subprocess.run(
        [str(x) for x in args],
        input=data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def run(args, *, check=True, timeout=40, data=None):
    try:
        p = _exec(args, timeout, data)
    except subprocess.TimeoutExpired:
        if check:
            raise RuntimeError(f"{args[0]} timed out after {timeout}s")
        return ""
    if check and p.returncode:
        raise RuntimeError(
            f"{args[0]} failed: {p.stderr.strip() or p.stdout.strip()}"
        )
    return p.stdout.strip()


def run_rc(args, timeout=60):
    """Return (exit code, output); never raises for a failing command."""
    try:
        p = _exec(args, timeout, None)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return p.returncode, (p.stdout + p.stderr).strip()


def yes(question):
    return input(question + " [y/N]: ").strip().lower() == "y"


def ask(question, default=""):
    value = input(
        f"{question}" + (f" [{default}]" if default else "") + ": "
    ).strip()
    return value or default


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.is_symlink():
        raise ValueError(f"Refusing symlink: {path}")

    fd, name = tempfile.mkstemp(prefix=".frp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(content.encode() if isinstance(content, str) else content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_config(path):
    text = Path(path).read_text()
    if "{{" in text:
        raise ValueError(
            "Templated configs need manual migration; nothing changed."
        )
    if str(path).endswith(".json"):
        value = json.loads(text)
    elif tomllib:
        value = tomllib.loads(text)
    else:
        raise ValueError(
            "A legacy TOML config needs Python 3.11+ to be read; reinstall to migrate it to JSON."
        )
    if not isinstance(value, dict):
        raise ValueError("Config root must be an object.")
    return value


def paths(side):
    role = "server" if side == "frps" else "client"
    name = f"{role}-{PORT}"
    unit = f"{side}@{name}.service"
    return (
        ROOT / role / f"{name}.json",
        Path("/etc/systemd/system") / unit,
        unit,
    )


def existing(side):
    cfg = paths(side)[0]
    if cfg.exists():
        return cfg
    old = cfg.with_suffix(".toml")
    return old if old.exists() else None


def parse_ports(value, reserved=()):
    found = set()
    for part in value.split(","):
        part = part.strip()
        if not re.fullmatch(r"[0-9]{1,5}(?:\s*-\s*[0-9]{1,5})?", part):
            raise ValueError(
                "Use decimal ports/ranges, e.g. 80,443,8000-8010; no empty entries."
            )
        ends = [int(x.strip(), 10) for x in part.split("-")]
        start, end = ends[0], ends[-1]
        if not 1 <= start <= end <= 65535:
            raise ValueError("Ports must be in 1..65535, ascending ranges only.")
        if end - start + 1 > 1024:
            raise ValueError("Maximum 1024 unique ports per managed configuration.")
        found.update(range(start, end + 1))

    if len(found) > 1024:
        raise ValueError("Maximum 1024 unique ports per managed configuration.")
    if found.intersection(reserved):
        raise ValueError("A selected port conflicts with a control/dashboard port.")
    return sorted(found)


def valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", host):
        return False  # looks like an IPv4 address but is not a valid one
    return len(host) <= 253 and bool(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host)
    )


def profile_file(side):
    return STATE / f"{side}-{PORT}.profile"


def load_profile(side):
    try:
        name = profile_file(side).read_text().strip()
    except OSError:
        name = DEFAULT_PROFILE
    name = PROFILE_ALIASES.get(name, name)
    return name if name in PROFILES else DEFAULT_PROFILE


def choose_profile(preset=None):
    if preset:
        if preset not in PROFILES:
            raise ValueError(f"Unknown profile: {preset}")
        return preset
    names = list(PROFILES)
    default_number = names.index(DEFAULT_PROFILE) + 1
    say("\nConnection profile:")
    for i, name in enumerate(names, 1):
        suffix = " [default]" if name == DEFAULT_PROFILE else ""
        say(f"  {i}) {name:<10} - {PROFILES[name]['desc']}{suffix}")
    while True:
        raw = ask("Profile", str(default_number)).lower()
        if raw in PROFILES:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(names):
            return names[int(raw) - 1]
        say(f"Enter 1-{len(names)} or a profile name.")


def validate_profiles():
    for name, p in PROFILES.items():
        if p["proto"] != "tcp":
            raise ValueError(f"{name}: only tcp is supported by the four managed profiles")
        if not isinstance(p["mux"], bool):
            raise ValueError(f"{name}: mux must be boolean")
        if not 0 <= int(p["pool"]) <= MAX_POOL:
            raise ValueError(f"{name}: pool must be 0..{MAX_POOL}")
        if p["mux"]:
            if p["hb_iv"] is not None or p["hb_to_c"] is not None or p["hb_to_s"] is not None:
                raise ValueError(f"{name}: mux profiles must not define application heartbeats")
            if int(p["mux_ka"]) <= 0:
                raise ValueError(f"{name}: mux_ka must be positive")
        else:
            if int(p["hb_iv"]) <= 0 or int(p["hb_to_c"]) <= int(p["hb_iv"]):
                raise ValueError(f"{name}: invalid client heartbeat interval/timeout")
            if int(p["hb_to_s"]) <= int(p["hb_iv"]):
                raise ValueError(f"{name}: server heartbeat timeout must exceed client interval")
        if int(p["tcp_ka"]) <= 0 or int(p["dial_to"]) <= 0 or int(p["user_to"]) <= 0:
            raise ValueError(f"{name}: invalid timeout/keepalive value")
        if int(p["strikes"]) < 1:
            raise ValueError(f"{name}: strikes must be >= 1")


def transport_signature(side, c):
    t = c.get("transport", {})
    mux = bool(t.get("tcpMux", True))
    if side == "frpc":
        proto = str(t.get("protocol", "tcp")).lower()
    else:
        proto = "kcp" if c.get("kcpBindPort") else "tcp"
    return proto, mux


def validate_peer_transport(side, profile):
    peer = "frpc" if side == "frps" else "frps"
    path = existing(peer)
    if not path:
        return
    other = read_config(path)
    actual_proto, actual_mux = transport_signature(peer, other)
    expected_proto = PROFILES[profile]["proto"]
    expected_mux = PROFILES[profile]["mux"]
    if actual_proto != expected_proto or actual_mux != expected_mux:
        raise ValueError(
            f"Transport mismatch with installed {peer}: "
            f"{actual_proto}, tcpMux {'on' if actual_mux else 'off'}; "
            f"selected '{profile}' needs {expected_proto}, "
            f"tcpMux {'on' if expected_mux else 'off'}. "
            "Choose a compatible profile before changing this side."
        )


def patch_transport(c, side, p):
    t = c.setdefault("transport", {})
    t["tcpMux"] = p["mux"]

    if p["mux"]:
        # FRP's tcpMux already provides the application-level liveness signal.
        # Explicitly disabling the second heartbeat avoids redundant traffic and,
        # on frp 0.71.0, avoids the server-side heartbeat-timeout reconnect issue
        # reported for stale control sessions after reconnect.
        t.update(
            tcpMuxKeepaliveInterval=p["mux_ka"],
            tcpKeepalive=p["tcp_ka"],
        )
    else:
        # No mux: application heartbeat is the control-session liveness signal.
        t.update(
            tcpKeepalive=p["tcp_ka"],
            heartbeatInterval=p["hb_iv"] if side == "frpc" else None,
        )
        if side == "frpc":
            t["heartbeatTimeout"] = p["hb_to_c"]
        else:
            t["heartbeatTimeout"] = p["hb_to_s"]

    if side == "frps":
        # The server-side heartbeat timer is disabled whenever tcpMux is used.
        if p["mux"]:
            t["heartbeatTimeout"] = -1
        t["maxPoolCount"] = MAX_POOL
        c["userConnTimeout"] = p["user_to"]
    else:
        t.update(
            poolCount=p["pool"],
            dialServerTimeout=p["dial_to"],
            dialServerKeepalive=p["tcp_ka"],
        )
        if p["mux"]:
            t["heartbeatInterval"] = -1
            t["heartbeatTimeout"] = -1
        c["loginFailExit"] = False

    # Avoid serializing a JSON null field that is not part of FRP's integer config.
    if t.get("heartbeatInterval", "__missing__") is None:
        t.pop("heartbeatInterval", None)


def dashboard_password(side):
    """Preserve the existing dashboard password during reinstall/profile changes."""
    old = existing(side)
    if not old:
        return None
    try:
        value = read_config(old).get("webServer", {}).get("password")
    except (OSError, ValueError) as error:
        # Never silently rotate a credential because an old configuration could
        # not be parsed. This is especially important for Python <3.11, where
        # legacy TOML cannot be parsed by the standard library.
        raise ValueError(
            f"Cannot safely preserve the existing dashboard password from {old}: {error}"
        )
    if value:
        return str(value)
    raise ValueError(f"Existing config {old} has no dashboard password to preserve.")


def base_config(side, token, p):
    c = {
        "auth": {
            "method": "token",
            "token": token,
        },
        "webServer": {
            "addr": "127.0.0.1",
            "port": 7500 if side == "frps" else 7400,
            "user": "admin",
            "password": dashboard_password(side) or secrets.token_urlsafe(32),
        },
        "log": {
            "to": "console",
            "level": "info",
            "disablePrintColor": True,
        },
    }
    patch_transport(c, side, p)
    c["transport"]["tls"] = {"force": True} if side == "frps" else {"enable": True}
    if side == "frpc":
        c["transport"]["protocol"] = p["proto"]
    return c


def api(c, endpoint, timeout=3):
    w = c.get("webServer", {})
    addr = w.get("addr", "127.0.0.1")
    addr = "127.0.0.1" if addr == "0.0.0.0" else "::1" if addr == "::" else addr
    host = f"[{addr}]" if ":" in addr else addr
    tls = w.get("tls", {})
    scheme = "https" if tls.get("certFile") else "http"

    request = urllib.request.Request(
        f"{scheme}://{host}:{int(w['port'])}{endpoint}"
    )
    credentials = (str(w.get("user", "")) + ":" + str(w.get("password", ""))).encode()
    request.add_header("Authorization", "Basic " + base64.b64encode(credentials).decode())

    handlers = [urllib.request.ProxyHandler({})]
    if scheme == "https":
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )
    opener = urllib.request.build_opener(*handlers)

    with opener.open(request, timeout=timeout) as r:
        if r.status != 200:
            raise ValueError(f"Unexpected API status: {r.status}")
        if endpoint == "/healthz":
            return True
        return json.load(r)


def proxy_counts(status):
    rows = [
        p
        for group in status.values()
        if isinstance(group, list)
        for p in group
        if isinstance(p, dict) and "status" in p
    ]
    return (
        sum(p["status"] == "running" for p in rows),
        len(rows),
    )


def check_free(port, udp=False):
    listeners = run(
        ["ss", "-H", "-lunp" if udp else "-ltnp", f"sport = :{int(port)}"]
    )
    if listeners:
        raise RuntimeError(
            f"{'UDP' if udp else 'TCP'} port {port} is busy; no process killed.\n{listeners}"
        )


def fetch(url, limit, tries=3):
    if not url.startswith("https://"):
        raise ValueError("HTTPS download required.")
    last = None
    for attempt in range(tries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "frp-manager-v5"})
            with urllib.request.urlopen(request, timeout=60) as response:
                if not response.url.startswith("https://"):
                    raise ValueError("Insecure download redirect.")
                content = response.read(limit + 1)
            if len(content) > limit:
                raise ValueError("Download exceeds size limit.")
            return content
        except (OSError, http.client.HTTPException) as error:
            last = error
            if attempt + 1 < tries:
                say(f"  download problem ({type(error).__name__}); retrying ...")
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Download failed after {tries} attempts: {last}")


def download(side, directory):
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv8l": "arm_hf",
        "armv7l": "arm_hf",
        "armv6l": "arm",
        "i386": "386",
        "i686": "386",
        "ppc64le": "ppc64le",
        "loongarch64": "loong64",
        "mips": "mips",
    }.get(os.uname().machine)
    if not arch:
        raise ValueError("Unsupported architecture.")

    pkg = f"frp_{VERSION}_linux_{arch}"
    base = f"https://github.com/fatedier/frp/releases/download/v{VERSION}"
    say(f"Downloading and SHA256-checking {side} {VERSION} ({arch}) ...")

    sums = fetch(base + "/frp_sha256_checksums.txt", 1024 * 1024).decode()
    expected = None
    for line in sums.splitlines():
        fields = line.split()
        if len(fields) == 2 and Path(fields[1].lstrip("*")).name == pkg + ".tar.gz":
            if expected is not None:
                raise ValueError("Duplicate checksum entry.")
            expected = fields[0]

    if not expected or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("Official SHA256 missing; refusing unverified download.")

    archive = fetch(base + "/" + pkg + ".tar.gz", 100 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != expected.lower():
        raise ValueError("SHA256 mismatch.")

    tarpath = directory / "frp.tar.gz"
    tarpath.write_bytes(archive)
    output = directory / side

    with tarfile.open(tarpath, "r:gz") as tar:
        member = tar.getmember(pkg + "/" + side)
        if not member.isfile() or not 0 < member.size <= 100 * 1024 * 1024:
            raise ValueError("Invalid binary archive entry.")
        with tar.extractfile(member) as source:
            output.write_bytes(source.read())

    output.chmod(0o755)
    if run([output, "-v"]) != VERSION:
        raise ValueError("Unexpected FRP binary version.")
    return output


def binary_version(path):
    if not Path(path).is_file():
        return None
    try:
        return run([path, "-v"], timeout=10)
    except (RuntimeError, OSError):
        return None


def snapshot(files, folder):
    folder.mkdir(parents=True, mode=0o700)
    entries = []
    for i, path in enumerate(files):
        if path.is_symlink():
            raise ValueError(f"Refusing symlink: {path}")
        saved = folder / str(i)
        if path.exists():
            shutil.copy2(path, saved)
        entries.append((path, saved if path.exists() else None))

    atomic(
        folder / "manifest.json",
        json.dumps(
            [
                {"path": str(p), "backup": str(s) if s else None}
                for p, s in entries
            ],
            indent=2,
        ),
    )
    return entries


def restore(entries):
    for path, saved in entries:
        if saved:
            atomic(path, saved.read_bytes(), saved.stat().st_mode & 0o777)
        else:
            path.unlink(missing_ok=True)


def wd_name(side):
    return f"frp-v5-watchdog-{side}-{PORT}"


def service_text(side, cfg):
    # Restart=always: also revives the daemon after a plain SIGTERM/exit 0.
    # A crash loop is bounded by the start limit; the watchdog then recovers the
    # "failed" unit slowly (with exponential backoff) instead of a tight loop.
    return f"""{TAG}
[Unit]
Description=FRP {side} ({PORT})
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
ExecStartPre=/usr/local/bin/{side} verify -c {cfg}
ExecStart=/usr/local/bin/{side} -c {cfg}
Restart=always
RestartSec=5s
TimeoutStopSec=20s
LimitNOFILE=262144
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
"""


def install(side, c, profile):
    source = Path(os.environ.get("FRP_MANAGER_SOURCE", ""))
    if not source.is_file():
        raise ValueError("Save this script to a regular file before running it.")

    cfg, unitfile, unit = paths(side)
    executable = Path("/usr/local/bin") / side
    unitdir = unitfile.parent

    wd = wd_name(side)
    ws = unitdir / (wd + ".service")
    wt = unitdir / (wd + ".timer")
    pfile = profile_file(side)

    legacy = f"frp-watchdog@{side}.timer"
    old = existing(side)

    targets = [cfg, unitfile, ws, wt, executable, SELF, pfile]
    if old and old != cfg:
        targets.append(old)

    with tempfile.TemporaryDirectory(prefix="frp-v5-") as tmp:
        tmp = Path(tmp)
        if binary_version(executable) == VERSION:
            staged = executable
            say(f"{side} {VERSION} is already installed; skipping download.")
        else:
            staged = download(side, tmp)

        candidate = tmp / "candidate.json"
        atomic(candidate, json.dumps(c, ensure_ascii=False, indent=2))
        run([staged, "verify", "-c", candidate])

        backupdir = ROOT / "backups" / f"v5-{side}-{time.time_ns()}"
        saved = snapshot(targets, backupdir)

        states = {
            u: (
                run(["systemctl", "is-active", u], check=False) == "active",
                run(["systemctl", "is-enabled", u], check=False) == "enabled",
            )
            for u in (unit, wd + ".timer", legacy)
        }

        try:
            for timer in (legacy, wd + ".timer"):
                run(["systemctl", "disable", "--now", timer], check=False)

            run(["systemctl", "stop", f"frp-watchdog@{side}.service"], check=False)
            run(["systemctl", "stop", wd + ".service"], check=False)
            run(["systemctl", "stop", unit], check=False)

            check_free(c["webServer"]["port"])
            if side == "frps":
                check_free(c["bindPort"])
                if c.get("kcpBindPort"):
                    check_free(c["kcpBindPort"], udp=True)

            if staged != executable:
                atomic(executable, staged.read_bytes(), 0o755)

            atomic(cfg, candidate.read_bytes())
            atomic(pfile, profile + "\n")
            atomic(SELF, source.read_bytes(), 0o700)
            atomic(unitfile, service_text(side, cfg), 0o644)
            atomic(
                ws,
                f"""{TAG}
[Unit]
Description=FRP local watchdog ({side}, {PORT})

[Service]
Type=oneshot
ExecStart={SELF} --port {PORT} --watchdog {side}
TimeoutStartSec=90s
UMask=0077
""",
                0o644,
            )
            atomic(
                wt,
                f"""{TAG}
[Unit]
Description=FRP watchdog timer ({side}, {PORT})

[Timer]
OnBootSec=120s
OnUnitActiveSec=60s
AccuracySec=5s
Unit={wd}.service

[Install]
WantedBy=timers.target
""",
                0o644,
            )

            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", unit, wd + ".timer"])
            run(["systemctl", "restart", unit])

            ready = False
            for _ in range(15):
                time.sleep(1)
                active = run(["systemctl", "is-active", unit], check=False)
                if active == "active":
                    try:
                        api(c, "/healthz", timeout=1)
                        ready = True
                        break
                    except (OSError, ValueError, http.client.HTTPException):
                        pass

            if not ready:
                raise RuntimeError(
                    "Service/local health check failed. Inspect the journal."
                )

            (RUNTIME / f"{side}-{PORT}.json").unlink(missing_ok=True)  # fresh watchdog history after a (re)install
            run(["systemctl", "start", wd + ".timer"])
            if old and old != cfg:
                # BUG FIX: previously just chmod'd 0600 and left it in place forever.
                # It has already been migrated into cfg (JSON) and a copy already
                # sits in this install's own backup snapshot, so keeping the live
                # legacy file around only risked read_config() or a human picking
                # up stale settings by mistake.
                old.unlink(missing_ok=True)

            legacy_helper = Path("/usr/local/bin/frp-watchdog.sh")
            if legacy_helper.is_file() and not legacy_helper.is_symlink():
                legacy_helper.chmod(0o700)

        except BaseException:
            say(f"Installation failed; restoring snapshot: {backupdir}")
            for u in (wd + ".timer", unit):
                run(["systemctl", "stop", u], check=False)
            restore(saved)
            run(["systemctl", "daemon-reload"], check=False)
            for u, (active, enabled) in states.items():
                run(
                    ["systemctl", "enable" if enabled else "disable", u],
                    check=False,
                )
                if active:
                    run(["systemctl", "start", u], check=False)
            raise

    say(f"Service installed [{profile}]; backup: {backupdir}\nConfig: {cfg}")
    return backupdir


def build_config(side, profile, host=None, ports=()):
    prof = PROFILES[profile]
    c = base_config(side, TOKEN, prof)
    if side == "frps":
        c.update(
            bindAddr="0.0.0.0",
            bindPort=PORT,
            proxyBindAddr="0.0.0.0",
            detailedErrorsToClient=False,
        )
    else:
        c.update(serverAddr=host, serverPort=PORT)
        c["proxies"] = [
            {
                "name": f"{kind}-{p}",
                "type": kind,
                "localIP": "127.0.0.1",
                "localPort": p,
                "remotePort": p,
            }
            for kind in ("tcp", "udp")
            for p in ports
        ]
    return c


def wait_tunnel(c, seconds):
    running = total = 0
    deadline = time.time() + seconds
    while True:
        try:
            running, total = proxy_counts(api(c, "/api/status"))
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            pass
        if (total and running == total) or time.time() >= deadline:
            return running, total
        time.sleep(2)


def post_install(side, c, profile):
    """Non-fatal verification after a successful install; only prints."""
    unit = paths(side)[2]
    wd = wd_name(side)

    if side == "frpc":
        say("Waiting up to 30s for the tunnel to come up ...")
        running, total = wait_tunnel(c, 30)
        if total and running == total:
            say(f"TUNNEL UP: {running}/{total} proxies running.")
        else:
            if total:
                say(f"WARNING: tunnel is not fully up yet ({running}/{total} proxies running).")
            else:
                say("WARNING: tunnel is NOT up: frpc has no connection to frps yet.")
            control = f"{PORT}/tcp"
            say(
                "  Check: frps installed and running on the Iran server; its firewall/provider "
                f"firewall allows {control}; the same token is configured on both sides; then: "
                f"journalctl -u {unit} -n 50 --no-pager"
            )
            if not PROFILES[profile]["mux"]:
                say(
                    f"  '{profile}' uses tcpMux off: frps must also use tcpMux off. "
                    "The manager rejects incompatible transport settings when the peer is present."
                )
    else:
        say(
            f"frps is up and listening on {PORT}/tcp. Install frpc on the foreign server "
            "with the same token."
        )
        if not PROFILES[profile]["mux"]:
            say(
                f"Because '{profile}' uses tcpMux off, install a tcpMux-off profile "
                "(the four-profile 'gaming' profile) on the other side."
            )

    timer = run(["systemctl", "is-active", wd + ".timer"], check=False)
    code, out = run_rc(["systemctl", "start", wd + ".service"], timeout=90)
    verdict, msg = probe(side, c)
    say(
        f"Watchdog self-test: timer={timer}, service run={'OK' if code == 0 else 'FAILED'}, "
        f"probe={verdict} ({msg})"
    )
    if timer != "active" or code != 0:
        say(f"WARNING: the watchdog is NOT working correctly: {out}")
        say(f"  See: journalctl -u {wd}.service -n 30 --no-pager")

    if not PROFILES[profile]["mux"]:
        say(
            "NOTE: tcpMux-off is intentionally more socket-heavy and can reduce "
            "head-of-line blocking between independent proxied flows."
        )


def configure(side, preset=None):
    # All questions are asked BEFORE taking the lock, so an idle prompt can never
    # pause the watchdog.
    host = None
    ports = []

    if side == "frpc":
        host = ask("Server IP (Iran frps address, IPv4 or hostname)")
        if not valid_host(host):
            raise ValueError("Invalid hostname/IP.")
        if ":" in host:
            say("WARNING: frps of this manager listens on IPv4 only; an IPv6 address will not connect.")

        ports = parse_ports(
            ask("Ports to forward, comma-separated (ranges OK, e.g. 80,443,8000-8010)", "8080"),
            {PORT, 7400, 7500},
        )

    profile = choose_profile(preset)
    prof = PROFILES[profile]
    validate_profiles()
    validate_peer_transport(side, profile)
    if side == "frpc" and not prof["mux"]:
        say(
            f"NOTE: '{profile}' disables tcpMux. The installed frps must also have "
            "tcpMux disabled; compatibility is checked before installation."
        )
    c = build_config(side, profile, host, ports)

    locked(lambda: install(side, c, profile))
    say("No firewall was changed. Allow ONLY required ports in the Iran host/provider firewall.")
    if ports:
        say(f"Control: {PORT}/tcp; forwarded TCP+UDP ports: " + " ".join(map(str, ports)))
    w = c["webServer"]
    say(f"Dashboard (loopback only - reach it via an SSH tunnel): "
        f"http://127.0.0.1:{w['port']}  user={w['user']}  password={w['password']}")
    say("This password is kept across reinstalls/profile switches now; it only changes if you remove "
        "this instance and set it up again.")
    post_install(side, c, profile)


# --------------------------------------------------------------------------
# Watchdog
# --------------------------------------------------------------------------

def load_state(record):
    state = {"fails": 0, "last": -1e9, "restarts": 0, "ok_since": None}
    try:
        loaded = json.loads(Path(record).read_text())
        if isinstance(loaded, dict):
            state.update({k: loaded[k] for k in state if k in loaded})
    except (OSError, ValueError):
        pass
    return state


def probe(side, c):
    """One health probe -> (verdict, message).

    ok    healthy
    fail  unhealthy and a restart may help (counts as a strike)
    wait  unhealthy but a restart cannot help (peer/network down); never counted
    skip  config/API problem on our side; never restart because of it
    """
    unit = paths(side)[2]
    try:
        api(c, "/healthz")
        if side == "frps":
            port = int(c["bindPort"])
            try:
                pid = int(run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                              check=False) or 0)
            except ValueError:
                pid = 0
            listeners = run(["ss", "-H", "-ltnp", f"sport = :{port}"], check=False)
            if not listeners:
                return "fail", f"nothing is listening on {port}/tcp"
            if pid > 0 and "pid=" in listeners and f"pid={pid}," not in listeners:
                return "fail", f"{port}/tcp is held by a process other than the service"
            return "ok", f"API healthy, listening on {port}/tcp"

        running, total = proxy_counts(api(c, "/api/status"))
    except (urllib.error.HTTPError, ssl.SSLError, ValueError, KeyError) as error:
        return "skip", f"admin API/config error ({type(error).__name__}); not restarting"
    except (OSError, http.client.HTTPException) as error:
        return "fail", f"admin API not responding ({type(error).__name__})"

    if running > 0:
        return "ok", f"{running}/{total} proxies running"

    expected = len(c.get("proxies") or [])
    if total == 0 and expected == 0:
        return "ok", "no proxies configured"

    # Nothing is running. NOTE: while frpc has no connection to frps, its API
    # returns an EMPTY list (total == 0), not "stopped" proxies - so total == 0
    # with proxies configured means "tunnel down", exactly like 0/N running.
    # Is the server even reachable from here?
    seen = f"0/{total or expected} proxies running"
    try:
        socket.create_connection((c["serverAddr"], int(c["serverPort"])), timeout=5).close()
    except OSError as error:
        return "wait", (f"{seen} and the server is unreachable ({type(error).__name__}); "
                        "frpc keeps retrying by itself, a restart would not help")
    return "fail", f"{seen} although the server port is reachable"


def watchdog(side):
    path = existing(side)
    if not path:
        return

    unit = paths(side)[2]
    c = read_config(path)
    strikes_needed = PROFILES[load_profile(side)]["strikes"]

    record = RUNTIME / f"{side}-{PORT}.json"
    state = load_state(record)
    now = MONO()
    if state["last"] > now:  # monotonic clock restarted after a reboot
        state["last"] = -1e9
        state["fails"] = 0
        state["ok_since"] = None
    state["fails"] = int(state["fails"])
    state["restarts"] = int(state["restarts"])

    def save():
        atomic(record, json.dumps(state))

    def restart(reason, reset_failed=False):
        # 1st automatic restart: immediate; 2nd: >=10 min later; 3rd: >=20 min; ... capped
        wait = min(WD_BACKOFF * 2 ** min(max(state["restarts"] - 1, 0), 10), WD_BACKOFF_MAX)
        since = now - state["last"]
        if since < wait:
            say(f"watchdog: {unit}: {reason}; restart suppressed, backoff {int(wait - since)}s left")
            return
        state["last"] = now
        state["restarts"] += 1
        state["fails"] = 0
        state["ok_since"] = None
        save()  # persist first, so a failing restart can never turn into a retry loop
        say(f"watchdog: restarting {unit}: {reason} (automatic restart #{state['restarts']})")
        if reset_failed:
            run(["systemctl", "reset-failed", unit], check=False)
        run(["systemctl", "restart", unit])

    active = run(["systemctl", "is-active", unit], check=False)

    if active == "failed":  # crashed and hit the start limit: systemd gave up
        restart("unit is in the failed state", reset_failed=True)
        save()
        return

    if active != "active":
        # "inactive" = stopped on purpose (leave it alone); "activating" /
        # "deactivating" = systemd is already handling it.
        state["fails"] = 0
        save()
        return

    entered = int(
        run(["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", unit],
            check=False) or 0
    ) / 1e6
    if entered and now - entered < WD_GRACE:
        return

    verdict, msg = probe(side, c)

    if verdict == "ok":
        if state["fails"] or state["restarts"]:
            say(f"watchdog: {unit}: healthy again ({msg})")
        state["fails"] = 0
        if state["ok_since"] is None:
            state["ok_since"] = now
        elif state["restarts"] and now - state["ok_since"] >= WD_HEALTHY_RESET:
            state["restarts"] = 0
    elif verdict == "fail":
        state["ok_since"] = None
        state["fails"] += 1
        say(f"watchdog: {unit}: strike {state['fails']}/{strikes_needed}: {msg}")
        if state["fails"] >= strikes_needed:
            restart(msg)
    else:  # wait / skip
        state["ok_since"] = None
        state["fails"] = 0
        say(f"watchdog: {unit}: {msg}")

    save()


# --------------------------------------------------------------------------
# Status / removal
# --------------------------------------------------------------------------

def transport_summary(c, side):
    t = c.get("transport", {})
    if side == "frpc":
        proto = t.get("protocol", "tcp")
    else:
        proto = "tcp+kcp" if c.get("kcpBindPort") else "tcp"
    return f"{proto}, tcpMux {'on' if t.get('tcpMux', True) else 'off'}"


def status():
    found = False
    for side in ("frps", "frpc"):
        path = existing(side)
        if not path:
            continue
        found = True
        c = read_config(path)
        unit = paths(side)[2]
        profile = load_profile(side)
        say(f"\n{unit}  [profile: {profile}; transport: {transport_summary(c, side)}]")
        say(run(["systemctl", "status", "--no-pager", "--lines=5", unit], check=False))
        try:
            data = api(
                c,
                "/api/serverinfo" if side == "frps" else "/api/status",
            )
            if side == "frpc":
                running, total = proxy_counts(data)
                if total == 0:
                    say("Tunnel is DOWN: frpc has no active connection to frps (it keeps retrying by itself)")
                else:
                    say(f"Registered running proxies: {running}/{total} (not a backend reachability test)")
                rows = [p for g in data.values() if isinstance(g, list)
                        for p in g if isinstance(p, dict)]
                bad = [p for p in rows if p.get("status") != "running"]
                for p in bad[:20]:
                    say(f"  {p.get('name', '?')}: {p.get('status', '?')} {p.get('err', '')}")
                if len(bad) > 20:
                    say(f"  ... and {len(bad) - 20} more not running")
            else:
                say(f"Server API reachable; connected clients: {data.get('clientCounts', 'unknown')}")
        except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
            say(f"Admin API unavailable: {type(error).__name__}")

        if side == "frpc":
            try:
                with socket.create_connection((c["serverAddr"], c["serverPort"]), timeout=5):
                    say("Tunnel to Iran server: control port TCP connect OK")
            except OSError as error:
                say(f"Tunnel to Iran server: control TCP connect FAILED ({error})")

            proxies = [p for p in c.get("proxies", []) if p.get("type") == "tcp" and "localPort" in p]
            ok = 0
            for p in proxies[:20]:
                try:
                    with socket.create_connection(
                        (p.get("localIP", "127.0.0.1"), p["localPort"]), timeout=2
                    ):
                        ok += 1
                except OSError:
                    say(f"  Backend {p['name']}: TCP FAILED")
            if proxies:
                say(f"TCP backends reachable: {ok}/{min(len(proxies), 20)}"
                    + (" (first 20 checked)" if len(proxies) > 20 else ""))

        timer = run(["systemctl", "is-active", wd_name(side) + ".timer"], check=False)
        st = load_state(RUNTIME / f"{side}-{PORT}.json")
        say(f"Watchdog: timer {timer}; strikes {st['fails']}/{PROFILES[profile]['strikes']}; "
            f"automatic restarts so far: {st['restarts']}")

    if not found:
        say("Nothing is installed yet.")


def remove():
    side = ask("Remove which instance: frps or frpc")
    if side not in ("frps", "frpc") or not existing(side):
        raise ValueError("No such managed configuration.")

    cfg, unitfile, unit = paths(side)

    if not yes(f"Stop and remove ONLY {unit}? Backups and shared binaries will remain"):
        return

    def do_remove():
        wd = wd_name(side)
        files = [
            cfg,
            cfg.with_suffix(".toml"),
            unitfile,
            unitfile.parent / (wd + ".timer"),
            unitfile.parent / (wd + ".service"),
            profile_file(side),
        ]
        backup = ROOT / "backups" / f"removed-{side}-{time.time_ns()}"
        snapshot(files, backup)

        run(["systemctl", "disable", "--now", wd + ".timer"], check=False)
        run(["systemctl", "stop", wd + ".service"], check=False)
        run(["systemctl", "disable", "--now", unit], check=False)
        for path in files:
            path.unlink(missing_ok=True)
        (RUNTIME / f"{side}-{PORT}.json").unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)

        say(f"Instance removed; backup: {backup}")
        say("Shared binaries/templates and journal were retained.")

    locked(do_remove)


def uninstall_all():
    if not yes("Are you sure you want to COMPLETELY UNINSTALL FRP and all components?"):
        return False

    def do_uninstall():
        unitdir = Path("/etc/systemd/system")

        # Complete uninstall is global because binaries, manager state and the
        # watchdog implementation are shared across all custom --port instances.
        managed_units = set()
        patterns = (
            "frps@server-*.service",
            "frpc@client-*.service",
            "frp-v5-watchdog-frps-*.service",
            "frp-v5-watchdog-frpc-*.service",
            "frp-v5-watchdog-frps-*.timer",
            "frp-v5-watchdog-frpc-*.timer",
            "frp-watchdog@frps.service",
            "frp-watchdog@frpc.service",
            "frp-watchdog@frps.timer",
            "frp-watchdog@frpc.timer",
        )
        for pattern in patterns:
            managed_units.update(p.name for p in unitdir.glob(pattern))

        say(f"Stopping and removing {len(managed_units)} managed systemd unit(s)...")
        for unit_name in sorted(managed_units):
            run(["systemctl", "disable", "--now", unit_name], check=False)
            run(["systemctl", "stop", unit_name], check=False)

        # Remove only unit files matching this manager's naming scheme. Do not
        # touch unrelated systemd units.
        for unit_name in managed_units:
            (unitdir / unit_name).unlink(missing_ok=True)

        say("Removing binaries, configurations, and state...")
        Path("/usr/local/bin/frps").unlink(missing_ok=True)
        Path("/usr/local/bin/frpc").unlink(missing_ok=True)
        Path("/usr/local/bin/frp-watchdog.sh").unlink(missing_ok=True)
        SELF.unlink(missing_ok=True)

        shutil.rmtree(ROOT, ignore_errors=True)
        shutil.rmtree(STATE, ignore_errors=True)
        shutil.rmtree(RUNTIME, ignore_errors=True)

        # Reload only after unit files have actually been removed.
        run(["systemctl", "daemon-reload"], check=False)

        say("FRP and all related components have been successfully uninstalled.")

    locked(do_uninstall)
    return True


def locked(action, nonblocking=False):
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(RUNTIME / "manager.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if nonblocking:
                return
            raise RuntimeError("Another FRP manager action is running.")
        return action()


def main():
    global PORT, TOKEN
    parser = argparse.ArgumentParser(description="FRP v5.3 safe local manager")
    parser.add_argument("--port", type=int, default=2087)
    parser.add_argument("--watchdog", choices=["frps", "frpc"])
    parser.add_argument("--profile", choices=list(PROFILES),
                        help="skip the profile question when installing")
    parser.add_argument("--token", default=DEFAULT_TOKEN,
                        help="auth token; must be identical on both servers (default: 123)")
    args = parser.parse_args()
    PORT = args.port
    TOKEN = args.token

    if not 1 <= PORT <= 65535 or PORT in (7400, 7500):
        raise ValueError("Invalid/conflicting FRP control port.")

    if not re.fullmatch(r"[A-Za-z0-9._~+=-]{3,128}", TOKEN):
        raise ValueError("Token must be 3-128 characters from A-Z a-z 0-9 . _ ~ + = -")

    if os.geteuid() != 0:
        raise ValueError("Run as root.")

    validate_profiles()

    os.umask(0o077)
    for command in ("systemctl", "ss"):
        if not shutil.which(command):
            raise ValueError(f"Missing required command: {command}")

    if not Path("/run/systemd/system").is_dir():
        raise ValueError("A running systemd Linux host is required.")

    if args.watchdog:
        locked(lambda: watchdog(args.watchdog), nonblocking=True)
        return

    if not sys.stdin.isatty():
        sys.stdin = open("/dev/tty")

    say(f"FRP manager v{MANAGER_VERSION} / FRP {VERSION} / control port {PORT}")
    if TOKEN == DEFAULT_TOKEN:
        say("WARNING: default token '123' is public knowledge. Anyone who can reach the control port")
        say("         can register ports on the Iran server. Use --token <secret> on BOTH servers.")
    else:
        say("Custom token in use (must be identical on both servers).")

    actions = {
        "1": lambda: configure("frps", args.profile),
        "2": lambda: configure("frpc", args.profile),
        "3": status,
        "5": remove,
    }

    while True:
        say("\n1) Install IRAN frps\n2) Install OUTSIDE frpc\n3) Status\n4) Live logs")
        say("5) Remove one instance\n6) Exit\n7) Complete Uninstall")
        try:
            choice = ask("Select", "6")
        except (KeyboardInterrupt, EOFError):
            say("")
            return
        if choice == "6":
            return

        try:
            if choice == "7":
                if uninstall_all():
                    return
            elif choice == "4":
                side = ask("frps or frpc", "frpc")
                if side not in ("frps", "frpc"):
                    raise ValueError("Invalid side.")
                subprocess.run(
                    ["journalctl", "-u", paths(side)[2], "-f", "--no-pager"],
                    check=False,
                )
            elif choice in actions:
                actions[choice]()
            else:
                say("Invalid menu option.")
        except KeyboardInterrupt:
            say("Cancelled.")
        except Exception as error:
            say(f"ERROR: {error}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("Cancelled.")
        sys.exit(130)
    except Exception as error:
        say(f"ERROR: {error}")
        sys.exit(1)
PYTHON
