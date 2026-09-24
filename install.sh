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
PORT = 2087
DEFAULT_TOKEN = "123"
TOKEN = DEFAULT_TOKEN
MAX_POOL = 100    # frps accepts any client pool size up to this

# Connection profiles. Timers, keepalives and pool size are per side, so frps and
# frpc may use different profiles. Two fields change the TRANSPORT itself and must
# therefore agree between the two servers ("strict" profiles - choose them on BOTH):
#   mux     tcpMux on/off. frp requires the same value on frps and frpc.
#           on  = every proxied flow shares ONE TCP connection (few sockets, but a
#                 lost packet or a bulk download stalls every other flow, game UDP included)
#           off = every flow gets its own TCP connection (no head-of-line blocking)
#   proto   tcp | kcp. frpc dials it; frps opens the matching listener (kcp = UDP).
#           frps ALWAYS also keeps its plain TCP bindPort listening, even when a kcp
#           profile is installed, so mixing a tcp frpc against a kcp frps (or the
#           reverse) simply fails the login rather than silently limping along.
# Measured (100 ms RTT, 1% loss each way, game UDP + bulk in one tunnel): mux on gave
# 141 ms median / 273 ms p95, mux off 105 / 210, kcp 119 / 135; with a saturated link
# the median game RTT was 1326 ms (mux on) vs 158 ms (mux off).
#
# Per profile, only ONE of the next two knobs is ever live - the other is inert and
# kept only so the table stays easy to compare:
#   mux_ka   yamux keepalive interval (s) - LIVE only when mux=True; ignored when mux=False.
#   hb_iv    frpc heartbeat interval (s) - LIVE only when mux=False. When mux=True,
#            frpc gets heartbeatInterval=-1 instead: tcpMux already keeps the session
#            alive via mux_ka, and frp skips heartbeat-timeout enforcement entirely
#            while tcpMux is on, so a second heartbeat would be pure overhead.
#   hb_to_c  frpc heartbeat timeout (s) - LIVE only when mux=False, same reason as hb_iv.
# These two are always live regardless of mux, since frps keeps enforcing them even
# when the paired frpc has gone silent under tcpMux (harmless when it never fires):
#   tcp_ka   TCP keepalive (s): frps accepted conns / frpc dial
#   hb_to_s  frps heartbeat timeout (s) - always >= 8x the paired frpc's hb_iv, so a
#            profile mismatch or one slow beat never trips a false disconnect
#   dial_to  frpc dial timeout to frps (s)
#   pool     frpc pre-established work-connection pool
#   user_to  frps: how long a user connection waits for a free work conn (s)
#   strikes  consecutive failed watchdog checks (1/min) before a restart
PROFILES = {
    "balanced": dict(
        desc="recommended default: good speed, stable, low overhead",
        proto="tcp", mux=True, strict=False,
        mux_ka=20, tcp_ka=30, hb_iv=15, hb_to_c=60, hb_to_s=120,
        dial_to=15, pool=10, user_to=30, strikes=5,
    ),
    # gaming heartbeat 5/15/45: with mux off, a 25 s path blackout took 8.8 s to recover
    # with 10/40/80 but 1.9 s with 5/15/45 (kcp recovers in ~1.4 s with either).
    "gaming": dict(
        desc="lowest jitter over TCP: own connection per flow, bulk can't stall games [BOTH servers]",
        proto="tcp", mux=False, strict=True,
        mux_ka=10, tcp_ka=15, hb_iv=5, hb_to_c=15, hb_to_s=45,
        dial_to=10, pool=16, user_to=10, strikes=3,
    ),
    # mux stays ON here (unlike plain "gaming"): a KCP session already carries its own
    # ARQ/ordering cost per session, so splitting every flow into its own KCP session
    # (mux off) trades one head-of-line-blocking problem for extra per-session
    # handshake/window overhead instead of removing it. This profile only comes out
    # ahead if the tunnel carries GAME PORTS ONLY - mix in a bulk transfer and the
    # same stall this table warns about for TCP+mux applies here too.
    "gaming-kcp": dict(
        desc="best jitter tail if UDP passes (KCP); game ports only, nothing else in this tunnel [BOTH servers]",
        proto="kcp", mux=True, strict=True,
        mux_ka=10, tcp_ka=15, hb_iv=10, hb_to_c=40, hb_to_s=80,
        dial_to=10, pool=16, user_to=10, strikes=3,
    ),
    "streaming": dict(
        desc="smooth long sessions: tolerant timeouts, big pool, no false drops",
        proto="tcp", mux=True, strict=False,
        mux_ka=30, tcp_ka=30, hb_iv=20, hb_to_c=90, hb_to_s=180,
        dial_to=15, pool=16, user_to=45, strikes=5,
    ),
    "speed": dict(
        desc="max throughput: biggest pool, timeouts tolerant of a saturated link",
        proto="tcp", mux=True, strict=False,
        mux_ka=30, tcp_ka=30, hb_iv=30, hb_to_c=120, hb_to_s=240,
        dial_to=20, pool=32, user_to=30, strikes=5,
    ),
}
DEFAULT_PROFILE = "balanced"

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
    return name if name in PROFILES else DEFAULT_PROFILE


def choose_profile(preset=None):
    if preset:
        return preset
    names = list(PROFILES)
    say("\nConnection profile ([BOTH servers] = must be the same profile on frps and frpc):")
    for i, name in enumerate(names, 1):
        say(f"  {i}) {name:<10} - {PROFILES[name]['desc']}")
    while True:
        raw = ask("Profile", "1").lower()
        if raw in PROFILES:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(names):
            return names[int(raw) - 1]
        say(f"Enter 1-{len(names)} or a profile name.")


def patch_transport(c, side, p):
    t = c.setdefault("transport", {})
    t["tcpMux"] = p["mux"]
    if p["mux"]:
        t["tcpMuxKeepaliveInterval"] = p["mux_ka"]
    if side == "frps":
        # frps' own heartbeatTimeout is harmless to keep set even when the paired
        # frpc runs tcpMux: frps then relies on the tcpMux keepalive instead, same
        # as frpc does below, so this value only matters for a non-mux frpc.
        t.update(heartbeatTimeout=p["hb_to_s"], tcpKeepalive=p["tcp_ka"], maxPoolCount=MAX_POOL)
        c["userConnTimeout"] = p["user_to"]
    else:
        t.update(
            poolCount=p["pool"],
            dialServerTimeout=p["dial_to"],
            dialServerKeepalive=p["tcp_ka"],
        )
        if p["mux"]:
            # Once tcpMux is enabled the client should NOT send an extra application
            # heartbeat (tcpMux carries its own keepalive) and frp ignores
            # heartbeatTimeout for session-liveness while tcpMux is on anyway - so
            # hb_iv/hb_to_c would be pure wasted round trips here, not a safety margin.
            t.update(heartbeatInterval=-1, heartbeatTimeout=-1)
        else:
            # No mux: this pair IS the only liveness signal, so it must be real.
            t.update(heartbeatInterval=p["hb_iv"], heartbeatTimeout=p["hb_to_c"])
        c["loginFailExit"] = False


def dashboard_password(side):
    """Reuse the current dashboard password across reinstalls/profile switches.

    Without this, every reinstall (even just to switch a profile) would silently
    rotate the dashboard password - and the script never prints it anywhere after
    first install, so the old one would become unrecoverable without manually
    reading the root-only config.
    """
    old = existing(side)
    if not old:
        return None
    try:
        return read_config(old).get("webServer", {}).get("password") or None
    except (OSError, ValueError):
        return None


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
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "i386": "386",
        "i686": "386",
    }.get(os.uname().machine)
    if not arch:
        raise ValueError("Unsupported architecture.")

    pkg = f"frp_{VERSION}_linux_{arch}"
    base = f"https://github.com/fatedier/frp/releases/download/v{VERSION}"
    say(f"Downloading and SHA256-checking {side} {VERSION} ...")

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
        present = path.exists()
        if present:
            shutil.copy2(path, saved)
        entries.append((path, saved if present else None))

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
                # It has already been migrated into cfg (JSON) and a copy already
                # sits in this install's own backup snapshot, so keeping the live
                # legacy file around only risks read_config() or a human picking
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
        if prof["proto"] == "kcp":
            c["kcpBindPort"] = PORT  # UDP listener next to the TCP one
        # No allowPorts restriction: whatever the client registers is accepted,
        # so a forgotten server-side allow-list can never block the tunnel.
    else:
        c.update(serverAddr=host, serverPort=PORT)
        # TLS stays encrypted but unauthenticated (frps uses its own automatic
        # certificate, so there is nothing fixed to pin against).
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
            pr = PROFILES[profile]
            # frpc's control connection is UDP-only under the kcp profile, so the
            # tcp port is irrelevant to ITS connectivity - say the right one during
            # exactly the troubleshooting moment where precision matters most.
            control = f"{PORT}/udp (KCP)" if pr["proto"] == "kcp" else f"{PORT}/tcp"
            say("  Check: frps installed and running on the Iran server; its firewall allows "
                f"{control}; the same token on both sides; then: journalctl -u {unit} -n 50 --no-pager")
            if pr["proto"] == "kcp":
                say(f"  '{profile}' uses UDP: allow {PORT}/udp on the Iran server and its provider firewall, "
                    f"and install frps with '{profile}' too. If UDP is filtered on this route, use 'gaming' "
                    "(TCP) on both servers instead.")
            elif not pr["mux"]:
                say(f"  '{profile}' turns tcpMux off: frps must ALSO be installed with '{profile}' "
                    "(a tcpMux mismatch makes the login fail).")
            else:
                say("  If frps runs 'gaming' (tcpMux off) or 'gaming-kcp', use that same profile here.")
    else:
        kcp = f" and {PORT}/udp (KCP)" if c.get("kcpBindPort") else ""
        same = f" and the same profile ('{profile}')" if PROFILES[profile]["strict"] else ""
        say(f"frps is up and listening on {PORT}/tcp{kcp}. Install frpc on the foreign server "
            f"with the same token{same}.")

    timer = run(["systemctl", "is-active", wd + ".timer"], check=False)
    code, out = run_rc(["systemctl", "start", wd + ".service"], timeout=90)
    verdict, msg = probe(side, c)
    say(f"Watchdog self-test: timer={timer}, service run={'OK' if code == 0 else 'FAILED'}, "
        f"probe={verdict} ({msg})")
    if timer != "active" or code != 0:
        say(f"WARNING: the watchdog is NOT working correctly: {out}")
        say(f"  See: journalctl -u {wd}.service -n 30 --no-pager")

    if not PROFILES[profile]["mux"]:
        say(f"NOTE ('{profile}' runs tcpMux off): frp {VERSION} has an open upstream report "
            "(fatedier/frp PR #5539, not merged/released yet) where a stale control session's "
            "heartbeat timer can close a healthy, just-reconnected non-mux session on the frps "
            "side. frpc reconnects by itself within seconds when this happens (loginFailExit is "
            "off), so in practice it looks like an occasional short blip rather than real downtime, "
            "and the watchdog only restarts the service if it does NOT recover on its own. Worth "
            "knowing if you ever see an unexplained brief reconnect on this profile.")
    elif profile == "gaming-kcp":
        say("NOTE ('gaming-kcp' keeps tcpMux on): only forward game ports through this tunnel. "
            "Adding a bulk-transfer port to the same instance reintroduces the head-of-line "
            "stall this profile exists to avoid - use plain 'gaming' instead for a mixed tunnel.")


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
    if prof["strict"]:
        say(f"NOTE: '{profile}' changes the transport, so the OTHER server must use '{profile}' as well.")
    c = build_config(side, profile, host, ports)

    locked(lambda: install(side, c, profile))
    say("No firewall was changed. Allow ONLY required ports in the Iran host/provider firewall.")
    if side == "frps" and c.get("kcpBindPort"):
        say(f"KCP needs {PORT}/udp open in the Iran host/provider firewall (in addition to {PORT}/tcp).")
    if ports:
        control = f"{PORT}/udp (KCP)" if prof["proto"] == "kcp" else f"{PORT}/tcp"
        say(f"Control: {control}; forwarded TCP+UDP ports: " + " ".join(map(str, ports)))
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
    if state["last"] > now:
        # BUG FIX (v5.3): a reboot resets time.monotonic()'s reference point, so an
        # old "last restart" timestamp from before the reboot can land in the
        # future relative to the new clock. The previous code caught that for
        # "last" (so backoff correctly forgets it and can restart immediately
        # again if needed) but NOT for "ok_since": a stale, still-in-the-future
        # ok_since made `now - ok_since` permanently negative, so the healthy-long-
        # enough check below could never fire and the restart-count backoff could
        # stay elevated forever after a reboot, even after the tunnel had been
        # healthy for hours. Reset both together.
        state["last"] = -1e9
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
                say(f"Backends reachable: {ok}/{min(len(proxies), 20)}"
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
        say("Stopping and removing services...")
        for side in ("frps", "frpc"):
            _, unitfile, unit = paths(side)
            wd = wd_name(side)
            for target in (wd + ".timer", wd + ".service", unit,
                           f"frp-watchdog@{side}.timer", f"frp-watchdog@{side}.service"):
                run(["systemctl", "disable", "--now", target], check=False)
                run(["systemctl", "stop", target], check=False)
            (unitfile.parent / (wd + ".timer")).unlink(missing_ok=True)
            (unitfile.parent / (wd + ".service")).unlink(missing_ok=True)
            unitfile.unlink(missing_ok=True)

        run(["systemctl", "daemon-reload"], check=False)

        say("Removing binaries, configurations, and state...")
        Path("/usr/local/bin/frps").unlink(missing_ok=True)
        Path("/usr/local/bin/frpc").unlink(missing_ok=True)
        Path("/usr/local/bin/frp-watchdog.sh").unlink(missing_ok=True)
        SELF.unlink(missing_ok=True)

        shutil.rmtree(ROOT, ignore_errors=True)
        shutil.rmtree(STATE, ignore_errors=True)
        shutil.rmtree(RUNTIME, ignore_errors=True)

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

    say(f"FRP manager v5.3 / FRP {VERSION} / control port {PORT}")
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
