#!/usr/bin/env bash
# FRP v5.4: safe, highly-optimized local manager for FRP 0.71.0.
# Requirements: Python >= 3.8, systemd Linux.
set -Eeuo pipefail

FRP_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$FRP_SOURCE" ]]; then
    export FRP_MANAGER_SOURCE="$(readlink -f -- "$FRP_SOURCE")"
else
    echo "ERROR: this script must be saved to a file and run directly." >&2
    echo "Fix: save it first, e.g.:" >&2
    echo "  nano frp-manager.sh && chmod +x frp-manager.sh && sudo ./frp-manager.sh" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required. Install it first: apt update && apt install -y python3" >&2
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
    import tomllib
except ImportError:
    tomllib = None

VERSION = "0.71.0"
PORT = 2087
DEFAULT_TOKEN = "123"
TOKEN = DEFAULT_TOKEN

PROFILES = {
    "balanced": dict(
        desc="Balanced default: multiplexed TCP, low resource usage, solid stability",
        proto="tcp", mux=True, strict=False,
        mux_ka=25, tcp_ka=30, hb_iv=20, hb_to_c=60, hb_to_s=75,
        dial_to=10, pool=12, user_to=30, strikes=4,
    ),
    "gaming": dict(
        desc="Lowest latency & jitter over TCP: mux OFF (no Head-of-Line blocking), pool=32 [BOTH servers]",
        proto="tcp", mux=False, strict=True,
        mux_ka=10, tcp_ka=15, hb_iv=10, hb_to_c=30, hb_to_s=35,
        dial_to=10, pool=32, user_to=25, strikes=3,
    ),
    "gaming-kcp": dict(
        desc="Resistant to packet-loss: KCP over UDP, fast recovery, best for lossy routes [BOTH servers]",
        proto="kcp", mux=True, strict=True,
        mux_ka=15, tcp_ka=15, hb_iv=15, hb_to_c=40, hb_to_s=45,
        dial_to=10, pool=24, user_to=25, strikes=3,
    ),
    "streaming": dict(
        desc="Continuous high-bitrate media: large pool, tolerant timeouts to prevent buffering stalls",
        proto="tcp", mux=True, strict=False,
        mux_ka=30, tcp_ka=45, hb_iv=25, hb_to_c=75, hb_to_s=90,
        dial_to=15, pool=24, user_to=45, strikes=5,
    ),
    "speed": dict(
        desc="Maximum throughput: mux OFF (bypasses Yamux buffer limits), massive pool=40 [BOTH servers]",
        proto="tcp", mux=False, strict=True,
        mux_ka=20, tcp_ka=30, hb_iv=20, hb_to_c=60, hb_to_s=90,
        dial_to=20, pool=40, user_to=60, strikes=5,
    ),
}
DEFAULT_PROFILE = "balanced"

MAX_POOL = max(p["pool"] for p in PROFILES.values()) + 32

WD_GRACE = 90
WD_BACKOFF = 300
WD_BACKOFF_MAX = 3600
WD_HEALTHY_RESET = 1200
MONO = time.monotonic

ROOT = Path("/root/frp")
STATE = Path("/etc/frp-manager")
SELF = Path("/usr/local/libexec/frp-manager")
RUNTIME = Path("/run/frp-manager")

TAG = "# Managed by frp-manager-v5.4"


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
    try:
        p = _exec(args, timeout, None)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return p.returncode, (p.stdout + p.stderr).strip()


def yes(question):
    return input(question + " [y/N]: ").strip().lower() == "y"


def ask(question, default=""):
    prompt = f"{question}" + (f" [{default}]" if default else "") + ": "
    value = input(prompt).strip()
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
        raise ValueError("Templated configs need manual migration.")
    if str(path).endswith(".json"):
        value = json.loads(text)
    elif tomllib:
        value = tomllib.loads(text)
    else:
        raise ValueError("Legacy TOML config requires Python 3.11+.")
    if not isinstance(value, dict):
        raise ValueError("Config root must be a JSON object.")
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
            raise ValueError("Maximum 1024 unique ports allowed per config.")
        found.update(range(start, end + 1))

    if len(found) > 1024:
        raise ValueError("Maximum 1024 unique ports allowed per config.")
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
        return False
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
    say("\nSelect Connection Profile ([BOTH servers] must match on frps and frpc):")
    for i, name in enumerate(names, 1):
        say(f"  {i}) {name:<11} - {PROFILES[name]['desc']}")
    while True:
        raw = ask("Profile", "1").lower()
        if raw in PROFILES:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(names):
            return names[int(raw) - 1]
        say(f"Enter 1-{len(names)} or profile name.")


def patch_transport(c, side, p):
    t = c.setdefault("transport", {})
    t["tcpMux"] = p["mux"]
    if p["mux"]:
        t["tcpMuxKeepaliveInterval"] = p["mux_ka"]

    if side == "frps":
        t.update(
            heartbeatTimeout=p["hb_to_s"],
            tcpKeepalive=p["tcp_ka"],
            maxPoolCount=MAX_POOL,
            userConnTimeout=p["user_to"],
        )
    else:
        t.update(
            poolCount=p["pool"],
            dialServerTimeout=p["dial_to"],
            dialServerKeepalive=p["tcp_ka"],
            heartbeatInterval=p["hb_iv"],
            heartbeatTimeout=p["hb_to_c"],
        )
        c["loginFailExit"] = False


def dashboard_password(side):
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
            f"{'UDP' if udp else 'TCP'} port {port} is busy; cannot bind.\n{listeners}"
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
                    raise ValueError("Insecure redirect.")
                content = response.read(limit + 1)
            if len(content) > limit:
                raise ValueError("Download exceeds size limit.")
            return content
        except (OSError, http.client.HTTPException) as error:
            last = error
            if attempt + 1 < tries:
                say(f"  Download error ({type(error).__name__}); retrying...")
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
    say(f"Downloading FRP {side} {VERSION} [{arch}]...")

    sums = fetch(base + "/frp_sha256_checksums.txt", 1024 * 1024).decode()
    expected = None
    for line in sums.splitlines():
        fields = line.split()
        if len(fields) == 2 and Path(fields[1].lstrip("*")).name == pkg + ".tar.gz":
            expected = fields[0]
            break

    if not expected or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("Official SHA256 missing.")

    archive = fetch(base + "/" + pkg + ".tar.gz", 100 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != expected.lower():
        raise ValueError("SHA256 checksum mismatch.")

    tarpath = directory / "frp.tar.gz"
    tarpath.write_bytes(archive)
    output = directory / side

    with tarfile.open(tarpath, "r:gz") as tar:
        try:
            member = tar.getmember(pkg + "/" + side)
        except KeyError:
            raise ValueError(f"Archive missing {side} binary.")
        if not member.isfile() or not 0 < member.size <= 100 * 1024 * 1024:
            raise ValueError("Invalid binary in archive.")
        with tar.extractfile(member) as source:
            output.write_bytes(source.read())

    output.chmod(0o755)
    if run([output, "-v"]) != VERSION:
        raise ValueError("Binary version mismatch.")
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
RestartSec=3s
TimeoutStopSec=15s
LimitNOFILE=262144
LimitNPROC=65535
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
    old = existing(side)

    targets = [cfg, unitfile, ws, wt, executable, SELF, pfile]
    if old and old != cfg:
        targets.append(old)

    with tempfile.TemporaryDirectory(prefix="frp-v5-") as tmp:
        tmp = Path(tmp)
        if binary_version(executable) == VERSION:
            staged = executable
            say(f"{side} {VERSION} already present; skipping binary download.")
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
            for u in (unit, wd + ".timer")
        }

        try:
            run(["systemctl", "disable", "--now", wd + ".timer"], check=False)
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
OnBootSec=90s
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
                if run(["systemctl", "is-active", unit], check=False) == "active":
                    try:
                        api(c, "/healthz", timeout=1)
                        ready = True
                        break
                    except (OSError, ValueError, http.client.HTTPException):
                        pass

            if not ready:
                raise RuntimeError("Service health check failed. Run journalctl -u " + unit)

            (RUNTIME / f"{side}-{PORT}.json").unlink(missing_ok=True)
            run(["systemctl", "start", wd + ".timer"])
            if old and old != cfg:
                old.unlink(missing_ok=True)

        except BaseException:
            say(f"Installation failed; restoring backup snapshot: {backupdir}")
            for u in (wd + ".timer", unit):
                run(["systemctl", "stop", u], check=False)
            restore(saved)
            run(["systemctl", "daemon-reload"], check=False)
            for u, (active, enabled) in states.items():
                run(["systemctl", "enable" if enabled else "disable", u], check=False)
                if active:
                    run(["systemctl", "start", u], check=False)
            raise

    say(f"Successfully configured [{profile}]. Backup: {backupdir}\nConfig: {cfg}")
    return backupdir


def build_config(side, profile, token, host=None, ports=()):
    prof = PROFILES[profile]
    c = base_config(side, token, prof)
    if side == "frps":
        c.update(
            bindAddr="0.0.0.0",
            bindPort=PORT,
            proxyBindAddr="0.0.0.0",
            detailedErrorsToClient=False,
        )
        if prof["proto"] == "kcp":
            c["kcpBindPort"] = PORT
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
    unit = paths(side)[2]
    wd = wd_name(side)

    if side == "frpc":
        say("Checking tunnel status (waiting up to 25s)...")
        running, total = wait_tunnel(c, 25)
        if total and running == total:
            say(f"TUNNEL UP: {running}/{total} proxies active.")
        else:
            say(f"STATUS: {running}/{total} proxies running.")
            pr = PROFILES[profile]
            control = f"{PORT}/udp (KCP)" if pr["proto"] == "kcp" else f"{PORT}/tcp"
            say(f"Notice: Verify port {control} is opened in Iran firewall and frps is active.")
    else:
        kcp = f" and {PORT}/udp (KCP)" if c.get("kcpBindPort") else ""
        say(f"frps is active on {PORT}/tcp{kcp}.")

    timer = run(["systemctl", "is-active", wd + ".timer"], check=False)
    code, _ = run_rc(["systemctl", "start", wd + ".service"], timeout=90)
    verdict, msg = probe(side, c)
    say(f"Watchdog probe: {verdict} ({msg}); Timer: {timer}")


def configure(side, preset=None):
    global TOKEN
    host = None
    ports = []

    if side == "frpc":
        host = ask("Server IP (Iran frps IPv4 address or domain)")
        if not valid_host(host):
            raise ValueError("Invalid hostname or IP.")
        ports = parse_ports(
            ask("Ports to forward (e.g. 443,8080,20000-20050)", "8080"),
            {PORT, 7400, 7500},
        )

    token = ask("Auth Token (must match on BOTH servers)", TOKEN)
    if not re.fullmatch(r"[A-Za-z0-9._~+=-]{3,128}", token):
        raise ValueError("Token must be 3-128 valid characters.")
    TOKEN = token

    profile = choose_profile(preset)
    prof = PROFILES[profile]
    if prof["strict"]:
        say(f"NOTE: '{profile}' requires the EXACT SAME profile on BOTH frps and frpc.")

    c = build_config(side, profile, TOKEN, host, ports)
    locked(lambda: install(side, c, profile))

    w = c["webServer"]
    say(f"Dashboard: http://127.0.0.1:{w['port']} (user={w['user']}, pass={w['password']})")
    post_install(side, c, profile)


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
    unit = paths(side)[2]
    try:
        api(c, "/healthz")
        if side == "frps":
            port = int(c["bindPort"])
            listeners = run(["ss", "-H", "-ltnp", f"sport = :{port}"], check=False)
            if not listeners:
                return "fail", f"nothing listening on {port}/tcp"
            return "ok", f"API healthy, bound to {port}/tcp"

        running, total = proxy_counts(api(c, "/api/status"))
    except (urllib.error.HTTPError, ssl.SSLError, ValueError, KeyError) as error:
        return "skip", f"admin API config issue ({type(error).__name__})"
    except (OSError, http.client.HTTPException) as error:
        return "fail", f"admin API unreachable ({type(error).__name__})"

    if running > 0:
        return "ok", f"{running}/{total} proxies active"

    expected = len(c.get("proxies") or [])
    if total == 0 and expected == 0:
        return "ok", "no proxies registered"

    seen = f"0/{total or expected} proxies active"
    # Reachability test
    proto = c.get("transport", {}).get("protocol", "tcp")
    if proto == "tcp":
        try:
            socket.create_connection((c["serverAddr"], int(c["serverPort"])), timeout=4).close()
        except OSError as error:
            return "wait", f"{seen}; Iran server unreachable ({type(error).__name__}), deferring restart"

    return "fail", f"{seen} while control port is accessible"


def watchdog(side):
    path = existing(side)
    if not path:
        return

    unit = paths(side)[2]
    c = read_config(path)
    profile = load_profile(side)
    strikes_needed = PROFILES[profile]["strikes"]

    record = RUNTIME / f"{side}-{PORT}.json"
    state = load_state(record)
    now = MONO()
    if state["last"] > now:
        state["last"] = -1e9
    state["fails"] = int(state["fails"])
    state["restarts"] = int(state["restarts"])

    def save():
        atomic(record, json.dumps(state))

    def restart(reason, reset_failed=False):
        current = run(["systemctl", "is-active", unit], check=False)
        if current in ("activating", "deactivating"):
            return
        wait = min(WD_BACKOFF * (2 ** min(max(state["restarts"] - 1, 0), 6)), WD_BACKOFF_MAX)
        since = now - state["last"]
        if since < wait:
            say(f"watchdog: restart suppressed; backoff cooling {int(wait - since)}s left")
            return
        state["last"] = now
        state["restarts"] += 1
        state["fails"] = 0
        state["ok_since"] = None
        save()
        say(f"watchdog: restarting {unit}: {reason} (restart #{state['restarts']})")
        if reset_failed:
            run(["systemctl", "reset-failed", unit], check=False)
        run(["systemctl", "restart", unit])

    active = run(["systemctl", "is-active", unit], check=False)
    if active == "failed":
        restart("unit failed", reset_failed=True)
        save()
        return

    if active != "active":
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
        state["fails"] = 0
        if state["ok_since"] is None:
            state["ok_since"] = now
        elif state["restarts"] and now - state["ok_since"] >= WD_HEALTHY_RESET:
            state["restarts"] = 0
    elif verdict == "fail":
        state["ok_since"] = None
        state["fails"] += 1
        say(f"watchdog: {unit} strike {state['fails']}/{strikes_needed}: {msg}")
        if state["fails"] >= strikes_needed:
            restart(msg)
    else:
        state["ok_since"] = None
        state["fails"] = 0

    save()


def transport_summary(c, side):
    t = c.get("transport", {})
    proto = t.get("protocol", "tcp") if side == "frpc" else ("tcp+kcp" if c.get("kcpBindPort") else "tcp")
    return f"{proto}, tcpMux={'on' if t.get('tcpMux', True) else 'off'}"


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
        say(f"\n{unit} [Profile: {profile}; Transport: {transport_summary(c, side)}]")
        say(run(["systemctl", "status", "--no-pager", "--lines=4", unit], check=False))
        try:
            data = api(c, "/api/serverinfo" if side == "frps" else "/api/status")
            if side == "frpc":
                running, total = proxy_counts(data)
                say(f"Active Proxies: {running}/{total}")
            else:
                say(f"Connected Clients: {data.get('clientCounts', 'unknown')}")
        except Exception as e:
            say(f"API readout unavailable: {type(e).__name__}")
    if not found:
        say("No FRP service installed.")


def remove():
    side = ask("Remove which instance: frps or frpc")
    if side not in ("frps", "frpc") or not existing(side):
        raise ValueError("Instance does not exist.")

    cfg, unitfile, unit = paths(side)
    if not yes(f"Remove {unit} and its configuration?"):
        return

    def do_remove():
        wd = wd_name(side)
        run(["systemctl", "disable", "--now", wd + ".timer", unit], check=False)
        run(["systemctl", "stop", wd + ".service"], check=False)
        for p in (cfg, unitfile, unitfile.parent / (wd + ".timer"), unitfile.parent / (wd + ".service"), profile_file(side)):
            p.unlink(missing_ok=True)
        (RUNTIME / f"{side}-{PORT}.json").unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
        say(f"{unit} removed successfully.")

    locked(do_remove)


def uninstall_all():
    if not yes("Completely remove FRP, services, and all configs?"):
        return False

    def do_uninstall():
        for side in ("frps", "frpc"):
            _, unitfile, unit = paths(side)
            wd = wd_name(side)
            run(["systemctl", "disable", "--now", wd + ".timer", unit], check=False)
            (unitfile.parent / (wd + ".timer")).unlink(missing_ok=True)
            (unitfile.parent / (wd + ".service")).unlink(missing_ok=True)
            unitfile.unlink(missing_ok=True)

        run(["systemctl", "daemon-reload"], check=False)
        for b in ("/usr/local/bin/frps", "/usr/local/bin/frpc", "/usr/local/bin/frp-watchdog.sh", str(SELF)):
            Path(b).unlink(missing_ok=True)

        shutil.rmtree(ROOT, ignore_errors=True)
        shutil.rmtree(STATE, ignore_errors=True)
        shutil.rmtree(RUNTIME, ignore_errors=True)
        say("All FRP components have been uninstalled.")

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
    parser = argparse.ArgumentParser(description="FRP v5.4 Safe Manager")
    parser.add_argument("--port", type=int, default=2087)
    parser.add_argument("--watchdog", choices=["frps", "frpc"])
    parser.add_argument("--profile", choices=list(PROFILES))
    parser.add_argument("--token", default=DEFAULT_TOKEN)
    args = parser.parse_args()
    PORT = args.port
    TOKEN = args.token

    if not 1 <= PORT <= 65535 or PORT in (7400, 7500):
        raise ValueError("Invalid port.")
    if os.geteuid() != 0:
        raise ValueError("Must run as root.")

    for cmd in ("systemctl", "ss"):
        if not shutil.which(cmd):
            raise ValueError(f"Missing command: {cmd}")

    if args.watchdog:
        locked(lambda: watchdog(args.watchdog), nonblocking=True)
        return

    if not sys.stdin.isatty():
        sys.stdin = open("/dev/tty")

    say(f"FRP Manager v5.4 | FRP {VERSION} | Control Port: {PORT}")

    actions = {
        "1": lambda: configure("frps", args.profile),
        "2": lambda: configure("frpc", args.profile),
        "3": status,
        "5": remove,
    }

    while True:
        say("\n1) Install IRAN (frps)\n2) Install OUTSIDE (frpc)\n3) Status\n4) Live logs\n5) Remove instance\n6) Exit\n7) Complete Uninstall")
        try:
            choice = ask("Select", "6")
        except (KeyboardInterrupt, EOFError):
            return
        if choice == "6":
            return
        try:
            if choice == "7":
                if uninstall_all():
                    return
            elif choice == "4":
                side = ask("frps or frpc", "frpc")
                subprocess.run(["journalctl", "-u", paths(side)[2], "-f", "--no-pager"], check=False)
            elif choice in actions:
                actions[choice]()
        except KeyboardInterrupt:
            say("Cancelled.")
        except Exception as e:
            say(f"ERROR: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as error:
        say(f"ERROR: {error}")
        sys.exit(1)
PYTHON
