#!/usr/bin/env bash
# FRP v5.3 safe local manager (frp 0.71.0) - rebuilt from the v5.2 analysis notes.
# frps = IRAN server, frpc = OUTSIDE server. Same control port / token on both.
#
# Verified against the real frp 0.71.0 binaries and source (not against your links):
#  * frps ENFORCES an explicit heartbeatTimeout even with tcpMux on (only the DEFAULT becomes -1).
#    A mux client sends no heartbeat, so an explicit value makes frps cut the session every N seconds.
#    => with mux, heartbeatTimeout is -1 on both sides; the yamux keepalive does the liveness work.
#  * yamux ping reply timeout is a fixed 10 s: dead-path detection in mux mode is 10..(ka+10) s.
#  * transport.wireProtocol=v2 (new in 0.71) roughly halves CPU per UDP packet vs v1 (loopback test).
set -Eeuo pipefail

FRP_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$FRP_SOURCE" ]]; then
    FRP_MANAGER_SOURCE="$(readlink -f -- "$FRP_SOURCE")"
    export FRP_MANAGER_SOURCE
else
    echo "ERROR: run this manager from a saved file, not from a pipe: sudo bash frp-manager.sh" >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 (3.8+) is required." >&2; exit 1; }

exec python3 - "$@" <<'PYTHON'
import argparse, base64, fcntl, hashlib, http.client, ipaddress, json, os, re, secrets
import shutil, socket, subprocess, sys, tarfile, tempfile, time, urllib.error, urllib.request
from pathlib import Path

if sys.version_info < (3, 8):
    raise SystemExit("ERROR: Python 3.8 or newer is required.")
try:
    import tomllib  # only needed to migrate an old TOML config
except ImportError:
    tomllib = None

VERSION = "0.71.0"
PORT = 2087                      # control port (TCP; UDP too for KCP) - the same on both servers
DEFAULT_TOKEN = "123"            # public knowledge: pass --token for anything exposed
MAX_POOL = 100                   # frps maxPoolCount: frps clamps the client's poolCount to this
ROOT = Path("/root/frp")
STATE = Path("/etc/frp-manager")
RUNTIME = Path("/run/frp-manager")
SELF = Path("/usr/local/libexec/frp-manager")
BINDIR = Path("/usr/local/bin")
UNITDIR = Path("/etc/systemd/system")
DASH = {"frps": 7500, "frpc": 7400}   # loopback-only dashboards
KEEP_BACKUPS = 5
WD_GRACE = 120                   # s after (re)start during which the watchdog does nothing
WD_BACKOFF = 600                 # min gap between watchdog restarts; doubles each time
WD_BACKOFF_MAX = 6 * 3600
WD_HEALTHY_RESET = 1800          # healthy this long => restart counter back to 0
MONO = time.monotonic

# sha256 of the official frp_0.71.0_linux_*.tar.gz release assets (pinned: a mirror / --tarball is safe)
PINNED = {
    "amd64": "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716",
    "arm": "f40a984f83e8d34a9241b0be4a9d5fbcfe513a4a5c022b84a02637ff6d36833b",
    "arm64": "f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266",
    "arm_hf": "eab1ecb45b00e2f9cf2ebc458fde570ceecb50689c4c5c728677f44825bf3d88",
    "loong64": "e5f4d7e25b677cca885f3db5cc958441bfa12e7214e05304601331ac3d84cebc",
    "riscv64": "92b48d5e4d44d2f1415fde24489d3dfff5badbd52ddf7e816467cdcaa973aa5c",
}
ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
          "armv7l": "arm_hf", "armv7": "arm_hf", "armv6l": "arm", "armv5tel": "arm",
          "riscv64": "riscv64", "loongarch64": "loong64"}

# ---------------------------------------------------------------------------------------------
# Profiles. Only knobs that really change behaviour are listed.
#   mux / mux_ka : tcpMux and its yamux keepalive (s). Dead-path detection = 10 .. ka+10 s.
#   hb           : (client interval, client timeout, server timeout) in s - NON-mux only.
#                  Detection <= client timeout; the server cleans a stale session after its timeout.
#   tcp_ka       : TCP keepalive on tunnel sockets (keeps NAT/firewall state alive).
#   dial_to      : frpc dial timeout.   user_to: how long frps holds a user connection waiting
#                  for a work connection.   pool: pre-opened work connections.
#   strikes      : consecutive failed 1-minute watchdog probes before a restart.
#   wire         : frp wire protocol (v2 = binary UDP codec, ~2x UDP packets per CPU second).
# Measured on loopback + 100 ms emulated RTT, 60 simultaneous new connections (median connect):
#   mux pool 16 = 220 ms, pool 32 = 119 ms | non-mux pool 16 = 366 ms, pool 32 = 238 ms, pool 48 = 236 ms.
# These knobs change failure detection and connection set-up, NOT the raw link speed (that is TCP/kernel/path).
# ---------------------------------------------------------------------------------------------
DEFAULT_PROFILE = "balanced"
PROFILES = {
    "balanced": dict(
        desc="recommended default: one multiplexed session, moderate timers, quick connection bursts",
        proto="tcp", mux=True, mux_ka=20, hb=None, tcp_ka=30, dial_to=15, pool=16, user_to=30, strikes=5, wire="v2"),
    "gaming": dict(
        desc="lowest ping/jitter: one TCP connection per proxy (no head-of-line blocking), fast failover (<=15 s); same profile on BOTH servers",
        proto="tcp", mux=False, mux_ka=None, hb=(5, 15, 45), tcp_ka=15, dial_to=8, pool=32, user_to=12, strikes=3, wire="v2"),
    "gaming-kcp": dict(
        desc="gaming over KCP (UDP transport, UDP control port must be open); measured +16 ms median on loopback, so only for lossy paths; same profile on BOTH servers",
        proto="kcp", mux=True, mux_ka=10, hb=None, tcp_ka=15, dial_to=8, pool=16, user_to=12, strikes=3, wire="v2"),
    "streaming": dict(
        desc="steady video: tolerant timers (fewer false drops), multiplexed session",
        proto="tcp", mux=True, mux_ka=30, hb=None, tcp_ka=30, dial_to=15, pool=16, user_to=30, strikes=5, wire="v2"),
    "speed": dict(
        desc="tolerant timers, large pool, one multiplexed session (raw speed is set by the path, not by these knobs)",
        proto="tcp", mux=True, mux_ka=30, hb=None, tcp_ka=30, dial_to=20, pool=32, user_to=30, strikes=5, wire="v2"),
    "speed-multi": dict(
        desc="experimental A/B for speed: separate TCP connections (aggregate throughput on lossy paths - untested on your link); same profile on BOTH servers",
        proto="tcp", mux=False, mux_ka=None, hb=(10, 40, 90), tcp_ka=30, dial_to=15, pool=48, user_to=20, strikes=5, wire="v2"),
}


def validate_profiles():
    for name, p in PROFILES.items():
        bad = []
        if p["proto"] not in ("tcp", "kcp"): bad.append("proto")
        if p["wire"] not in ("v1", "v2"): bad.append("wire")
        if p["proto"] == "kcp" and not p["mux"]: bad.append("kcp needs mux")
        if p["mux"]:
            if p["hb"] is not None or not p["mux_ka"] or p["mux_ka"] < 5: bad.append("mux: hb must be None, mux_ka >= 5")
        else:
            iv, tc, ts = p["hb"]
            if p["mux_ka"] is not None or iv < 1 or tc < 3 * iv or ts < 2 * tc: bad.append("non-mux: need timeout >= 3*interval, server >= 2*timeout")
            if p["user_to"] < p["dial_to"] + 2: bad.append("user_to must be >= dial_to + 2")
        if not 1 <= p["pool"] <= MAX_POOL or p["dial_to"] < 5 or p["tcp_ka"] < 5 or p["strikes"] < 1: bad.append("range")
        if bad:
            raise RuntimeError(f"internal error: profile {name!r} invalid: {', '.join(bad)}")


def transport_key(p):
    return (p["proto"], p["mux"])          # both servers must agree on these two


# --------------------------------------------------------------------------------------------- helpers
def say(msg=""):
    print(msg, flush=True)


def warn(msg):
    print(f"WARNING: {msg}", flush=True)


def _exec(args, timeout, data=None):
    return subprocess.run([str(a) for a in args], input=data, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def run(args, *, check=True, timeout=40, data=None):
    try:
        p = _exec(args, timeout, data)
    except subprocess.TimeoutExpired:
        if check:
            raise RuntimeError(f"{args[0]} timed out after {timeout}s")
        return ""
    except OSError as e:
        if check:
            raise RuntimeError(f"cannot run {args[0]}: {e}")
        return ""
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} failed: {(p.stderr or p.stdout).strip()}")
    return p.stdout.strip()


def ask(question, default=None):
    value = input(f"{question}" + (f" [{default}]" if default is not None else "") + ": ").strip()
    return value or (default if default is not None else "")


def yes(question):
    return input(f"{question} [y/N]: ").strip().lower() in ("y", "yes")


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing to write through a symlink: {path}")
    fd, name = tempfile.mkstemp(prefix=".frp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(content if isinstance(content, bytes) else content.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_config(path):
    path = Path(path)
    text = path.read_text()
    if "{{" in text:
        raise ValueError(f"{path} uses templates; migrate it by hand")
    if path.suffix == ".json":
        return json.loads(text)
    if tomllib is None:
        raise ValueError(f"{path} is TOML and this Python has no tomllib (need 3.11+)")
    return tomllib.loads(text)


def paths(side):
    role = "server" if side == "frps" else "client"
    name = f"{role}-{PORT}"
    unit = f"{side}@{name}.service"
    return ROOT / role / f"{name}.json", UNITDIR / unit, unit


def existing(side):
    cfg = paths(side)[0]
    for candidate in (cfg, cfg.with_suffix(".toml")):
        if candidate.is_file():
            return candidate
    return None


def wd_name(side):
    return f"frp-v5-watchdog-{side}-{PORT}"


def profile_file(side):
    return STATE / f"{side}-{PORT}.profile"


def load_profile(side):
    try:
        name = profile_file(side).read_text().strip()
    except OSError:
        return DEFAULT_PROFILE
    return name if name in PROFILES else DEFAULT_PROFILE


def parse_ports(value, reserved=()):
    found = set()
    for part in value.split(","):
        part = part.strip()
        if not re.fullmatch(r"[0-9]{1,5}(?:\s*-\s*[0-9]{1,5})?", part):
            raise ValueError(f"bad port entry {part!r} (use 80,443,2000-2010; no empty entries)")
        ends = [int(x.strip(), 10) for x in part.split("-")]
        start, end = ends[0], ends[-1]
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"bad port range {part!r}")
        if end - start + 1 > 1024:
            raise ValueError(f"range {part!r} is larger than 1024 ports")
        found.update(range(start, end + 1))
    if len(found) > 1024:
        raise ValueError("more than 1024 ports selected")
    clash = found.intersection(reserved)
    if clash:
        raise ValueError(f"reserved by this manager: {sorted(clash)}")
    return sorted(found)


def valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", host):
        return False
    return len(host) <= 253 and bool(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host))


# --------------------------------------------------------------------------------------------- config
TOKEN_ARG = None      # --token (set by main)


def existing_value(side, *keys):
    old = existing(side)
    if not old:
        return None
    try:
        cur = read_config(old)
        for k in keys:
            cur = cur[k]
        return cur
    except (OSError, ValueError, KeyError, TypeError):
        return None


def dashboard_password(side):
    pw = existing_value(side, "webServer", "password")
    return pw if isinstance(pw, str) and len(pw) >= 16 else secrets.token_urlsafe(24)


def resolve_token(side):
    """--token wins; otherwise KEEP the token of the existing config (a reinstall must not silently
    fall back to the public default); otherwise the default."""
    if TOKEN_ARG:
        return TOKEN_ARG, "from --token"
    old = existing_value(side, "auth", "token")
    if isinstance(old, str) and old:
        return old, "kept from the existing config"
    return DEFAULT_TOKEN, "DEFAULT (public knowledge!)"


def patch_transport(c, side, p):
    t = c.setdefault("transport", {})
    t["tcpMux"] = p["mux"]
    if p["mux"]:
        t["tcpMuxKeepaliveInterval"] = p["mux_ka"]
    if side == "frps":
        t["tcpKeepalive"] = p["tcp_ka"]
        t["maxPoolCount"] = MAX_POOL
        # FIX (critical): with mux the client sends no heartbeat, so the server must not wait for one.
        t["heartbeatTimeout"] = -1 if p["mux"] else p["hb"][2]
        c["userConnTimeout"] = p["user_to"]
    else:
        t["poolCount"] = p["pool"]
        t["dialServerTimeout"] = p["dial_to"]
        t["dialServerKeepalive"] = p["tcp_ka"]
        t["wireProtocol"] = p["wire"]
        if p["mux"]:
            t["heartbeatInterval"] = -1
            t["heartbeatTimeout"] = -1
        else:
            t["heartbeatInterval"], t["heartbeatTimeout"] = p["hb"][0], p["hb"][1]
        c["loginFailExit"] = False        # keep retrying if frps is down at start


def build_config(side, name, token, host=None, ports=(), wire=None):
    p = dict(PROFILES[name])
    if wire:
        p["wire"] = wire
    c = {
        "auth": {"method": "token", "token": token},
        "webServer": {"addr": "127.0.0.1", "port": DASH[side], "user": "admin", "password": dashboard_password(side)},
        "log": {"to": "console", "level": "info", "disablePrintColor": True},
        "transport": {"tls": {"force": True} if side == "frps" else {"enable": True}},
    }
    patch_transport(c, side, p)
    if side == "frps":
        c.update(bindAddr="0.0.0.0", bindPort=PORT, proxyBindAddr="0.0.0.0", detailedErrorsToClient=False)
        if p["proto"] == "kcp":
            c["kcpBindPort"] = PORT
    else:
        c["transport"]["protocol"] = p["proto"]
        c.update(serverAddr=host, serverPort=PORT)
        c["proxies"] = [{"name": f"{kind}-{n}", "type": kind, "localIP": "127.0.0.1", "localPort": n, "remotePort": n}
                        for n in ports for kind in ("tcp", "udp")]
    return c


# --------------------------------------------------------------------------------------------- health
def api(c, endpoint, timeout=5):
    w = c.get("webServer", {})
    addr = w.get("addr", "127.0.0.1")
    addr = "127.0.0.1" if addr in ("", "0.0.0.0") else "::1" if addr == "::" else addr
    host = f"[{addr}]" if ":" in addr else addr
    req = urllib.request.Request(f"http://{host}:{int(w['port'])}{endpoint}")
    cred = base64.b64encode(f"{w.get('user', '')}:{w.get('password', '')}".encode()).decode()
    req.add_header("Authorization", "Basic " + cred)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        if r.status != 200:
            raise RuntimeError(f"HTTP {r.status} from {endpoint}")
        body = r.read()
    return True if endpoint == "/healthz" else json.loads(body)


def proxy_counts(status):
    rows = [x for group in status.values() if isinstance(group, list) for x in group if isinstance(x, dict)]
    return sum(1 for x in rows if x.get("status") == "running"), len(rows)


def check_free(port, udp=False):
    out = run(["ss", "-H", "-lunp" if udp else "-ltnp", f"sport = :{port}"], check=False)
    if out.strip():
        raise RuntimeError(f"{'UDP' if udp else 'TCP'} port {port} is already in use:\n{out}")


def journal_tail(unit, n=12):
    return run(["journalctl", "-u", unit, "-n", str(n), "--no-pager", "-o", "cat"], check=False, timeout=15)


def probe(side, c, unit):
    """-> (verdict, text). verdict: ok | fail (restart may help) | wait (restart would not help) | skip."""
    try:
        api(c, "/healthz", timeout=5)
    except (urllib.error.HTTPError, ValueError, KeyError) as e:
        return "skip", f"admin API answered oddly ({e}); not judging"
    except (OSError, http.client.HTTPException) as e:
        return "fail", f"admin API not answering: {e}"
    if side == "frps":
        port = int(c["bindPort"])
        pid = int(run(["systemctl", "show", "-p", "MainPID", "--value", unit], check=False) or 0)
        listeners = run(["ss", "-H", "-ltnp", f"sport = :{port}"], check=False)
        if not listeners:
            return "fail", f"nothing listens on TCP {port}"
        if pid > 0 and "pid=" in listeners and f"pid={pid}," not in listeners:
            return "fail", f"TCP {port} is held by another process"
        if c.get("kcpBindPort") and not run(["ss", "-H", "-lunp", f"sport = :{int(c['kcpBindPort'])}"], check=False):
            return "fail", f"nothing listens on UDP {c['kcpBindPort']} (KCP)"
        return "ok", f"listening on {port}"
    try:
        running, total = proxy_counts(api(c, "/api/status"))
    except (urllib.error.HTTPError, ValueError, KeyError) as e:
        return "skip", f"status answered oddly ({e})"
    except (OSError, http.client.HTTPException) as e:
        return "fail", f"status not answering: {e}"
    expected = len(c.get("proxies", []))
    if running > 0:
        return "ok", f"{running}/{total} proxies running"
    if expected == 0 and total == 0:
        return "ok", "no proxies configured"
    if c.get("transport", {}).get("protocol", "tcp") == "kcp":
        return "fail", "0 proxies running (KCP: reachability cannot be tested over TCP)"
    try:
        socket.create_connection((c["serverAddr"], int(c["serverPort"])), timeout=5).close()
    except OSError as e:
        return "wait", f"IRAN server unreachable ({e}); restarting frpc would not help"
    return "fail", f"0/{expected} proxies running although the control port is reachable"


# --------------------------------------------------------------------------------------------- download
def binary_version(path):
    return run([path, "-v"], check=False, timeout=10) if Path(path).is_file() else ""


def arch_name():
    m = os.uname().machine.lower()
    a = ARCHES.get(m)
    if not a or a not in PINNED:
        raise RuntimeError(f"unsupported CPU architecture {m!r}: put frp {VERSION} in {BINDIR} yourself")
    return a


def fetch(url, limit):
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "frp-manager/5.3"})
            with urllib.request.urlopen(req, timeout=30) as r:
                if not r.url.startswith("https://"):
                    raise ValueError("redirected to a non-HTTPS URL")
                data = r.read(limit + 1)
            if len(data) > limit:
                raise ValueError("download is larger than expected")
            return data
        except (OSError, http.client.HTTPException) as e:
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"download failed ({last}). If github.com is blocked on this server, download the "
                       f"tarball elsewhere, copy it here and run again with --tarball FILE")


def obtain(side, tmp, tarball=None):
    arch = arch_name()
    pkg = f"frp_{VERSION}_linux_{arch}"
    if tarball:
        data = Path(tarball).read_bytes()
        say(f"Using local tarball {tarball}")
    else:
        url = f"https://github.com/fatedier/frp/releases/download/v{VERSION}/{pkg}.tar.gz"
        say(f"Downloading {url}")
        data = fetch(url, 100 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED[arch]:
        raise RuntimeError(f"SHA-256 mismatch for {pkg}.tar.gz (got {digest}); refusing to install")
    archive = tmp / "frp.tar.gz"
    archive.write_bytes(data)
    out = tmp / side
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.getmember(f"{pkg}/{side}")
        if not member.isfile():
            raise RuntimeError("unexpected archive layout")
        with tar.extractfile(member) as src:
            out.write_bytes(src.read())
    out.chmod(0o755)
    got = binary_version(out)
    if got != VERSION:
        raise RuntimeError(f"{side} reports version {got!r}, expected {VERSION}")
    return out


# --------------------------------------------------------------------------------------------- snapshot
def snapshot(files, folder):
    folder.mkdir(parents=True, mode=0o700)
    entries = []
    for i, path in enumerate(files):
        path = Path(path)
        if path.is_symlink():
            raise ValueError(f"refusing to touch a symlink: {path}")
        if path.exists():
            saved = folder / str(i)
            shutil.copy2(path, saved)
            entries.append((path, saved))
        else:
            entries.append((path, None))
    atomic(folder / "manifest.json", json.dumps([[str(a), str(b) if b else None] for a, b in entries], indent=2))
    return entries


def restore(entries):
    for path, saved in entries:
        if saved is None:
            Path(path).unlink(missing_ok=True)
        else:
            atomic(path, Path(saved).read_bytes(), Path(saved).stat().st_mode & 0o777)


def prune_backups(side):
    base = ROOT / "backups"
    for prefix in (f"v5-{side}-", f"removed-{side}-"):
        old = sorted(d for d in base.glob(prefix + "*") if d.is_dir())     # names carry time_ns
        for d in old[:-KEEP_BACKUPS]:
            shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------------------------------------- units
def service_text(side, cfg):
    who = "server (IRAN)" if side == "frps" else "client (OUTSIDE)"
    return f"""[Unit]
Description=FRP {who} {cfg.stem}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
ExecStartPre={BINDIR}/{side} verify -c {cfg}
ExecStart={BINDIR}/{side} -c {cfg}
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


def watchdog_service_text(side):
    return f"""[Unit]
Description=FRP {side} watchdog {PORT}
After=network-online.target

[Service]
Type=oneshot
ExecStart={SELF} --port {PORT} --watchdog {side}
TimeoutStartSec=90s
Nice=10
"""


def watchdog_timer_text(side):
    return f"""[Unit]
Description=FRP {side} watchdog timer {PORT}

[Timer]
OnBootSec=120s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
"""


# --------------------------------------------------------------------------------------------- install
def install(side, c, name, tarball=None):
    cfg, unitfile, unit = paths(side)
    executable = BINDIR / side
    wd = wd_name(side)
    ws, wt = UNITDIR / f"{wd}.service", UNITDIR / f"{wd}.timer"
    pfile = profile_file(side)
    legacy = f"frp-watchdog@{side}.timer"
    old = existing(side)
    source = Path(os.environ["FRP_MANAGER_SOURCE"])
    targets = [cfg, unitfile, ws, wt, executable, SELF, pfile]
    if old and old != cfg:
        targets.append(old)
    with tempfile.TemporaryDirectory(prefix="frp-v5-") as tmpname:
        tmp = Path(tmpname)
        if binary_version(executable) == VERSION:
            staged = executable
            say(f"{executable} is already frp {VERSION}")
        else:
            staged = obtain(side, tmp, tarball)
        candidate = tmp / "candidate.json"
        atomic(candidate, json.dumps(c, ensure_ascii=False, indent=2) + "\n")
        run([staged, "verify", "-c", candidate])          # frp itself validates every key
        backupdir = ROOT / "backups" / f"v5-{side}-{time.time_ns()}"
        saved = snapshot(targets, backupdir)
        states = {u: (run(["systemctl", "is-active", u], check=False) == "active",
                      run(["systemctl", "is-enabled", u], check=False) == "enabled")
                  for u in (unit, wd + ".timer", legacy)}
        try:
            for u in (legacy, wd + ".timer"):
                run(["systemctl", "disable", "--now", u], check=False)
            for u in (f"frp-watchdog@{side}.service", wd + ".service", unit):
                run(["systemctl", "stop", u], check=False)
            check_free(c["webServer"]["port"])
            if side == "frps":
                check_free(c["bindPort"])
                if c.get("kcpBindPort"):
                    check_free(c["kcpBindPort"], udp=True)
            if staged != executable:
                atomic(executable, staged.read_bytes(), 0o755)
            atomic(cfg, candidate.read_bytes())
            atomic(pfile, name + "\n")
            atomic(SELF, source.read_bytes(), 0o700)
            atomic(unitfile, service_text(side, cfg), 0o644)
            atomic(ws, watchdog_service_text(side), 0o644)
            atomic(wt, watchdog_timer_text(side), 0o644)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", unit, wd + ".timer"])
            run(["systemctl", "restart", unit], timeout=60)
            ready = False
            for _ in range(15):
                time.sleep(1)
                if run(["systemctl", "is-active", unit], check=False) == "active":
                    try:
                        api(c, "/healthz", timeout=1)
                        ready = True
                        break
                    except (OSError, http.client.HTTPException, ValueError):
                        pass
            if not ready:
                raise RuntimeError(f"{unit} did not become healthy:\n{journal_tail(unit)}")
            run(["systemctl", "start", wd + ".timer"])
            if old and old != cfg:
                old.unlink(missing_ok=True)
        except BaseException:
            say(f"Installation failed; restoring snapshot {backupdir}")
            for u in (wd + ".timer", unit):
                run(["systemctl", "stop", u], check=False)
            restore(saved)
            run(["systemctl", "daemon-reload"], check=False)
            for u, (active, enabled) in states.items():
                run(["systemctl", "enable" if enabled else "disable", u], check=False)
                if active:
                    run(["systemctl", "start", u], check=False)
            raise
    prune_backups(side)


def post_install(side, c, name):
    cfg, _, unit = paths(side)
    p = PROFILES[name]
    t = c["transport"]
    say()
    wire = f"wire {t.get('wireProtocol', 'v1')}" if side == "frpc" else "wire: the client decides (v1 and v2 accepted)"
    say(f"=== {side} is running: profile '{name}' ({p['proto']}, {'mux' if p['mux'] else 'no mux'}, {wire}) ===")
    say(f"Config {cfg} | unit {unit} | dashboard http://127.0.0.1:{c['webServer']['port']} "
        f"(loopback) user {c['webServer']['user']} password {c['webServer']['password']}")
    if side == "frps":
        say(f"Open on the IRAN firewall: TCP {PORT}" + (f" and UDP {PORT}" if p["proto"] == "kcp" else "")
            + " (no firewall was changed) + every port you forward from the outside server.")
    else:
        say("Waiting for the tunnel ...")
        verdict, text = "fail", "not checked"
        for _ in range(15):
            verdict, text = probe(side, c, unit)
            if verdict == "ok":
                break
            time.sleep(2)
        if verdict == "ok":
            say(f"TUNNEL UP: {text}")
        else:
            warn(f"tunnel is NOT up yet: {text}. Check that TCP {PORT}" + (f"/UDP {PORT}" if p["proto"] == "kcp" else "")
                 + " is open on the IRAN server, the token matches and the IRAN server uses a compatible profile.")
    wd = wd_name(side)
    try:
        r = _exec(["systemctl", "start", wd + ".service"], 90)
        selftest = "self-test OK" if r.returncode == 0 else f"self-test FAILED: {(r.stderr or r.stdout).strip()}"
    except subprocess.TimeoutExpired:
        selftest = "self-test timed out"
    say(f"Watchdog: {selftest} | timer {run(['systemctl', 'is-active', wd + '.timer'], check=False)}")
    keys = [n for n, q in PROFILES.items() if transport_key(q) == transport_key(p)]
    say(f"The OTHER server must use the same transport ({p['proto']}, {'mux' if p['mux'] else 'no mux'}): profiles {', '.join(keys)}.")


# --------------------------------------------------------------------------------------------- watchdog
def watchdog(side):
    """One probe per minute (systemd timer). Restarts only after `strikes` consecutive failures, never
    faster than the exponential backoff, never when the fault is the other server / the path."""
    cfg, _, unit = paths(side)
    if not cfg.is_file():
        return
    c = read_config(cfg)
    strikes_needed = PROFILES[load_profile(side)]["strikes"]
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    spath = RUNTIME / f"{side}-{PORT}.json"
    state = {"fails": 0, "restarts": 0, "last": -1e9, "ok_since": None}
    try:
        state.update(json.loads(spath.read_text()))
    except (OSError, ValueError):
        pass
    now = MONO()
    if state["last"] > now:                                   # stale record from before a reboot
        state.update(fails=0, restarts=0, last=-1e9, ok_since=None)

    def save():
        atomic(spath, json.dumps(state))

    def restart(reason, reset_failed=False):
        wait = min(WD_BACKOFF * 2 ** min(max(state["restarts"] - 1, 0), 10), WD_BACKOFF_MAX)
        since = now - state["last"]
        if since < wait:
            say(f"watchdog: {reason}; restart suppressed by backoff ({int(wait - since)}s left)")
            return
        say(f"watchdog: {reason}; restarting {unit}")
        state.update(restarts=state["restarts"] + 1, last=now, fails=0, ok_since=None)
        save()
        if reset_failed:
            run(["systemctl", "reset-failed", unit], check=False)
        run(["systemctl", "restart", unit], timeout=60)

    active = run(["systemctl", "is-active", unit], check=False)
    if active == "failed":
        restart("unit is in the failed state", reset_failed=True)
        save()
        return
    if active != "active":
        say(f"watchdog: {unit} is {active or 'unknown'}; leaving it alone")
        return
    raw = run(["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", unit], check=False)
    entered = int(raw) / 1e6 if raw.isdigit() else 0
    if entered and now - entered < WD_GRACE:
        return
    verdict, text = probe(side, c, unit)
    if verdict == "ok":
        state["fails"] = 0
        if state["ok_since"] is None:
            state["ok_since"] = now
        elif state["restarts"] and now - state["ok_since"] >= WD_HEALTHY_RESET:
            state["restarts"] = 0
    elif verdict in ("wait", "skip"):
        state.update(fails=0, ok_since=None)
        say(f"watchdog: {text}")
    else:
        state["ok_since"] = None
        state["fails"] += 1
        say(f"watchdog: probe failed ({state['fails']}/{strikes_needed}): {text}")
        if state["fails"] >= strikes_needed:
            restart(text)
    save()


def locked(fn, nonblocking=False):
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(RUNTIME / "manager.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if nonblocking:
                return None
            raise RuntimeError("another manager operation is running; try again in a minute")
        return fn()


# --------------------------------------------------------------------------------------------- menu actions
def installed_sides():
    return [s for s in ("frps", "frpc") if existing(s)]


def pick_side(prompt):
    sides = installed_sides()
    if not sides:
        raise ValueError("nothing is installed yet")
    if len(sides) == 1:
        return sides[0]
    side = ask(f"{prompt} (frps or frpc)")
    if side not in sides:
        raise ValueError("no such instance")
    return side


def status():
    sides = installed_sides()
    if not sides:
        say("Nothing is installed yet.")
    for side in sides:
        cfg, _, unit = paths(side)
        name = load_profile(side)
        p = PROFILES[name]
        wd = wd_name(side)
        say(f"--- {side} | profile {name} | {unit} ---")
        say(f"unit {run(['systemctl', 'is-active', unit], check=False)}/{run(['systemctl', 'is-enabled', unit], check=False)}"
            f" | watchdog timer {run(['systemctl', 'is-active', wd + '.timer'], check=False)}"
            f" | transport {p['proto']}, {'mux' if p['mux'] else 'no mux'}")
        try:
            c = read_config(cfg)
        except (OSError, ValueError) as e:
            say(f"config unreadable: {e}")
            continue
        verdict, text = probe(side, c, unit)
        say(f"health: {verdict} - {text}")
        if side == "frpc":
            if c.get("transport", {}).get("protocol", "tcp") != "kcp":
                try:
                    socket.create_connection((c["serverAddr"], int(c["serverPort"])), timeout=5).close()
                    say(f"control port {c['serverAddr']}:{c['serverPort']} reachable")
                except OSError as e:
                    say(f"control port {c['serverAddr']}:{c['serverPort']} NOT reachable: {e}")
            tcp_ports = [x["localPort"] for x in c.get("proxies", []) if x.get("type") == "tcp"][:20]
            okc = 0
            for port in tcp_ports:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    okc += 1
                except OSError:
                    pass
            say(f"local backends answering: {okc}/{len(tcp_ports)}" + (" (first 20)" if len(tcp_ports) == 20 else ""))
        else:
            try:
                info = api(c, "/api/serverinfo")
                say(f"clients {info.get('clientCounts')} | current connections {info.get('curConns')}")
            except (OSError, ValueError, http.client.HTTPException) as e:
                say(f"serverinfo unavailable: {e}")
        say(f"dashboard http://127.0.0.1:{c['webServer']['port']}  user {c['webServer']['user']}  password {c['webServer']['password']}")


def logs():
    side = pick_side("Logs of which instance")
    unit = paths(side)[2]
    say(f"journalctl -u {unit} -f   (Ctrl-C returns to the menu)")
    subprocess.run(["journalctl", "-u", unit, "-f", "-n", "50", "--no-pager"], check=False)


def remove():
    side = pick_side("Remove which instance")
    if not yes(f"Remove the {side} instance on port {PORT}?"):
        say("Cancelled.")
        return

    def go():
        cfg, unitfile, unit = paths(side)
        wd = wd_name(side)
        files = [cfg, cfg.with_suffix(".toml"), unitfile, UNITDIR / f"{wd}.service", UNITDIR / f"{wd}.timer", profile_file(side)]
        backup = ROOT / "backups" / f"removed-{side}-{time.time_ns()}"
        snapshot(files, backup)
        for u in (wd + ".timer", wd + ".service", unit):
            run(["systemctl", "disable", "--now", u], check=False)
        for f in files:
            f.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
        run(["systemctl", "reset-failed"], check=False)
        (RUNTIME / f"{side}-{PORT}.json").unlink(missing_ok=True)
        prune_backups(side)
        say(f"Removed. Backup of the old files: {backup} (frp binaries and the manager copy are kept).")
    locked(go)


def uninstall_all():
    say("This removes EVERY frps/frpc instance of this manager (all ports), the frp binaries, "
        f"{ROOT} (configs AND backups), {STATE} and the manager copy.")
    if input("Type UNINSTALL to continue: ").strip() != "UNINSTALL":
        say("Cancelled.")
        return

    def go():
        names = set()
        for pat in ("frps@server-*.service", "frpc@client-*.service", "frp-v5-watchdog-*.service",
                    "frp-v5-watchdog-*.timer", "frp-watchdog@*.service", "frp-watchdog@*.timer"):
            names.update(x.name for x in UNITDIR.glob(pat))
        ordered = sorted(names, key=lambda n: (not n.endswith(".timer"), n))     # timers first
        for n in ordered:
            run(["systemctl", "disable", "--now", n], check=False)
        for n in ordered:
            (UNITDIR / n).unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
        run(["systemctl", "reset-failed"], check=False)
        for exe in ("frps", "frpc"):
            (BINDIR / exe).unlink(missing_ok=True)
        for d in (ROOT, STATE):
            shutil.rmtree(d, ignore_errors=True)
        for f in RUNTIME.glob("*.json"):
            f.unlink(missing_ok=True)
        SELF.unlink(missing_ok=True)
        say(f"Everything removed ({len(ordered)} unit files).")
    locked(go)


def choose_profile(preset=None):
    if preset:
        return preset
    names = list(PROFILES)
    say("Profiles:")
    for i, n in enumerate(names, 1):
        say(f"  {i}) {n:12s} {PROFILES[n]['desc']}")
    while True:
        pick = ask("Profile (number or name)", str(names.index(DEFAULT_PROFILE) + 1))
        if pick in PROFILES:
            return pick
        if pick.isdigit() and 1 <= int(pick) <= len(names):
            return names[int(pick) - 1]
        say("Invalid choice.")


def configure(side, preset=None, tarball=None, wire=None):
    host, ports = None, []
    if side == "frpc":
        host = ask("IRAN server IP or hostname")
        if not valid_host(host):
            raise ValueError("that is not a valid IP address or hostname")
        if ":" in host:
            warn("the frps of this manager listens on IPv4 only (0.0.0.0)")
        ports = parse_ports(ask("Ports to forward, TCP+UDP (e.g. 80,443,2000-2010)", "8080"),
                            {PORT, DASH["frps"], DASH["frpc"]})
    name = choose_profile(preset)
    token, source = resolve_token(side)
    say(f"Token: {source}")
    if token == DEFAULT_TOKEN:
        warn("the default token is public knowledge - anyone could register ports on your IRAN server. Use --token.")
    c = build_config(side, name, token, host, ports, wire)
    locked(lambda: install(side, c, name, tarball))
    post_install(side, c, name)


def main():
    global PORT, TOKEN_ARG
    ap = argparse.ArgumentParser(prog="frp-manager", description="FRP v5.3 safe local manager")
    ap.add_argument("--port", type=int, default=PORT, help="control port, same on both servers (default 2087)")
    ap.add_argument("--token", help="auth token (default: keep the existing one, else the public default)")
    ap.add_argument("--profile", choices=list(PROFILES), help="skip the profile menu")
    ap.add_argument("--wire", choices=("v1", "v2"), help="override the profile's frp wire protocol")
    ap.add_argument("--tarball", metavar="FILE", help="use a local frp tarball (checked against the pinned SHA-256)")
    ap.add_argument("--watchdog", choices=("frps", "frpc"), help=argparse.SUPPRESS)
    args = ap.parse_args()
    validate_profiles()
    PORT = args.port
    if not 1 <= PORT <= 65535 or PORT in DASH.values():
        raise SystemExit(f"ERROR: --port must be 1-65535 and not {DASH['frpc']}/{DASH['frps']} (dashboards)")
    if args.token is not None and not re.fullmatch(r"[A-Za-z0-9._~+=-]{1,128}", args.token):
        raise SystemExit("ERROR: --token may only contain letters, digits and . _ ~ + = - (max 128)")
    TOKEN_ARG = args.token
    if os.geteuid() != 0:
        raise SystemExit("ERROR: run as root: sudo bash frp-manager.sh")
    os.umask(0o077)
    for tool in ("systemctl", "ss"):
        if not shutil.which(tool):
            raise SystemExit(f"ERROR: {tool} is required")
    if args.watchdog:
        locked(lambda: watchdog(args.watchdog), nonblocking=True)
        return
    if not sys.stdin.isatty():
        try:
            sys.stdin = open("/dev/tty")
        except OSError:
            raise SystemExit("ERROR: this manager is interactive and needs a terminal (use 'ssh -t' or a real shell)")
    while True:
        say()
        say(f"=== FRP v5.3 manager | frp {VERSION} | control port {PORT} ===")
        say(" 1) Install IRAN server (frps)      2) Install OUTSIDE server (frpc)")
        say(" 3) Status                          4) Live logs")
        say(" 5) Remove one instance             6) Exit")
        say(" 7) Complete uninstall")
        choice = ""
        try:
            choice = ask("Select", "6")
            if choice == "1":
                configure("frps", args.profile, args.tarball, args.wire)
            elif choice == "2":
                configure("frpc", args.profile, args.tarball, args.wire)
            elif choice == "3":
                status()
            elif choice == "4":
                logs()
            elif choice == "5":
                remove()
            elif choice == "7":
                uninstall_all()
            elif choice == "6":
                return
            else:
                say("Invalid choice.")
        except (KeyboardInterrupt, EOFError):
            say("\nCancelled.")
            if choice in ("", "6"):
                return
        except Exception as e:                                # keep the menu alive
            print(f"ERROR: {e}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
PYTHON
