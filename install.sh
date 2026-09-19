#!/usr/bin/env bash
# FRP v5: safe local manager for FRP 0.71.0.
# Requirements: Python >= 3.11, systemd Linux.
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

exec python3 - "$@" <<'PYTHON'
import argparse
import base64
import fcntl
import hashlib
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

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required (standard-library tomllib).")

import tomllib

VERSION = "0.71.0"
PORT = 2087
FIXED_TOKEN = "123"
MUX = True    # tcpMux fixed on both sides; fewer TCP connections, more reliable through restrictive networks
POOL = 5      # pre-established connection pool, fixed

ROOT = Path("/root/frp")
STATE = Path("/etc/frp-manager")
SELF = Path("/usr/local/libexec/frp-manager")
RUNTIME = Path("/run/frp-manager")

TAG = "# Managed by frp-manager-v5"

def say(text):
    print(text, flush=True)

def run(args, *, check=True, timeout=40, data=None):
    p = subprocess.run(
        [str(x) for x in args],
        input=data,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and p.returncode:
        raise RuntimeError(
            f"{args[0]} failed: {p.stderr.strip() or p.stdout.strip()}"
        )
    return p.stdout.strip()

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
    value = json.loads(text) if str(path).endswith(".json") else tomllib.loads(text)
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

def patch_transport(c, side, mux, pool):
    t = c.setdefault("transport", {})
    t.update(
        tcpMux=mux,
        tcpMuxKeepaliveInterval=20,
        heartbeatTimeout=(120 if side == "frps" else 60),
    )
    if side == "frps":
        t.update(tcpKeepalive=30, maxPoolCount=100)
        c["userConnTimeout"] = 45
    else:
        t.update(
            poolCount=pool,
            heartbeatInterval=15,
            dialServerTimeout=15,
            dialServerKeepalive=30,
        )
        c["loginFailExit"] = False

def base_config(side, token, mux, pool):
    c = {
        "auth": {
            "method": "token",
            "token": token,
        },
        "webServer": {
            "addr": "127.0.0.1",
            "port": 7500 if side == "frps" else 7400,
            "user": "admin",
            "password": secrets.token_urlsafe(32),
        },
        "log": {
            "to": "console",
            "level": "info",
            "disablePrintColor": True,
        },
    }
    patch_transport(c, side, mux, pool)
    c["transport"]["tls"] = {"force": True} if side == "frps" else {"enable": True}
    if side == "frpc":
        c["transport"]["protocol"] = "tcp"
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

def check_free(port):
    listeners = run(
        ["ss", "-H", "-ltnp", f"sport = :{int(port)}"]
    )
    if listeners:
        raise RuntimeError(
            f"TCP port {port} is busy; no process killed.\n{listeners}"
        )

def fetch(url, limit):
    if not url.startswith("https://"):
        raise ValueError("HTTPS download required.")
    request = urllib.request.Request(url, headers={"User-Agent": "frp-manager-v5"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("Insecure download redirect.")
        content = response.read(limit + 1)
        if len(content) > limit:
            raise ValueError("Download exceeds size limit.")
        return content

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
StartLimitIntervalSec=120
StartLimitBurst=12

[Service]
Type=simple
ExecStartPre=/usr/local/bin/{side} verify -c {cfg}
ExecStart=/usr/local/bin/{side} -c {cfg}
Restart=on-failure
RestartSec=10s
TimeoutStopSec=20s
LimitNOFILE=262144
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
"""

def install(side, c, upgrade=False):
    source = Path(os.environ.get("FRP_MANAGER_SOURCE", ""))
    if not source.is_file():
        raise ValueError("Save this script to a regular file before running it.")

    cfg, unitfile, unit = paths(side)
    executable = Path("/usr/local/bin") / side
    unitdir = unitfile.parent

    wd = wd_name(side)
    ws = unitdir / (wd + ".service")
    wt = unitdir / (wd + ".timer")

    legacy = f"frp-watchdog@{side}.timer"
    old = existing(side)

    targets = [cfg, unitfile, ws, wt, executable, SELF]
    if old and old != cfg:
        targets.append(old)

    with tempfile.TemporaryDirectory(prefix="frp-v5-") as tmp:
        tmp = Path(tmp)
        staged = (
            download(side, tmp)
            if upgrade or not executable.exists()
            else executable
        )
        if run([staged, "-v"]) != VERSION:
            raise ValueError(
                f"Existing binary is not {VERSION}; use installation to upgrade."
            )

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

        changed = False
        try:
            changed = True
            for timer in (legacy, wd + ".timer"):
                run(["systemctl", "disable", "--now", timer], check=False)

            run(["systemctl", "stop", f"frp-watchdog@{side}.service"], check=False)
            run(["systemctl", "stop", wd + ".service"], check=False)

            if old or unitfile.exists():
                run(["systemctl", "stop", unit])

            check_free(c["webServer"]["port"])
            if side == "frps":
                check_free(c["bindPort"])

            if staged != executable:
                atomic(executable, staged.read_bytes(), 0o755)

            atomic(cfg, candidate.read_bytes())
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
TimeoutStartSec=60s
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
                    except (OSError, ValueError):
                        pass

            if not ready:
                raise RuntimeError(
                    "Service/local health check failed. Inspect the journal."
                )

            run(["systemctl", "start", wd + ".timer"])
            if old and old != cfg:
                old.chmod(0o600)

            legacy_helper = Path("/usr/local/bin/frp-watchdog.sh")
            if legacy_helper.is_file() and not legacy_helper.is_symlink():
                legacy_helper.chmod(0o700)

        except BaseException:
            if changed:
                say(f"Installation failed; restoring snapshot: {backupdir}")
                for u in (wd + ".timer", unit):
                    run(["systemctl", "stop", u], check=False)
                restore(saved)
                run(["systemctl", "daemon-reload"])
                for u, (active, enabled) in states.items():
                    run(
                        [
                            "systemctl",
                            "enable" if enabled else "disable",
                            u,
                        ],
                        check=False,
                    )
                    if active:
                        run(["systemctl", "start", u])
            raise

    say(f"Service installed; backup: {backupdir}\nConfig: {cfg}")
    say("Local liveness passed. This does NOT prove end-to-end tunnel connectivity.")

def configure(side):
    # frps (Iran server): fully automatic, nothing to ask.
    # frpc (Kharej/outside client): exactly two questions, Server IP first.
    host = None
    ports = []

    if side == "frpc":
        host = ask("Server IP (Iran frps address, IPv4/IPv6/hostname)")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host
            ):
                raise ValueError("Invalid hostname/IP.")

        ports = parse_ports(
            ask("Ports to forward, comma-separated (ranges OK, e.g. 80,443,8000-8010)", "8080"),
            {PORT, 7400, 7500},
        )

    c = base_config(side, FIXED_TOKEN, MUX, POOL)

    if side == "frps":
        c.update(
            bindAddr="0.0.0.0",
            bindPort=PORT,
            proxyBindAddr="0.0.0.0",
            detailedErrorsToClient=False,
        )
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

    install(side, c, upgrade=True)
    say("No firewall was changed. Allow ONLY required ports in the Iran host/provider firewall.")
    if ports:
        say(f"Control: {PORT}/tcp; forwarded TCP+UDP ports: " + " ".join(map(str, ports)))
    say("Dashboard stays on loopback. Credentials are in the root-only config; use an SSH tunnel.")

def watchdog(side):
    path = existing(side)
    unit = paths(side)[2]

    if not path or run(["systemctl", "is-active", unit], check=False) != "active":
        return

    c = read_config(path)
    entered = int(
        run(["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", unit]) or 0
    ) / 1e6
    now = float(Path("/proc/uptime").read_text().split()[0])
    if now - entered < 120:
        return

    record = RUNTIME / f"{side}-{PORT}.json"
    try:
        state = json.loads(record.read_text())
    except (FileNotFoundError, ValueError):
        state = {"fails": 0, "last": -600}

    try:
        api(c, "/healthz")
        if side == "frps":
            pid = int(run(["systemctl", "show", "-p", "MainPID", "--value", unit]))
            listeners = run(["ss", "-H", "-ltnp", f"sport = :{int(c['bindPort'])}"])
            if pid <= 0 or f"pid={pid}," not in listeners:
                raise OSError("MainPID does not own the FRP listening port")
        state["fails"] = 0
    except (urllib.error.HTTPError, ssl.SSLError, ValueError, KeyError) as error:
        say(f"Watchdog configuration/API error; no restart: {type(error).__name__}")
        return
    except (OSError, urllib.error.URLError):
        state["fails"] = int(state.get("fails", 0)) + 1
        say(f"Local liveness failure {state['fails']}/5 for {unit}")

    if state["fails"] >= 5 and now - float(state.get("last", -600)) >= 600:
        state["last"] = now
        atomic(record, json.dumps(state))
        run(["systemctl", "restart", unit])
        state["fails"] = 0

    atomic(record, json.dumps(state))

def status():
    for side in ("frps", "frpc"):
        path = existing(side)
        if not path:
            continue
        c = read_config(path)
        unit = paths(side)[2]
        say("\n" + unit)
        say(run(["systemctl", "status", "--no-pager", "--lines=5", unit], check=False))
        try:
            data = api(
                c,
                "/api/serverinfo" if side == "frps" else "/api/status",
            )
            if side == "frpc":
                running, total = proxy_counts(data)
                say(f"Registered running proxies: {running}/{total} (not a backend reachability test)")
                for group in data.values():
                    if isinstance(group, list):
                        for p in group:
                            say(f"  {p.get('name', '?')}: {p.get('status', '?')} {p.get('err', '')}")
            else:
                say(f"Server API reachable; connected clients: {data.get('clientCounts', 'unknown')}")
        except (OSError, ValueError, KeyError) as error:
            say(f"Admin API unavailable: {type(error).__name__}")

        if side == "frpc":
            try:
                with socket.create_connection((c["serverAddr"], c["serverPort"]), timeout=5):
                    say("Tunnel to Iran server: control port TCP connect OK")
            except OSError as error:
                say(f"Tunnel to Iran server: control TCP connect FAILED ({error})")

            proxies = [p for p in c.get("proxies", []) if p.get("type") == "tcp" and "localPort" in p]
            for p in proxies[:20]:
                try:
                    with socket.create_connection(
                        (p.get("localIP", "127.0.0.1"), p["localPort"]), timeout=2
                    ):
                        say(f"  Backend {p['name']}: TCP reachable")
                except OSError:
                    say(f"  Backend {p['name']}: TCP FAILED")
            if len(proxies) > 20:
                say("  Backend tests limited to the first 20 proxies.")

def remove():
    side = ask("Remove which instance: frps or frpc")
    if side not in ("frps", "frpc") or not existing(side):
        raise ValueError("No such managed configuration.")

    cfg, unitfile, unit = paths(side)

    if not yes(f"Stop and remove ONLY {unit}? Backups and shared binaries will remain"):
        return

    wd = wd_name(side)
    files = [
        cfg,
        cfg.with_suffix(".toml"),
        unitfile,
        unitfile.parent / (wd + ".timer"),
        unitfile.parent / (wd + ".service"),
    ]
    backup = ROOT / "backups" / f"removed-{side}-{time.time_ns()}"
    snapshot(files, backup)

    run(["systemctl", "disable", "--now", wd + ".timer"])
    run(["systemctl", "stop", wd + ".service"], check=False)
    run(["systemctl", "disable", "--now", unit])
    for path in files:
        path.unlink(missing_ok=True)
    run(["systemctl", "daemon-reload"])

    say(f"Instance removed; backup: {backup}")
    say("Shared binaries/templates and journal were retained.")

def uninstall_all():
    if not yes("Are you sure you want to COMPLETELY UNINSTALL FRP and all components?"):
        return

    say("Stopping and removing services...")
    for side in ("frps", "frpc"):
        _, unitfile, unit = paths(side)
        wd = wd_name(side)
        for target in (wd + ".timer", wd + ".service", unit):
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
    global PORT
    parser = argparse.ArgumentParser(description="FRP v5 safe local manager")
    parser.add_argument("--port", type=int, default=2087)
    parser.add_argument("--watchdog", choices=["frps", "frpc"])
    args = parser.parse_args()
    PORT = args.port

    if not 1 <= PORT <= 65535 or PORT in (7400, 7500):
        raise ValueError("Invalid/conflicting FRP control port.")

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

    say(f"FRP manager v5 / FRP {VERSION} / control port {PORT}")
    say("PSK token set to fixed value: 123")

    actions = {
        "1": lambda: configure("frps"),
        "2": lambda: configure("frpc"),
        "3": status,
        "5": remove,
    }

    while True:
        say("\n1) Install IRAN frps\n2) Install OUTSIDE frpc\n3) Status\n4) Live logs")
        say("5) Remove one instance\n6) Exit\n7) Complete Uninstall")
        choice = ask("Select", "6")
        if choice == "6":
            return
        if choice == "7":
            uninstall_all()
            return

        try:
            if choice == "4":
                side = ask("frps or frpc", "frpc")
                if side not in ("frps", "frpc"):
                    raise ValueError("Invalid side.")
                subprocess.run(
                    ["journalctl", "-u", paths(side)[2], "-f", "--no-pager"],
                    check=False,
                )
            elif choice in actions:
                locked(actions[choice])
            else:
                say("Invalid menu option.")
        except KeyboardInterrupt:
            say("Cancelled.")
        except Exception as error:
            say(f"ERROR: {error}")

if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        say(f"ERROR: {error}")
        sys.exit(1)
PYTHON
