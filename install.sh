#!/usr/bin/env bash
# FRP v5: safe local manager for FRP 0.71.0.
# Requirements: Python >= 3.11, systemd Linux.
set -Eeuo pipefail

# Fallback safely if piped or sourced
FRP_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$FRP_SOURCE" ]]; then
    export FRP_MANAGER_SOURCE="$(readlink -f -- "$FRP_SOURCE")"
else
    export FRP_MANAGER_SOURCE="/usr/local/libexec/frp-manager"
fi

exec python3 - "$@" <<'PYTHON'
import argparse
import base64
import contextlib
import fcntl
import getpass
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
PORT = 8443

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

def choose_transport():
    mode = ask(
        "Mode: 1=multiplexed, 2=parallel; MUST match on both hosts",
        "2",
    )
    if mode not in ("1", "2"):
        raise ValueError("Invalid mode.")
    pool = int(ask("Pre-established pool count (0..100)", "5"))
    if not 0 <= pool <= 100:
        raise ValueError("Pool must be 0..100.")
    return mode == "1", pool

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
    if existing(side) and not yes(
        "Replace existing configuration? Use menu 4 to preserve settings"
    ):
        return

    mux, pool = choose_transport()
    token = getpass.getpass(
        "Shared FRP token (same on BOTH hosts; >=24 characters): "
    )
    if len(token) < 24:
        raise ValueError("Choose a strong token of at least 24 characters.")

    c = base_config(side, token, mux, pool)
    ports = parse_ports(
        ask("Forwarded/allowed ports", "8080"),
        {PORT, 7400, 7500},
    )

    if side == "frps":
        c.update(
            bindAddr="0.0.0.0",
            bindPort=PORT,
            proxyBindAddr="0.0.0.0",
            allowPorts=[{"single": p} for p in ports],
            detailedErrorsToClient=False,
        )
        cert = ask(
            "TLS certificate fullchain path (blank = FRP automatic certificate)"
        )
        if cert:
            key = ask("TLS private key path")
            for p in (cert, key):
                if not Path(p).is_file():
                    raise ValueError("Certificate/private-key file missing.")
            c["transport"]["tls"].update(
                certFile=str(Path(cert).resolve()),
                keyFile=str(Path(key).resolve()),
            )
    else:
        host = ask("Iran frps hostname or IP, WITHOUT scheme or port")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", host
            ):
                raise ValueError("Invalid hostname/IP.")
        c.update(serverAddr=host, serverPort=PORT)

        ca = ask(
            "Trusted CA PEM path (recommended; blank disables server-certificate verification)"
        )
        if ca:
            if not Path(ca).is_file():
                raise ValueError("CA file not found.")
            c["transport"]["tls"].update(
                trustedCaFile=str(Path(ca).resolve()),
                serverName=ask("Certificate DNS name or IP (SAN)", host),
            )
        elif not yes(
            "WARNING: encryption WITHOUT server identity verification. Continue insecurely"
        ):
            return
        else:
            sni = ask("Optional SNI (does NOT authenticate the server)")
            if sni:
                c["transport"]["tls"]["serverName"] = sni

        kinds = (
            ["tcp", "udp"]
            if yes("Also forward UDP? Only if the application needs it")
            else ["tcp"]
        )
        c["proxies"] = [
            {
                "name": f"{kind}-{p}",
                "type": kind,
                "localIP": "127.0.0.1",
                "localPort": p,
                "remotePort": p,
            }
            for kind in kinds
            for p in ports
        ]

    install(side, c, upgrade=True)
    say("No firewall was changed. Allow ONLY required ports in the Iran host/provider firewall.")
    say(f"Control: {PORT}/tcp; proxy TCP ports: " + " ".join(map(str, ports)))
    if side == "frpc" and "udp" in [p.get("type") for p in c.get("proxies", [])]:
        say("Also allow these UDP proxy ports on the Iran server.")
    say("Dashboard stays on loopback. Credentials are in the root-only config; use an SSH tunnel.")

def migrate():
    available = [s for s in ("frps", "frpc") if existing(s)]
    if not available:
        raise ValueError("No existing configuration found for this --port.")

    side = available[0] if len(available) == 1 else ask("Which side: frps or frpc")
    if side not in available:
        raise ValueError("Invalid side.")

    c = read_config(existing(side))
    mux, pool = choose_transport()
    patch_transport(c, side, mux, pool)

    if side == "frpc" and yes("Remove only UDP proxies from this configuration"):
        c["proxies"] = [p for p in c.get("proxies", []) if p.get("type") != "udp"]
        if not c["proxies"]:
            raise ValueError("Refusing to leave zero proxies.")

    c.setdefault("webServer", {})["addr"] = "127.0.0.1"
    if c["webServer"].get("tls", {}).get("certFile"):
        raise ValueError("Custom HTTPS dashboard requires manual loopback/TLS migration.")

    if not c["webServer"].get("port"):
        c["webServer"]["port"] = 7500 if side == "frps" else 7400
    if not c["webServer"].get("user"):
        c["webServer"]["user"] = "admin"
    c["webServer"]["password"] = secrets.token_urlsafe(32)

    c.setdefault("log", {}).update(to="console", disablePrintColor=True)

    say("Shared auth token, TLS settings, proxies and other fields are preserved.")
    say("Dashboard becomes loopback-only with a new independent password; logs go to journald.")

    if side == "frps" and not c.get("allowPorts"):
        say("WARNING: existing unrestricted allowPorts is preserved; restrict it manually.")

    token = c.get("auth", {}).get("token", "")
    if token and len(token) < 24:
        say("WARNING: legacy weak token preserved to avoid breaking the other host. Rotate BOTH sides.")

    if yes("Apply this migration and restart this one instance"):
        install(side, c)

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

def diagnose():
    status()
    side = existing("frpc")
    if not side:
        say("Run destination/backend checks on the OUTSIDE client host.")
        return

    c = read_config(side)
    try:
        with socket.create_connection((c["serverAddr"], c["serverPort"]), timeout=5):
            say("FRP control port TCP connect: OK (not an authentication test)")
    except OSError as error:
        say(f"FRP control TCP connect failed: {error}")

    proxies = [p for p in c.get("proxies", []) if p.get("type") == "tcp" and "localPort" in p]
    for p in proxies[:20]:
        try:
            with socket.create_connection(
                (p.get("localIP", "127.0.0.1"), p["localPort"]), timeout=2
            ):
                say(f"Backend {p['name']}: TCP reachable")
        except OSError:
            say(f"Backend {p['name']}: TCP FAILED")

    if len(proxies) > 20:
        say("Backend tests limited to the first 20 proxies.")

    if shutil.which("curl"):
        for family in ("-4", "-6"):
            for url in ("https://www.google.com", "https://www.cloudflare.com"):
                result = run(
                    [
                        "curl", "--noproxy", "*", family, "-sS", "-o", "/dev/null",
                        "-w", "%{http_code}", "--connect-timeout", "4", "--max-time", "8", url,
                    ],
                    check=False,
                )
                say(f"{family} {url}: HTTP {result or 'unavailable'}")

    say("A failed site/IPv6 test is not proof of a broken tunnel. No network settings were changed.")
    say("FRP forwards ports; it is not itself a general-purpose VPN or an open Internet proxy.")

def network_options():
    say("1) Optional minimal sysctl tuning  2) Restore v5 tuning  3) IPv4 preference  4) Undo IPv4 preference")
    say("5) Enable host-wide UDP/443 reject (nftables)  6) Disable v5 UDP/443 reject")
    choice = ask("Select")

    if choice in ("1", "2"):
        statefile = STATE / "sysctl.json"
        conf = Path("/etc/sysctl.d/99-frp-v5.conf")
        if choice == "1":
            if statefile.exists() or conf.exists():
                raise ValueError("Existing v5 tuning found; restore it first.")
            if not yes("Change these HOST-WIDE settings: TCP MTU probing and keepalive timers"):
                return
            values = {
                "net.ipv4.tcp_mtu_probing": "1",
                "net.ipv4.tcp_keepalive_time": "30",
                "net.ipv4.tcp_keepalive_intvl": "10",
                "net.ipv4.tcp_keepalive_probes": "6",
            }
            state = {k: {"old": run(["sysctl", "-n", k]), "new": v} for k, v in values.items()}
            atomic(statefile, json.dumps(state))
            try:
                for k, v in values.items():
                    run(["sysctl", "-w", f"{k}={v}"])
                atomic(
                    conf,
                    TAG + "\n" + "\n".join(f"{k} = {v}" for k, v in values.items()) + "\n",
                    0o644,
                )
            except BaseException:
                for k, v in state.items():
                    run(["sysctl", "-w", f"{k}={v['old']}"], check=False)
                say("Apply failed; restoration attempted. Snapshot retained in /etc/frp-manager/sysctl.json")
                raise
        elif statefile.exists():
            state = json.loads(statefile.read_text())
            if conf.exists() and not conf.read_text().startswith(TAG):
                raise ValueError("Tuning file ownership marker changed; refusing removal.")
            for k, v in state.items():
                current = run(["sysctl", "-n", k])
                if current == v["new"]:
                    run(["sysctl", "-w", f"{k}={v['old']}"])
                else:
                    say(f"Leaving externally changed value: {k}")
            conf.unlink(missing_ok=True)
            statefile.unlink()

    elif choice in ("3", "4"):
        path = Path("/etc/gai.conf")
        block = "\n# BEGIN frp-manager-v5\nprecedence ::ffff:0:0/96 100\n# END frp-manager-v5\n"
        text = path.read_text() if path.exists() else ""
        if choice == "3":
            if not yes("Prefer IPv4 system-wide for glibc applications (Go apps may ignore it)"):
                return
            if block not in text:
                snapshot([path], ROOT / "backups" / f"gai-{time.time_ns()}")
                atomic(path, text + block, 0o644)
        elif block in text:
            atomic(path, text.replace(block, ""), 0o644)

    elif choice in ("5", "6"):
        nft = shutil.which("nft")
        if not nft:
            raise ValueError("nft is required. No iptables/nftables backends are mixed automatically.")
        rules = STATE / "quic.nft"
        unit = Path("/etc/systemd/system/frp-v5-quic.service")

        if choice == "5":
            if rules.exists() or unit.exists():
                raise ValueError("v5 QUIC block already configured; disable it first.")
            p = subprocess.run([nft, "list", "table", "inet", "frp_v5_quic"], capture_output=True)
            if p.returncode == 0:
                raise ValueError("Reserved nft table already exists; refusing to replace it.")
            if not yes("Reject ALL outbound/forwarded UDP/443 on this host? This affects non-FRP apps too"):
                return

            atomic(
                rules,
                """table inet frp_v5_quic {
 chain output {
  type filter hook output priority -5;
  policy accept;
  udp dport 443 reject;
 }
 chain forward {
  type filter hook forward priority -5;
  policy accept;
  udp dport 443 reject;
 }
}
""",
            )
            try:
                run([nft, "-c", "-f", rules])
                atomic(
                    unit,
                    f"""{TAG}
[Unit]
Description=Explicit host-wide UDP443 reject (FRP manager)
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={nft} -f {rules}
ExecStop={nft} delete table inet frp_v5_quic

[Install]
WantedBy=multi-user.target
""",
                    0o644,
                )
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "enable", "--now", unit.name])
            except BaseException:
                run(["systemctl", "disable", "--now", unit.name], check=False)
                unit.unlink(missing_ok=True)
                rules.unlink(missing_ok=True)
                run(["systemctl", "daemon-reload"], check=False)
                raise
        elif unit.exists() and unit.read_text().startswith(TAG):
            run(["systemctl", "disable", "--now", unit.name])
            unit.unlink()
            rules.unlink(missing_ok=True)
            run(["systemctl", "daemon-reload"])
            say("Only the v5 dedicated nft table is managed; legacy untagged iptables rules are untouched.")
    else:
        raise ValueError("Invalid option.")

def remove():
    side = ask("Remove which instance: frps or frpc")
    if side not in ("frps", "frpc") or not existing(side):
        raise ValueError("No such managed configuration.")

    cfg, unitfile, unit = paths(side)
    if not unitfile.exists() or not unitfile.read_text().startswith(TAG):
        raise ValueError("Migrate this legacy instance using option 4 before v5 removal.")

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
    say("Shared binaries/templates, journal, firewall and global network settings were retained.")
    say("Use menu 9 to explicitly undo v5 network changes. Legacy v4 settings need manual review.")

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
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--watchdog", choices=["frps", "frpc"])
    args = parser.parse_args()
    PORT = args.port

    if not 1 <= PORT <= 65535 or PORT in (7400, 7500):
        raise ValueError("Invalid/conflicting FRP control port.")

    if os.geteuid() != 0:
        raise ValueError("Run as root.")

    os.umask(0o077)
    for command in ("systemctl", "ss", "sysctl"):
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
    say("Existing v4 kernel/IPv6/firewall changes are NOT automatically undone.")

    actions = {
        "1": lambda: configure("frps"),
        "2": lambda: configure("frpc"),
        "3": status,
        "4": migrate,
        "5": diagnose,
        "7": remove,
        "9": network_options,
    }

    while True:
        say("\n1) Install IRAN frps\n2) Install OUTSIDE frpc\n3) Status\n4) Preserve/migrate + fix existing")
        say("5) Diagnose\n6) Live logs\n7) Remove one instance\n8) Exit\n9) Optional network settings")
        choice = ask("Select", "8")
        if choice == "8":
            return

        try:
            if choice == "6":
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
