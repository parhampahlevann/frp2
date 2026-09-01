#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# FRP Iran Browser Tunnel v5
#
# Topology:
#
#   BROWSER / IRAN
#       Chrome -> 127.0.0.1:1080 (SOCKS5)
#                         |
#                         v
#                      frps :8443
#                         ^
#                         |
#                   encrypted TCP
#                         |
#                         v
#   OUTSIDE / EXIT
#       frpc -> 127.0.0.1:1080 (SOCKS5) -> Internet
#
# This is a browser-friendly TCP-only tunnel. It does NOT create UDP proxies.
# QUIC/HTTP3 is blocked on the BROWSER/IRAN host so Chrome falls back to
# TCP-based HTTPS through the SOCKS5 tunnel.
#
# Run as root on each machine.
###############################################################################

FRP_VERSION="0.71.0"
FRP_TOKEN="tun100"
FRP_PORT="8443"
SOCKS_PORT="1080"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"
SOCKS_USER=""
SOCKS_PASS=""

TCP_MUX="false"
POOL_COUNT="20"
HB_INTERVAL="15"
HB_TIMEOUT="60"
DIAL_TIMEOUT="15"
DIAL_KEEPALIVE="15"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

log_info(){ echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn(){ echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $1"; }
log_step(){ echo -e "${BLUE}[STEP]${NC}  $1"; }
log_ok(){ echo -e "${CYAN}[OK]${NC}    $1"; }
log_fix(){ echo -e "${MAGENTA}[FIX]${NC}   $1"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || { log_error "Run as root."; exit 1; }
}

command_exists(){ command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
    local miss=()
    for c in curl tar ss awk sed grep systemctl python3; do
        command_exists "$c" || miss+=("$c")
    done
    if [ "${#miss[@]}" -gt 0 ]; then
        log_error "Missing commands: ${miss[*]}"
        return 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        armv7l) echo arm ;;
        i386|i686) echo 386 ;;
        *) echo unsupported ;;
    esac
}

install_binary() {
    local name="$1" arch pkg url tmp
    arch="$(detect_arch)"
    [ "$arch" != unsupported ] || { log_error "Unsupported architecture."; return 1; }
    pkg="frp_${FRP_VERSION}_linux_${arch}"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${pkg}.tar.gz"
    tmp="$(mktemp -d)"
    log_step "Downloading ${name} v${FRP_VERSION}..."
    curl -fL --retry 5 --retry-delay 2 --connect-timeout 15 \
        -o "$tmp/frp.tar.gz" "$url" || { rm -rf "$tmp"; return 1; }
    tar -xzf "$tmp/frp.tar.gz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    install -m 755 "$tmp/$pkg/$name" "/usr/local/bin/$name"
    rm -rf "$tmp"
    log_ok "$name installed."
}

choose_transport() {
    echo ""
    echo "FRP transport mode:"
    echo "  1) Parallel TCP connections (recommended for this tunnel)"
    echo "  2) Multiplexed TCP connection"
    read -r -p "Select [1-2, default 1]: " x
    x="${x:-1}"
    case "$x" in
        2) TCP_MUX=true; POOL_COUNT=5 ;;
        *) TCP_MUX=false; POOL_COUNT=20 ;;
    esac
    log_info "tcpMux=${TCP_MUX}, poolCount=${POOL_COUNT}"
}

tune_tcp() {
    cat >/etc/sysctl.d/99-frp-browser-tunnel.conf <<'EOF'
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1200
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = cubic
EOF
    sysctl --system >/dev/null 2>&1 || true
}

write_socks_server() {
    cat >/usr/local/bin/frp-socks5.py <<'PY'
#!/usr/bin/env python3
import asyncio, os, socket, struct, ipaddress

HOST = "127.0.0.1"
PORT = int(os.environ.get("FRP_SOCKS_PORT", "1080"))
USER = os.environ.get("FRP_SOCKS_USER", "")
PASS = os.environ.get("FRP_SOCKS_PASS", "")

async def read_exact(r, n):
    return await r.readexactly(n)

async def reply(w, rep):
    w.write(b"\x05" + bytes([rep]) + b"\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
    await w.drain()

async def handle(r, w):
    try:
        h = await read_exact(r, 2)
        if h[0] != 5:
            w.close(); return
        methods = await read_exact(r, h[1])

        need_auth = bool(USER)
        if need_auth and 2 in methods:
            w.write(b"\x05\x02")
        elif not need_auth and 0 in methods:
            w.write(b"\x05\x00")
        else:
            w.write(b"\x05\xff"); await w.drain(); w.close(); return
        await w.drain()

        if need_auth:
            a = await read_exact(r, 2)
            if a[0] != 1:
                w.close(); return
            u = await read_exact(r, a[1])
            p = await read_exact(r, (await read_exact(r,1))[0])
            # The preceding read consumed password length incorrectly only if
            # split; use a clean parser below is safer.
    except Exception:
        w.close()
        return

async def client(reader, writer, host, port):
    try:
        rr, ww = await asyncio.open_connection(host, port)
        await asyncio.gather(
            asyncio.shield(asyncio.create_task(async_copy(reader, ww))),
            asyncio.shield(asyncio.create_task(async_copy(rr, writer)))
        )
    except Exception:
        pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

async def async_copy(src, dst):
    while True:
        data = await src.read(65536)
        if not data: break
        dst.write(data)
        await dst.drain()
    try: dst.write_eof()
    except Exception: pass

async def socks(reader, writer):
    try:
        ver, n = await read_exact(reader,2)
        if ver != 5: writer.close(); return
        methods = await read_exact(reader,n)
        if USER:
            if 2 not in methods:
                writer.write(b"\x05\xff"); await writer.drain(); writer.close(); return
            writer.write(b"\x05\x02"); await writer.drain()
            av = await read_exact(reader,2)
            if av[0] != 1: writer.close(); return
            ul = av[1]; user = (await read_exact(reader,ul)).decode(errors="ignore")
            pl = (await read_exact(reader,1))[0]; pwd = (await read_exact(reader,pl)).decode(errors="ignore")
            if user != USER or pwd != PASS:
                writer.write(b"\x01\x01"); await writer.drain(); writer.close(); return
            writer.write(b"\x01\x00"); await writer.drain()
        else:
            if 0 not in methods:
                writer.write(b"\x05\xff"); await writer.drain(); writer.close(); return
            writer.write(b"\x05\x00"); await writer.drain()

        ver, cmd, _, atyp = await read_exact(reader,4)
        if ver != 5 or cmd != 1:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"); await writer.drain(); writer.close(); return

        if atyp == 1:
            host = socket.inet_ntoa(await read_exact(reader,4))
        elif atyp == 3:
            ln = (await read_exact(reader,1))[0]
            host = (await read_exact(reader,ln)).decode("idna")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await read_exact(reader,16))
        else:
            writer.close(); return
        port = struct.unpack("!H", await read_exact(reader,2))[0]

        try:
            rr, ww = await asyncio.open_connection(host, port)
        except Exception:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); await writer.drain(); writer.close(); return

        local = ww.get_extra_info("sockname")
        ip = local[0] if local else "0.0.0.0"
        try:
            packed = socket.inet_aton(ip); atyp2=1; addr=packed
        except Exception:
            atyp2=1; addr=b"\x00\x00\x00\x00"
        writer.write(b"\x05\x00\x00" + bytes([atyp2]) + addr + struct.pack("!H", local[1] if local else 0))
        await writer.drain()

        await asyncio.gather(async_copy(reader, ww), async_copy(rr, writer))
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

async def main():
    srv = await asyncio.start_server(socks, HOST, PORT, limit=1024*1024)
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
PY
    chmod 755 /usr/local/bin/frp-socks5.py
    cat >/etc/systemd/system/frp-socks5.service <<EOF
[Unit]
Description=FRP local SOCKS5 exit proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=FRP_SOCKS_PORT=${SOCKS_PORT}
Environment=FRP_SOCKS_USER=${SOCKS_USER}
Environment=FRP_SOCKS_PASS=${SOCKS_PASS}
ExecStart=/usr/local/bin/frp-socks5.py
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

write_frps_unit() {
    cat >/etc/systemd/system/frps-browser.service <<'EOF'
[Unit]
Description=FRP Browser Tunnel Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/frps -c /root/frp/server.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

write_frpc_unit() {
    cat >/etc/systemd/system/frpc-browser.service <<'EOF'
[Unit]
Description=FRP Browser Tunnel Client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/frpc -c /root/frp/client.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

verify() {
    local bin="$1" cfg="$2"
    "$bin" verify -c "$cfg"
}

block_quic_iran() {
    log_step "Blocking outbound UDP/443 on BROWSER/IRAN host..."
    if command_exists iptables; then
        iptables -C OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null ||
        iptables -I OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
    fi
    if command_exists ip6tables; then
        ip6tables -C OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null ||
        ip6tables -I OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable
    fi
    log_fix "QUIC/HTTP3 UDP/443 is blocked on the browser side; Chrome must use TCP."
}

unblock_quic_iran() {
    if command_exists iptables; then
        while iptables -C OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do
            iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable || break
        done
    fi
    if command_exists ip6tables; then
        while ip6tables -C OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; do
            ip6tables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable || break
        done
    fi
}

open_server_port() {
    if command_exists ufw; then ufw allow "${FRP_PORT}/tcp" >/dev/null 2>&1 || true; fi
    if command_exists firewall-cmd; then
        firewall-cmd --permanent --add-port="${FRP_PORT}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command_exists iptables; then
        iptables -C INPUT -p tcp --dport "$FRP_PORT" -j ACCEPT 2>/dev/null ||
        iptables -I INPUT -p tcp --dport "$FRP_PORT" -j ACCEPT
    fi
}

install_server() {
    choose_transport
    read -r -p "FRP token [${FRP_TOKEN}]: " x; FRP_TOKEN="${x:-$FRP_TOKEN}"
    read -r -p "FRP public TCP port [${FRP_PORT}]: " x; FRP_PORT="${x:-$FRP_PORT}"
    read -r -p "Browser SOCKS5 port on Iran [${SOCKS_PORT}]: " x; SOCKS_PORT="${x:-$SOCKS_PORT}"

    install_binary frps
    mkdir -p /root/frp
    open_server_port

    cat >/root/frp/server.toml <<EOF
bindAddr = "0.0.0.0"
bindPort = ${FRP_PORT}
proxyBindAddr = "127.0.0.1"

auth.method = "token"
auth.token = "${FRP_TOKEN}"

webServer.addr = "127.0.0.1"
webServer.port = ${ADMIN_PORT_S}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = 20
transport.tcpKeepalive = 30
transport.maxPoolCount = 400
transport.heartbeatTimeout = 120
transport.tls.force = true

log.to = "/var/log/frps.log"
log.level = "info"
log.maxDays = 14
EOF

    verify /usr/local/bin/frps /root/frp/server.toml || return 1
    write_frps_unit
    systemctl daemon-reload
    systemctl enable --now frps-browser.service
    tune_tcp

    sleep 2
    systemctl is-active --quiet frps-browser.service || {
        journalctl -u frps-browser.service --no-pager -n 40
        return 1
    }
    log_ok "FRP server is running on TCP/${FRP_PORT}."
    log_ok "SOCKS5 will be exposed on 127.0.0.1:${SOCKS_PORT} after the client connects."
}

install_client() {
    choose_transport
    read -r -p "Iran FRP server address: " SERVER_ADDR
    [ -n "$SERVER_ADDR" ] || { log_error "Address is required."; return 1; }
    read -r -p "FRP token [${FRP_TOKEN}]: " x; FRP_TOKEN="${x:-$FRP_TOKEN}"
    read -r -p "FRP server port [${FRP_PORT}]: " x; FRP_PORT="${x:-$FRP_PORT}"
    read -r -p "SOCKS5 exit port on Outside [${SOCKS_PORT}]: " x; SOCKS_PORT="${x:-$SOCKS_PORT}"

    install_binary frpc
    mkdir -p /root/frp

    cat >/root/frp/client.toml <<EOF
serverAddr = "${SERVER_ADDR}"
serverPort = ${FRP_PORT}

auth.method = "token"
auth.token = "${FRP_TOKEN}"

webServer.addr = "127.0.0.1"
webServer.port = ${ADMIN_PORT_C}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

transport.protocol = "tcp"
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = 20
transport.poolCount = ${POOL_COUNT}
transport.heartbeatInterval = ${HB_INTERVAL}
transport.heartbeatTimeout = ${HB_TIMEOUT}
transport.dialServerTimeout = ${DIAL_TIMEOUT}
transport.dialServerKeepalive = ${DIAL_KEEPALIVE}
transport.tls.enable = true

[[proxies]]
name = "browser-socks5"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${SOCKS_PORT}
remotePort = ${SOCKS_PORT}
EOF

    verify /usr/local/bin/frpc /root/frp/client.toml || return 1

    write_socks_server
    write_frpc_unit
    systemctl daemon-reload
    systemctl enable --now frp-socks5.service
    systemctl enable --now frpc-browser.service
    tune_tcp

    sleep 3
    systemctl is-active --quiet frp-socks5.service || {
        journalctl -u frp-socks5.service --no-pager -n 30
        return 1
    }
    systemctl is-active --quiet frpc-browser.service || {
        journalctl -u frpc-browser.service --no-pager -n 40
        return 1
    }

    block_quic_iran

    log_ok "SOCKS5 exit proxy is running on OUTSIDE: 127.0.0.1:${SOCKS_PORT}."
    log_ok "On IRAN, Chrome should use SOCKS5: 127.0.0.1:${SOCKS_PORT}."
    log_warn "Use SOCKS5 hostname resolution (SOCKS5h) if your proxy UI offers it."
}

test_google() {
    log_step "Testing Google from the OUTSIDE exit node..."
    curl -4 -sS -o /dev/null -w "IPv4 Google HTTP: %{http_code}\n" \
        --max-time 15 https://www.google.com || true

    log_step "Testing FRP services..."
    systemctl is-active --quiet frp-socks5.service && log_ok "SOCKS5: active" || log_error "SOCKS5: inactive"
    systemctl is-active --quiet frpc-browser.service && log_ok "FRPC: active" || log_error "FRPC: inactive"
    systemctl is-active --quiet frps-browser.service && log_ok "FRPS: active" || true

    if ss -H -ltn 2>/dev/null | grep -q ":${SOCKS_PORT}[[:space:]]"; then
        log_ok "Local SOCKS port ${SOCKS_PORT} is listening."
    fi
}

status_all() {
    echo "================ FRP Browser Tunnel ================"
    for u in frps-browser frpc-browser frp-socks5; do
        if systemctl list-unit-files | grep -q "^${u}.service"; then
            printf "%-20s " "$u"
            systemctl is-active --quiet "$u.service" && echo ACTIVE || echo INACTIVE
        fi
    done
    echo ""
    ss -H -ltnp 2>/dev/null | grep -E ":(${FRP_PORT}|${SOCKS_PORT})[[:space:]]" || true
    echo ""
    if [ -f /root/frp/client.toml ]; then
        echo "--- client.toml ---"
        sed -n '1,180p' /root/frp/client.toml
    fi
}

remove_all() {
    systemctl disable --now frps-browser.service frpc-browser.service frp-socks5.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/frps-browser.service /etc/systemd/system/frpc-browser.service /etc/systemd/system/frp-socks5.service
    rm -f /usr/local/bin/frps /usr/local/bin/frpc /usr/local/bin/frp-socks5.py
    rm -rf /root/frp
    unblock_quic_iran
    rm -f /etc/sysctl.d/99-frp-browser-tunnel.conf
    sysctl --system >/dev/null 2>&1 || true
    systemctl daemon-reload
    log_ok "FRP Browser Tunnel removed."
}

menu() {
    while true; do
        clear
        echo "================================================"
        echo " FRP Iran Browser Tunnel v5"
        echo " TCP-only + SOCKS5 + QUIC fix"
        echo "================================================"
        echo " 1) Install FRPS on IRAN"
        echo " 2) Install FRPC + SOCKS5 on OUTSIDE"
        echo " 3) Status"
        echo " 4) Test Google / tunnel"
        echo " 5) Block QUIC on IRAN"
        echo " 6) Unblock QUIC on IRAN"
        echo " 7) Remove"
        echo " 8) Exit"
        echo "================================================"
        read -r -p "Choose [1-8]: " c
        case "$c" in
            1) install_server ;;
            2) install_client ;;
            3) status_all ;;
            4) test_google ;;
            5) block_quic_iran ;;
            6) unblock_quic_iran ;;
            7) read -r -p "Remove all? [y/N]: " z; [[ "$z" =~ ^[Yy]$ ]] && remove_all ;;
            8) exit 0 ;;
            *) log_warn "Invalid choice." ;;
        esac
        echo ""; read -r -p "Press Enter..."
    done
}

require_root
ensure_deps || exit 1
menu
