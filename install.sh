#!/bin/bash
#==============================================================
#  FRP TUNNEL MANAGER v4.1 (Server + Client) - Single Script
#  Generic TCP/UDP port forwarding over FRP
#  Features: Smart Watchdog | Google/QUIC Fix | MTU Fix | Live Monitor
#
#  Notes:
#  - FRP only forwards TCP and UDP. ICMP (ping) is never tunneled -
#    the watchdog's ping is a direct ICMP check between the two
#    servers themselves, used only to measure link health.
#  - This script only builds the tunnel. It does not install any
#    panel or application on either machine - point the forwarded
#    ports at whatever local service you're already running there.
#==============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

FRP_VERSION="0.58.1"
INSTALL_DIR="/opt/frp"
BIN_DIR="$INSTALL_DIR/bin"
CONFIG_DIR="/etc/frp"
LOG_DIR="/var/log/frp"
SCRIPTS_DIR="$INSTALL_DIR/scripts"

#---------------- helpers ----------------
msg()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[X]${NC} $1"; }

check_root() {
    [ "$EUID" -ne 0 ] && { err "Run as root -> sudo bash $0"; exit 1; }
}

detect_arch() {
    case $(uname -m) in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "arm" ;;
        *) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

is_port() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    fi
    command -v wget >/dev/null 2>&1 || { err "Failed to install wget"; exit 1; }
}

# Download with fallback mirrors (for servers without direct GitHub access)
fetch_file() {
    local url="$1" out="$2"
    local mirrors=("" "https://ghfast.top/" "https://ghproxy.net/" "https://mirror.ghproxy.com/")
    local m
    for m in "${mirrors[@]}"; do
        wget -q --timeout=25 "${m}${url}" -O "$out" 2>/dev/null && [ -s "$out" ] && return 0
    done
    curl -sL --max-time 90 "$url" -o "$out" 2>/dev/null && [ -s "$out" ] && return 0
    return 1
}

install_frp_binaries() {
    local need="$1"   # frps | frpc | both
    local arch; arch=$(detect_arch)
    local file="frp_${FRP_VERSION}_linux_${arch}.tar.gz"
    local url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${file}"
    local ext="frp_${FRP_VERSION}_linux_${arch}"

    mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR"

    msg "Downloading FRP v${FRP_VERSION} (${arch})..."
    fetch_file "$url" "/tmp/$file" || { err "Download failed (GitHub + mirrors)"; exit 1; }
    tar -xzf "/tmp/$file" -C /tmp || { err "Extraction failed"; exit 1; }

    [ "$need" != "frpc" ] && cp "/tmp/$ext/frps" "$BIN_DIR/" && chmod +x "$BIN_DIR/frps"
    [ "$need" != "frps" ] && cp "/tmp/$ext/frpc" "$BIN_DIR/" && chmod +x "$BIN_DIR/frpc"
    rm -rf "/tmp/$ext" "/tmp/$file"
    msg "FRP binaries installed -> $BIN_DIR"
}

sys_optimize() {
    msg "Optimizing system (BBR, buffers, MTU probing)..."
    modprobe tcp_bbr 2>/dev/null
    modprobe nf_conntrack 2>/dev/null

    cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 536
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.udp_mem = 786432 1048576 1572864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.ipfrag_high_thresh = 4194304
net.ipv4.ipfrag_low_thresh = 3145728
net.ipv4.ipfrag_time = 30
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
vm.swappiness = 10
fs.file-max = 1000000
EOF
    sysctl -p /etc/sysctl.d/99-frp-tuning.conf >/dev/null 2>&1 || true

    cat > /etc/security/limits.d/frp-limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF
}

open_firewall() {
    local p
    for p in $1; do
        if command -v ufw >/dev/null 2>&1; then
            ufw allow "${p//-/:}" >/dev/null 2>&1
        elif command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="$p" >/dev/null 2>&1
        fi
    done
    command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1
    return 0
}

#==============================================================
#  Option 1 - Install FRP SERVER (frps) - run on the externally
#             exposed server (the one users connect to)
#==============================================================
install_server() {
    echo ""
    msg "=== Installing FRP SERVER (frps) ==="

    if [ -f /etc/systemd/system/frps.service ]; then
        read -rp "frps is already installed. Reinstall? (y/N): " R
        [ "$R" = "y" ] || return 0
        systemctl stop frps 2>/dev/null
    fi

    install_deps
    sys_optimize
    install_frp_binaries frps

    read -rp "Tunnel port - must match on the client [8443]: " P; P=${P:-8443}; is_port "$P" || { err "Invalid port"; return 1; }
    read -rp "Dashboard port [7500]: " DP; DP=${DP:-7500};  is_port "$DP" || { err "Invalid port"; return 1; }
    # Forwarded-port selection happens on the client only; the server just needs a
    # wide-enough allowed range so it never blocks whatever the client asks for.
    RSTART=1024; REND=65535

    read -rp "Token - must match on the client [123]: " TOKEN; TOKEN=${TOKEN:-123}
    [ "$TOKEN" = "123" ] && warn "Using the default token (123) - fine for quick testing, but change it on both sides for anything internet-facing"
    DASH_USER="admin"
    DASH_PASS=$(openssl rand -hex 8)
    SRV_IP=$(curl -s4 --max-time 6 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    cat > "$CONFIG_DIR/frps.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = ${P}
kcpBindPort = ${P}

auth.method = "token"
auth.token = "${TOKEN}"

webServer.addr = "0.0.0.0"
webServer.port = ${DP}
webServer.user = "${DASH_USER}"
webServer.password = "${DASH_PASS}"

allowPorts = [ { start = ${RSTART}, end = ${REND} } ]
maxPortsPerClient = 0

transport.heartbeatTimeout = 90
transport.maxPoolCount = 50
transport.tcpMuxKeepaliveInterval = 30

log.to = "${LOG_DIR}/frps.log"
log.level = "warn"
log.maxDays = 3

udpPacketSize = 1500
EOF

    # Validate config before starting the service
    VERIFY_OUT=$("$BIN_DIR/frps" verify -c "$CONFIG_DIR/frps.toml" 2>&1)
    if [ $? -ne 0 ]; then
        err "frps config is invalid:"
        echo "$VERIFY_OUT"
        return 1
    fi

    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server (frps)
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=${BIN_DIR}/frps -c ${CONFIG_DIR}/frps.toml
LimitNOFILE=1000000
LimitNPROC=500000
KillMode=process
TimeoutStopSec=5
Environment="GOMAXPROCS=$(nproc)"

[Install]
WantedBy=multi-user.target
EOF

    open_firewall "${P}/tcp ${P}/udp ${DP}/tcp ${RSTART}-${REND}/tcp ${RSTART}-${REND}/udp"

    systemctl daemon-reload
    systemctl enable frps >/dev/null 2>&1
    systemctl restart frps
    sleep 3

    cat > "$CONFIG_DIR/server-info.txt" <<EOF
Server IP   : ${SRV_IP}
FRP Port    : ${P} (tcp/kcp)
Token       : ${TOKEN}
Dashboard   : http://${SRV_IP}:${DP}  (${DASH_USER} / ${DASH_PASS})
EOF

    echo ""
    if systemctl is-active --quiet frps; then
        echo -e "${GREEN}+---------------- FRP SERVER READY -----------------+${NC}"
        echo -e "${GREEN}| Server IP : ${SRV_IP}${NC}"
        echo -e "${GREEN}| FRP Port  : ${P} (tcp/kcp)${NC}"
        echo -e "${YELLOW}| TOKEN     : ${TOKEN}${NC}"
        echo -e "${GREEN}| Dashboard : http://${SRV_IP}:${DP}${NC}"
        echo -e "${GREEN}|             user=${DASH_USER}  pass=${DASH_PASS}${NC}"
        echo -e "${GREEN}| (saved to ${CONFIG_DIR}/server-info.txt)${NC}"
        echo -e "${GREEN}+-----------------------------------------------------+${NC}"
        warn "Next step: on the client machine -> option 2, then 4, then 5"
    else
        err "frps failed to start:"; journalctl -u frps --no-pager -n 15
    fi
}

#==============================================================
#  Client-side proxy writers
#==============================================================
write_tcp_proxy() {  # $1=name $2=lport $3=rport
cat >> "$CONFIG_DIR/frpc.toml" <<EOF

[[proxies]]
name = "$1"
type = "tcp"
localIP = "127.0.0.1"
localPort = $2
remotePort = $3
transport.useEncryption = false
transport.useCompression = false
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10
EOF
}

write_udp_proxy() {  # $1=name $2=lport $3=rport
cat >> "$CONFIG_DIR/frpc.toml" <<EOF

[[proxies]]
name = "$1"
type = "udp"
localIP = "127.0.0.1"
localPort = $2
remotePort = $3
transport.useEncryption = false
transport.useCompression = false
EOF
}

proxy_count() {
    local n
    n=$(grep -c '^\[\[proxies\]\]' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    [ -z "$n" ] && n=0
    echo "$n"
}

#==============================================================
#  Option 2 - Install FRP CLIENT (frpc) - run on the internal
#             server that has the local service(s) to expose
#==============================================================
install_client() {
    echo ""
    msg "=== Installing FRP CLIENT (frpc) ==="

    if [ -f "$CONFIG_DIR/frpc.toml" ]; then
        read -rp "frpc is already configured. Reconfigure from scratch? (y/N): " R
        [ "$R" = "y" ] || return 0
        systemctl stop frpc 2>/dev/null
    fi

    install_deps
    sys_optimize
    install_frp_binaries frpc

    read -rp "FRP server IP (frps): " SERVER_IP
    [ -z "$SERVER_IP" ] && { err "IP is required"; return 1; }
    read -rp "Tunnel port - must match the server [8443]: " P; P=${P:-8443}; is_port "$P" || { err "Invalid port"; return 1; }
    read -rp "Token - must match the server [123]: " TOKEN; TOKEN=${TOKEN:-123}

    echo ""
    echo "Transport protocol used to reach the server:"
    echo "  1) tcp       - default, most stable"
    echo "  2) kcp       - better speed on lossy links (needs UDP open between the two servers)"
    echo "  3) websocket - for getting through strict firewalls"
    read -rp "Choice [1]: " T
    case $T in
        2) TP="kcp" ;; 3) TP="websocket" ;; *) TP="tcp" ;;
    esac

    # ---------- Port mappings ----------
    echo ""
    echo -e "${CYAN}-- Ports to forward --${NC}"
    echo "Enter the ports you want forwarded, comma-separated."
    echo "Each one is forwarded 1:1 (same port number on the server as locally), e.g: 443,8443,2096"
    read -rp "Ports: " PORTS_RAW
    read -rp "Protocol for these ports: tcp/udp/both [both]: " PP; PP=${PP:-both}
    case $PP in tcp|udp|both) ;; *) PP="both" ;; esac

    MAPPINGS=()
    IFS=',' read -ra PORT_ARR <<< "$PORTS_RAW"
    for raw in "${PORT_ARR[@]}"; do
        port=$(echo "$raw" | tr -d '[:space:]')
        [ -z "$port" ] && continue
        if ! is_port "$port"; then
            warn "Skipping invalid port: $port"
            continue
        fi
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; then
                warn "Port ${port} is not listening locally yet - make sure your service is bound to it"
            fi
        fi
        MAPPINGS+=("${port}:${port}:${PP}")
    done

    [ ${#MAPPINGS[@]} -eq 0 ] && { err "At least one valid port is required"; return 1; }

    # ---------- Main config ----------
    cat > "$CONFIG_DIR/frpc.toml" <<EOF
serverAddr = "${SERVER_IP}"
serverPort = ${P}

auth.method = "token"
auth.token = "${TOKEN}"

transport.protocol = "${TP}"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
transport.poolCount = 10
transport.tcpKeepalive = 30
transport.dialServerTimeout = 10

loginFailExit = false

log.to = "${LOG_DIR}/frpc.log"
log.level = "info"
log.maxDays = 3

udpPacketSize = 1500
EOF

    # ---------- Proxies ----------
    i=0
    for m in "${MAPPINGS[@]}"; do
        i=$((i+1))
        LP=${m%%:*}; rest=${m#*:}; RP=${rest%%:*}; PP=${rest#*:}
        case $PP in
            tcp)  write_tcp_proxy "fwd-tcp-$i" "$LP" "$RP" ;;
            udp)  write_udp_proxy "fwd-udp-$i" "$LP" "$RP" ;;
            both) write_tcp_proxy "fwd-tcp-$i" "$LP" "$RP"
                  write_udp_proxy "fwd-udp-$i" "$LP" "$RP" ;;
        esac
    done

    # ---------- Validate ----------
    VERIFY_OUT=$("$BIN_DIR/frpc" verify -c "$CONFIG_DIR/frpc.toml" 2>&1)
    if [ $? -ne 0 ]; then
        err "frpc config is invalid:"
        echo "$VERIFY_OUT"
        return 1
    fi

    # ---------- Service ----------
    cat > /etc/systemd/system/frpc.service <<EOF
[Unit]
Description=FRP Client (frpc)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=${BIN_DIR}/frpc -c ${CONFIG_DIR}/frpc.toml
LimitNOFILE=1000000
LimitNPROC=500000
KillMode=process
TimeoutStopSec=5
Environment="GOMAXPROCS=$(nproc)"

[Install]
WantedBy=multi-user.target
EOF

    open_firewall "${P}/tcp ${P}/udp"

    systemctl daemon-reload
    systemctl enable frpc >/dev/null 2>&1
    systemctl restart frpc
    sleep 4

    echo ""
    if systemctl is-active --quiet frpc; then
        msg "frpc is running"
        if tail -20 "$LOG_DIR/frpc.log" 2>/dev/null | grep -q "login to server success"; then
            msg "Tunnel connected to ${SERVER_IP}:${P}"
        else
            warn "Not connected yet - check IP/Token, see logs via menu -> option 9"
        fi
    else
        err "frpc failed to start:"; journalctl -u frpc --no-pager -n 15
        return 1
    fi

    echo ""
    echo -e "${CYAN}Port mappings:${NC}"
    for m in "${MAPPINGS[@]}"; do
        LP=${m%%:*}; rest=${m#*:}; RP=${rest%%:*}; PP=${rest#*:}
        echo -e "  local ${LP} -> remote ${RP} (${PP})"
    done
    warn "Next: option 4 (watchdog) and option 5 (Google/QUIC fix - run it here, since this machine has the internet egress)"
}

#==============================================================
#  Option 3 - Add a new port mapping without reinstalling
#==============================================================
add_mapping() {
    [ -f "$CONFIG_DIR/frpc.toml" ] || { err "Run option 2 (install client) first"; return 1; }

    echo "Enter the ports you want to add, comma-separated (each forwarded 1:1), e.g: 2053,2083"
    read -rp "Ports: " PORTS_RAW
    read -rp "Protocol for these ports: tcp/udp/both [both]: " PP; PP=${PP:-both}
    case $PP in tcp|udp|both) ;; *) PP="both" ;; esac

    NEW_MAPPINGS=()
    IFS=',' read -ra PORT_ARR <<< "$PORTS_RAW"
    for raw in "${PORT_ARR[@]}"; do
        port=$(echo "$raw" | tr -d '[:space:]')
        [ -z "$port" ] && continue
        if ! is_port "$port"; then
            warn "Skipping invalid port: $port"
            continue
        fi
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; then
                warn "Port ${port} is not listening locally yet"
            fi
        fi
        NEW_MAPPINGS+=("${port}:${port}:${PP}")
    done

    [ ${#NEW_MAPPINGS[@]} -eq 0 ] && { err "No valid ports given"; return 1; }

    # Back up so we can actually revert if the new config turns out invalid
    cp "$CONFIG_DIR/frpc.toml" "$CONFIG_DIR/frpc.toml.bak"

    N=$(proxy_count)
    for m in "${NEW_MAPPINGS[@]}"; do
        N=$((N+1))
        LP=${m%%:*}; rest=${m#*:}; RP=${rest%%:*}; PP=${rest#*:}
        case $PP in
            tcp)  write_tcp_proxy "fwd-tcp-$N" "$LP" "$RP" ;;
            udp)  write_udp_proxy "fwd-udp-$N" "$LP" "$RP" ;;
            both) write_tcp_proxy "fwd-tcp-$N" "$LP" "$RP"
                  write_udp_proxy "fwd-udp-$N" "$LP" "$RP" ;;
        esac
    done

    VERIFY_OUT=$("$BIN_DIR/frpc" verify -c "$CONFIG_DIR/frpc.toml" 2>&1)
    if [ $? -ne 0 ]; then
        err "New config is invalid - reverted to the previous version:"
        echo "$VERIFY_OUT"
        mv "$CONFIG_DIR/frpc.toml.bak" "$CONFIG_DIR/frpc.toml"
        return 1
    fi
    rm -f "$CONFIG_DIR/frpc.toml.bak"

    systemctl restart frpc 2>/dev/null
    msg "Port mapping(s) added and frpc restarted"
    warn "If ufw/firewalld is active on the frps server, open the matching remote port(s) there too"
}

#==============================================================
#  Option 4 - Smart watchdog
#==============================================================
install_watchdog() {
    [ -f "$CONFIG_DIR/frpc.toml" ] || { err "Run option 2 (install client) first"; return 1; }

    msg "Installing smart watchdog..."

    cat > "$SCRIPTS_DIR/frp-watchdog.sh" <<'WEOF'
#!/bin/bash
# ============ Smart FRP Watchdog v4.1 ============
# Checks every 5s | acts after 2 consecutive failures (10s) | cooldown to avoid restart loops
LOG_DIR="/var/log/frp"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
CONFIG="/etc/frp/frpc.toml"

SERVER_ADDR=$(grep -oP '^\s*serverAddr\s*=\s*"\K[^"]+' "$CONFIG" 2>/dev/null)
SERVER_PORT=$(grep -oP '^\s*serverPort\s*=\s*\K[0-9]+' "$CONFIG" 2>/dev/null)

CHECK_INTERVAL=5
FAIL_THRESHOLD=2
RESTART_COOLDOWN=30
fail_count=0
last_restart=0
total_restarts=0
cycle=0

log(){ echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$WATCHDOG_LOG"; }

# Prevent the log from growing unbounded (truncate above 1MB)
if [ -f "$WATCHDOG_LOG" ]; then
    sz=$(stat -c%s "$WATCHDOG_LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 1048576 ] && : > "$WATCHDOG_LOG"
fi

[ -z "$SERVER_ADDR" ] && { echo "$(date) ERROR: frpc.toml not found" >> "$WATCHDOG_LOG"; exit 1; }

proc_ok(){ pgrep -x frpc >/dev/null 2>&1; }

tcp_ok(){ timeout 3 bash -c "exec 3<>/dev/tcp/$SERVER_ADDR/$SERVER_PORT" 2>/dev/null; }

log_ok(){
    [ -f "$LOG_DIR/frpc.log" ] || return 0
    recent=$(tail -n 15 "$LOG_DIR/frpc.log" 2>/dev/null)
    echo "$recent" | grep -qE 'login to server success|start proxy success' && return 0
    echo "$recent" | grep -qiE 'connect to server error|dial tcp.*(refused|timeout|i/o timeout)' && return 1
    return 0
}

mem_kb(){ ps -C frpc -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}'; }

restart_frpc(){
    now=$(date +%s)
    if [ $((now - last_restart)) -lt $RESTART_COOLDOWN ]; then
        log "COOLDOWN - restart skipped (avoiding restart loop)"
        return 1
    fi
    log "ACTION: restarting frpc..."
    systemctl stop frpc 2>/dev/null
    pkill -9 -x frpc 2>/dev/null
    sleep 1
    # Clean up half-dead sockets toward the server
    ss -K dst "$SERVER_ADDR" 2>/dev/null
    systemctl reset-failed frpc 2>/dev/null
    systemctl start frpc 2>/dev/null
    sleep 3
    last_restart=$(date +%s)
    total_restarts=$((total_restarts+1))
    if proc_ok; then
        log "OK: frpc restarted (total=$total_restarts)"
        fail_count=0
    else
        log "ERROR: restart failed!"
    fi
}

net_repair(){
    log "ACTION: repairing network (dead sockets / ARP / sysctl)"
    ss -K dst "$SERVER_ADDR" 2>/dev/null
    ip neigh flush "$SERVER_ADDR" 2>/dev/null
    sysctl -p /etc/sysctl.d/99-frp-tuning.conf >/dev/null 2>&1
}

log "==================================================="
log "START watchdog -> server=$SERVER_ADDR:$SERVER_PORT interval=${CHECK_INTERVAL}s threshold=$FAIL_THRESHOLD"

while true; do
    sleep "$CHECK_INTERVAL"
    cycle=$((cycle+1))

    # --- 1) Is the process alive? ---
    if ! proc_ok; then
        fail_count=$((fail_count+1))
        log "WARN: frpc process is dead ($fail_count/$FAIL_THRESHOLD)"
        [ $fail_count -ge $FAIL_THRESHOLD ] && restart_frpc
        continue
    fi

    # --- 2) Is there a real TCP connection to the server? (fastest check) ---
    if ! tcp_ok; then
        fail_count=$((fail_count+1))
        log "WARN: server is unreachable ($fail_count/$FAIL_THRESHOLD)"
        if [ $fail_count -ge $FAIL_THRESHOLD ]; then
            net_repair
            sleep 2
            tcp_ok || restart_frpc
            fail_count=0
        fi
        continue
    fi

    # --- 3) Does the frpc log look healthy? ---
    if ! log_ok; then
        fail_count=$((fail_count+1))
        log "WARN: frpc log shows an error ($fail_count/$FAIL_THRESHOLD)"
        [ $fail_count -ge $FAIL_THRESHOLD ] && restart_frpc
        continue
    fi

    if [ $fail_count -gt 0 ]; then
        log "OK: connection recovered"
        fail_count=0
    fi

    # --- 4) Every 60s: direct ICMP ping + memory check ---
    if [ $((cycle % 12)) -eq 0 ]; then
        lat=$(ping -c1 -W2 "$SERVER_ADDR" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2 | cut -d. -f1)
        [ -n "$lat" ] && log "INFO: direct ping ${lat}ms"
        m=$(mem_kb)
        if [ "$m" -gt 524288 ]; then
            log "WARN: frpc memory usage high ($((m/1024))MB) -> restarting"
            restart_frpc
        fi
    fi
done
WEOF
    chmod +x "$SCRIPTS_DIR/frp-watchdog.sh"

    cat > /etc/systemd/system/frp-watchdog.service <<EOF
[Unit]
Description=FRP Smart Watchdog
After=frpc.service

[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=${SCRIPTS_DIR}/frp-watchdog.sh
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frp-watchdog >/dev/null 2>&1
    systemctl restart frp-watchdog

    if systemctl is-active --quiet frp-watchdog; then
        msg "Watchdog is active (checks every 5s - acts after 10s - 30s cooldown)"
    else
        err "Watchdog failed to start:"; journalctl -u frp-watchdog --no-pager -n 10
    fi
}

#==============================================================
#  Option 5 and 6 - Google/QUIC fix + MTU
#==============================================================
ensure_fix_rules() {
    cat > "$SCRIPTS_DIR/apply-fix-rules.sh" <<'FEOF'
#!/bin/bash
# Block QUIC/UDP-443 so Chrome falls back to TCP immediately (fixes Google search hangs)
iptables  -C OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null || iptables  -I OUTPUT  1 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
ip6tables -C OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null || ip6tables -I OUTPUT  1 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable
iptables  -C FORWARD -p udp --dport 443 -j REJECT 2>/dev/null || iptables  -I FORWARD 1 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
ip6tables -C FORWARD -p udp --dport 443 -j REJECT 2>/dev/null || ip6tables -I FORWARD 1 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable

# MSS clamp - fixes half-loaded pages / hangs on heavy content
iptables  -t mangle -C OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables  -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables  -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables  -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -C OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Apply the saved MTU from the optimizer menu
MTU_FILE=/etc/frp/mtu.conf
if [ -f "$MTU_FILE" ]; then
    MTU=$(cat "$MTU_FILE")
    for i in /sys/class/net/*; do
        iface=${i##*/}
        [ "$iface" = "lo" ] && continue
        cur=$(cat "$i/mtu" 2>/dev/null)
        [ -n "$cur" ] && [ "$cur" -gt "$MTU" ] && ip link set dev "$iface" mtu "$MTU" 2>/dev/null
    done
fi
exit 0
FEOF
    chmod +x "$SCRIPTS_DIR/apply-fix-rules.sh"

    cat > /etc/systemd/system/frp-fix-rules.service <<EOF
[Unit]
Description=FRP Fix Rules (QUIC/MSS/MTU) - persistent
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/apply-fix-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frp-fix-rules >/dev/null 2>&1
}

google_fix() {
    msg "Applying Google/QUIC fix (block QUIC + MSS clamp)..."
    install_deps
    ensure_fix_rules
    "$SCRIPTS_DIR/apply-fix-rules.sh"
    msg "Done - Chrome no longer waits for QUIC and falls back to TCP right away"
    warn "Run this on the machine with the actual internet egress (the frpc/client machine)"
    warn "If DNS is still an issue: in your outbound app settings, set DNS to tcp://8.8.8.8"
}

mtu_opt() {
    read -rp "IP to test MTU against (the frps server IP): " TIP
    [ -z "$TIP" ] && { err "IP is required"; return 1; }

    msg "Auto-detecting the optimal MTU (binary search)..."
    low=500; high=1500; optimal=1500
    while [ $((high - low)) -gt 1 ]; do
        mid=$(( (low + high) / 2 ))
        payload=$((mid - 28))
        if ping -M do -s "$payload" -c1 -W2 "$TIP" >/dev/null 2>&1; then
            low=$mid
        else
            high=$mid
        fi
    done
    optimal=$low

    mkdir -p "$CONFIG_DIR"
    echo "$optimal" > "$CONFIG_DIR/mtu.conf"
    install_deps
    ensure_fix_rules
    "$SCRIPTS_DIR/apply-fix-rules.sh"
    msg "Best MTU: $optimal -> applied to all interfaces (persistent - re-applied automatically after reboot)"
}

#==============================================================
#  Option 7 - Status
#==============================================================
show_status() {
    echo ""
    echo -e "${CYAN}============ FRP STATUS ============${NC}"
    for svc in frps frpc frp-watchdog frp-fix-rules; do
        [ -f "/etc/systemd/system/$svc.service" ] || continue
        if systemctl is-active --quiet "$svc"; then
            echo -e "  $svc : ${GREEN}RUNNING${NC}"
        else
            echo -e "  $svc : ${RED}STOPPED${NC}"
        fi
    done

    if [ -f "$CONFIG_DIR/frpc.toml" ]; then
        SA=$(grep -oP 'serverAddr\s*=\s*"\K[^"]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
        SP=$(grep -oP 'serverPort\s*=\s*\K[0-9]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
        if [ -n "$SA" ]; then
            if timeout 2 bash -c "exec 3<>/dev/tcp/$SA/$SP" 2>/dev/null; then
                echo -e "  Server $SA:$SP : ${GREEN}REACHABLE${NC}"
            else
                echo -e "  Server $SA:$SP : ${RED}UNREACHABLE${NC}"
            fi
            P=$(ping -c1 -W2 "$SA" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            [ -n "$P" ] && echo -e "  Latency: ${YELLOW}${P}ms${NC}"
            C=$(ss -tn 2>/dev/null | grep -c "$SA")
            echo -e "  Active connections: ${YELLOW}$C${NC}"
        fi

        echo ""
        echo -e "${CYAN}-- Configured port mappings --${NC}"
        awk '
            /^\[\[proxies\]\]/ { name=""; type=""; lport=""; rport="" }
            /^name *=/ { split($0,a,"="); gsub(/["\ ]/,"",a[2]); name=a[2] }
            /^type *=/ { split($0,a,"="); gsub(/["\ ]/,"",a[2]); type=a[2] }
            /^localPort *=/ { split($0,a,"="); gsub(/ /,"",a[2]); lport=a[2] }
            /^remotePort *=/ { split($0,a,"="); gsub(/ /,"",a[2]); rport=a[2]; print "  " name " (" type "): local " lport " -> remote " rport }
        ' "$CONFIG_DIR/frpc.toml" 2>/dev/null
    fi

    PID=$(pgrep -x frpc | head -1)
    [ -n "$PID" ] && echo -e "  frpc MEM: $(ps -p $PID -o rss= | awk '{printf "%.0f MB", $1/1024}')  CPU: $(ps -p $PID -o %cpu= | tr -d ' ')%"

    echo ""
    echo -e "${CYAN}-- Recent watchdog events --${NC}"
    tail -5 "$LOG_DIR/watchdog.log" 2>/dev/null || echo "  (no events yet)"
    echo ""
}

#==============================================================
#  Option 8 - Live monitor
#==============================================================
show_monitor() {
    SA=$(grep -oP 'serverAddr\s*=\s*"\K[^"]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    SP=$(grep -oP 'serverPort\s*=\s*\K[0-9]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    trap 'trap - INT; echo; return' INT
    while true; do
        clear
        echo -e "${CYAN}==== FRP LIVE MONITOR - $(date '+%H:%M:%S') ====${NC}  (Ctrl+C = back to menu)"
        systemctl is-active --quiet frpc 2>/dev/null && echo -e " frpc      : ${GREEN}RUNNING${NC}" || echo -e " frpc      : ${RED}STOPPED${NC}"
        systemctl is-active --quiet frp-watchdog 2>/dev/null && echo -e " watchdog  : ${GREEN}RUNNING${NC}" || echo -e " watchdog  : ${RED}STOPPED${NC}"
        if [ -n "$SA" ]; then
            if timeout 2 bash -c "exec 3<>/dev/tcp/$SA/$SP" 2>/dev/null; then
                echo -e " server    : ${GREEN}CONNECTED${NC} ($SA:$SP)"
            else
                echo -e " server    : ${RED}DISCONNECTED${NC} ($SA:$SP)"
            fi
            P=$(ping -c1 -W2 "$SA" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            [ -n "$P" ] && echo -e " latency   : ${YELLOW}${P}ms${NC}"
            echo -e " conns     : $(ss -tn 2>/dev/null | grep -c "$SA")"
        fi
        PID=$(pgrep -x frpc | head -1)
        [ -n "$PID" ] && echo -e " frpc mem  : $(ps -p $PID -o rss= | awk '{printf "%.0f MB", $1/1024}') | uptime: $(ps -p $PID -o etime= | tr -d ' ')"
        echo "--------------------------------"
        tail -3 "$LOG_DIR/watchdog.log" 2>/dev/null
        sleep 3
    done
}

#==============================================================
#  Option 9 / 10 / 11 / 12
#==============================================================
view_logs() {
    echo "  1) frpc log   2) frps log   3) watchdog log   4) frpc journal"
    read -rp "Choice: " L
    case $L in
        1) tail -f "$LOG_DIR/frpc.log" 2>/dev/null ;;
        2) tail -f "$LOG_DIR/frps.log" 2>/dev/null ;;
        3) tail -f "$LOG_DIR/watchdog.log" 2>/dev/null ;;
        4) journalctl -u frpc -f --no-pager ;;
    esac
}

restart_services() {
    for svc in frpc frps frp-watchdog frp-fix-rules; do
        if [ -f "/etc/systemd/system/$svc.service" ]; then
            systemctl restart "$svc" 2>/dev/null && msg "$svc restarted"
        fi
    done
    sleep 2
    show_status
}

# Full teardown: services + iptables/ip6tables rules + sysctl/limits tuning + all files
uninstall() {
    read -rp "Remove everything - tunnel, iptables rules, and system tuning? (yes/no): " C
    [ "$C" = "yes" ] || return 0

    msg "Stopping and removing services..."
    for svc in frp-watchdog frpc frps frp-fix-rules; do
        systemctl disable --now "$svc" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$svc.service"
    done

    msg "Removing iptables/ip6tables rules..."
    iptables  -D OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null
    ip6tables -D OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null
    iptables  -D FORWARD -p udp --dport 443 -j REJECT 2>/dev/null
    ip6tables -D FORWARD -p udp --dport 443 -j REJECT 2>/dev/null
    iptables  -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    ip6tables -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    iptables  -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    pkill -9 -x frpc 2>/dev/null; pkill -9 -x frps 2>/dev/null

    msg "Removing files and system tuning..."
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    rm -f /etc/sysctl.d/99-frp-tuning.conf /etc/security/limits.d/frp-limits.conf
    sysctl --system >/dev/null 2>&1

    msg "Complete removal finished - tunnel, iptables rules, and system tuning are all gone."
}

#==============================================================
#  Main menu
#==============================================================
show_menu() {
    clear
    echo -e "${CYAN}+====================================================+${NC}"
    echo -e "${CYAN}|          FRP TUNNEL MANAGER v4.1 (TCP/UDP)         |${NC}"
    echo -e "${CYAN}+====================================================+${NC}"
    echo -e "${CYAN}|${NC}  1) Install FRP Server (frps)   - exposed server  ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  2) Install FRP Client (frpc)   - internal server ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  3) Add new port mapping (client)                 ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  4) Smart watchdog                                ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  5) Google/QUIC fix (block QUIC + MSS clamp)      ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  6) MTU optimizer                                 ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  7) Status                                        ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  8) Live monitor                                  ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  9) View logs                                     ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  10) Restart services                             ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  11) Re-apply system tuning                       ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  12) Uninstall everything                         ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  0) Exit                                          ${CYAN}|${NC}"
    echo -e "${CYAN}+====================================================+${NC}"
}

check_root
while true; do
    show_menu
    read -rp "Choice: " CH
    case $CH in
        1)  install_server ;;
        2)  install_client ;;
        3)  add_mapping ;;
        4)  install_watchdog ;;
        5)  google_fix ;;
        6)  mtu_opt ;;
        7)  show_status ;;
        8)  show_monitor ;;
        9)  view_logs ;;
        10) restart_services ;;
        11) sys_optimize ;;
        12) uninstall ;;
        0)  exit 0 ;;
        *)  warn "Invalid choice" ;;
    esac
    read -rp $'\nPress Enter to return to the menu...'
done
