#!/bin/bash

# =============================================================================
# FRP Iran-Optimized Installation Script (v3.0)
# =============================================================================
# Version: frp v0.69.1  |  Script v3.0
# Optimized for: Iran / High-censorship networks
# Key changes:
#   - Default port: 443 (blends with HTTPS)
#   - Default protocol: http2 (harder to fingerprint than websocket)
#   - tcpMux enabled for traffic blending
#   - TLS SNI/domain fronting support
#   - Proxy chaining (socks5/http) for existing tunnel users
#   - UDP/KCP disabled by default (blocked in Iran)
#   - Removed client-only fields from server config
#   - StartLimitIntervalSec / StartLimitBurst in [Unit]
# =============================================================================

set -o pipefail

FRP_VERSION="0.69.1"
FRP_TOKEN="tun100"
FRP_PORT="443"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[ERROR] This script must be run as root (sudo).${NC}"
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "arm" ;;
        i386|i686) echo "386" ;;
        *) echo "unsupported" ;;
    esac
}

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $1"; }
log_ok()    { echo -e "${CYAN}[OK]${NC}    $1"; }
log_ir()    { echo -e "${MAGENTA}[IRAN]${NC}  $1"; }

download_frp_binary() {
    local bin_name="$1"
    local arch
    arch=$(detect_arch)
    if [ "$arch" = "unsupported" ]; then
        log_error "Unsupported architecture: $(uname -m)"
        exit 1
    fi

    local pkg="frp_${FRP_VERSION}_linux_${arch}"
    local url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${pkg}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    log_step "Downloading ${bin_name} (frp v${FRP_VERSION}, ${arch})..."
    if ! curl -fL --retry 5 --retry-delay 3 --connect-timeout 15 -o "${tmp_dir}/frp.tar.gz" "$url"; then
        log_error "Download failed: $url"
        rm -rf "$tmp_dir"
        exit 1
    fi

    if ! tar -xzf "${tmp_dir}/frp.tar.gz" -C "$tmp_dir"; then
        log_error "Archive extraction failed."
        rm -rf "$tmp_dir"
        exit 1
    fi

    if [ ! -f "${tmp_dir}/${pkg}/${bin_name}" ]; then
        log_error "Binary ${bin_name} not found inside archive."
        rm -rf "$tmp_dir"
        exit 1
    fi

    install -m 755 "${tmp_dir}/${pkg}/${bin_name}" "/usr/local/bin/${bin_name}"
    rm -rf "$tmp_dir"
    log_info "${bin_name} installed at /usr/local/bin/${bin_name}"
}

tune_tcp_for_frp() {
    log_step "Applying TCP kernel tuning for tunnel stability..."

    cat > /etc/sysctl.d/99-frp-tuning.conf <<'EOF'
# FRP Long-Haul TCP Optimization
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

    sysctl --system >/dev/null 2>&1
    log_info "TCP kernel tuning applied."
}

remove_tcp_tuning() {
    rm -f /etc/sysctl.d/99-frp-tuning.conf
    sysctl --system >/dev/null 2>&1
}

open_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1 || \
        iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1 || true
    fi
}

install_watchdog() {
    log_step "Installing Watchdog for health monitoring..."

    cat > /usr/local/bin/frp-watchdog.sh <<'WATCHDOG_EOF'
#!/bin/bash
LOG_FILE="/var/log/frp-watchdog.log"
MAX_LOG_SIZE=1048576

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

rotate_log() {
    if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt "$MAX_LOG_SIZE" ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
    fi
}

check_admin_api() {
    local port="$1"
    local user="$2"
    local pass="$3"
    curl -sf --max-time 5 -u "${user}:${pass}" "http://127.0.0.1:${port}/api/status" >/dev/null 2>&1
}

check_frps() {
    local fail=0
    if ! pgrep -x "frps" >/dev/null 2>&1; then
        log_msg "WATCHDOG: frps process NOT RUNNING"
        fail=1
    fi
    if ! ss -tlnp 2>/dev/null | grep -q ":${FRP_PORT}"; then
        if ! netstat -tlnp 2>/dev/null | grep -q ":${FRP_PORT}"; then
            log_msg "WATCHDOG: frps NOT LISTENING on port ${FRP_PORT}"
            fail=1
        fi
    fi
    if ! check_admin_api "7500" "admin" "tun100"; then
        log_msg "WATCHDOG: frps admin API not responding"
    fi
    if [ "$fail" -eq 1 ]; then
        log_msg "WATCHDOG: RESTARTING frps@server-${FRP_PORT}..."
        systemctl restart frps@server-${FRP_PORT}.service >/dev/null 2>&1
        sleep 5
        if pgrep -x "frps" >/dev/null 2>&1; then
            log_msg "WATCHDOG: frps restarted OK"
        else
            log_msg "WATCHDOG: CRITICAL - frps restart FAILED"
        fi
    fi
}

check_frpc() {
    local fail=0
    if ! pgrep -x "frpc" >/dev/null 2>&1; then
        log_msg "WATCHDOG: frpc process NOT RUNNING"
        fail=1
    fi
    if ! check_admin_api "7400" "admin" "tun100"; then
        log_msg "WATCHDOG: frpc admin API not responding"
        fail=1
    else
        local status
        status=$(curl -sf --max-time 5 -u "admin:tun100" "http://127.0.0.1:7400/api/status" 2>/dev/null)
        if [ -n "$status" ] && echo "$status" | grep -q '"online":false'; then
            log_msg "WATCHDOG: frpc reports OFFLINE status"
            fail=1
        fi
    fi
    if [ "$fail" -eq 1 ]; then
        log_msg "WATCHDOG: RESTARTING frpc@client-${FRP_PORT}..."
        systemctl restart frpc@client-${FRP_PORT}.service >/dev/null 2>&1
        sleep 10
        if pgrep -x "frpc" >/dev/null 2>&1; then
            log_msg "WATCHDOG: frpc restarted OK"
        else
            log_msg "WATCHDOG: CRITICAL - frpc restart FAILED"
        fi
    fi
}

rotate_log
case "$1" in
    frps) check_frps ;;
    frpc) check_frpc ;;
    *)    log_msg "Usage: $0 {frps|frpc}" ;;
esac
WATCHDOG_EOF

    chmod 755 /usr/local/bin/frp-watchdog.sh

    (crontab -l 2>/dev/null | grep -v 'frp-watchdog' ; \
     echo "* * * * * /usr/local/bin/frp-watchdog.sh frps >/dev/null 2>&1" ; \
     echo "* * * * * /usr/local/bin/frp-watchdog.sh frpc >/dev/null 2>&1") | crontab -

    log_info "Watchdog installed. Health check runs every 60 seconds."
    log_info "Watchdog log: /var/log/frp-watchdog.log"
}

remove_watchdog() {
    rm -f /usr/local/bin/frp-watchdog.sh
    (crontab -l 2>/dev/null | grep -v 'frp-watchdog') | crontab -
    rm -f /var/log/frp-watchdog.log /var/log/frp-watchdog.log.old
}

generate_tcp_proxies() {
    local ports="$1"
    local config_file="$2"
    local IFS=','

    read -ra PORT_ARRAY <<< "$ports"
    for entry in "${PORT_ARRAY[@]}"; do
        entry=$(echo "$entry" | tr -d ' ')
        [ -z "$entry" ] && continue

        if [[ "$entry" == *"-"* ]]; then
            local start=${entry%%-*}
            local end=${entry##*-}
            for ((p=start; p<=end; p++)); do
                cat >> "$config_file" <<PROXY
[[proxies]]
name = "tcp-${p}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
transport.useEncryption = true
transport.useCompression = true

PROXY
            done
        else
            cat >> "$config_file" <<PROXY
[[proxies]]
name = "tcp-${entry}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}
transport.useEncryption = true
transport.useCompression = true

PROXY
        fi
    done
}

generate_udp_proxies() {
    local ports="$1"
    local config_file="$2"
    local IFS=','

    read -ra PORT_ARRAY <<< "$ports"
    for entry in "${PORT_ARRAY[@]}"; do
        entry=$(echo "$entry" | tr -d ' ')
        [ -z "$entry" ] && continue

        if [[ "$entry" == *"-"* ]]; then
            local start=${entry%%-*}
            local end=${entry##*-}
            for ((p=start; p<=end; p++)); do
                cat >> "$config_file" <<PROXY
[[proxies]]
name = "udp-${p}"
type = "udp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
transport.useEncryption = true
transport.useCompression = true

PROXY
            done
        else
            cat >> "$config_file" <<PROXY
[[proxies]]
name = "udp-${entry}"
type = "udp"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}
transport.useEncryption = true
transport.useCompression = true

PROXY
        fi
    done
}

show_menu() {
    clear
    echo "============================================"
    echo "     FRP Iran-Optimized Tunnel Setup        "
    echo "         (frp v${FRP_VERSION})                "
    echo "============================================"
    echo "1) Install FRP Server (frps)"
    echo "2) Install FRP Client (frpc)"
    echo "3) Check Status / Health"
    echo "4) Remove FRP"
    echo "5) Exit"
    echo "============================================"
    read -p "Choose an option [1-5]: " choice
}

install_server() {
    log_step "=== Installing FRP Server (frps) ==="
    log_ir "Iran-optimized: Port 443, HTTP/2 ready, UDP disabled"

    download_frp_binary "frps"
    mkdir -p /root/frp/server /var/log

    open_firewall_port "$FRP_PORT" "tcp"
    open_firewall_port "$ADMIN_PORT_S" "tcp"

    cat > /root/frp/server/server-${FRP_PORT}.toml <<EOF
# FRP Server Configuration - Iran Optimized
# frp v${FRP_VERSION}  |  Port ${FRP_PORT}  |  TCP Only

bindAddr = "::"
bindPort = ${FRP_PORT}
# KCP/UDP disabled - blocked in Iran
kcpBindPort = 0

# Web Dashboard
webServer.addr = "0.0.0.0"
webServer.port = ${ADMIN_PORT_S}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

# Logging
log.to = "/var/log/frps.log"
log.level = "info"
log.maxDays = 30
log.disablePrintColor = true

# Transport - server side
transport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
transport.tcpMux = true
transport.tcpKeepalive = 30

# TLS - force TLS connections
transport.tls.force = true

# Authentication
auth.method = "token"
auth.token = "${FRP_TOKEN}"
EOF

    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frps@server-${FRP_PORT}.service
    systemctl restart frps@server-${FRP_PORT}.service

    tune_tcp_for_frp
    install_watchdog

    sleep 3

    if systemctl is-active --quiet frps@server-${FRP_PORT}.service; then
        log_info "FRP Server installed and running!"
        echo ""
        echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Server Status: RUNNING                              ║${NC}"
        echo -e "${GREEN}║  Bind Port:     ${FRP_PORT} (TCP Only)                      ║${NC}"
        echo -e "${GREEN}║  Dashboard:    http://YOUR_IP:${ADMIN_PORT_S}              ║${NC}"
        echo -e "${GREEN}║  Dashboard PW: ${FRP_TOKEN}                          ║${NC}"
        echo -e "${GREEN}║  Token:        ${FRP_TOKEN}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        log_info "View logs: journalctl -u frps@server-${FRP_PORT} -f"
        log_info "Dashboard: http://YOUR_IP:${ADMIN_PORT_S}"
    else
        log_error "Failed to start server!"
        journalctl -u frps@server-${FRP_PORT} --no-pager -n 20
    fi
}

install_client() {
    log_step "=== Installing FRP Client (frpc) ==="
    log_ir "Iran-optimized: HTTP/2 default, TLS camouflage, proxy support"

    download_frp_binary "frpc"
    mkdir -p /root/frp/client /var/log

    read -p "Enter server address (IP or domain): " server_addr
    while [ -z "$server_addr" ]; do
        log_warn "Server address cannot be empty!"
        read -p "Enter server address: " server_addr
    done

    read -p "Enter inbound ports to forward [default: 8080]: " ports
    ports=${ports:-8080}

    read -p "Also forward UDP ports? (y/n) [default: n]: " forward_udp

    echo ""
    echo "Select connection protocol:"
    echo "  1) http2     - RECOMMENDED: Looks like HTTPS, hardest to block"
    echo "  2) websocket - Good, but easier to fingerprint than http2"
    echo "  3) tcp       - Simplest, no obfuscation (NOT recommended for Iran)"
    echo "  4) kcp       - UDP-based, usually BLOCKED in Iran"
    echo "  5) quic      - UDP-based, usually BLOCKED in Iran"
    read -p "Select [1-5, default 1]: " proto_choice
    proto_choice=${proto_choice:-1}

    local transport_protocol
    local pool_count
    local kcp_config=""
    local iran_warn=""

    case "$proto_choice" in
        3)
            transport_protocol="tcp"
            pool_count=10
            iran_warn="WARNING: Plain TCP is easily detected in Iran. Consider HTTP/2."
            ;;
        4)
            transport_protocol="kcp"
            pool_count=1
            iran_warn="WARNING: KCP uses UDP which is heavily filtered in Iran."
            kcp_config='
# KCP tuning for lossy links
transport.kcp.mtu = 1350
transport.kcp.sndwnd = 128
transport.kcp.rcvwnd = 1024
transport.kcp.datashard = 10
transport.kcp.parityshard = 3
transport.kcp.dscp = 46
'
            ;;
        5)
            transport_protocol="quic"
            pool_count=1
            iran_warn="WARNING: QUIC uses UDP which is heavily filtered in Iran."
            ;;
        2)
            transport_protocol="websocket"
            pool_count=10
            ;;
        *)
            transport_protocol="http2"
            pool_count=10
            ;;
    esac

    if [ -n "$iran_warn" ]; then
        log_warn "$iran_warn"
    fi

    echo ""
    echo "TLS / Domain Fronting Options:"
    echo "  1) Basic TLS (default) - Encrypted but SNI reveals your server IP"
    echo "  2) Domain Fronting     - Fake SNI to a real site (e.g., microsoft.com)"
    echo "  3) Real Domain         - Your own domain with valid certificate"
    read -p "Select [1-3, default 1]: " tls_choice
    tls_choice=${tls_choice:-1}

    local tls_config=""
    local sni_note=""

    case "$tls_choice" in
        2)
            read -p "Enter fake SNI domain [default: www.microsoft.com]: " fake_sni
            fake_sni=${fake_sni:-www.microsoft.com}
            tls_config="transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
transport.tls.serverName = \"${fake_sni}\""
            sni_note="SNI: ${fake_sni} (domain fronting)"
            log_ir "Domain fronting active: SNI will show ${fake_sni}"
            ;;
        3)
            read -p "Enter your real domain: " real_domain
            while [ -z "$real_domain" ]; do
                log_warn "Domain cannot be empty!"
                read -p "Enter your real domain: " real_domain
            done
            tls_config="transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
transport.tls.serverName = \"${real_domain}\""
            sni_note="SNI: ${real_domain} (real domain)"
            ;;
        *)
            tls_config="transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true"
            sni_note="SNI: ${server_addr} (basic TLS)"
            ;;
    esac

    echo ""
    echo "Proxy Chaining (optional):"
    echo "  If you already have a working proxy (Shadowsocks/V2Ray/Xray),"
    echo "  FRP can tunnel through it for extra stability."
    read -p "Use existing proxy? (y/n) [default: n]: " use_proxy

    local proxy_config=""
    if [[ "$use_proxy" =~ ^[Yy]$ ]]; then
        echo "  1) SOCKS5 (e.g., V2Ray/Xray default: 127.0.0.1:10808)"
        echo "  2) HTTP   (e.g., local HTTP proxy)"
        read -p "Select proxy type [1-2, default 1]: " proxy_type
        proxy_type=${proxy_type:-1}
        read -p "Enter proxy address [default: 127.0.0.1:10808]: " proxy_addr
        proxy_addr=${proxy_addr:-127.0.0.1:10808}

        if [ "$proxy_type" = "2" ]; then
            proxy_config="transport.proxyURL = \"http://${proxy_addr}\""
        else
            proxy_config="transport.proxyURL = \"socks5://${proxy_addr}\""
        fi
        log_ir "Proxy chaining enabled: ${proxy_config}"
    fi

    cat > /root/frp/client/client-${FRP_PORT}.toml <<EOF
# FRP Client Configuration - Iran Optimized
# frp v${FRP_VERSION}  |  Protocol: ${transport_protocol}  |  Port: ${FRP_PORT}

serverAddr = "${server_addr}"
serverPort = ${FRP_PORT}

loginFailExit = false

# Admin API (localhost only) - used by watchdog
webServer.addr = "127.0.0.1"
webServer.port = ${ADMIN_PORT_C}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

# Logging
log.to = "/var/log/frpc.log"
log.level = "info"
log.maxDays = 30
log.disablePrintColor = true

# Authentication
auth.method = "token"
auth.token = "${FRP_TOKEN}"

# Protocol
transport.protocol = "${transport_protocol}"
transport.poolCount = ${pool_count}
transport.tcpMux = true
transport.dialServerTimeout = 15
transport.dialServerKeepalive = 30

# Heartbeat - client side only
transport.heartbeatInterval = 15
transport.heartbeatTimeout = 90

# TLS Configuration
${tls_config}

${proxy_config}
${kcp_config}
EOF

    generate_tcp_proxies "$ports" "/root/frp/client/client-${FRP_PORT}.toml"

    if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
        log_warn "Adding UDP forwarding... (may not work in Iran)"
        generate_udp_proxies "$ports" "/root/frp/client/client-${FRP_PORT}.toml"
    fi

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frpc@client-${FRP_PORT}.service
    systemctl restart frpc@client-${FRP_PORT}.service

    tune_tcp_for_frp
    install_watchdog

    log_step "Waiting for connection to establish..."
    sleep 5

    local connected=false
    for i in {1..6}; do
        if pgrep -x "frpc" >/dev/null 2>&1; then
            local status
            status=$(curl -sf --max-time 3 -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
            if [ -n "$status" ]; then
                connected=true
                break
            fi
        fi
        sleep 2
    done

    echo ""
    if [ "$connected" = true ]; then
        log_info "FRP Client installed and connected!"
        echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Client Status: CONNECTED                            ║${NC}"
        echo -e "${GREEN}║  Server:        ${server_addr}:${FRP_PORT}                  ║${NC}"
        echo -e "${GREEN}║  Protocol:     ${transport_protocol}                          ║${NC}"
        echo -e "${GREEN}║  ${sni_note}                    ║${NC}"
        echo -e "${GREEN}║  TCP Ports:    ${ports}                              ║${NC}"
        if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}║  UDP Ports:    ${ports} (also forwarded)              ║${NC}"
        fi
        if [ -n "$proxy_config" ]; then
        echo -e "${GREEN}║  Proxy:        ENABLED                               ║${NC}"
        fi
        echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    else
        log_warn "Connection not yet established. This may take a few seconds."
        echo -e "${YELLOW}Check status: journalctl -u frpc@client-${FRP_PORT} -f${NC}"
    fi

    echo ""
    log_info "View logs: journalctl -u frpc@client-${FRP_PORT} -f"
    log_info "Check status: curl -u admin:${FRP_TOKEN} http://127.0.0.1:${ADMIN_PORT_C}/api/status"
}

check_status() {
    echo "============================================"
    echo "           FRP Health Status                "
    echo "============================================"

    local has_service=false

    if systemctl list-units --type=service | grep -q 'frps@'; then
        has_service=true
        echo ""
        echo "--- FRP Server (frps) ---"
        systemctl status frps@server-${FRP_PORT}.service --no-pager 2>/dev/null || echo "Not installed"

        if [ -f /var/log/frp-watchdog.log ]; then
            echo ""
            echo "--- Recent Watchdog Logs ---"
            tail -n 5 /var/log/frp-watchdog.log 2>/dev/null
        fi
    fi

    if systemctl list-units --type=service | grep -q 'frpc@'; then
        has_service=true
        echo ""
        echo "--- FRP Client (frpc) ---"
        systemctl status frpc@client-${FRP_PORT}.service --no-pager 2>/dev/null || echo "Not installed"

        echo ""
        echo "--- Connection Status ---"
        curl -sf --max-time 3 -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null || echo "Admin API not available (client may be starting)"
    fi

    if [ "$has_service" = false ]; then
        log_warn "No active FRP service found."
    fi

    echo ""
    echo "--- TCP Kernel Settings ---"
    sysctl net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes 2>/dev/null || true
}

remove_frp() {
    log_step "=== Removing FRP ==="

    systemctl stop frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true
    systemctl disable frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
    rm -rf /root/frp
    rm -f /usr/local/bin/frps /usr/local/bin/frpc

    remove_watchdog
    remove_tcp_tuning

    systemctl daemon-reload

    log_info "FRP removed completely."
}

require_root

while true; do
    show_menu
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) check_status ;;
        4) remove_frp ;;
        5) echo "Goodbye!"; exit 0 ;;
        *) log_warn "Invalid option. Please try again." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
