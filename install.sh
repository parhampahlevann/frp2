#!/bin/bash

# FRP Reverse Tunnel Manager - Optimized & Hardened High-Performance Version
# Compatible with standard Bash environments (Ubuntu / Debian / CentOS)

set -uo pipefail

BASE_DIR="/root/frp"
FRP_VERSION="0.58.1"
FRP_SHA256_LINUX_AMD64="5bd9f8860b580ed9c42eed1c99dfaa03b196d0f68007dca088f6c098d498430d"
FRP_SHA256_LINUX_ARM64="25a77f4d7f4c5efeeaa89ed65b951a19014e79baac1efcbd57f0598b3ba95fd7"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root." >&2
        exit 1
    fi
}

gen_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        tr -d '-' < /proc/sys/kernel/random/uuid
    else
        date +%s%N | sha256sum | head -c32
    fi
}

detect_frp_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "linux_amd64" ;;
        aarch64|arm64) echo "linux_arm64" ;;
        *) echo "" ;;
    esac
}

download_frp() {
    local bin_name="$1" arch expected_sha tarball url tmp_dir actual_sha extracted
    arch=$(detect_frp_arch)
    if [[ -z "$arch" ]]; then
        echo "ERROR: Unsupported architecture ($(uname -m))."
        return 1
    fi

    case "$arch" in
        linux_amd64) expected_sha="$FRP_SHA256_LINUX_AMD64" ;;
        linux_arm64) expected_sha="$FRP_SHA256_LINUX_ARM64" ;;
    esac

    tarball="frp_${FRP_VERSION}_${arch}.tar.gz"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${tarball}"
    tmp_dir=$(mktemp -d)

    echo "Downloading official FRP binary (${bin_name} v${FRP_VERSION})..."
    if ! curl -fL --retry 3 --retry-delay 2 -o "$tmp_dir/$tarball" "$url"; then
        echo "ERROR: Download failed."
        rm -rf "$tmp_dir"
        return 1
    fi

    actual_sha=$(sha256sum "$tmp_dir/$tarball" | awk '{print $1}')
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "ERROR: Checksum mismatch. Refusing installation."
        rm -rf "$tmp_dir"
        return 1
    fi

    tar -xzf "$tmp_dir/$tarball" -C "$tmp_dir"
    extracted="$tmp_dir/frp_${FRP_VERSION}_${arch}/${bin_name}"
    if [[ ! -f "$extracted" ]]; then
        echo "ERROR: ${bin_name} not found in archive."
        rm -rf "$tmp_dir"
        return 1
    fi

    install -m 755 "$extracted" "/usr/local/bin/${bin_name}"
    rm -rf "$tmp_dir"
    echo "OK: Verified & installed /usr/local/bin/${bin_name}"
}

port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -qE "(:|\])${port}\b"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -qE "(:|\])${port}\b"
    else
        return 1
    fi
}

open_firewall() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow "${port}/tcp" >/dev/null 2>&1
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

# Solves website rendering issues, half-loaded pages, and TLS handshake timeouts
apply_tcp_mss_clamping() {
    echo "Applying TCP MSS Clamping to fix partial webpage loads..."
    if command -v iptables >/dev/null 2>&1; then
        iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
        iptables -t mangle -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
    fi
}

remove_tcp_mss_clamping() {
    if command -v iptables >/dev/null 2>&1; then
        iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
    fi
}

tune_tcp_stack() {
    echo "Tuning Linux network parameters (BBR, Queue Disciplines & Buffer Sizes)..."
    modprobe tcp_bbr 2>/dev/null || true

    cat > /etc/sysctl.d/99-frp-tuning.conf <<'EOF'
# Network performance tuning for lossy links
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Buffer Optimization (Autotuning with max 64MB)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 10000

# Connection tracking and fast reuse
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# MTU probing to prevent packet stalls over restricted links
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_window_scaling = 1

# Increase ephemeral port range
net.ipv4.ip_local_port_range = 1024 65535
EOF

    if [[ ! -f /etc/modules-load.d/frp-bbr.conf ]]; then
        echo "tcp_bbr" > /etc/modules-load.d/frp-bbr.conf
    fi

    sysctl --system >/dev/null 2>&1
    apply_tcp_mss_clamping
}

setup_watchdog_infra() {
    mkdir -p "$BASE_DIR"

    cat > "$BASE_DIR/watchdog.sh" <<'WDEOF'
#!/bin/bash
ROLE="$1"
BASE_DIR="/root/frp"
LOG="$BASE_DIR/watchdog.log"
INTERVAL=10
FAIL_THRESHOLD=3

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$ROLE] $*" >> "$LOG"; }

port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -qE "(:|\])${port}\b"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -qE "(:|\])${port}\b"
    else
        return 1
    fi
}

if [[ "$ROLE" == "server" ]]; then
    META="$BASE_DIR/server/meta.env"
    SERVICE="frps"
elif [[ "$ROLE" == "client" ]]; then
    META="$BASE_DIR/client/meta.env"
    SERVICE="frpc"
else
    exit 1
fi

[[ ! -f "$META" ]] && exit 1
# shellcheck disable=SC1090
source "$META"

fail_count=0

while true; do
    healthy=true
    reason=""

    if ! systemctl is-active --quiet "${SERVICE}@${INSTANCE}.service"; then
        healthy=false
        reason="service not active"
    elif [[ "$ROLE" == "server" ]]; then
        if ! port_listening "$PORT"; then
            healthy=false
            reason="not listening on bind port ${PORT}"
        fi
    elif [[ "$ROLE" == "client" ]]; then
        # Check client local admin port to ensure engine is responding
        if ! port_listening 7400; then
            healthy=false
            reason="frpc internal engine unresponsive"
        fi
    fi

    if $healthy; then
        fail_count=0
    else
        fail_count=$((fail_count + 1))
        log "Health check failed: $reason (attempt $fail_count/$FAIL_THRESHOLD)"
        if (( fail_count >= FAIL_THRESHOLD )); then
            log "Initiating fast-recovery restart of ${SERVICE}@${INSTANCE}.service"
            systemctl restart "${SERVICE}@${INSTANCE}.service"
            fail_count=0
            sleep 8
        fi
    fi

    sleep "$INTERVAL"
done
WDEOF
    chmod +x "$BASE_DIR/watchdog.sh"

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP Auto-Recovery Watchdog (%i)
After=network.target

[Service]
Type=simple
ExecStart=/root/frp/watchdog.sh %i
Restart=always
RestartSec=3s
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

enable_watchdog() {
    local role="$1"
    systemctl enable "frp-watchdog@${role}.service" >/dev/null 2>&1
    systemctl restart "frp-watchdog@${role}.service"
}

install_server() {
    echo "=== Installing FRP Server (frps) on Iran ==="
    mkdir -p "$BASE_DIR/server"

    tune_tcp_stack
    download_frp frps || return 1

    local token admin_pass
    token=$(gen_secret)
    admin_pass=$(gen_secret)

    cat > "$BASE_DIR/server/server-3090.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = 3090

# Performance & Multiplexing
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 15
transport.tcpKeepalive = 30
transport.heartbeatTimeout = 60
transport.maxPoolCount = 100
transport.tls.force = true

auth.method = "token"
auth.token = "$token"

# Admin Dashboard
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "$admin_pass"

log.level = "error"
EOF
    chmod 600 "$BASE_DIR/server/server-3090.toml"

    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3s
StartLimitIntervalSec=0
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frps@server-3090.service >/dev/null 2>&1
    systemctl restart frps@server-3090.service
    sleep 1

    if ! systemctl is-active --quiet frps@server-3090.service; then
        echo "ERROR: frps failed to start."
        journalctl -u frps@server-3090.service -n 20 --no-pager
        return 1
    fi

    cat > "$BASE_DIR/server/meta.env" <<EOF
PORT=3090
INSTANCE=server-3090
TOKEN=$token
EOF
    chmod 600 "$BASE_DIR/server/meta.env"

    open_firewall 3090
    setup_watchdog_infra
    enable_watchdog server

    echo
    echo "=================================================="
    echo " FRP Server is successfully running on port 3090"
    echo " TOKEN (Required on Kharej Client):"
    echo
    echo "    $token"
    echo "=================================================="
}

install_client() {
    echo "=== Installing FRP Client (frpc) on Kharej ==="
    mkdir -p "$BASE_DIR/client"

    tune_tcp_stack
    download_frp frpc || return 1

    local server_addr ports token
    read -p "Enter Iran Server IP: " server_addr
    while [[ -z "$server_addr" ]]; do
        read -p "Server IP cannot be empty: " server_addr
    done

    read -p "Enter Token: " token
    while [[ -z "$token" ]]; do
        read -p "Token cannot be empty: " token
    done

    read -p "Enter Forward Ports [default: 8080]: " ports
    ports=${ports:-8080}

    local escaped_ports admin_pass
    escaped_ports=$(printf '%s' "$ports" | sed 's/"/\\"/g')
    admin_pass=$(gen_secret)

    cat > "$BASE_DIR/client/client-3090.toml" <<EOF
serverAddr = "$server_addr"
serverPort = 3090
loginFailExit = false

auth.method = "token"
auth.token = "$token"

# TCP Link Tuning
transport.protocol = "tcp"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 15
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 30
transport.poolCount = 10
transport.heartbeatInterval = 20
transport.heartbeatTimeout = 60
transport.tls.enable = true

webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "$admin_pass"

log.level = "error"

{{- range \$_, \$v := parseNumberRangePair "$escaped_ports" "$escaped_ports" }}
[[proxies]]
name = "tcp-{{ \$v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = true
transport.useCompression = true
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 2
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10
{{- end }}
EOF
    chmod 600 "$BASE_DIR/client/client-3090.toml"

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3s
StartLimitIntervalSec=0
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frpc@client-3090.service >/dev/null 2>&1
    systemctl restart frpc@client-3090.service
    sleep 1

    if ! systemctl is-active --quiet frpc@client-3090.service; then
        echo "ERROR: frpc failed to start."
        journalctl -u frpc@client-3090.service -n 20 --no-pager
        return 1
    fi

    cat > "$BASE_DIR/client/meta.env" <<EOF
INSTANCE=client-3090
SERVER_ADDR=$server_addr
SERVER_PORT=3090
PORTS="$ports"
EOF
    chmod 600 "$BASE_DIR/client/meta.env"

    setup_watchdog_infra
    enable_watchdog client

    echo
    echo "FRP Client installed and tunnel is online."
    echo "Target Server: $server_addr:3090"
    echo "Forwarding Ports: $ports"
}

show_status() {
    clear
    echo "=================================="
    echo "       FRP Tunnel Status          "
    echo "=================================="

    local found=false

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        found=true
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        echo
        echo "-- Iran Server (frps) [${INSTANCE}] --"
        systemctl is-active --quiet "frps@${INSTANCE}.service" && echo "  Service:   ACTIVE" || echo "  Service:   FAILED"
        port_listening "$PORT" && echo "  Bind Port ($PORT): LISTENING" || echo "  Bind Port ($PORT): NOT LISTENING"
        systemctl is-active --quiet "frp-watchdog@server.service" && echo "  Watchdog:  ACTIVE" || echo "  Watchdog:  INACTIVE"
    fi

    if [[ -f "$BASE_DIR/client/meta.env" ]]; then
        found=true
        # shellcheck disable=SC1090
        source "$BASE_DIR/client/meta.env"
        echo
        echo "-- Kharej Client (frpc) [${INSTANCE}] --"
        systemctl is-active --quiet "frpc@${INSTANCE}.service" && echo "  Service:   ACTIVE" || echo "  Service:   FAILED"
        systemctl is-active --quiet "frp-watchdog@client.service" && echo "  Watchdog:  ACTIVE" || echo "  Watchdog:  INACTIVE"
    fi

    if ! $found; then
        echo
        echo "No FRP installation detected on this machine."
    fi

    if [[ -f "$BASE_DIR/watchdog.log" ]]; then
        echo
        echo "-- Recent Watchdog Events --"
        tail -n 6 "$BASE_DIR/watchdog.log" | sed 's/^/  /'
    fi
}

remove_frp() {
    echo "=== Full FRP Cleanup ==="
    read -p "Are you sure you want to completely uninstall FRP? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        return
    fi

    systemctl stop frps@server-3090.service frpc@client-3090.service \
        frp-watchdog@server.service frp-watchdog@client.service 2>/dev/null || true
    systemctl disable frps@server-3090.service frpc@client-3090.service \
        frp-watchdog@server.service frp-watchdog@client.service 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service \
          /etc/systemd/system/frp-watchdog@.service
    systemctl daemon-reload

    remove_tcp_mss_clamping

    rm -rf "$BASE_DIR"
    rm -f /usr/local/bin/frps /usr/local/bin/frpc

    if [[ -f /etc/sysctl.d/99-frp-tuning.conf ]]; then
        rm -f /etc/sysctl.d/99-frp-tuning.conf /etc/modules-load.d/frp-bbr.conf
        sysctl --system >/dev/null 2>&1
    fi

    echo "FRP and its configurations have been removed."
}

press_enter() {
    echo
    read -p "Press Enter to return to menu..." _
}

show_menu() {
    clear
    echo "=================================="
    echo "     FRP Reverse Tunnel Pro       "
    echo "=================================="
    echo "1) Install FRP Server (Iran)"
    echo "2) Install FRP Client (Kharej)"
    echo "3) Show Status"
    echo "4) Uninstall"
    echo "5) Exit"
    echo "=================================="
    read -p "Selection [1-5]: " choice
}

check_root

while true; do
    show_menu
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) show_status ;;
        4) remove_frp ;;
        5) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
    press_enter
done
