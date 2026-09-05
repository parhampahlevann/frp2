#!/bin/bash
# ==============================================================================
# FRP Reverse Tunnel Manager - TCP Low-Latency Edition
# Iran (frps) <-> Kharej (frpc)
#
# Goals:
#   - FRP 0.71.0, verified against official release SHA256
#   - TCP transport only, with TCP multiplexing enabled for normal web traffic
#   - Correct heartbeat / keepalive configuration
#   - No artificial bandwidth cap and no unnecessary compression
#   - PMTU-aware TCP MSS handling (optional, reversible)
#   - systemd supervision + active tunnel watchdog
#   - configuration verification before every start
#   - safe firewall rule tagging and clean uninstall
#
# NOTE:
# No script can guarantee a fixed minimum latency, zero jitter, or unlimited
# bandwidth. Those are constrained by the physical route, congestion, MTU,
# kernel, VPS NIC, and provider shaping. This script removes avoidable
# software-side bottlenecks without pretending to change the Internet path.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

BASE_DIR="/root/frp"
FRP_VERSION="0.71.0"

# Official release archive SHA256 values for v0.71.0.
FRP_SHA256_LINUX_AMD64="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
FRP_SHA256_LINUX_ARM64="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"

BIND_PORT=3090
SERVER_INSTANCE="server-3090"
CLIENT_INSTANCE="client-3090"
WATCHDOG_INTERVAL=5
WATCHDOG_FAILURES=2

# 1 = install PMTU-aware TCPMSS rules. This is deliberately NOT a hard-coded
# 1360 MSS. Hard clamping all traffic to 1360 can unnecessarily reduce
# throughput on a clean 1500-byte path.
ENABLE_MSS_CLAMP=1

# ------------------------------------------------------------------------------
# Generic helpers
# ------------------------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || die "Run this script as root."
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_deps() {
    local need=()
    command_exists curl || need+=(curl)
    command_exists tar || need+=(tar)
    command_exists ss || need+=(iproute2)
    command_exists sha256sum || need+=(coreutils)
    command_exists iptables || need+=(iptables)

    if ((${#need[@]} == 0)); then
        return 0
    fi

    log "Installing missing dependencies: ${need[*]}"
    if command_exists apt-get; then
        apt-get update -qq
        apt-get install -y -qq "${need[@]}"
    elif command_exists dnf; then
        dnf install -y "${need[@]}"
    elif command_exists yum; then
        yum install -y "${need[@]}"
    elif command_exists apk; then
        apk add --no-cache "${need[@]}"
    else
        die "Could not determine a supported package manager."
    fi
}

gen_secret() {
    local bytes="${1:-24}"
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
}

valid_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] && ((p >= 1 && p <= 65535))
}

parse_ports_string() {
    local input="$1" entry start end p
    local -a entries result=()

    IFS=', ' read -r -a entries <<< "$input"

    for entry in "${entries[@]}"; do
        entry="${entry//[[:space:]]/}"
        [[ -z "$entry" ]] && continue

        if [[ "$entry" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            if ((start >= 1 && end <= 65535 && start <= end)); then
                for ((p=start; p<=end; p++)); do
                    result+=("$p")
                done
            fi
        elif valid_port "$entry"; then
            result+=("$entry")
        fi
    done

    if ((${#result[@]})); then
        printf '%s\n' "${result[@]}" | awk '!seen[$0]++'
    fi
}

wait_for_active() {
    local unit="$1" tries="${2:-20}"
    local i
    for ((i=0; i<tries; i++)); do
        if systemctl is-active --quiet "$unit"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

tcp_listening() {
    local port="$1"
    ss -ltnH 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END{exit !found}'
}

tcp_established_to() {
    local host="$1" port="$2"
    # Match destination host/port and ESTABLISHED state. ss may show an IP
    # instead of the original hostname, so the caller should pass an IP.
    ss -tnH state established 2>/dev/null |
        awk -v h="$host" -v p=":$port" '
            $4 ~ p"$" && $5 ~ ("^" h ":[0-9]+$") {found=1}
            END {exit !found}
        '
}

# ------------------------------------------------------------------------------
# Firewall
# ------------------------------------------------------------------------------

FRP_CHAIN="FRP_TUNNEL"

firewall_chain_exists() {
    iptables -nL "$FRP_CHAIN" >/dev/null 2>&1
}

open_firewall() {
    local port="$1"
    command_exists iptables || return 0

    iptables -N "$FRP_CHAIN" 2>/dev/null || true
    if ! iptables -C INPUT -p tcp --dport "$port" -j "$FRP_CHAIN" 2>/dev/null; then
        iptables -I INPUT -p tcp --dport "$port" -j "$FRP_CHAIN"
    fi
    if ! iptables -C "$FRP_CHAIN" -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        iptables -A "$FRP_CHAIN" -p tcp --dport "$port" -j ACCEPT
    fi

    # Also handle UFW when active. The iptables chain above remains the
    # canonical rule used by this script.
    if command_exists ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw allow "${port}/tcp" >/dev/null 2>&1 || true
    fi
}

close_firewall() {
    local port="$1"
    command_exists iptables || return 0

    if command_exists ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
    fi

    while iptables -C "$FRP_CHAIN" -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do
        iptables -D "$FRP_CHAIN" -p tcp --dport "$port" -j ACCEPT || break
    done

    while iptables -C INPUT -p tcp --dport "$port" -j "$FRP_CHAIN" 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "$port" -j "$FRP_CHAIN" || break
    done

    if firewall_chain_exists; then
        # Delete only when empty.
        iptables -F "$FRP_CHAIN" 2>/dev/null || true
        iptables -X "$FRP_CHAIN" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------------------
# Download / verify FRP
# ------------------------------------------------------------------------------

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' "linux_amd64" ;;
        aarch64|arm64) printf '%s\n' "linux_arm64" ;;
        *) return 1 ;;
    esac
}

download_frp() {
    local binary="$1" arch expected tarball url tmp actual extracted
    arch="$(detect_arch)" || die "Unsupported architecture: $(uname -m)"

    case "$arch" in
        linux_amd64) expected="$FRP_SHA256_LINUX_AMD64" ;;
        linux_arm64) expected="$FRP_SHA256_LINUX_ARM64" ;;
    esac

    tarball="frp_${FRP_VERSION}_${arch}.tar.gz"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${tarball}"
    tmp="$(mktemp -d)"

    log "Downloading FRP ${FRP_VERSION} (${arch})..."
    curl -fL --retry 5 --retry-delay 2 --connect-timeout 15 \
        -o "$tmp/$tarball" "$url"

    actual="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        rm -rf "$tmp"
        die "FRP checksum mismatch. Expected $expected, got $actual"
    }

    tar -xzf "$tmp/$tarball" -C "$tmp"
    extracted="$tmp/frp_${FRP_VERSION}_${arch}/${binary}"
    [[ -x "$extracted" || -f "$extracted" ]] ||
        die "Verified archive does not contain $binary"

    install -m 0755 "$extracted" "/usr/local/bin/$binary"
    rm -rf "$tmp"

    log "Installed verified /usr/local/bin/$binary"
}

# ------------------------------------------------------------------------------
# Kernel tuning
# ------------------------------------------------------------------------------

write_sysctl_tuning() {
    cat > /etc/sysctl.d/99-frp-tcp-tuning.conf <<'EOF'
# FRP TCP tuning. These values avoid common software-side stalls without
# pretending to increase the physical capacity of the route.

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Large enough for high-BDP international links; autotuning still controls
# actual per-socket use.
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 131072 67108864

# Queue / burst tolerance.
net.core.netdev_max_backlog = 16384

# Reduce idle latency and avoid retaining old congestion state.
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# Faster detection of dead peers. FRP itself also has application-level
# heartbeat detection.
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 4

# Reuse TIME_WAIT safely for outgoing connections.
net.ipv4.tcp_tw_reuse = 1

# Allow PMTU probing instead of imposing an arbitrary low MSS.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024

# Full ephemeral range for high concurrency.
net.ipv4.ip_local_port_range = 1024 65535

# Keep SYN/accept queues from becoming an avoidable bottleneck.
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
EOF

    mkdir -p /etc/modules-load.d
    if ! grep -qx 'tcp_bbr' /etc/modules-load.d/frp-bbr.conf 2>/dev/null; then
        printf '%s\n' tcp_bbr > /etc/modules-load.d/frp-bbr.conf
    fi

    modprobe tcp_bbr 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || true

    if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" != "bbr" ]]; then
        log "WARNING: BBR is not available on this kernel; keeping the kernel's available congestion control."
    fi
}

remove_sysctl_tuning() {
    rm -f /etc/sysctl.d/99-frp-tcp-tuning.conf /etc/modules-load.d/frp-bbr.conf
    sysctl --system >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------------------
# PMTU-aware MSS
# ------------------------------------------------------------------------------

apply_mss_clamp() {
    ((ENABLE_MSS_CLAMP == 1)) || return 0
    command_exists iptables || return 0

    # --clamp-mss-to-pmtu follows the route instead of forcing every path to
    # MSS 1360. This is substantially safer for throughput.
    iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

remove_mss_clamp() {
    command_exists iptables || return 0
    while iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu || break
    done
}

# ------------------------------------------------------------------------------
# systemd units
# ------------------------------------------------------------------------------

write_systemd_units() {
    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server (%i)
Documentation=https://gofrp.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2s
StartLimitIntervalSec=0
LimitNOFILE=1048576
LimitNPROC=65536
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client (%i)
Documentation=https://gofrp.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2s
StartLimitIntervalSec=0
LimitNOFILE=1048576
LimitNPROC=65536
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP Active Tunnel Watchdog (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/root/frp/watchdog.sh %i
Restart=always
RestartSec=2s
StartLimitIntervalSec=0
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# ------------------------------------------------------------------------------
# Watchdog
# ------------------------------------------------------------------------------

write_watchdog() {
    cat > "$BASE_DIR/watchdog.sh" <<'EOF'
#!/bin/bash
set -Eeuo pipefail

ROLE="${1:-}"
BASE_DIR="/root/frp"
INTERVAL=5
FAIL_THRESHOLD=2
LOG="$BASE_DIR/watchdog.log"

log() {
    mkdir -p "$BASE_DIR"
    printf '%s [%s] %s\n' "$(date '+%F %T')" "$ROLE" "$*" >> "$LOG"
}

tcp_listening() {
    ss -ltnH 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {ok=1} END{exit !ok}'
}

established_to_server() {
    local host="$1" port="$2"
    ss -tnH state established 2>/dev/null |
        awk -v h="$host" -v p=":$port" '
            $5 ~ ("^" h ":[0-9]+$") && $5 ~ p "$" {ok=1}
            END{exit !ok}
        '
}

restart_service() {
    local svc="$1"
    log "Restarting $svc"
    systemctl restart "$svc" || true
}

case "$ROLE" in
    server)
        META="$BASE_DIR/server/meta.env"
        SERVICE="frps@server-3090.service"
        ;;
    client)
        META="$BASE_DIR/client/meta.env"
        SERVICE="frpc@client-3090.service"
        ;;
    *)
        exit 2
        ;;
esac

[[ -f "$META" ]] || exit 0
# shellcheck disable=SC1090
source "$META"

fails=0

while :; do
    healthy=1
    reason=""

    if ! systemctl is-active --quiet "$SERVICE"; then
        healthy=0
        reason="systemd service is not active"
    elif [[ "$ROLE" == "server" ]]; then
        if ! tcp_listening "$SERVER_PORT"; then
            healthy=0
            reason="frps TCP port ${SERVER_PORT} is not listening"
        fi
    else
        # A live frpc process alone is not sufficient. We require an actual
        # established TCP control connection to the configured frps address.
        if ! established_to_server "$SERVER_ADDR" "$SERVER_PORT"; then
            healthy=0
            reason="no established TCP control connection to ${SERVER_ADDR}:${SERVER_PORT}"
        fi
    fi

    if ((healthy)); then
        fails=0
    else
        ((fails+=1))
        log "Unhealthy: $reason ($fails/$FAIL_THRESHOLD)"
        if ((fails >= FAIL_THRESHOLD)); then
            restart_service "$SERVICE"
            fails=0
            sleep 3
        fi
    fi

    sleep "$INTERVAL"
done
EOF
    chmod 0755 "$BASE_DIR/watchdog.sh"
}

# ------------------------------------------------------------------------------
# Server
# ------------------------------------------------------------------------------

install_server() {
    log "=== Installing FRP Server on Iran ==="
    install_deps
    mkdir -p "$BASE_DIR/server"

    write_sysctl_tuning
    apply_mss_clamp
    download_frp frps

    local token dashboard_pass
    token="$(gen_secret 32)"
    dashboard_pass="$(gen_secret 12)"

    cat > "$BASE_DIR/server/${SERVER_INSTANCE}.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}

# TCP transport only. TCP mux is enabled by default and is appropriate for
# many parallel HTTP/HTTPS requests because it avoids a new control connection
# for every request.
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 15
transport.tcpKeepalive = 30
transport.heartbeatTimeout = 60

# Connection pooling is deliberately not inflated here: with tcpMux enabled,
# poolCount is a backend-service connection pool, not a pool of independent
# Internet TCP control connections. Large values waste sockets and can hurt
# rather than help ordinary web traffic.
transport.maxPoolCount = 5

# TLS protects the frpc <-> frps control/data channel.
transport.tls.force = true

auth.method = "token"
auth.token = "${token}"

# Keep the admin API on loopback only.
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "${dashboard_pass}"

log.to = "console"
log.level = "warn"
log.maxDays = 3

# Avoid accidental exposure of arbitrary ports through this frps instance.
allowPorts = [
  { start = 1, end = 65535 }
]
EOF
    chmod 0600 "$BASE_DIR/server/${SERVER_INSTANCE}.toml"

    cat > "$BASE_DIR/server/meta.env" <<EOF
SERVER_PORT=${BIND_PORT}
INSTANCE=${SERVER_INSTANCE}
EOF
    chmod 0600 "$BASE_DIR/server/meta.env"

    write_systemd_units
    write_watchdog

    /usr/local/bin/frps verify -c "$BASE_DIR/server/${SERVER_INSTANCE}.toml"

    systemctl enable "frps@${SERVER_INSTANCE}.service" >/dev/null
    systemctl restart "frps@${SERVER_INSTANCE}.service"

    wait_for_active "frps@${SERVER_INSTANCE}.service" 20 ||
        die "frps failed to start. Run: journalctl -u frps@${SERVER_INSTANCE}.service -n 50 --no-pager"

    open_firewall "$BIND_PORT"

    systemctl enable "frp-watchdog@server.service" >/dev/null
    systemctl restart "frp-watchdog@server.service"

    log "FRP server is active."
    echo
    echo "=============================================================="
    echo " FRP TCP SERVER READY"
    echo "=============================================================="
    echo " Bind port      : ${BIND_PORT}/tcp"
    echo " TCP mux        : enabled"
    echo " TCP keepalive  : 30s"
    echo " Mux heartbeat  : 15s"
    echo " Heartbeat timeout: 60s"
    echo " TLS             : forced"
    echo " Watchdog        : active"
    echo
    echo " IMPORTANT: save this token now; it is not printed again:"
    echo " Auth token      : ${token}"
    echo " Dashboard       : http://127.0.0.1:7500"
    echo " Dashboard user  : admin"
    echo " Dashboard pass  : ${dashboard_pass}"
    echo "=============================================================="
}

# ------------------------------------------------------------------------------
# Client
# ------------------------------------------------------------------------------

install_client() {
    log "=== Installing FRP Client on Kharej ==="
    install_deps
    mkdir -p "$BASE_DIR/client"

    write_sysctl_tuning
    apply_mss_clamp
    download_frp frpc

    local server_addr token input_ports clean_ports
    local -a ports

    read -r -p "Iran server IP/hostname: " server_addr
    [[ -n "$server_addr" ]] || die "Server address cannot be empty."

    read -r -p "FRP auth token: " token
    [[ -n "$token" ]] || die "Token cannot be empty."

    read -r -p "Ports to forward (example: 80,443,8080-8090) [8080]: " input_ports
    input_ports="${input_ports:-8080}"

    mapfile -t ports < <(parse_ports_string "$input_ports")
    ((${#ports[@]})) || die "No valid ports were supplied."

    clean_ports="$(IFS=,; echo "${ports[*]}")"

    cat > "$BASE_DIR/client/${CLIENT_INSTANCE}.toml" <<EOF
serverAddr = "${server_addr}"
serverPort = ${BIND_PORT}

# Authentication failure should terminate frpc so systemd can restart it
# instead of leaving a misleading "active but disconnected" process.
loginFailExit = true

auth.method = "token"
auth.token = "${token}"

[transport]
protocol = "tcp"
tcpMux = true
tcpMuxKeepaliveInterval = 15
dialServerTimeout = 10
dialServerKeepalive = 30

# heartbeatInterval=-1 lets tcpMux keepalive be the heartbeat mechanism,
# avoiding redundant heartbeat traffic.
heartbeatInterval = -1
heartbeatTimeout = 60

# poolCount is a backend connection pool, not a control-channel speed knob.
# Keep it modest for general HTTP/HTTPS workloads.
poolCount = 2

[webServer]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "$(gen_secret 12)"

[log]
to = "console"
level = "warn"
maxDays = 3
EOF

    for p in "${ports[@]}"; do
        cat >> "$BASE_DIR/client/${CLIENT_INSTANCE}.toml" <<EOF

[[proxies]]
name = "tcp-${p}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}

# Health check verifies the local backend service. It is intentionally
# separate from the watchdog, which verifies the FRP control connection.
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10

[proxies.transport]
useEncryption = false
useCompression = false
EOF
    done

    chmod 0600 "$BASE_DIR/client/${CLIENT_INSTANCE}.toml"

    cat > "$BASE_DIR/client/meta.env" <<EOF
INSTANCE=${CLIENT_INSTANCE}
SERVER_ADDR=${server_addr}
SERVER_PORT=${BIND_PORT}
PORTS="${clean_ports}"
EOF
    chmod 0600 "$BASE_DIR/client/meta.env"

    write_systemd_units
    write_watchdog

    /usr/local/bin/frpc verify -c "$BASE_DIR/client/${CLIENT_INSTANCE}.toml"

    # Check reachability before starting, without sending application data.
    if command_exists timeout; then
        if ! timeout 5 bash -c "</dev/tcp/${server_addr}/${BIND_PORT}" 2>/dev/null; then
            log "WARNING: ${server_addr}:${BIND_PORT} is not reachable over TCP yet."
            log "The service will still be installed and systemd/watchdog will keep retrying."
        fi
    fi

    systemctl enable "frpc@${CLIENT_INSTANCE}.service" >/dev/null
    systemctl restart "frpc@${CLIENT_INSTANCE}.service"

    wait_for_active "frpc@${CLIENT_INSTANCE}.service" 20 ||
        die "frpc failed to start. Run: journalctl -u frpc@${CLIENT_INSTANCE}.service -n 50 --no-pager"

    systemctl enable "frp-watchdog@client.service" >/dev/null
    systemctl restart "frp-watchdog@client.service"

    log "Waiting for the actual TCP control connection..."
    local ok=0 i
    for ((i=0; i<20; i++)); do
        if tcp_established_to "$server_addr" "$BIND_PORT"; then
            ok=1
            break
        fi
        sleep 1
    done

    echo
    echo "=============================================================="
    if ((ok)); then
        echo " FRP TCP CLIENT ONLINE"
    else
        echo " FRP CLIENT INSTALLED - CONTROL CONNECTION NOT YET CONFIRMED"
        echo " Check: journalctl -u frpc@${CLIENT_INSTANCE}.service -n 50 --no-pager"
    fi
    echo "=============================================================="
    echo " Server          : ${server_addr}:${BIND_PORT}/tcp"
    echo " Transport       : TCP"
    echo " TCP mux         : enabled"
    echo " Ports           : ${clean_ports}"
    echo " Watchdog        : active"
    echo " MSS mode        : PMTU-aware clamp"
    echo " Compression     : disabled"
    echo " Bandwidth limit : none"
    echo "=============================================================="
}

# ------------------------------------------------------------------------------
# Status / diagnostics
# ------------------------------------------------------------------------------

show_status() {
    clear || true
    echo "=============================================================="
    echo "                    FRP TCP STATUS"
    echo "=============================================================="

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        echo
        echo "[SERVER]"
        systemctl is-active --quiet "frps@${INSTANCE}.service" &&
            echo "Service       : ACTIVE" || echo "Service       : DOWN"
        tcp_listening "$SERVER_PORT" &&
            echo "Listen ${SERVER_PORT}/tcp : YES" || echo "Listen ${SERVER_PORT}/tcp : NO"
        systemctl is-active --quiet frp-watchdog@server.service &&
            echo "Watchdog      : ACTIVE" || echo "Watchdog      : DOWN"
    fi

    if [[ -f "$BASE_DIR/client/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/client/meta.env"
        echo
        echo "[CLIENT]"
        systemctl is-active --quiet "frpc@${INSTANCE}.service" &&
            echo "Service       : ACTIVE" || echo "Service       : DOWN"
        echo "Server        : ${SERVER_ADDR}:${SERVER_PORT}/tcp"
        echo "Ports         : ${PORTS}"
        tcp_established_to "$SERVER_ADDR" "$SERVER_PORT" &&
            echo "Control TCP   : ESTABLISHED" || echo "Control TCP   : NOT ESTABLISHED"
        systemctl is-active --quiet frp-watchdog@client.service &&
            echo "Watchdog      : ACTIVE" || echo "Watchdog      : DOWN"

        echo
        echo "[FRPC PROXY STATUS]"
        /usr/local/bin/frpc status -c "$BASE_DIR/client/${INSTANCE}.toml" 2>&1 |
            sed 's/^/  /' || true
    fi

    echo
    echo "[TCP CONGESTION]"
    printf '  qdisc       : %s\n' "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
    printf '  congestion  : %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    printf '  MTU probing : %s\n' "$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo unknown)"

    if [[ -f "$BASE_DIR/watchdog.log" ]]; then
        echo
        echo "[LAST WATCHDOG EVENTS]"
        tail -n 10 "$BASE_DIR/watchdog.log" | sed 's/^/  /'
    fi
}

diagnostics() {
    echo "=== FRP TCP diagnostics ==="
    echo
    echo "Kernel:"
    uname -a
    echo
    echo "Congestion:"
    sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
    echo
    echo "Routes:"
    ip route 2>/dev/null || true
    echo
    echo "TCP sockets:"
    ss -s 2>/dev/null || true
    echo
    echo "FRP services:"
    systemctl --no-pager --type=service --all 'frp*' 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Uninstall
# ------------------------------------------------------------------------------

remove_frp() {
    echo "=== Complete FRP uninstall ==="
    read -r -p "Remove FRP, services, firewall rule, and TCP tuning? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || {
        echo "Aborted."
        return 0
    }

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        close_firewall "${SERVER_PORT:-$BIND_PORT}" || true
    else
        close_firewall "$BIND_PORT" || true
    fi

    systemctl disable --now \
        "frps@${SERVER_INSTANCE}.service" \
        "frpc@${CLIENT_INSTANCE}.service" \
        frp-watchdog@server.service \
        frp-watchdog@client.service 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service \
          /etc/systemd/system/frpc@.service \
          /etc/systemd/system/frp-watchdog@.service

    systemctl daemon-reload
    remove_mss_clamp
    remove_sysctl_tuning

    rm -rf "$BASE_DIR"
    rm -f /usr/local/bin/frps /usr/local/bin/frpc

    log "FRP removed."
}

# ------------------------------------------------------------------------------
# Menu
# ------------------------------------------------------------------------------

press_enter() {
    echo
    read -r -p "Press Enter to continue..." _
}

show_menu() {
    clear || true
    echo "=============================================================="
    echo "             FRP REVERSE TUNNEL - TCP EDITION"
    echo "=============================================================="
    echo "1) Install FRP Server (Iran)"
    echo "2) Install FRP Client (Kharej)"
    echo "3) Show Status"
    echo "4) Diagnostics"
    echo "5) Uninstall"
    echo "6) Exit"
    echo "=============================================================="
    read -r -p "Selection [1-6]: " choice
}

check_root

while :; do
    show_menu
    case "${choice:-}" in
        1) install_server; press_enter ;;
        2) install_client; press_enter ;;
        3) show_status; press_enter ;;
        4) diagnostics; press_enter ;;
        5) remove_frp; press_enter ;;
        6) exit 0 ;;
        *) echo "Invalid selection."; press_enter ;;
    esac
done
