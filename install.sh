#!/bin/bash
set -o pipefail

###############################################################################
# FRP Iran-Optimized Tunnel -- TCP-ONLY STABLE EDITION (frp v0.71.0)
# FIXES APPLIED:
# 1. REMOVED: wss, websocket, kcp, quic — only TCP remains (avoids UDP blocks)
# 2. FIXED: PMTU/MSS black holes causing "some websites don't load"
#    - Added iptables TCPMSS clamping on the tunnel interface
#    - tcp_mtu_probing=2 (aggressive, not just 1)
#    - Disabled TCP slow-start-after-idle (prevents stalls)
# 3. FIXED: TCP buffer bloat / window scaling issues
#    - Proper rmem/wmem values for high-latency paths
#    - tcp_adv_win_scale adjusted
# 4. FIXED: Connection tracking timeout mismatch (idle tunnel drops)
# 5. FIXED: systemd start-limit storms and watchdog false-positives
# 6. FIXED: TLS handshake issues — optional real cert, no fake SNI
###############################################################################

FRP_VERSION="0.71.0"
FRP_TOKEN="tun100"
FRP_PORT="8443"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"

--- Stability knobs -------------------------------------------------------
TCP_MUX="true"
MUX_KEEPALIVE="20"
HB_INTERVAL="15"
HB_TIMEOUT_C="60"
HB_TIMEOUT_S="120"
DIAL_TIMEOUT="15"
DIAL_KEEPALIVE="15"
USER_CONN_TIMEOUT="30"        # increased for high-latency Iran links
ADMIN_BIND_S="0.0.0.0"

WD_FAIL_THRESHOLD="5"
WD_COOLDOWN="600"
WD_GRACE="120"

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

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_ok() { echo -e "${CYAN}[OK]${NC} $1"; }
log_ir() { echo -e "${MAGENTA}[IRAN]${NC} $1"; }
log_perf() { echo -e "${CYAN}[PERF]${NC} $1"; }

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

###############################################################################
# Kernel tuning -- TCP-ONLY + PMTU FIX EDITION
###############################################################################
tune_tcp_for_frp() {
    log_step "Applying TCP kernel tuning for tunnel stability..."

    local cc_line="net.ipv4.tcp_congestion_control = cubic"
    local qdisc_line="# net.core.default_qdisc = fq (bbr unavailable, staying on cubic)"

    modprobe tcp_bbr >/dev/null 2>&1 || true
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        cc_line="net.ipv4.tcp_congestion_control = bbr"
        qdisc_line="net.core.default_qdisc = fq"
        log_perf "BBR congestion control available, enabling it."
    else
        log_warn "BBR module not available on this kernel, staying on cubic."
    fi

    modprobe nf_conntrack >/dev/null 2>&1 || true
    local conntrack_block="# nf_conntrack module not loaded, skipping conntrack tuning"
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        conntrack_block="net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30"
    fi

    cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
# FRP TCP-Only Tunnel Optimization
# PMTU / MSS black hole fix
net.ipv4.tcp_mtu_probing = 2
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_mtu_probe_floor = 576

# Fast dead peer detection
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# Fail fast on black-holed links
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3

# Disable slow start after idle (critical for tunnel stability)
net.ipv4.tcp_slow_start_after_idle = 0

# Backlogs
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Connection tracking
${conntrack_block}

# Port reuse / timeouts
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535

# Window scaling / buffers optimized for high-latency tunnel
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = -2
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_mem = 786432 1048576 26777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144

${cc_line}
${qdisc_line}
EOF

    sysctl --system >/dev/null 2>&1
    log_info "TCP kernel tuning applied."
}

# CRITICAL FIX: MSS Clamping for tunneled TCP
# Without this, websites sending large packets will fail to load.
apply_mss_clamping() {
    log_step "Applying MSS clamping (fixes 'some websites don't load')..."

    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$iface" ]; then
        iface="eth0"
    fi

    # Using iptables-legacy or nftables backend — both work
    if command -v iptables >/dev/null 2>&1; then
        # Clamp MSS to 1300 to leave room for FRP/TLS overhead
        iptables -t mangle -C POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 >/dev/null 2>&1 || \
        iptables -t mangle -I POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 2>/dev/null || true
        
        # Also clamp on INPUT chain for inbound SYN
        iptables -t mangle -C INPUT -i "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 >/dev/null 2>&1 || \
        iptables -t mangle -I INPUT -i "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 2>/dev/null || true
        
        # Make rules persistent if iptables-persistent exists
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        elif command -v iptables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        log_ok "MSS clamped to 1300 on $iface (iptables)."
    fi

    if command -v nft >/dev/null 2>&1; then
        # nftables version
        if ! nft list table inet mangle >/dev/null 2>&1; then
            nft add table inet mangle 2>/dev/null || true
        fi
        if ! nft list chain inet mangle postrouting >/dev/null 2>&1; then
            nft add chain inet mangle postrouting { type filter hook postrouting priority mangle \; } 2>/dev/null || true
        fi
        nft add rule inet mangle postrouting oifname "$iface" tcp flags syn tcp option maxseg size set 1300 2>/dev/null || true
        log_ok "MSS clamped to 1300 on $iface (nftables)."
    fi
}

remove_tcp_tuning() {
    rm -f /etc/sysctl.d/99-frp-tuning.conf
    sysctl --system >/dev/null 2>&1
    
    # Remove MSS clamping
    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    [ -z "$iface" ] && iface="eth0"
    iptables -t mangle -D POSTROUTING -o "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 2>/dev/null || true
    iptables -t mangle -D INPUT -i "$iface" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-to-mss 1300 2>/dev/null || true
}

###############################################################################
# Firewall / ports
###############################################################################
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

free_stale_port() {
    local port="$1" proc_name="$2" label="$3"
    local line pids pid pname stale="" other=""

    line=$(ss -tlnp 2>/dev/null | grep ":${port} ")
    [ -z "$line" ] && line=$(netstat -tlnp 2>/dev/null | grep ":${port} ")
    [ -z "$line" ] && return 0

    pids=$(echo "$line" | grep -oP '(?<=pid=)[0-9]+' | sort -u)
    [ -z "$pids" ] && pids=$(echo "$line" | grep -oP '\d+(?=/)' | sort -u)
    [ -z "$pids" ] && return 0

    for pid in $pids; do
        pname=$(ps -p "$pid" -o comm= 2>/dev/null)
        if [ "$pname" = "$proc_name" ]; then
            stale="${stale} ${pid}"
        else
            other="${other} ${pid}"
        fi
    done

    if [ -n "$stale" ]; then
        log_warn "${label}: stale ${proc_name} process(es) [PID:${stale} ] still bound - killing."
        for pid in $stale; do kill -9 "$pid" 2>/dev/null || true; done
        sleep 1
    fi

    if [ -n "$other" ]; then
        log_error "${label}: in use by a DIFFERENT process (PID:${other} ). This will block startup:"
        ps -p $other -o pid,comm,args 2>/dev/null
        read -p "Press Enter to continue anyway, or Ctrl+C to abort..."
    fi
}

###############################################################################
# Transport config blocks (TCP-ONLY)
###############################################################################
server_transport_block() {
cat <<EOF
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = ${MUX_KEEPALIVE}
transport.tcpKeepalive = 30
transport.maxPoolCount = 100
transport.heartbeatTimeout = ${HB_TIMEOUT_S}
EOF
}

client_transport_block() {
    local pool="$1"
cat <<EOF
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = ${MUX_KEEPALIVE}
transport.poolCount = ${pool}
transport.heartbeatInterval = ${HB_INTERVAL}
transport.heartbeatTimeout = ${HB_TIMEOUT_C}
transport.dialServerTimeout = ${DIAL_TIMEOUT}
transport.dialServerKeepalive = ${DIAL_KEEPALIVE}
EOF
}

patch_transport_block() {
    local file="$1" side="$2" pool="${3:-5}"
    local tmp block
    tmp=$(mktemp)

    grep -Ev '^[[:space:]]*(transport\.tcpMux|transport\.tcpMuxKeepaliveInterval|transport\.tcpKeepalive|transport\.maxPoolCount|transport\.poolCount|transport\.heartbeatInterval|transport\.heartbeatTimeout|transport\.dialServerTimeout|transport\.dialServerKeepalive|transport\.kcp\.[a-zA-Z]+|transport\.quic\.[a-zA-Z]+|transport\.protocol|userConnTimeout)[[:space:]]*=' "$file" > "$tmp"

    if [ "$side" = "server" ]; then
        block="$(server_transport_block)
userConnTimeout = ${USER_CONN_TIMEOUT}"
    else
        block="$(client_transport_block "$pool")"
    fi

    awk -v block="$block" '
        BEGIN { inserted = 0 }
        /^\[\[proxies\]\]/ && !inserted { print block; print ""; inserted = 1 }
        { print }
        END { if (!inserted) { print ""; print block } }
    ' "$tmp" > "$file"
    rm -f "$tmp"
}

current_pool_count() {
    local file="$1" p
    p=$(grep -oP '^\stransport.poolCount\s=\s*\K[0-9]+' "$file" 2>/dev/null | head -n1)
    if [ "$TCP_MUX" = "true" ]; then
        if [ -z "$p" ] || [ "$p" -gt 10 ]; then p=5; fi
    else
        [ -z "$p" ] && p=20
    fi
    echo "$p"
}

###############################################################################
# systemd units
###############################################################################
write_server_unit() {
cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
}

write_client_unit() {
cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
}

###############################################################################
# Watchdog
###############################################################################
install_watchdog() {
    local side="$1"
    log_step "Installing watchdog for ${side}..."

cat > /usr/local/bin/frp-watchdog.sh <<HEADER_EOF
#!/bin/bash
FRP_PORT="${FRP_PORT}"
ADMIN_PORT_S="${ADMIN_PORT_S}"
ADMIN_PORT_C="${ADMIN_PORT_C}"
FRP_TOKEN="${FRP_TOKEN}"
FAIL_THRESHOLD=${WD_FAIL_THRESHOLD}
RESTART_COOLDOWN=${WD_COOLDOWN}
START_GRACE=${WD_GRACE}
HEADER_EOF

cat >> /usr/local/bin/frp-watchdog.sh <<'WATCHDOG_EOF'
LOG_FILE="/var/log/frp-watchdog.log"
MAX_LOG_SIZE=1048576
STATE_DIR="/run/frp-watchdog"
API_TIMEOUT=8

mkdir -p "$STATE_DIR"

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"; }

rotate_log() {
    if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt "$MAX_LOG_SIZE" ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
    fi
}

check_admin_api() {
    curl -sf --max-time "$API_TIMEOUT" -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${1}/api/status" >/dev/null 2>&1
}

read_count() { local f="${STATE_DIR}/$1.fails"; [ -f "$f" ] && cat "$f" || echo 0; }
write_count() { echo "$2" > "${STATE_DIR}/$1.fails"; }

unit_exists() { systemctl cat "$1" >/dev/null 2>&1; }

started_recently() {
    local ts now
    ts=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$1" 2>/dev/null)
    [ -z "$ts" ] || [ "$ts" = "0" ] && return 1
    now=$(awk '{printf "%d", $1 * 1000000}' /proc/uptime)
    [ $(( (now - ts) / 1000000 )) -lt "$START_GRACE" ]
}

can_restart_now() {
    local ts_file="${STATE_DIR}/$1.last_restart" now last
    now=$(date +%s)
    if [ -f "$ts_file" ]; then
        last=$(cat "$ts_file")
        [ $(( now - last )) -lt "$RESTART_COOLDOWN" ] && return 1
    fi
    echo "$now" > "$ts_file"
    return 0
}

do_restart() {
    local proc="$1" unit="$2" svc_key="$3"
    if ! unit_exists "${unit}.service"; then
        return
    fi
    if started_recently "${unit}.service"; then
        log_msg "WATCHDOG: ${proc} started less than ${START_GRACE}s ago, giving it time"
        return
    fi
    if ! can_restart_now "$svc_key"; then
        log_msg "WATCHDOG: ${proc} needs a restart but cooldown is active, skipping"
        return
    fi
    log_msg "WATCHDOG: RESTARTING ${unit}.service..."
    systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
    systemctl restart "${unit}.service" >/dev/null 2>&1
    sleep 5
    if pgrep -x "$proc" >/dev/null 2>&1; then
        log_msg "WATCHDOG: ${proc} restarted OK"
        write_count "$svc_key" 0
    else
        log_msg "WATCHDOG: CRITICAL - ${proc} restart FAILED"
    fi
}

bump_fail() {
    local key="$1" msg="$2" proc="$3" unit="$4"
    local n=$(( $(read_count "$key") + 1 ))
    write_count "$key" "$n"
    log_msg "WATCHDOG: ${msg} (${n}/${FAIL_THRESHOLD})"
    [ "$n" -ge "$FAIL_THRESHOLD" ] && do_restart "$proc" "$unit" "$key"
}

check_frps() {
    local key="frps" unit="frps@server-${FRP_PORT}"
    unit_exists "${unit}.service" || return 0

    if ! pgrep -x "frps" >/dev/null 2>&1; then
        log_msg "WATCHDOG: frps process NOT RUNNING"
        do_restart "frps" "$unit" "$key"
        return
    fi

    local listening=1
    if ss -tlnp 2>/dev/null | grep -q ":${FRP_PORT} "; then
        listening=0
    elif netstat -tlnp 2>/dev/null | grep -q ":${FRP_PORT} "; then
        listening=0
    fi
    if [ "$listening" -eq 1 ]; then
        log_msg "WATCHDOG: frps NOT LISTENING on port ${FRP_PORT}"
        do_restart "frps" "$unit" "$key"
        return
    fi

    if check_admin_api "$ADMIN_PORT_S"; then
        write_count "$key" 0
    else
        bump_fail "$key" "frps admin API not responding" "frps" "$unit"
    fi
}

check_frpc() {
    local key="frpc" unit="frpc@client-${FRP_PORT}"
    unit_exists "${unit}.service" || return 0

    if ! pgrep -x "frpc" >/dev/null 2>&1; then
        log_msg "WATCHDOG: frpc process NOT RUNNING"
        do_restart "frpc" "$unit" "$key"
        return
    fi

    local status
    status=$(curl -sf --max-time "$API_TIMEOUT" -u "admin:${FRP_TOKEN}" \
             "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)

    if [ -z "$status" ]; then
        bump_fail "$key" "frpc admin API not responding" "frpc" "$unit"
        return
    fi

    if echo "$status" | grep -q '"status":"running"'; then
        write_count "$key" 0
    else
        bump_fail "$key" "frpc has NO running proxy (tunnel down)" "frpc" "$unit"
    fi
}

rotate_log
mkdir -p "$STATE_DIR"
(
flock -n 200 || { log_msg "WATCHDOG: previous '$1' check still running, skipping tick"; exit 0; }
case "$1" in
    frps) check_frps ;;
    frpc) check_frpc ;;
    *) log_msg "Usage: $0 {frps|frpc}" ;;
esac
) 200>"${STATE_DIR}/$1.lock"
WATCHDOG_EOF

    chmod 755 /usr/local/bin/frp-watchdog.sh
    mkdir -p /run/frp-watchdog

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v 'frp-watchdog') | crontab - 2>/dev/null || true
    fi

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP watchdog check (%i)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/frp-watchdog.sh %i
EOF

    cat > /etc/systemd/system/frp-watchdog@.timer <<'EOF'
[Unit]
Description=FRP watchdog timer (%i)

[Timer]
OnBootSec=120
OnUnitActiveSec=60
AccuracySec=5s
Unit=frp-watchdog@%i.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl disable --now frp-watchdog@frps.timer >/dev/null 2>&1 || true
    systemctl disable --now frp-watchdog@frpc.timer >/dev/null 2>&1 || true
    systemctl enable --now "frp-watchdog@${side}.timer" >/dev/null 2>&1
    log_info "Watchdog installed for ${side} (checks every 60s, ${WD_COOLDOWN}s restart cooldown)."
}

remove_watchdog() {
    systemctl disable --now frp-watchdog@frps.timer >/dev/null 2>&1 || true
    systemctl disable --now frp-watchdog@frpc.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/frp-watchdog@.service /etc/systemd/system/frp-watchdog@.timer
    rm -f /usr/local/bin/frp-watchdog.sh
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v 'frp-watchdog') | crontab - 2>/dev/null || true
    fi
    rm -f /var/log/frp-watchdog.log /var/log/frp-watchdog.log.old
    rm -rf /run/frp-watchdog /var/run/frp-watchdog
    systemctl daemon-reload
}

###############################################################################
# Proxy generation
###############################################################################
count_ports() {
    local ports="$1"
    local IFS=','
    local total=0
    read -ra PORT_ARRAY <<< "$ports"
    for entry in "${PORT_ARRAY[@]}"; do
        entry=$(echo "$entry" | tr -d ' ')
        [ -z "$entry" ] && continue
        if [[ "$entry" == *"-"* ]]; then
            local start=${entry%%-*}
            local end=${entry##*-}
            total=$(( total + (end - start + 1) ))
        else
            total=$(( total + 1 ))
        fi
    done
    echo "$total"
}

generate_proxies() {
    local kind="$1" ports="$2" config_file="$3"
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
name = "${kind}-${p}"
type = "${kind}"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
PROXY
            done
        else
            cat >> "$config_file" <<PROXY

[[proxies]]
name = "${kind}-${entry}"
type = "${kind}"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}
PROXY
        fi
    done
}

###############################################################################
# Menu
###############################################################################
show_menu() {
    clear
    echo "================================================"
    echo " FRP Iran-Optimized Tunnel -- TCP-ONLY EDITION "
    echo " (frp v${FRP_VERSION}) "
    echo "================================================"
    echo " Protocol: TCP ONLY | Multiplexing: ${TCP_MUX} "
    echo " Port: ${FRP_PORT}"
    echo "------------------------------------------------"
    echo "1) Install FRP Server (frps) - IRAN"
    echo "2) Install FRP Client (frpc) - OUTSIDE"
    echo "3) Check Status / Health"
    echo "4) Apply stability fix to an EXISTING install"
    echo "5) Live logs (flap diagnostics)"
    echo "6) Remove FRP"
    echo "7) Exit"
    echo "================================================"
    read -p "Choose an option [1-7]: " choice
}

###############################################################################
# Server
###############################################################################
install_server() {
    log_step "=== Installing FRP Server (frps) on IRAN ==="
    log_ir "Reverse tunnel: frpc (outside) -> frps (Iran) via TCP"

    systemctl stop frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    free_stale_port "$FRP_PORT" "frps" "Bind port ${FRP_PORT}"
    free_stale_port "$ADMIN_PORT_S" "frps" "Admin dashboard port ${ADMIN_PORT_S}"

    download_frp_binary "frps"
    mkdir -p /root/frp/server /var/log

    open_firewall_port "$FRP_PORT" "tcp"
    open_firewall_port "$ADMIN_PORT_S" "tcp"

    # Optional real certificate
    local cert_block=""
    read -p "Do you have a real TLS cert for this server? (y/n) [default: n]: " use_cert
    if [[ "$use_cert" =~ ^[Yy]$ ]]; then
        read -p "  Full path to fullchain.pem: " cert_file
        read -p "  Full path to privkey.pem:  " key_file
        if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
            cert_block="transport.tls.certFile = \"${cert_file}\"
transport.tls.keyFile = \"${key_file}\""
            log_ok "Real certificate will be used."
        else
            log_warn "Cert or key not found - falling back to frp's self-signed cert."
        fi
    fi

    cat > /root/frp/server/server-${FRP_PORT}.toml <<EOF
bindAddr = "0.0.0.0"
bindPort = ${FRP_PORT}
proxyBindAddr = "0.0.0.0"

webServer.addr = "${ADMIN_BIND_S}"
webServer.port = ${ADMIN_PORT_S}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

log.to = "/var/log/frps.log"
log.level = "info"
log.maxDays = 30
log.disablePrintColor = true

auth.method = "token"
auth.token = "${FRP_TOKEN}"

$(server_transport_block)
transport.tls.force = true
${cert_block}

maxPortsPerClient = 0
userConnTimeout = ${USER_CONN_TIMEOUT}
detailedErrorsToClient = false
EOF

    log_step "Testing frps config validity (5 seconds)..."
    echo ""
    echo -e "${CYAN}========== DIRECT FRPS TEST ==========${NC}"
    timeout 5 /usr/local/bin/frps -c /root/frp/server/server-${FRP_PORT}.toml 2>&1 || true
    echo -e "${CYAN}========== END OF TEST ==========${NC}"
    echo ""
    read -p "If you see an error above, press Ctrl+C to fix it. Otherwise press Enter to continue..."

    write_server_unit
    systemctl daemon-reload
    systemctl enable frps@server-${FRP_PORT}.service >/dev/null 2>&1
    systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl restart frps@server-${FRP_PORT}.service

    tune_tcp_for_frp
    apply_mss_clamping
    install_watchdog "frps"

    sleep 3

    if systemctl is-active --quiet frps@server-${FRP_PORT}.service; then
        log_info "FRP Server installed and running!"
        echo ""
        echo -e "${GREEN}+------------------------------------------------------+${NC}"
        echo -e "${GREEN}|  Server (IRAN) Status: RUNNING                       |${NC}"
        echo -e "${GREEN}|  Bind Port:   ${FRP_PORT} (TCP)                              |${NC}"
        echo -e "${GREEN}|  Dashboard:   http://IRAN_IP:${ADMIN_PORT_S}                    |${NC}"
        echo -e "${GREEN}|  Token:       ${FRP_TOKEN}                              |${NC}"
        echo -e "${GREEN}|  tcpMux:      ${TCP_MUX}  (must match the client!)         |${NC}"
        echo -e "${GREEN}+------------------------------------------------------+${NC}"
        echo ""
        log_warn "Open port ${FRP_PORT} in your cloud firewall as well."
        log_warn "Test from outside: nc -vz IRAN_IP ${FRP_PORT}"
    else
        log_error "Failed to start server!"
        journalctl -u frps@server-${FRP_PORT} --no-pager -n 30
    fi
}

###############################################################################
# Client
###############################################################################
install_client() {
    log_step "=== Installing FRP Client (frpc) on OUTSIDE server ==="
    log_ir "Connecting to Iran server via TCP (TLS)"

    systemctl stop frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl reset-failed frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
    free_stale_port "$ADMIN_PORT_C" "frpc" "Admin dashboard port ${ADMIN_PORT_C}"

    download_frp_binary "frpc"
    mkdir -p /root/frp/client /var/log

    read -p "Enter Iran server address (IP or domain): " server_addr
    while [ -z "$server_addr" ]; do
        log_warn "Server address cannot be empty!"
        read -p "Enter Iran server address: " server_addr
    done

    log_step "Testing reachability to ${server_addr}:${FRP_PORT}..."
    if nc -z -w 5 "$server_addr" "$FRP_PORT" 2>/dev/null; then
        log_ok "Port ${FRP_PORT} is reachable from this server!"
    else
        log_warn "Port ${FRP_PORT} seems UNREACHABLE from here."
        log_warn "If this is a timeout, your Iran IP may be blocked by this datacenter."
        read -p "Press Enter to continue anyway, or Ctrl+C to abort..."
    fi

    read -p "Enter inbound ports to forward [default: 8080]: " ports
    ports=${ports:-8080}

    read -p "Also forward UDP ports? (y/n) [default: n]: " forward_udp

    echo ""
    echo "Connection load profile:"
    echo "  1) Light  - few users"
    echo "  2) Medium - typical single-user [default]"
    echo "  3) Heavy  - many concurrent connections"
    read -p "Select [1-3, default 2]: " load_choice
    load_choice=${load_choice:-2}

    local base_pool pool_cap
    if [ "$TCP_MUX" = "true" ]; then
        case "$load_choice" in
            1) base_pool=2 ;;
            3) base_pool=10 ;;
            *) base_pool=5 ;;
        esac
        pool_cap=100
    else
        case "$load_choice" in
            1) base_pool=8 ;;
            3) base_pool=40 ;;
            *) base_pool=20 ;;
        esac
        pool_cap=400
    fi

    local n_ports
    n_ports=$(count_ports "$ports")
    [ "$n_ports" -lt 1 ] && n_ports=1

    local pool_count=$base_pool
    local total_pool=$(( n_ports * base_pool ))
    if [ "$total_pool" -gt "$pool_cap" ]; then
        pool_count=$(( pool_cap / n_ports ))
        [ "$pool_count" -lt 1 ] && pool_count=1
        log_warn "Capping pool to ${pool_count} per port (~${pool_cap} total)."
    fi

    echo ""
    echo "TLS Configuration:"
    echo "  1) Basic TLS with self-signed cert (default)"
    echo "  2) Real domain - Your own domain with valid cert"
    read -p "Select [1-2, default 1]: " tls_choice
    tls_choice=${tls_choice:-1}

    local tls_config="" sni_note=""

    case "$tls_choice" in
        2) read -p "Enter your real domain: " real_domain
           while [ -z "$real_domain" ]; do
               log_warn "Domain cannot be empty!"
               read -p "Enter your real domain: " real_domain
           done
           tls_config="transport.tls.serverName = \"${real_domain}\""
           sni_note="SNI: ${real_domain} (real domain)" ;;
        *) sni_note="SNI: ${server_addr} (basic TLS)" ;;
    esac

    echo ""
    echo "Proxy Chaining (optional):"
    read -p "Use an existing proxy (Shadowsocks/V2Ray/Xray)? (y/n) [default: n]: " use_proxy

    local proxy_config=""
    if [[ "$use_proxy" =~ ^[Yy]$ ]]; then
        echo "  1) SOCKS5 (e.g., 127.0.0.1:10808)"
        echo "  2) HTTP proxy"
        read -p "Select proxy type [1-2, default 1]: " proxy_type
        proxy_type=${proxy_type:-1}
        read -p "Enter proxy address [default: 127.0.0.1:10808]: " proxy_addr
        proxy_addr=${proxy_addr:-127.0.0.1:10808}

        if [ "$proxy_type" = "2" ]; then
            proxy_config="transport.proxyURL = \"http://${proxy_addr}\""
        else
            proxy_config="transport.proxyURL = \"socks5://${proxy_addr}\""
        fi
        log_ir "Proxy chaining enabled."
    fi

    # TCP-ONLY: transport.protocol defaults to tcp, no need to set
    cat > /root/frp/client/client-${FRP_PORT}.toml <<EOF
serverAddr = "${server_addr}"
serverPort = ${FRP_PORT}

loginFailExit = false

webServer.addr = "127.0.0.1"
webServer.port = ${ADMIN_PORT_C}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

log.to = "/var/log/frpc.log"
log.level = "info"
log.maxDays = 30
log.disablePrintColor = true

auth.method = "token"
auth.token = "${FRP_TOKEN}"

$(client_transport_block "$pool_count")
${tls_config}
${proxy_config}
EOF

    generate_proxies "tcp" "$ports" "/root/frp/client/client-${FRP_PORT}.toml"

    if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
        log_warn "Adding UDP forwarding..."
        generate_proxies "udp" "$ports" "/root/frp/client/client-${FRP_PORT}.toml"
    fi

    log_step "Testing frpc config validity (10 seconds)..."
    echo ""
    echo -e "${CYAN}========== DIRECT FRPC TEST ==========${NC}"
    timeout 10 /usr/local/bin/frpc -c /root/frp/client/client-${FRP_PORT}.toml 2>&1 || true
    echo -e "${CYAN}========== END OF TEST ==========${NC}"
    echo ""
    read -p "If you see an error above, press Ctrl+C to fix it. Otherwise press Enter to continue..."

    write_client_unit
    systemctl daemon-reload
    systemctl enable frpc@client-${FRP_PORT}.service >/dev/null 2>&1
    systemctl reset-failed frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl restart frpc@client-${FRP_PORT}.service

    tune_tcp_for_frp
    apply_mss_clamping
    install_watchdog "frpc"

    log_step "Waiting for connection..."
    sleep 5

    local connected=false status
    for i in {1..10}; do
        if pgrep -x "frpc" >/dev/null 2>&1; then
            status=$(curl -sf --max-time 3 -u "admin:${FRP_TOKEN}" \
                     "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
            if [ -n "$status" ] && echo "$status" | grep -q '"status":"running"'; then
                connected=true
                break
            fi
        fi
        sleep 2
    done

    echo ""
    if [ "$connected" = true ]; then
        log_info "FRP Client installed and connected to Iran!"
        echo -e "${GREEN}+------------------------------------------------------+${NC}"
        echo -e "${GREEN}|  Client (OUTSIDE) Status: CONNECTED${NC}"
        echo -e "${GREEN}|  Iran Server:  ${server_addr}:${FRP_PORT}${NC}"
        echo -e "${GREEN}|  Protocol:     TCP (TLS)${NC}"
        echo -e "${GREEN}|  ${sni_note}${NC}"
        echo -e "${GREEN}|  tcpMux:       ${TCP_MUX} (keepalive ${MUX_KEEPALIVE}s)${NC}"
        echo -e "${GREEN}|  Heartbeat:    every ${HB_INTERVAL}s, timeout ${HB_TIMEOUT_C}s${NC}"
        echo -e "${GREEN}|  Pool:         ${pool_count} per port${NC}"
        echo -e "${GREEN}|  TCP Ports:    ${ports}${NC}"
        [[ "$forward_udp" =~ ^[Yy]$ ]] && echo -e "${GREEN}|  UDP Ports:    ${ports}${NC}"
        [ -n "$proxy_config" ] && echo -e "${GREEN}|  Proxy:        ENABLED${NC}"
        echo -e "${GREEN}+------------------------------------------------------+${NC}"
        echo ""
        log_warn "Make sure the IRAN side also runs this new script (tcpMux must match)."
    else
        log_warn "Connection not established."
        log_warn "  1. Is tcpMux the same (${TCP_MUX}) on the Iran server?"
        log_warn "  2. Iran IP blocked from this datacenter?"
        log_warn "  3. Iran cloud firewall blocking port ${FRP_PORT}?"
        echo -e "${YELLOW}journalctl -u frpc@client-${FRP_PORT} -f${NC}"
        echo -e "${YELLOW}cat /root/frp/client/client-${FRP_PORT}.toml${NC}"
    fi
}

###############################################################################
# Apply stability fix to existing install
###############################################################################
apply_stability_fix() {
    log_step "=== Applying stability fix to existing configuration ==="
    local touched=false

    local srv="/root/frp/server/server-${FRP_PORT}.toml"
    if [ -f "$srv" ]; then
        cp "$srv" "${srv}.bak.$(date +%s)"
        patch_transport_block "$srv" "server"
        write_server_unit
        touched=true
        log_ok "Server config patched (backup kept)."
    fi

    local cli="/root/frp/client/client-${FRP_PORT}.toml"
    if [ -f "$cli" ]; then
        cp "$cli" "${cli}.bak.$(date +%s)"
        patch_transport_block "$cli" "client" "$(current_pool_count "$cli")"
        write_client_unit
        touched=true
        log_ok "Client config patched (backup kept)."
    fi

    if [ "$touched" = false ]; then
        log_warn "No existing FRP config found at /root/frp. Use option 1 or 2 first."
        return
    fi

    tune_tcp_for_frp
    apply_mss_clamping
    systemctl daemon-reload

    if [ -f "$srv" ]; then
        log_step "Validating new server config..."
        timeout 4 /usr/local/bin/frps -c "$srv" 2>&1 | head -n 20 || true
        systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
        systemctl restart frps@server-${FRP_PORT}.service
        install_watchdog "frps"
    fi
    if [ -f "$cli" ]; then
        log_step "Validating new client config..."
        timeout 4 /usr/local/bin/frpc -c "$cli" 2>&1 | head -n 20 || true
        systemctl reset-failed frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
        systemctl restart frpc@client-${FRP_PORT}.service
        install_watchdog "frpc"
    fi

    sleep 4
    log_info "Stability fix applied. IMPORTANT: run this on BOTH servers so tcpMux matches."
}

###############################################################################
# Status / logs
###############################################################################
check_status() {
    echo "================================================"
    echo " FRP Health Status "
    echo "================================================"

    local has_service=false

    if systemctl cat frps@server-${FRP_PORT}.service >/dev/null 2>&1; then
        has_service=true
        echo ""
        echo "--- FRP Server (frps) - IRAN ---"
        systemctl status frps@server-${FRP_PORT}.service --no-pager 2>&1 | head -n 12 || true
        echo ""
        echo "Clients currently connected:"
        curl -sf --max-time 5 -u "admin:${FRP_TOKEN}" \
            "http://127.0.0.1:${ADMIN_PORT_S}/api/serverinfo" 2>/dev/null \
            | grep -oP '"clientCounts":\s*\K[0-9]+' || echo "  (admin API not reachable)"
        if [ -f /var/log/frps.log ]; then
            echo ""
            echo "Control-connection churn (last 200 log lines):"
            echo "  logins:   $(tail -n 200 /var/log/frps.log | grep -c 'client login info')"
            echo "  closed:   $(tail -n 200 /var/log/frps.log | grep -ci 'client close\|control connection closed')"
        fi
    fi

    if systemctl cat frpc@client-${FRP_PORT}.service >/dev/null 2>&1; then
        has_service=true
        echo ""
        echo "--- FRP Client (frpc) - OUTSIDE ---"
        systemctl status frpc@client-${FRP_PORT}.service --no-pager 2>&1 | head -n 12 || true

        echo ""
        echo "--- Connection Status ---"
        local status
        status=$(curl -sf --max-time 5 -u "admin:${FRP_TOKEN}" \
                 "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
        if [ -n "$status" ]; then
            local running total
            running=$(echo "$status" | grep -o '"status":"running"' | wc -l)
            total=$(echo "$status" | grep -o '"status":"' | wc -l)
            if [ "$running" -gt 0 ]; then
                echo -e "${GREEN}ONLINE - ${running}/${total} proxies running.${NC}"
            else
                echo -e "${RED}OFFLINE - 0/${total} proxies running.${NC}"
                echo "$status" | head -c 400
            fi
        else
            echo "Admin API not available."
        fi

        if [ -f /var/log/frpc.log ]; then
            echo ""
            echo "Reconnect churn (last 300 log lines):"
            echo "  login success: $(tail -n 300 /var/log/frpc.log | grep -c 'login to server success')"
            echo "  reconnects:    $(tail -n 300 /var/log/frpc.log | grep -ci 'try to reconnect')"
            echo ""
            echo "Last errors:"
            tail -n 300 /var/log/frpc.log | grep -iE '\[E\]|error|timeout|reset' | tail -n 6
        fi
    fi

    [ "$has_service" = false ] && log_warn "No FRP service found on this machine."

    if [ -f /var/log/frp-watchdog.log ]; then
        echo ""
        echo "--- Recent Watchdog Logs ---"
        tail -n 6 /var/log/frp-watchdog.log 2>/dev/null
    fi

    echo ""
    echo "--- Kernel Settings ---"
    sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_keepalive_time \
           net.ipv4.tcp_mtu_probing 2>/dev/null || true
    sysctl net.netfilter.nf_conntrack_tcp_timeout_established 2>/dev/null || true
    
    echo ""
    echo "--- MSS Clamping ---"
    iptables -t mangle -L POSTROUTING -v -n 2>/dev/null | grep -i mss || echo "  (no MSS rules found)"
}

live_logs() {
    echo "1) frps (Iran) 2) frpc (Outside) 3) watchdog"
    read -p "Select [1-3]: " l
    case "$l" in
        1) journalctl -u frps@server-${FRP_PORT} -f --no-pager ;;
        2) journalctl -u frpc@client-${FRP_PORT} -f --no-pager ;;
        3) tail -f /var/log/frp-watchdog.log ;;
        *) log_warn "Invalid choice." ;;
    esac
}

###############################################################################
# Removal
###############################################################################
remove_frp() {
    log_step "=== Removing FRP ==="

    systemctl stop frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true
    systemctl disable frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
    rm -rf /root/frp
    rm -f /usr/local/bin/frps /usr/local/bin/frpc

    pkill -9 -x frps 2>/dev/null || true
    pkill -9 -x frpc 2>/dev/null || true

    remove_watchdog
    remove_tcp_tuning

    systemctl daemon-reload
    log_info "FRP removed completely."
}

###############################################################################
require_root

while true; do
    show_menu
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) check_status ;;
        4) apply_stability_fix ;;
        5) live_logs ;;
        6) remove_frp ;;
        7) echo "Goodbye!"; exit 0 ;;
        *) log_warn "Invalid option. Please try again." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
