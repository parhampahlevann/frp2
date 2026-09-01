#!/bin/bash
set -o pipefail

###############################################################################
#  FRP Iran-Optimized Tunnel  --  STABILITY FIXED EDITION  (frp v0.71.0)
#
#  WHY THE OLD SCRIPT KEPT DROPPING THE TUNNEL  (all fixed below):
#
#   1. KILLER BUG - conntrack:
#      "net.netfilter.nf_conntrack_tcp_timeout_established = 600" told the
#      kernel firewall to FORGET any TCP flow that stayed quiet for 10 min,
#      while frpc's control socket used Go's default TCP keepalive of
#      2 HOURS. So every idle period silently killed the tunnel and the
#      client only noticed much later -> classic connect / drop / reconnect.
#      -> raised to 2h AND real keepalives added on the frp layer.
#
#   2. transport.tcpMux = false on BOTH sides:
#      every single proxied connection (plus every pooled socket) opened a
#      brand-new TLS/WSS handshake through the filtering layer. Iranian DPI
#      throttles/resets bursts of identical handshakes to one IP:port.
#      -> multiplexing ON: one long-lived session + yamux keepalive.
#
#   3. No heartbeat / dial keepalive on the client (they were deliberately
#      deleted). Dead-link detection therefore took minutes.
#      -> heartbeatInterval/Timeout + dialServerKeepalive/Timeout added.
#         (These ARE valid frpc v1 fields; only transport.tcpKeepalive is
#          server-only, which is why the old config crashed.)
#
#   4. Connection pool up to 400 pre-opened sockets -> handshake storm.
#      -> small pool when mux is on (mux streams are nearly free).
#
#   5. transport.kcp.* is NOT a valid key in frp v1 TOML. With strict config
#      parsing frpc refused to start whenever KCP was chosen. -> removed,
#      replaced with the valid transport.quic.* options for QUIC.
#
#   6. systemd StartLimitBurst=10 / StartLimitIntervalSec=300: after 10 flaps
#      systemd GAVE UP permanently ("start request repeated too quickly").
#      -> start limiting disabled, RestartSec lowered to 5s.
#
#   7. Watchdog restart storms: it was installed on BOTH machines (the Iran
#      box kept trying to restart a non-existent frpc every minute), it
#      restarted services on a single slow admin-API reply, and its frpc
#      health check grepped '"online":false' - a string frpc's API never
#      returns, so real outages were missed while false ones triggered.
#      -> side-aware install, systemd timer instead of cron, startup grace
#         period, longer cooldown, correct health signal.
#
#   8. Kernel: added tcp_mtu_probing (PMTU black holes stall tunnels dead),
#      lower tcp_retries2 (fail fast + reconnect), bigger conntrack table.
###############################################################################

FRP_VERSION="0.71.0"
FRP_TOKEN="tun100"
FRP_PORT="8443"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"

# --- Stability knobs -------------------------------------------------------
# TCP_MUX MUST BE IDENTICAL ON BOTH SERVERS, otherwise login fails.
TCP_MUX="true"          # true = stable (recommended). false = max raw speed.
MUX_KEEPALIVE="20"      # yamux keepalive, seconds
HB_INTERVAL="15"        # client -> server ping
HB_TIMEOUT_C="60"       # client reconnects after this silence
HB_TIMEOUT_S="120"      # server evicts a silent client after this
DIAL_TIMEOUT="15"
DIAL_KEEPALIVE="15"     # TCP keepalive on the control socket (Go default 7200!)
USER_CONN_TIMEOUT="45"  # was 20s - too tight for the full multi-hop chain on
                         # slow/heavy sites; this is the #1 suspect for
                         # "some sites just don't come up" while others work
ADMIN_BIND_S="0.0.0.0"  # set to 127.0.0.1 for a safer dashboard

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
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "arm" ;;
        i386|i686)     echo "386" ;;
        *)             echo "unsupported" ;;
    esac
}

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $1"; }
log_ok()    { echo -e "${CYAN}[OK]${NC}    $1"; }
log_ir()    { echo -e "${MAGENTA}[IRAN]${NC}  $1"; }
log_perf()  { echo -e "${CYAN}[PERF]${NC}  $1"; }

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
# Kernel tuning
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

    # conntrack lines only if the module is actually present, otherwise
    # sysctl --system throws errors on every boot.
    modprobe nf_conntrack >/dev/null 2>&1 || true
    local conntrack_block="# nf_conntrack module not loaded, skipping conntrack tuning"
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        conntrack_block="net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60"
    fi

    cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
# FRP Long-Haul TCP Optimization (stability edition)

# --- keepalive: notice a dead peer in ~90s instead of ~2h ---
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# --- fail fast on a black-holed link so frpc can reconnect ---
net.ipv4.tcp_retries2 = 8

# --- PMTU black holes are a top cause of "tunnel hangs then dies" ---
# mode 1 only starts probing AFTER a stall is detected (first big response
# on a path can still hang for a bit). Mode 2 starts every connection from
# a conservative base MSS and grows it - no detection delay, no reliance
# on ICMP (which Iranian ISPs/DPI frequently drop).
net.ipv4.tcp_mtu_probing = 2
net.ipv4.tcp_base_mss = 1024

# --- backlogs ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# --- connection tracking: 600s was killing idle tunnel flows ---
${conntrack_block}

net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65535

# --- buffers ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
${cc_line}
${qdisc_line}
EOF

    sysctl --system >/dev/null 2>&1
    log_info "TCP kernel tuning applied."
}

remove_tcp_tuning() {
    rm -f /etc/sysctl.d/99-frp-tuning.conf
    sysctl --system >/dev/null 2>&1
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

# Frees a port before (re)starting a service. A stale copy of the SAME binary
# is killed automatically; anything else only produces a warning.
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
# Transport config blocks (the actual stability fix)
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

# Strips the transport keys we manage and re-inserts the tuned ones BEFORE
# the first [[proxies]] table (TOML requires bare keys above any table).
patch_transport_block() {
    local file="$1" side="$2" pool="${3:-5}"
    local tmp block
    tmp=$(mktemp)

    grep -Ev '^[[:space:]]*(transport\.tcpMux|transport\.tcpMuxKeepaliveInterval|transport\.tcpKeepalive|transport\.maxPoolCount|transport\.poolCount|transport\.heartbeatInterval|transport\.heartbeatTimeout|transport\.dialServerTimeout|transport\.dialServerKeepalive|transport\.kcp\.[a-zA-Z]+|userConnTimeout)[[:space:]]*=' "$file" > "$tmp"

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
    p=$(grep -oP '^\s*transport\.poolCount\s*=\s*\K[0-9]+' "$file" 2>/dev/null | head -n1)
    if [ "$TCP_MUX" = "true" ]; then
        # a huge legacy pool makes no sense once mux is on
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
# No start limit: systemd must NEVER give up on a tunnel.
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
# Watchdog (side-aware, storm-proof, systemd timer instead of cron)
###############################################################################
install_watchdog() {
    local side="$1"   # frps | frpc
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

read_count()  { local f="${STATE_DIR}/$1.fails"; [ -f "$f" ] && cat "$f" || echo 0; }
write_count() { echo "$2" > "${STATE_DIR}/$1.fails"; }

unit_exists() { systemctl cat "$1" >/dev/null 2>&1; }

# Never judge a service that has just (re)started - it needs time to dial out.
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
        # e.g. the frpc check running on an frps-only box - nothing to do.
        return
    fi
    if started_recently "${unit}.service"; then
        log_msg "WATCHDOG: ${proc} started less than ${START_GRACE}s ago, giving it time"
        return
    fi
    if ! can_restart_now "$svc_key"; then
        log_msg "WATCHDOG: ${proc} needs a restart but cooldown is active, skipping (no restart storms)"
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

    # A slow dashboard is NOT a reason to drop every client - only a long
    # streak of failures counts.
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

    # frpc's /api/status returns the proxy list with "status":"running".
    # (The old script looked for '"online":false', which frpc never emits,
    #  so a truly dead tunnel was reported as healthy.)
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
        *)    log_msg "Usage: $0 {frps|frpc}" ;;
    esac
) 200>"${STATE_DIR}/$1.lock"
WATCHDOG_EOF

    chmod 755 /usr/local/bin/frp-watchdog.sh
    mkdir -p /run/frp-watchdog

    # Legacy cleanup: the old version put BOTH sides in cron on every host.
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
    # only the side that actually runs here
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
    echo "  FRP Iran-Optimized Tunnel - STABILITY EDITION "
    echo "            (frp v${FRP_VERSION})                    "
    echo "================================================"
    echo " Multiplexing: ${TCP_MUX}   |  Port: ${FRP_PORT}"
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
    log_ir "Reverse tunnel: frpc (outside) -> frps (Iran)"

    systemctl stop frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    free_stale_port "$FRP_PORT" "frps" "Bind port ${FRP_PORT}"
    free_stale_port "$ADMIN_PORT_S" "frps" "Admin dashboard port ${ADMIN_PORT_S}"

    download_frp_binary "frps"
    mkdir -p /root/frp/server /var/log

    open_firewall_port "$FRP_PORT" "tcp"
    open_firewall_port "$ADMIN_PORT_S" "tcp"

    # Optional real certificate - a self-signed cert behind a fake SNI is a
    # strong DPI fingerprint and a common reason a session gets reset after
    # a few minutes.
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
    # The direct test above can leave a real frps process running past its
    # timeout, squatting on these ports and blocking the service below.
    free_stale_port "$FRP_PORT" "frps" "Bind port ${FRP_PORT}"
    free_stale_port "$ADMIN_PORT_S" "frps" "Admin dashboard port ${ADMIN_PORT_S}"
    systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl restart frps@server-${FRP_PORT}.service

    tune_tcp_for_frp
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
    log_ir "Connecting to Iran server via WSS/TLS"

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

    # QUIC/HTTP3 (used heavily by Google and other major services) needs
    # UDP. Without it, those specific destinations fail outright while
    # ordinary TCP/HTTPS traffic works fine - a confirmed real-world failure
    # mode, so this now defaults to yes.
    read -p "Also forward UDP ports? (y/n) [default: y - needed for QUIC/HTTP3]: " forward_udp
    forward_udp=${forward_udp:-y}

    echo ""
    echo "Connection load profile:"
    echo "  1) Light  - few users"
    echo "  2) Medium - typical single-user [default]"
    echo "  3) Heavy  - many concurrent connections"
    read -p "Select [1-3, default 2]: " load_choice
    load_choice=${load_choice:-2}

    # With multiplexing ON a huge pool is pointless AND harmful: each pooled
    # socket is a separate TLS handshake through the filter.
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

    # Per your request: only tcp is offered now. wss/websocket/kcp/quic were
    # removed. NOTE: switching this transport was already tested (wss) and
    # did not fix the Google-only failure - that leg (frpc<->frps) tested
    # healthy, so don't expect this choice alone to fix that issue. See the
    # chat answer for where the actual problem most likely is.
    local transport_protocol="tcp" extra_proto_config=""
    log_warn "transport.protocol=tcp: no HTTP/WS framing, so a TLS ClientHello with no SNI set is an anomaly DPI can fingerprint. Strongly set a fake or real SNI in the TLS step below - don't leave it blank."

    echo ""
    echo "TLS / Domain Fronting:"
    echo "  1) Basic TLS (default)"
    echo "  2) Domain Fronting - Fake SNI"
    echo "  3) Real Domain - Your own domain"
    read -p "Select [1-3, default 1]: " tls_choice
    tls_choice=${tls_choice:-1}

    local tls_config="" sni_note=""

    case "$tls_choice" in
        2) read -p "Enter fake SNI domain [default: www.microsoft.com]: " fake_sni
           fake_sni=${fake_sni:-www.microsoft.com}
           tls_config="transport.tls.serverName = \"${fake_sni}\""
           sni_note="SNI: ${fake_sni} (domain fronting)"
           log_ir "Domain fronting active: SNI will show ${fake_sni}"
           log_warn "A fake SNI with a self-signed cert can be reset by DPI after a while."
           log_warn "For a rock-solid link use a real domain + real cert on the Iran side." ;;
        3) read -p "Enter your real domain: " real_domain
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

transport.protocol = "${transport_protocol}"
$(client_transport_block "$pool_count")
${tls_config}
${proxy_config}
${extra_proto_config}
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
    # The direct test above can leave a real frpc process running past its
    # timeout, squatting on the admin port and blocking the service below.
    free_stale_port "$ADMIN_PORT_C" "frpc" "Admin dashboard port ${ADMIN_PORT_C}"
    systemctl reset-failed frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
    systemctl restart frpc@client-${FRP_PORT}.service

    tune_tcp_for_frp
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
        echo -e "${GREEN}|  Protocol:     ${transport_protocol}${NC}"
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
# Apply the stability fix to an already-deployed install
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
    systemctl daemon-reload

    if [ -f "$srv" ]; then
        log_step "Validating new server config..."
        timeout 4 /usr/local/bin/frps -c "$srv" 2>&1 | head -n 20 || true
        # The line above starts a REAL frps process. If it outlives the
        # 4s timeout (observed in the wild), it squats on the admin port
        # forever and the systemd-managed copy below can never bind it
        # ("address already in use"), crash-looping indefinitely.
        free_stale_port "$FRP_PORT" "frps" "Bind port ${FRP_PORT}"
        free_stale_port "$ADMIN_PORT_S" "frps" "Admin dashboard port ${ADMIN_PORT_S}"
        systemctl reset-failed frps@server-${FRP_PORT}.service >/dev/null 2>&1 || true
        systemctl restart frps@server-${FRP_PORT}.service
        install_watchdog "frps"
    fi
    if [ -f "$cli" ]; then
        log_step "Validating new client config..."
        timeout 4 /usr/local/bin/frpc -c "$cli" 2>&1 | head -n 20 || true
        # Same leak risk as above, on the client's admin port.
        free_stale_port "$ADMIN_PORT_C" "frpc" "Admin dashboard port ${ADMIN_PORT_C}"
        systemctl reset-failed frpc@client-${FRP_PORT}.service >/dev/null 2>&1 || true
        systemctl restart frpc@client-${FRP_PORT}.service
        install_watchdog "frpc"
    fi

    sleep 4
    log_info "Stability fix applied. IMPORTANT: run this on BOTH servers so tcpMux matches."
}

###############################################################################
# Port-hijack diagnostics
#
# Real-world bug found: frps can report a proxy port as "listening" in its
# own log while a COMPLETELY UNRELATED local process (or an iptables NAT
# rule) actually owns that port or intercepts traffic before it ever
# reaches frps. Everything then LOOKS healthy (control connection stable,
# frps log clean) while real client traffic never enters the tunnel at
# all. This function checks, for every port frp currently has registered,
# whether frps itself is really the one answering.
###############################################################################
verify_proxy_ports() {
    log_step "Checking which process is ACTUALLY bound to each forwarded port..."

    local ports
    ports=$(curl -sf --max-time 5 -u "admin:${FRP_TOKEN}" \
            "http://127.0.0.1:${ADMIN_PORT_S}/api/proxy/tcp" 2>/dev/null \
            | grep -oP '"name":"tcp-\K[0-9]+' | sort -un)

    if [ -z "$ports" ]; then
        log_warn "Could not read active proxy ports from the frps admin API."
        log_warn "(frpc not connected yet, or no proxies registered - nothing to check.)"
        return
    fi

    local bad=0 line owner nat_hit p
    for p in $ports; do
        line=$(ss -tlnp 2>/dev/null | grep ":${p} ")
        owner=$(echo "$line" | grep -oP '(?<=users:\(\(")[^"]+' | head -n1)

        if [ -z "$line" ]; then
            log_error "Port ${p}: NOTHING is listening locally, even though frps registered a proxy for it. Traffic here will just fail or hit whatever your cloud firewall/NAT does with it."
            bad=1
        elif [ "$owner" != "frps" ]; then
            log_error "Port ${p}: bound by '${owner}' (PID info: ${line}), NOT frps! Any client connecting to this port never reaches the tunnel - it talks straight to '${owner}' instead."
            bad=1
        else
            log_ok "Port ${p}: OK - frps is genuinely the one listening."
        fi

        if command -v iptables >/dev/null 2>&1; then
            nat_hit=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -E "dpt:${p}([^0-9]|$)")
            if [ -n "$nat_hit" ]; then
                log_warn "Port ${p}: an iptables NAT/PREROUTING rule ALSO matches this port:"
                echo "$nat_hit"
                log_warn "  -> if this redirects elsewhere, it can silently hijack traffic even when frps looks fine above. Review with: iptables -t nat -L PREROUTING -n -v --line-numbers"
            fi
        fi
    done

    echo ""
    if [ "$bad" -eq 1 ]; then
        log_error "One or more forwarded ports are NOT genuinely served by frps. THIS is very likely the real cause of inconsistent/failed destinations - that traffic never enters the tunnel to begin with, regardless of any frp transport/timeout/MTU setting."
    else
        log_info "All registered proxy ports are genuinely owned by frps. If specific destinations still fail, the cause is downstream of frps (the backend service on the outside box, or its own routing rules) - not this script."
    fi
}

###############################################################################
# Status / logs
###############################################################################
check_status() {
    echo "================================================"
    echo "              FRP Health Status                 "
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
        echo ""
        verify_proxy_ports
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
}

live_logs() {
    echo "1) frps (Iran)   2) frpc (Outside)   3) watchdog"
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
