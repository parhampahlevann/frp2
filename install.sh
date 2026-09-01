#!/usr/bin/env bash
set -o pipefail

###############################################################################
# FRP Iran Tunnel - v4 CLEAN / FIXED EDITION
# FRP v0.71.0
#
# Topology:
#   IRAN  : frps (public bind)
#   OUTSIDE: frpc (exit node)
#
# Main goals:
#   - Correct, validated FRP TOML
#   - Optional tcpMux / parallel mode
#   - TCP-only by default; optional UDP forwarding
#   - Optional outbound UDP/443 REJECT on exit node
#   - IPv6 health check + optional IPv4 preference / disable
#   - Kernel tuning with safe bounds
#   - systemd services + watchdog timers
#   - Destination diagnostics
#
# IMPORTANT:
#   This script manages the FRP service/configuration on the local machine.
#   Run it as root on each side.
###############################################################################

FRP_VERSION="0.71.0"
FRP_TOKEN="tun100"
FRP_PORT="8443"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"

TCP_MUX="false"
MUX_KEEPALIVE="20"
HB_INTERVAL="15"
HB_TIMEOUT_C="60"
HB_TIMEOUT_S="120"
DIAL_TIMEOUT="15"
DIAL_KEEPALIVE="15"
USER_CONN_TIMEOUT="45"
ADMIN_BIND_S="127.0.0.1"

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

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $1"; }
log_ok()    { echo -e "${CYAN}[OK]${NC}    $1"; }
log_ir()    { echo -e "${MAGENTA}[IRAN]${NC}  $1"; }
log_perf()  { echo -e "${CYAN}[PERF]${NC}  $1"; }
log_fix()   { echo -e "${MAGENTA}[FIX]${NC}   $1"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "arm" ;;
        i386|i686)     echo "386" ;;
        *)
            echo "unsupported"
            ;;
    esac
}

ensure_dependencies() {
    local missing=()
    local cmds=(curl tar ss awk sed grep ip sysctl systemctl)

    for c in "${cmds[@]}"; do
        command_exists "$c" || missing+=("$c")
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        log_error "Missing commands: ${missing[*]}"
        log_warn "Install the corresponding packages and run again."
        return 1
    fi

    return 0
}

download_frp_binary() {
    local bin_name="$1"
    local arch pkg url tmp_dir

    arch="$(detect_arch)"
    if [ "$arch" = "unsupported" ]; then
        log_error "Unsupported architecture: $(uname -m)"
        return 1
    fi

    pkg="frp_${FRP_VERSION}_linux_${arch}"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${pkg}.tar.gz"
    tmp_dir="$(mktemp -d)"

    log_step "Downloading ${bin_name} - FRP v${FRP_VERSION} (${arch})..."

    if ! command_exists curl; then
        log_error "curl is required."
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! curl -fL --retry 5 --retry-delay 3 --connect-timeout 15 \
        -o "${tmp_dir}/frp.tar.gz" "$url"; then
        log_error "Download failed."
        log_error "$url"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! tar -xzf "${tmp_dir}/frp.tar.gz" -C "$tmp_dir"; then
        log_error "Archive extraction failed."
        rm -rf "$tmp_dir"
        return 1
    fi

    if [ ! -f "${tmp_dir}/${pkg}/${bin_name}" ]; then
        log_error "Binary ${bin_name} not found in archive."
        rm -rf "$tmp_dir"
        return 1
    fi

    install -m 755 "${tmp_dir}/${pkg}/${bin_name}" "/usr/local/bin/${bin_name}"
    rm -rf "$tmp_dir"

    log_ok "${bin_name} installed."
}

choose_mux_mode() {
    echo ""
    echo "Tunnel mode:"
    echo "  1) Multiplexed"
    echo "     One underlying TCP connection; fewer handshakes."
    echo "  2) Parallel"
    echo "     Multiple underlying TCP connections; avoids shared HoL."
    echo ""
    read -r -p "Select [1-2, default 2]: " mux_choice
    mux_choice="${mux_choice:-2}"

    case "$mux_choice" in
        1)
            TCP_MUX="true"
            log_info "Tunnel mode: MULTIPLEXED (tcpMux=true)"
            ;;
        2)
            TCP_MUX="false"
            log_info "Tunnel mode: PARALLEL (tcpMux=false)"
            ;;
        *)
            log_warn "Invalid selection; using Parallel."
            TCP_MUX="false"
            ;;
    esac

    log_warn "Use the same tcpMux value on both servers."
}

tune_tcp_for_frp() {
    log_step "Applying conservative TCP/kernel tuning..."

    local cc="cubic"
    local qdisc_comment="# fq not forced because BBR/fq availability varies"

    modprobe tcp_bbr >/dev/null 2>&1 || true

    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null |
        grep -qw bbr; then
        cc="bbr"
        qdisc_comment="net.core.default_qdisc = fq"
        log_perf "BBR is available; enabling BBR + fq."
    else
        log_warn "BBR unavailable; using cubic."
    fi

    local conntrack_block
    conntrack_block="# nf_conntrack tuning skipped: module/sysctl unavailable"

    modprobe nf_conntrack >/dev/null 2>&1 || true

    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        conntrack_block="net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60"

        if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
            echo 65536 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
            mkdir -p /etc/modprobe.d
            echo "options nf_conntrack hashsize=65536" \
                > /etc/modprobe.d/frp-conntrack.conf
        fi
    fi

    cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
# FRP long-haul TCP tuning

net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

net.ipv4.tcp_retries2 = 10

# PMTU black-hole detection.
# Mode 1 keeps normal PMTUD and enables probing after a detected failure.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1200

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

${conntrack_block}

net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0

# Avoid common service ports as ephemeral source ports.
net.ipv4.ip_local_port_range = 16384 60999

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

net.ipv4.tcp_congestion_control = ${cc}
${qdisc_comment}
EOF

    sysctl --system >/dev/null 2>&1 || true
    log_info "Kernel tuning applied."
}

remove_tcp_tuning() {
    rm -f /etc/sysctl.d/99-frp-tuning.conf
    rm -f /etc/modprobe.d/frp-conntrack.conf
    sysctl --system >/dev/null 2>&1 || true
}

write_quicblock_helper() {
    cat > /usr/local/bin/frp-quicblock.sh <<'EOF'
#!/usr/bin/env bash

act="$1"

rules_v4() {
    local op="$1"
    iptables -t filter "$op" OUTPUT \
        -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable \
        2>/dev/null || true
    iptables -t filter "$op" FORWARD \
        -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable \
        2>/dev/null || true
}

rules_v6() {
    command -v ip6tables >/dev/null 2>&1 || return 0

    local op="$1"
    ip6tables -t filter "$op" OUTPUT \
        -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable \
        2>/dev/null || true
    ip6tables -t filter "$op" FORWARD \
        -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable \
        2>/dev/null || true
}

case "$act" in
    add)
        if command -v iptables >/dev/null 2>&1; then
            iptables -t filter -C OUTPUT -p udp --dport 443 \
                -j REJECT --reject-with icmp-port-unreachable \
                2>/dev/null || rules_v4 -I
        fi

        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -t filter -C OUTPUT -p udp --dport 443 \
                -j REJECT --reject-with icmp6-port-unreachable \
                2>/dev/null || rules_v6 -I
        fi
        ;;

    del)
        if command -v iptables >/dev/null 2>&1; then
            while iptables -t filter -C OUTPUT -p udp --dport 443 \
                -j REJECT --reject-with icmp-port-unreachable \
                2>/dev/null; do
                rules_v4 -D
            done
        fi

        if command -v ip6tables >/dev/null 2>&1; then
            while ip6tables -t filter -C OUTPUT -p udp --dport 443 \
                -j REJECT --reject-with icmp6-port-unreachable \
                2>/dev/null; do
                rules_v6 -D
            done
        fi
        ;;

    *)
        echo "Usage: $0 {add|del}"
        exit 1
        ;;
esac
EOF

    chmod 755 /usr/local/bin/frp-quicblock.sh

    cat > /etc/systemd/system/frp-quicblock.service <<'EOF'
[Unit]
Description=Reject outbound QUIC UDP/443
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/frp-quicblock.sh add
ExecStop=/usr/local/bin/frp-quicblock.sh del

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

enable_quic_block() {
    write_quicblock_helper
    systemctl enable --now frp-quicblock.service >/dev/null 2>&1 || true
    log_fix "Outbound UDP/443 is REJECTed; browsers can fall back to TCP."
}

disable_quic_block() {
    if [ -x /usr/local/bin/frp-quicblock.sh ]; then
        /usr/local/bin/frp-quicblock.sh del >/dev/null 2>&1 || true
    fi

    systemctl disable --now frp-quicblock.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/frp-quicblock.service
    rm -f /usr/local/bin/frp-quicblock.sh
    systemctl daemon-reload
}

quic_block_active() {
    command_exists iptables || return 1

    iptables -t filter -C OUTPUT -p udp --dport 443 \
        -j REJECT --reject-with icmp-port-unreachable \
        >/dev/null 2>&1
}

host_has_global_ipv6() {
    ip -6 addr show scope global 2>/dev/null |
        grep -qE 'inet6 [0-9a-f:]+/'
}

ipv6_egress_works() {
    curl -6 -sS -o /dev/null --max-time 8 \
        https://www.google.com >/dev/null 2>&1
}

prefer_ipv4_resolution() {
    touch /etc/gai.conf

    if ! grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' \
        /etc/gai.conf; then
        {
            echo ""
            echo "# Added by FRP tunnel script: prefer IPv4"
            echo "precedence ::ffff:0:0/96  100"
        } >> /etc/gai.conf
    fi

    log_fix "glibc address selection now prefers IPv4."
    log_warn "Go applications may not honor gai.conf."
    log_warn "For Xray/V2Ray/Sing-box, set the outbound domain strategy to IPv4."
}

hard_disable_ipv6() {
    cat > /etc/sysctl.d/98-frp-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

    sysctl --system >/dev/null 2>&1 || true

    log_fix "IPv6 disabled system-wide."
    log_warn "Restart applications that opened IPv6 sockets."
}

open_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"

    if command_exists ufw; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi

    if command_exists firewall-cmd; then
        firewall-cmd --permanent \
            --add-port="${port}/${proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi

    if command_exists iptables; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT \
            >/dev/null 2>&1 ||
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT \
            >/dev/null 2>&1 || true
    fi
}

free_stale_port() {
    local port="$1"
    local proc_name="$2"
    local label="$3"
    local line pids pid pname stale="" other=""

    line="$(ss -H -ltnp 2>/dev/null | grep -E ":${port}[[:space:]]" || true)"

    [ -z "$line" ] && return 0

    pids="$(echo "$line" |
        grep -oE 'pid=[0-9]+' |
        cut -d= -f2 |
        sort -u)"

    [ -z "$pids" ] && return 0

    for pid in $pids; do
        pname="$(ps -p "$pid" -o comm= 2>/dev/null || true)"

        if [ "$pname" = "$proc_name" ]; then
            stale="${stale} ${pid}"
        else
            other="${other} ${pid}"
        fi
    done

    if [ -n "$stale" ]; then
        log_warn "${label}: stale ${proc_name} process(es):${stale}. Killing."
        for pid in $stale; do
            kill "$pid" 2>/dev/null || true
        done
        sleep 1
    fi

    if [ -n "$other" ]; then
        log_error "${label}: another process owns the port:${other}"
        ps -p $other -o pid,comm,args 2>/dev/null || true
        return 1
    fi
}

server_transport_block() {
    local pool_max=100

    [ "$TCP_MUX" = "false" ] && pool_max=400

    cat <<EOF
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = ${MUX_KEEPALIVE}
transport.tcpKeepalive = 30
transport.maxPoolCount = ${pool_max}
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

remove_transport_lines() {
    local file="$1"
    local tmp

    tmp="$(mktemp)"

    grep -Ev \
        '^[[:space:]]*(transport\.tcpMux|transport\.tcpMuxKeepaliveInterval|transport\.tcpKeepalive|transport\.maxPoolCount|transport\.poolCount|transport\.heartbeatInterval|transport\.heartbeatTimeout|transport\.dialServerTimeout|transport\.dialServerKeepalive|transport\.kcp\.[A-Za-z]+|userConnTimeout)[[:space:]]*=' \
        "$file" > "$tmp"

    mv "$tmp" "$file"
}

patch_transport_block() {
    local file="$1"
    local side="$2"
    local pool="${3:-5}"
    local tmp block

    [ -f "$file" ] || return 1

    remove_transport_lines "$file"

    tmp="$(mktemp)"

    if [ "$side" = "server" ]; then
        block="$(server_transport_block)
userConnTimeout = ${USER_CONN_TIMEOUT}"
    else
        block="$(client_transport_block "$pool")"
    fi

    awk -v block="$block" '
        BEGIN { inserted=0 }
        /^\[\[proxies\]\]/ && !inserted {
            print block
            print ""
            inserted=1
        }
        { print }
        END {
            if (!inserted) {
                print ""
                print block
            }
        }
    ' "$file" > "$tmp"

    mv "$tmp" "$file"
}

current_pool_count() {
    local file="$1"
    local p

    p="$(grep -oP \
        '^[[:space:]]*transport\.poolCount[[:space:]]*=[[:space:]]*\K[0-9]+' \
        "$file" 2>/dev/null | head -n1 || true)"

    if [ "$TCP_MUX" = "true" ]; then
        if [ -z "$p" ] || [ "$p" -gt 10 ]; then
            p=5
        fi
    else
        if [ -z "$p" ] || [ "$p" -lt 10 ]; then
            p=25
        fi
    fi

    echo "$p"
}

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

verify_config() {
    local binary="$1"
    local config="$2"

    if [ ! -x "$binary" ]; then
        log_error "Missing binary: $binary"
        return 1
    fi

    if [ ! -f "$config" ]; then
        log_error "Missing config: $config"
        return 1
    fi

    log_step "Verifying $(basename "$config")..."

    if "$binary" verify -c "$config"; then
        log_ok "Configuration is valid."
        return 0
    fi

    log_error "Configuration verification FAILED."
    return 1
}

install_watchdog() {
    local side="$1"

    log_step "Installing watchdog for ${side}..."

    cat > /usr/local/bin/frp-watchdog.sh <<EOF
#!/usr/bin/env bash
FRP_PORT="${FRP_PORT}"
ADMIN_PORT_S="${ADMIN_PORT_S}"
ADMIN_PORT_C="${ADMIN_PORT_C}"
FRP_TOKEN="${FRP_TOKEN}"
FAIL_THRESHOLD=${WD_FAIL_THRESHOLD}
RESTART_COOLDOWN=${WD_COOLDOWN}
START_GRACE=${WD_GRACE}
EOF

    cat >> /usr/local/bin/frp-watchdog.sh <<'EOF'
LOG_FILE="/var/log/frp-watchdog.log"
MAX_LOG_SIZE=1048576
STATE_DIR="/run/frp-watchdog"
API_TIMEOUT=8

mkdir -p "$STATE_DIR"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

rotate_log() {
    if [ -f "$LOG_FILE" ] &&
       [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt "$MAX_LOG_SIZE" ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
    fi
}

read_count() {
    local f="${STATE_DIR}/$1.fails"
    [ -f "$f" ] && cat "$f" || echo 0
}

write_count() {
    echo "$2" > "${STATE_DIR}/$1.fails"
}

unit_exists() {
    systemctl cat "$1" >/dev/null 2>&1
}

started_recently() {
    local ts now

    ts="$(systemctl show -p ActiveEnterTimestampMonotonic \
        --value "$1" 2>/dev/null || true)"

    [ -z "$ts" ] || [ "$ts" = "0" ] && return 1

    now="$(awk '{printf "%d", $1 * 1000000}' /proc/uptime)"
    [ $(( (now - ts) / 1000000 )) -lt "$START_GRACE" ]
}

can_restart_now() {
    local key="$1"
    local ts_file="${STATE_DIR}/${key}.last_restart"
    local now last

    now="$(date +%s)"

    if [ -f "$ts_file" ]; then
        last="$(cat "$ts_file" 2>/dev/null || echo 0)"
        if [ $((now - last)) -lt "$RESTART_COOLDOWN" ]; then
            return 1
        fi
    fi

    echo "$now" > "$ts_file"
    return 0
}

do_restart() {
    local proc="$1"
    local unit="$2"
    local key="$3"

    unit_exists "${unit}.service" || return 0

    if started_recently "${unit}.service"; then
        log_msg "WATCHDOG: ${proc} started recently; waiting."
        return 0
    fi

    if ! can_restart_now "$key"; then
        log_msg "WATCHDOG: restart cooldown active for ${proc}."
        return 0
    fi

    log_msg "WATCHDOG: restarting ${unit}.service"
    systemctl reset-failed "${unit}.service" >/dev/null 2>&1 || true
    systemctl restart "${unit}.service" >/dev/null 2>&1 || true

    sleep 5

    if pgrep -x "$proc" >/dev/null 2>&1; then
        log_msg "WATCHDOG: ${proc} restarted OK"
        write_count "$key" 0
    else
        log_msg "WATCHDOG: ${proc} restart FAILED"
    fi
}

bump_fail() {
    local key="$1"
    local msg="$2"
    local proc="$3"
    local unit="$4"
    local n

    n=$(( $(read_count "$key") + 1 ))
    write_count "$key" "$n"

    log_msg "WATCHDOG: ${msg} (${n}/${FAIL_THRESHOLD})"

    if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
        do_restart "$proc" "$unit" "$key"
    fi
}

check_admin_api() {
    local port="$1"

    curl -sf --max-time "$API_TIMEOUT" \
        -u "admin:${FRP_TOKEN}" \
        "http://127.0.0.1:${port}/api/status" \
        >/dev/null 2>&1
}

check_frps() {
    local key="frps"
    local unit="frps@server-${FRP_PORT}"

    unit_exists "${unit}.service" || return 0

    if ! pgrep -x frps >/dev/null 2>&1; then
        log_msg "WATCHDOG: frps process not running"
        do_restart frps "$unit" "$key"
        return
    fi

    if ! ss -H -ltnp 2>/dev/null |
        grep -qE ":${FRP_PORT}[[:space:]]"; then
        log_msg "WATCHDOG: frps not listening on ${FRP_PORT}"
        do_restart frps "$unit" "$key"
        return
    fi

    if check_admin_api "$ADMIN_PORT_S"; then
        write_count "$key" 0
    else
        bump_fail "$key" "frps admin API failed" frps "$unit"
    fi
}

check_frpc() {
    local key="frpc"
    local unit="frpc@client-${FRP_PORT}"
    local status

    unit_exists "${unit}.service" || return 0

    if ! pgrep -x frpc >/dev/null 2>&1; then
        log_msg "WATCHDOG: frpc process not running"
        do_restart frpc "$unit" "$key"
        return
    fi

    status="$(curl -sf --max-time "$API_TIMEOUT" \
        -u "admin:${FRP_TOKEN}" \
        "http://127.0.0.1:${ADMIN_PORT_C}/api/status" \
        2>/dev/null || true)"

    if [ -z "$status" ]; then
        bump_fail "$key" "frpc admin API failed" frpc "$unit"
        return
    fi

    if echo "$status" | grep -q '"status":"running"'; then
        write_count "$key" 0
    else
        bump_fail "$key" "frpc has no running proxy" frpc "$unit"
    fi
}

rotate_log
mkdir -p "$STATE_DIR"

(
    flock -n 200 || {
        log_msg "WATCHDOG: previous check still running; skipping."
        exit 0
    }

    case "$1" in
        frps) check_frps ;;
        frpc) check_frpc ;;
        *) log_msg "WATCHDOG: usage: $0 {frps|frpc}" ;;
    esac
) 200>"${STATE_DIR}/${1}.lock"
EOF

    chmod 755 /usr/local/bin/frp-watchdog.sh

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

    systemctl disable --now frp-watchdog@frps.timer \
        >/dev/null 2>&1 || true
    systemctl disable --now frp-watchdog@frpc.timer \
        >/dev/null 2>&1 || true

    systemctl enable --now "frp-watchdog@${side}.timer" \
        >/dev/null 2>&1 || true

    log_info "Watchdog installed for ${side}."
}

remove_watchdog() {
    systemctl disable --now frp-watchdog@frps.timer \
        >/dev/null 2>&1 || true
    systemctl disable --now frp-watchdog@frpc.timer \
        >/dev/null 2>&1 || true

    rm -f /etc/systemd/system/frp-watchdog@.service
    rm -f /etc/systemd/system/frp-watchdog@.timer
    rm -f /usr/local/bin/frp-watchdog.sh

    rm -f /var/log/frp-watchdog.log
    rm -f /var/log/frp-watchdog.log.old
    rm -rf /run/frp-watchdog /var/run/frp-watchdog

    systemctl daemon-reload
}

count_ports() {
    local ports="$1"
    local IFS=','
    local total=0
    local entry start end

    read -ra PORT_ARRAY <<< "$ports"

    for entry in "${PORT_ARRAY[@]}"; do
        entry="$(echo "$entry" | tr -d ' ')"
        [ -z "$entry" ] && continue

        if [[ "$entry" == *-* ]]; then
            start="${entry%%-*}"
            end="${entry##*-}"

            if ! [[ "$start" =~ ^[0-9]+$ &&
                    "$end" =~ ^[0-9]+$ &&
                    "$end" -ge "$start" ]]; then
                continue
            fi

            total=$((total + end - start + 1))
        else
            [[ "$entry" =~ ^[0-9]+$ ]] &&
                total=$((total + 1))
        fi
    done

    echo "$total"
}

validate_port_list() {
    local ports="$1"
    local IFS=','
    local entry start end

    read -ra PORT_ARRAY <<< "$ports"

    for entry in "${PORT_ARRAY[@]}"; do
        entry="$(echo "$entry" | tr -d ' ')"
        [ -z "$entry" ] && continue

        if [[ "$entry" == *-* ]]; then
            start="${entry%%-*}"
            end="${entry##*-}"

            if ! [[ "$start" =~ ^[0-9]+$ &&
                    "$end" =~ ^[0-9]+$ &&
                    "$start" -ge 1 &&
                    "$end" -le 65535 &&
                    "$end" -ge "$start" ]]; then
                return 1
            fi
        else
            if ! [[ "$entry" =~ ^[0-9]+$ ]] ||
               [ "$entry" -lt 1 ] ||
               [ "$entry" -gt 65535 ]; then
                return 1
            fi
        fi
    done

    return 0
}

generate_proxies() {
    local kind="$1"
    local ports="$2"
    local config_file="$3"
    local IFS=','
    local entry start end p

    read -ra PORT_ARRAY <<< "$ports"

    for entry in "${PORT_ARRAY[@]}"; do
        entry="$(echo "$entry" | tr -d ' ')"
        [ -z "$entry" ] && continue

        if [[ "$entry" == *-* ]]; then
            start="${entry%%-*}"
            end="${entry##*-}"

            for ((p=start; p<=end; p++)); do
                cat >> "$config_file" <<EOF

[[proxies]]
name = "${kind}-${p}"
type = "${kind}"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
EOF
            done
        else
            cat >> "$config_file" <<EOF

[[proxies]]
name = "${kind}-${entry}"
type = "${kind}"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}
EOF
        fi
    done
}

exit_node_google_check() {
    GOOGLE_V4_OK=""
    GOOGLE_V6_BROKEN=""

    echo ""
    log_step "Exit-node destination test"

    if getent ahostsv4 www.google.com >/dev/null 2>&1; then
        log_ok "DNS: IPv4 resolution works."
    else
        log_error "DNS: www.google.com does not resolve over IPv4."
        return
    fi

    local code

    code="$(curl -4 -sS -o /dev/null -w '%{http_code}' \
        --max-time 12 https://www.google.com 2>/dev/null || true)"

    case "$code" in
        200|301|302)
            log_ok "IPv4 -> Google: HTTP ${code}"
            GOOGLE_V4_OK="yes"
            ;;
        403|429)
            log_error "IPv4 -> Google: HTTP ${code}"
            log_warn "The exit IP may be rate-limited or blocked."
            ;;
        *)
            log_error "IPv4 -> Google FAILED (${code:-timeout})"
            log_warn "Check exit-node routing, firewall and upstream connectivity."
            ;;
    esac

    if host_has_global_ipv6; then
        if ipv6_egress_works; then
            log_ok "IPv6 -> Google works."
        else
            log_error "Global IPv6 exists but IPv6 -> Google FAILED."
            GOOGLE_V6_BROKEN="yes"
        fi
    else
        log_ok "No global IPv6 detected."
    fi

    local cli="/root/frp/client/client-${FRP_PORT}.toml"

    if [ -f "$cli" ] &&
       grep -qE '^[[:space:]]*type[[:space:]]*=[[:space:]]*"udp"' "$cli"; then
        log_warn "UDP proxies are enabled."
        log_warn "If your application does not require UDP, TCP-only is safer."
    else
        log_ok "No UDP proxies in client config."
    fi

    if quic_block_active; then
        log_ok "Outbound UDP/443 is currently REJECTed."
    else
        log_warn "Outbound UDP/443 is allowed."
    fi
}

offer_exit_node_fixes() {
    echo ""

    if [ -n "$GOOGLE_V6_BROKEN" ]; then
        log_warn "Most Iran exit-node proxy software (Xray/V2Ray/sing-box/Hysteria/etc.) is written in Go and IGNORES /etc/gai.conf."
        log_warn "If that describes what's listening behind this tunnel, option 1 alone will NOT fix Google/YouTube-style failures - only option 2 will."
        read -r -p \
            "IPv6 is broken. Fix? (1=prefer IPv4 only, 2=disable IPv6 system-wide [recommended], n=skip) [2]: " v6fix
        v6fix="${v6fix:-2}"

        case "$v6fix" in
            1)
                prefer_ipv4_resolution
                log_warn "If Google/YouTube/other dual-stack sites still fail, re-run this check and choose option 2, or set the outbound domain strategy to IPv4-only inside your proxy app's own config."
                ;;
            2)
                prefer_ipv4_resolution
                hard_disable_ipv6
                log_warn "IPv6 is now off system-wide. If you manage this box over its IPv6 address (SSH, etc.), reconnect using its IPv4 address."
                ;;
            *) log_warn "IPv6 fix skipped." ;;
        esac
    fi

    if ! quic_block_active; then
        log_warn "Google properties aggressively prefer QUIC (UDP/443). If this exit node's outbound UDP is silently dropped upstream (no ICMP unreachable), browsers can hang or fail to load Google/YouTube while plain-TCP sites work fine."
        read -r -p \
            "Reject outbound UDP/443 to force TCP fallback? (y/n) [y]: " qb
        qb="${qb:-y}"

        if [[ "$qb" =~ ^[Yy]$ ]]; then
            enable_quic_block
        fi
    fi
}

path_mtu_probe() {
    local target="$1"

    [ -z "$target" ] && return 0

    local lo=1200
    local hi=1472
    local mid best=0

    if ! command_exists ping; then
        echo 0
        return
    fi

    while [ "$lo" -le "$hi" ]; do
        mid=$(( (lo + hi) / 2 ))

        if ping -4 -M do -s "$mid" -c 1 -W 2 \
            "$target" >/dev/null 2>&1; then
            best="$mid"
            lo=$((mid + 1))
        else
            hi=$((mid - 1))
        fi
    done

    if [ "$best" -gt 0 ]; then
        echo $((best + 28))
    else
        echo 0
    fi
}

verify_proxy_ports() {
    local json ports
    local srv="/root/frp/server/server-${FRP_PORT}.toml"

    json="$(curl -sf --max-time 5 \
        -u "admin:${FRP_TOKEN}" \
        "http://127.0.0.1:${ADMIN_PORT_S}/api/proxy/tcp" \
        2>/dev/null || true)"

    if [ -z "$json" ]; then
        log_warn "Could not read frps proxy API."
        return
    fi

    if command_exists python3; then
        ports="$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for p in d.get("proxies", []) or []:
    c = p.get("conf") or {}
    rp = c.get("remotePort")
    if rp is not None:
        print(rp)
' | sort -un)"
    else
        ports="$(printf '%s' "$json" |
            grep -oE '"remotePort"[[:space:]]*:[[:space:]]*[0-9]+' |
            grep -oE '[0-9]+' | sort -un || true)"
    fi

    if [ -z "$ports" ]; then
        log_warn "No registered TCP proxies found."
        return
    fi

    local bad=0
    local p line

    for p in $ports; do
        line="$(ss -H -ltnp 2>/dev/null |
            grep -E ":${p}[[:space:]]" || true)"

        if [ -z "$line" ]; then
            log_error "Port ${p}: nothing is listening."
            bad=1
        elif echo "$line" | grep -q 'users:(("frps"'; then
            log_ok "Port ${p}: frps is listening."
        else
            log_error "Port ${p}: another process appears to own the port."
            echo "$line"
            bad=1
        fi

        if command_exists iptables; then
            local nat_hit
            nat_hit="$(iptables -t nat -L PREROUTING -n --line-numbers \
                2>/dev/null |
                grep -E "dpt:${p}([^0-9]|$)" || true)"

            if [ -n "$nat_hit" ]; then
                log_warn "Port ${p}: NAT/PREROUTING rule also matches:"
                echo "$nat_hit"
            fi
        fi
    done

    if [ "$bad" -eq 0 ]; then
        log_info "Registered proxy ports look healthy."
    else
        log_error "One or more proxy ports have ownership/listener problems."
    fi

    [ -f "$srv" ] || true
}

diagnose_destinations() {
    echo "================================================================"
    echo "   DIAGNOSE: tunnel up, but selected destinations fail"
    echo "================================================================"

    local is_server=false
    local is_client=false

    systemctl cat "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1 && is_server=true

    systemctl cat "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 && is_client=true

    if [ "$is_client" = false ] && [ "$is_server" = false ]; then
        log_warn "No FRP service was found on this machine."
        return
    fi

    echo ""
    echo "--- Tunnel mode ---"

    local f cfgmux
    for f in \
        "/root/frp/server/server-${FRP_PORT}.toml" \
        "/root/frp/client/client-${FRP_PORT}.toml"; do

        [ -f "$f" ] || continue

        cfgmux="$(grep -oP \
            '^[[:space:]]*transport\.tcpMux[[:space:]]*=[[:space:]]*\K(true|false)' \
            "$f" 2>/dev/null | head -n1 || true)"

        echo "  $(basename "$f"): tcpMux=${cfgmux:-default}"
    done

    if [ "$is_client" = true ]; then
        echo ""
        echo "--- Exit-node reachability ---"
        exit_node_google_check

        echo ""
        echo "--- Path MTU to FRP server ---"

        local cli="/root/frp/client/client-${FRP_PORT}.toml"
        local sa mtu

        sa="$(grep -oP \
            '^[[:space:]]*serverAddr[[:space:]]*=[[:space:]]*"\K[^"]+' \
            "$cli" 2>/dev/null | head -n1 || true)"

        if [ -n "$sa" ]; then
            mtu="$(path_mtu_probe "$sa")"

            if [ "$mtu" -gt 0 ]; then
                if [ "$mtu" -lt 1500 ]; then
                    log_warn "Measured IPv4 path MTU: ${mtu}"
                    log_warn "For UDP/L3 applications, consider reducing their own MTU."
                else
                    log_ok "Measured IPv4 path MTU: ${mtu}"
                fi
            else
                log_warn "ICMP/DF MTU probe failed or is filtered."
            fi
        fi

        offer_exit_node_fixes
    fi

    if [ "$is_server" = true ]; then
        echo ""
        echo "--- Iran server proxy ownership ---"
        verify_proxy_ports
    fi

    echo ""
    echo "================================================================"
    echo " Interpretation:"
    echo "  UDP enabled       -> disable unless the application needs UDP."
    echo "  Broken IPv6       -> prefer IPv4 or disable IPv6."
    echo "  Google 403/429    -> likely exit-IP reputation/rate limiting."
    echo "  Google IPv4 fail  -> exit-node routing/firewall/upstream issue."
    echo "  All tests green   -> try Parallel mode on BOTH sides."
    echo "================================================================"
}

install_server() {
    log_step "=== Installing FRP Server (frps) on IRAN ==="
    log_ir "Reverse tunnel: OUTSIDE frpc -> IRAN frps"

    choose_mux_mode

    systemctl stop "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    systemctl reset-failed "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    free_stale_port "$FRP_PORT" frps "FRP bind port" || return 1
    free_stale_port "$ADMIN_PORT_S" frps "Admin port" || return 1

    download_frp_binary frps || return 1

    mkdir -p /root/frp/server /var/log

    open_firewall_port "$FRP_PORT" tcp

    read -r -p \
        "Expose frps dashboard publicly? (y/n) [n]: " pub_dash

    if [[ "$pub_dash" =~ ^[Yy]$ ]]; then
        ADMIN_BIND_S="0.0.0.0"
        open_firewall_port "$ADMIN_PORT_S" tcp
        log_warn "Dashboard is public. Protect it with a strong token."
    else
        ADMIN_BIND_S="127.0.0.1"
    fi

    local cert_block=""
    local use_cert cert_file key_file

    read -r -p \
        "Use a real TLS certificate on frps? (y/n) [n]: " use_cert

    if [[ "$use_cert" =~ ^[Yy]$ ]]; then
        read -r -p "Full path to fullchain.pem: " cert_file
        read -r -p "Full path to privkey.pem: " key_file

        if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
            cert_block="transport.tls.certFile = \"${cert_file}\"
transport.tls.keyFile = \"${key_file}\""
            log_ok "Real TLS certificate configured."
        else
            log_warn "Certificate/key not found; using FRP TLS."
        fi
    fi

    cat > "/root/frp/server/server-${FRP_PORT}.toml" <<EOF
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

    if ! verify_config \
        /usr/local/bin/frps \
        "/root/frp/server/server-${FRP_PORT}.toml"; then
        return 1
    fi

    write_server_unit
    systemctl daemon-reload

    systemctl enable "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    free_stale_port "$FRP_PORT" frps "FRP bind port" || return 1
    free_stale_port "$ADMIN_PORT_S" frps "Admin port" || return 1

    tune_tcp_for_frp

    systemctl reset-failed "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    systemctl restart "frps@server-${FRP_PORT}.service"

    install_watchdog frps

    sleep 3

    if systemctl is-active --quiet "frps@server-${FRP_PORT}.service"; then
        log_info "FRP server is RUNNING."
        echo ""
        echo "------------------------------------------------------"
        echo " FRP SERVER / IRAN"
        echo "------------------------------------------------------"
        echo " Bind:       ${FRP_PORT}/tcp"
        echo " Dashboard:  ${ADMIN_BIND_S}:${ADMIN_PORT_S}"
        echo " tcpMux:     ${TCP_MUX}"
        echo "------------------------------------------------------"
        log_warn "Also open ${FRP_PORT}/tcp in your cloud/provider firewall."
    else
        log_error "FRP server failed to start."
        journalctl -u "frps@server-${FRP_PORT}" \
            --no-pager -n 30
        return 1
    fi
}

install_client() {
    log_step "=== Installing FRP Client (frpc) on OUTSIDE ==="

    choose_mux_mode

    systemctl stop "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    systemctl reset-failed "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    free_stale_port "$ADMIN_PORT_C" frpc "Client admin port" || return 1

    download_frp_binary frpc || return 1

    mkdir -p /root/frp/client /var/log

    local server_addr
    read -r -p "Enter IRAN server address: " server_addr

    while [ -z "$server_addr" ]; do
        read -r -p "Server address cannot be empty. Enter again: " server_addr
    done

    log_step "Testing ${server_addr}:${FRP_PORT}..."

    if command_exists nc &&
       nc -z -w 5 "$server_addr" "$FRP_PORT" >/dev/null 2>&1; then
        log_ok "FRP server port is reachable."
    else
        log_warn "Could not verify TCP reachability."
        read -r -p "Continue anyway? (y/n) [n]: " cont
        cont="${cont:-n}"
        [[ "$cont" =~ ^[Yy]$ ]] || return 1
    fi

    local ports
    read -r -p \
        "Inbound ports to forward [default: 8080]: " ports
    ports="${ports:-8080}"

    if ! validate_port_list "$ports"; then
        log_error "Invalid port/range list: ${ports}"
        return 1
    fi

    echo ""
    log_warn "UDP forwarding is OFF by default."
    log_warn "Enable it only if the actual application requires UDP."

    local forward_udp
    read -r -p \
        "Forward UDP ports too? (y/n) [n]: " forward_udp
    forward_udp="${forward_udp:-n}"

    echo ""
    echo "Connection load:"
    echo "  1) Light"
    echo "  2) Medium [default]"
    echo "  3) Heavy"

    local load_choice
    read -r -p "Select [1-3]: " load_choice
    load_choice="${load_choice:-2}"

    local base_pool pool_cap n_ports pool_count total_pool

    if [ "$TCP_MUX" = "true" ]; then
        case "$load_choice" in
            1) base_pool=2 ;;
            3) base_pool=10 ;;
            *) base_pool=5 ;;
        esac
        pool_cap=100
    else
        case "$load_choice" in
            1) base_pool=10 ;;
            3) base_pool=50 ;;
            *) base_pool=25 ;;
        esac
        pool_cap=400
    fi

    n_ports="$(count_ports "$ports")"
    [ "$n_ports" -lt 1 ] && n_ports=1

    pool_count="$base_pool"
    total_pool=$((n_ports * base_pool))

    if [ "$total_pool" -gt "$pool_cap" ]; then
        pool_count=$((pool_cap / n_ports))
        [ "$pool_count" -lt 1 ] && pool_count=1
    fi

    echo ""
    echo "TLS SNI:"
    echo "  1) Basic TLS"
    echo "  2) Custom SNI/domain"
    echo ""
    read -r -p "Select [1-2, default 1]: " tls_choice
    tls_choice="${tls_choice:-1}"

    local tls_config=""
    local sni_note=""

    case "$tls_choice" in
        2)
            local sni
            read -r -p \
                "Enter TLS serverName [${server_addr}]: " sni
            sni="${sni:-$server_addr}"

            tls_config="transport.tls.serverName = \"${sni}\""
            sni_note="$sni"
            ;;
        *)
            sni_note="$server_addr"
            ;;
    esac

    cat > "/root/frp/client/client-${FRP_PORT}.toml" <<EOF
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

transport.protocol = "tcp"
$(client_transport_block "$pool_count")
${tls_config}
EOF

    generate_proxies \
        tcp \
        "$ports" \
        "/root/frp/client/client-${FRP_PORT}.toml"

    if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
        log_warn "Adding UDP proxies."
        generate_proxies \
            udp \
            "$ports" \
            "/root/frp/client/client-${FRP_PORT}.toml"
    fi

    if ! verify_config \
        /usr/local/bin/frpc \
        "/root/frp/client/client-${FRP_PORT}.toml"; then
        return 1
    fi

    write_client_unit
    systemctl daemon-reload

    systemctl enable "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    free_stale_port "$ADMIN_PORT_C" frpc "Client admin port" || return 1

    tune_tcp_for_frp

    systemctl reset-failed "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    systemctl restart "frpc@client-${FRP_PORT}.service"

    install_watchdog frpc

    echo ""
    exit_node_google_check
    offer_exit_node_fixes

    sleep 3

    if systemctl is-active --quiet "frpc@client-${FRP_PORT}.service"; then
        log_info "FRP client service is RUNNING."
        echo ""
        echo "------------------------------------------------------"
        echo " FRP CLIENT / OUTSIDE"
        echo "------------------------------------------------------"
        echo " Iran server: ${server_addr}:${FRP_PORT}"
        echo " SNI:         ${sni_note}"
        echo " tcpMux:      ${TCP_MUX}"
        echo " Pool:        ${pool_count}"
        echo " TCP ports:   ${ports}"

        if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
            echo " UDP ports:   ${ports}"
        fi

        echo "------------------------------------------------------"
    else
        log_error "FRP client failed to start."
        journalctl -u "frpc@client-${FRP_PORT}" \
            --no-pager -n 30
        return 1
    fi
}

remove_udp_proxies() {
    local cli="$1"
    local backup

    [ -f "$cli" ] || return 0

    backup="${cli}.bak.$(date +%s)"
    cp -a "$cli" "$backup"

    python3 - "$cli" <<'PY'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()

parts = re.split(r'(?m)^(?=\[\[proxies\]\])', text)
if not parts:
    raise SystemExit(0)

head = parts[0]
blocks = parts[1:]

kept = []
for block in blocks:
    if re.search(r'(?m)^\s*type\s*=\s*"udp"\s*$', block):
        continue
    kept.append(block)

open(path, "w", encoding="utf-8").write(head + "".join(kept))
PY

    log_fix "UDP proxy blocks removed. Backup: ${backup}"
}

apply_stability_fix() {
    log_step "=== Applying fixes to existing FRP installation ==="

    choose_mux_mode

    local touched=false
    local srv="/root/frp/server/server-${FRP_PORT}.toml"
    local cli="/root/frp/client/client-${FRP_PORT}.toml"

    if [ -f "$srv" ]; then
        cp -a "$srv" "${srv}.bak.$(date +%s)"
        patch_transport_block "$srv" server || return 1
        touched=true
        log_ok "Server transport block patched."
    fi

    if [ -f "$cli" ]; then
        cp -a "$cli" "${cli}.bak.$(date +%s)"

        if grep -qE \
            '^[[:space:]]*type[[:space:]]*=[[:space:]]*"udp"' "$cli"; then

            read -r -p \
                "Remove UDP proxies? (y/n) [y]: " rm_udp
            rm_udp="${rm_udp:-y}"

            if [[ "$rm_udp" =~ ^[Yy]$ ]]; then
                if command_exists python3; then
                    remove_udp_proxies "$cli"
                else
                    log_error "python3 is required to safely remove UDP blocks."
                    return 1
                fi
            fi
        fi

        local pool
        pool="$(current_pool_count "$cli")"
        patch_transport_block "$cli" client "$pool" || return 1

        touched=true
        log_ok "Client transport block patched."
    fi

    if [ "$touched" = false ]; then
        log_warn "No FRP configuration found under /root/frp."
        return 1
    fi

    tune_tcp_for_frp
    systemctl daemon-reload

    if [ -f "$srv" ]; then
        verify_config /usr/local/bin/frps "$srv" || return 1

        free_stale_port "$FRP_PORT" frps "FRP bind port" || return 1
        free_stale_port "$ADMIN_PORT_S" frps "Admin port" || return 1

        systemctl restart "frps@server-${FRP_PORT}.service"
        install_watchdog frps
    fi

    if [ -f "$cli" ]; then
        verify_config /usr/local/bin/frpc "$cli" || return 1

        free_stale_port "$ADMIN_PORT_C" frpc "Client admin port" || return 1

        systemctl restart "frpc@client-${FRP_PORT}.service"
        install_watchdog frpc

        exit_node_google_check
        offer_exit_node_fixes
    fi

    log_info "Existing installation updated."
}

check_status() {
    echo "================================================"
    echo "              FRP Health Status"
    echo "================================================"

    local has_service=false

    if systemctl cat "frps@server-${FRP_PORT}.service" \
        >/dev/null 2>&1; then

        has_service=true

        echo ""
        echo "--- FRP Server / IRAN ---"

        systemctl status "frps@server-${FRP_PORT}.service" \
            --no-pager 2>&1 | head -n 15 || true

        echo ""
        echo "--- Clients ---"

        curl -sf --max-time 5 \
            -u "admin:${FRP_TOKEN}" \
            "http://127.0.0.1:${ADMIN_PORT_S}/api/serverinfo" \
            2>/dev/null |
            grep -oE '"clientCounts"[[:space:]]*:[[:space:]]*[0-9]+' ||
            echo "Admin API unavailable."

        echo ""
        verify_proxy_ports
    fi

    if systemctl cat "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1; then

        has_service=true

        echo ""
        echo "--- FRP Client / OUTSIDE ---"

        systemctl status "frpc@client-${FRP_PORT}.service" \
            --no-pager 2>&1 | head -n 15 || true

        echo ""
        echo "--- Connection status ---"

        local status
        status="$(curl -sf --max-time 5 \
            -u "admin:${FRP_TOKEN}" \
            "http://127.0.0.1:${ADMIN_PORT_C}/api/status" \
            2>/dev/null || true)"

        if [ -n "$status" ]; then
            local running total
            running="$(echo "$status" |
                grep -o '"status":"running"' |
                wc -l)"

            total="$(echo "$status" |
                grep -o '"status":"' |
                wc -l)"

            if [ "$running" -gt 0 ]; then
                log_ok "ONLINE - ${running}/${total} proxies running."
            else
                log_error "No running proxies detected."
            fi
        else
            log_warn "Client admin API unavailable."
        fi

        echo ""
        echo "--- Exit-node destination health ---"
        exit_node_google_check
    fi

    if [ "$has_service" = false ]; then
        log_warn "No FRP service found."
    fi

    if [ -f /var/log/frp-watchdog.log ]; then
        echo ""
        echo "--- Watchdog ---"
        tail -n 8 /var/log/frp-watchdog.log 2>/dev/null || true
    fi

    echo ""
    echo "--- Kernel ---"

    sysctl \
        net.ipv4.tcp_congestion_control \
        net.ipv4.tcp_keepalive_time \
        net.ipv4.tcp_mtu_probing \
        net.ipv4.tcp_base_mss \
        net.ipv4.ip_local_port_range \
        2>/dev/null || true

    sysctl \
        net.netfilter.nf_conntrack_tcp_timeout_established \
        2>/dev/null || true
}

live_logs() {
    echo "1) frps / Iran"
    echo "2) frpc / Outside"
    echo "3) watchdog"

    local l
    read -r -p "Select [1-3]: " l

    case "$l" in
        1)
            journalctl \
                -u "frps@server-${FRP_PORT}" \
                -f --no-pager
            ;;
        2)
            journalctl \
                -u "frpc@client-${FRP_PORT}" \
                -f --no-pager
            ;;
        3)
            touch /var/log/frp-watchdog.log
            tail -f /var/log/frp-watchdog.log
            ;;
        *)
            log_warn "Invalid choice."
            ;;
    esac
}

remove_frp() {
    log_step "=== Removing FRP ==="

    systemctl stop \
        "frps@server-${FRP_PORT}.service" \
        "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    systemctl disable \
        "frps@server-${FRP_PORT}.service" \
        "frpc@client-${FRP_PORT}.service" \
        >/dev/null 2>&1 || true

    pkill -9 -x frps 2>/dev/null || true
    pkill -9 -x frpc 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service
    rm -f /etc/systemd/system/frpc@.service

    rm -rf /root/frp

    rm -f /usr/local/bin/frps
    rm -f /usr/local/bin/frpc

    remove_watchdog
    disable_quic_block
    remove_tcp_tuning

    rm -f /etc/sysctl.d/98-frp-disable-ipv6.conf

    sysctl --system >/dev/null 2>&1 || true
    systemctl daemon-reload

    log_info "FRP services, configs and script-created tuning were removed."
    log_warn "Firewall rules previously created by this script may remain in UFW/firewalld/iptables."
}

show_menu() {
    clear

    echo "================================================"
    echo " FRP Iran Tunnel - v4 CLEAN / FIXED"
    echo "             FRP v${FRP_VERSION}"
    echo "================================================"
    echo " Default mux: ${TCP_MUX} | Port: ${FRP_PORT}"
    echo "------------------------------------------------"
    echo " 1) Install FRP Server (frps) - IRAN"
    echo " 2) Install FRP Client (frpc) - OUTSIDE"
    echo " 3) Check Status / Health"
    echo " 4) Apply fixes to EXISTING installation"
    echo " 5) Diagnose destination failures"
    echo " 6) Live logs"
    echo " 7) Remove FRP"
    echo " 8) Exit"
    echo "================================================"
    read -r -p "Choose an option [1-8]: " choice
}

main() {
    require_root

    if ! ensure_dependencies; then
        exit 1
    fi

    while true; do
        show_menu

        case "$choice" in
            1)
                install_server
                ;;
            2)
                install_client
                ;;
            3)
                check_status
                ;;
            4)
                apply_stability_fix
                ;;
            5)
                diagnose_destinations
                ;;
            6)
                live_logs
                ;;
            7)
                echo ""
                read -r -p \
                    "Remove FRP completely? (y/n) [n]: " confirm
                confirm="${confirm:-n}"

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    remove_frp
                else
                    log_info "Removal cancelled."
                fi
                ;;
            8)
                log_info "Exiting."
                exit 0
                ;;
            *)
                log_warn "Invalid option. Select 1-8."
                ;;
        esac

        echo ""
        read -r -p "Press Enter to return to menu..."
    done
}

main "$@"
