#!/bin/bash
# =============================================================================
#  FRP Reverse Tunnel Manager  --  v3.0  (TCP-ONLY EDITION)
# =============================================================================
#  Topology:   Users --> [IRAN server : frps] ==TCP+TLS==> [FOREIGN server : frpc] --> local service
#
#  WHAT CHANGED IN v3.0
#  --------------------
#  1) FRP core pinned to v0.71.0 (latest stable). It contains the upstream fix
#     for the leaked control session when frpc reconnects over a half-open
#     tcpMux connection -- that bug was a direct cause of "drops every few
#     minutes then comes back".
#  2) TCP ONLY. The whole protocol menu (wss / websocket / kcp / quic) is gone,
#     together with every non-TCP config branch. The client hard-codes
#     transport.protocol = "tcp". Re-running the repair option also migrates an
#     old wss/kcp/quic install to TCP.
#  3) MTU / MSS black-hole fix -- this is the real cause of
#     "tunnel is up, traffic flows, but SOME sites never load".
#     frp is a TCP *relay*, not an IP encapsulator, so the stall does not come
#     from packet-in-packet overhead; it comes from the path between the end
#     user and the Iran server (mobile / PPPoE / stacked tunnels reduce MTU to
#     ~1400) combined with ICMP "fragmentation needed" being filtered.
#     Result: the handshake and small requests succeed, but the first full-size
#     data segment is silently dropped -> heavy pages hang forever while light
#     ones work. Fixed by clamping the advertised MSS on both boxes, made
#     persistent through a systemd unit, plus kernel MTU probing as a backstop.
#  4) Two more real "some sites don't load" causes are now detected and fixed:
#     broken IPv6 on the exit node (AAAA sites like Google/Cloudflare die while
#     IPv4-only sites work) and broken DNS on the exit node.
#  5) Remaining TCP-layer issues fixed: conntrack liberal window checking
#     (out-of-window drops on relayed flows = random frozen connections),
#     tcp_no_metrics_save (a bad cwnd cached during a lossy minute poisoned
#     every later connection), saner tcp_retries2, dependency pre-flight.
#
#  Menu: 1 = Iran server (frps)   2 = Foreign server (frpc)   3 = status
#        4 = repair/migrate existing install   5 = MTU/MSS fix only
#        6 = diagnose "some sites don't load"  7 = logs   8 = uninstall
# =============================================================================

set -o pipefail

# ------------------------------- constants ----------------------------------
FRP_VERSION="0.71.0"          # latest stable
FRP_DIR="/usr/local/frp"
CONF_DIR="/etc/frp"
LOG_DIR="/var/log/frp"
MSS_SCRIPT="/usr/local/bin/frp-mss-fix.sh"
MSS_UNIT="/etc/systemd/system/frp-mss.service"
SYSCTL_FILE="/etc/sysctl.d/99-frp-tunnel.conf"
LIMITS_DROPIN="/etc/systemd/system.conf.d/99-frp-limits.conf"

DEF_TOKEN="tun100"
DEF_PORT="8443"
DEF_ADMIN_S="7500"
DEF_ADMIN_C="7400"
DEF_MSS="1360"                # -> IP MTU 1400, safe on Iranian mobile/PPPoE paths

# transport tuning (identical semantics on both sides where required)
TCP_MUX="true"                # MUST be identical on frps and frpc
MUX_KEEPALIVE="20"
HB_INTERVAL="15"              # client heartbeat
HB_TIMEOUT_C="60"             # client gives up after 60s of silence
HB_TIMEOUT_S="120"            # server must be more tolerant than the client
DIAL_TIMEOUT="15"
DIAL_KEEPALIVE="15"
USER_CONN_TIMEOUT="20"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'
BLU=$'\033[0;34m'; CYN=$'\033[0;36m'; BLD=$'\033[1m'; NC=$'\033[0m'

ok()   { echo "${GRN}[ OK ]${NC} $*"; }
inf()  { echo "${BLU}[INFO]${NC} $*"; }
warn() { echo "${YEL}[WARN]${NC} $*"; }
err()  { echo "${RED}[FAIL]${NC} $*"; }
hdr()  { echo; echo "${CYN}${BLD}==> $*${NC}"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "Run this script as root:  sudo bash $0"
        exit 1
    fi
}

pause() { echo; read -r -p "Press Enter to continue..." _; }

# --------------------------- dependency pre-flight --------------------------
ensure_deps() {
    local missing=""
    command -v curl    >/dev/null 2>&1 || missing="$missing curl"
    command -v tar     >/dev/null 2>&1 || missing="$missing tar"
    command -v ss      >/dev/null 2>&1 || missing="$missing iproute2"
    command -v ping    >/dev/null 2>&1 || missing="$missing iputils-ping"
    command -v iptables>/dev/null 2>&1 || missing="$missing iptables"
    [ -z "$missing" ] && return 0

    inf "Installing missing packages:$missing"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
        # shellcheck disable=SC2086
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        dnf install -y -q $missing >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        yum install -y -q $missing >/dev/null 2>&1
    fi
    command -v curl >/dev/null 2>&1 || { err "curl is required and could not be installed."; exit 1; }
}

# ------------------------------ frp binary ----------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64"  ;;
        aarch64|arm64)  echo "arm64"  ;;
        armv7l|armv7)   echo "arm"    ;;
        i386|i686)      echo "386"    ;;
        *) err "Unsupported CPU architecture: $(uname -m)"; exit 1 ;;
    esac
}

download_frp() {
    local arch pkg url tmp
    arch="$(detect_arch)"
    pkg="frp_${FRP_VERSION}_linux_${arch}"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${pkg}.tar.gz"
    tmp="$(mktemp -d)"

    hdr "Installing frp v${FRP_VERSION} (${arch})"

    if [ -x "${FRP_DIR}/frps" ] && "${FRP_DIR}/frps" --version 2>/dev/null | grep -q "^${FRP_VERSION}$"; then
        ok "frp v${FRP_VERSION} already installed, skipping download."
        rm -rf "$tmp"; return 0
    fi

    local mirrors=(
        "$url"
        "https://ghproxy.net/${url}"
        "https://gh-proxy.com/${url}"
    )
    local got=1 m
    for m in "${mirrors[@]}"; do
        inf "Trying: ${m%%\?*}"
        if curl -fL --connect-timeout 15 --max-time 300 --retry 2 -o "${tmp}/frp.tar.gz" "$m" 2>/dev/null; then
            if tar -tzf "${tmp}/frp.tar.gz" >/dev/null 2>&1; then got=0; break; fi
        fi
        warn "Mirror failed, trying the next one."
    done
    if [ $got -ne 0 ]; then
        err "Could not download frp. Check outbound connectivity / DNS on this box."
        rm -rf "$tmp"; exit 1
    fi

    tar -xzf "${tmp}/frp.tar.gz" -C "$tmp" || { err "Archive extraction failed."; rm -rf "$tmp"; exit 1; }
    mkdir -p "$FRP_DIR" "$CONF_DIR" "$LOG_DIR"
    install -m 0755 "${tmp}/${pkg}/frps" "${FRP_DIR}/frps"
    install -m 0755 "${tmp}/${pkg}/frpc" "${FRP_DIR}/frpc"
    rm -rf "$tmp"
    ok "frp v${FRP_VERSION} installed to ${FRP_DIR}"
}

# ------------------------- kernel / TCP stack tuning ------------------------
tune_tcp() {
    hdr "Tuning the TCP stack"

    modprobe tcp_bbr 2>/dev/null
    local cc="cubic"
    grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null && cc="bbr"

    cat > "$SYSCTL_FILE" <<EOF
# managed by frp-tunnel.sh -- do not edit by hand

# --- queueing & congestion control ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${cc}

# --- socket buffers (long fat pipe Iran <-> abroad) ---
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
net.ipv4.tcp_mem = 786432 1048576 26777216

# --- MTU black-hole handling (backstop for the MSS clamp below) ---
# 1 = enable probing only after a suspected black hole is detected.
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024

# --- keepalive: notice a dead peer in ~75s instead of ~2h ---
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 3

# --- do not let one bad minute poison every later connection ---
net.ipv4.tcp_no_metrics_save = 1

# --- give up on a truly dead connection in ~100s instead of ~15min ---
net.ipv4.tcp_retries2 = 10

# --- connection handling ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 262144
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.ip_local_port_range = 10240 65000

# --- file descriptors ---
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

    # conntrack lives in a module that may not be loaded yet
    modprobe nf_conntrack 2>/dev/null
    if [ -d /proc/sys/net/netfilter ]; then
        cat >> "$SYSCTL_FILE" <<'EOF'

# --- netfilter connection tracking ---
# A relayed/idle tunnel connection must not be evicted after 5 days of default
# timers while the table fills up; and be_liberal stops conntrack from dropping
# out-of-window segments on relayed flows (a classic "random frozen tab" cause).
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_be_liberal = 1
EOF
    fi

    sysctl --system >/dev/null 2>&1
    ok "Sysctl applied (congestion control: ${cc})"

    # process-wide FD limits
    mkdir -p "$(dirname "$LIMITS_DROPIN")"
    printf '[Manager]\nDefaultLimitNOFILE=1048576\n' > "$LIMITS_DROPIN"
    if ! grep -q "frp-tunnel" /etc/security/limits.conf 2>/dev/null; then
        {
            echo "# frp-tunnel"
            echo "* soft nofile 1048576"
            echo "* hard nofile 1048576"
            echo "root soft nofile 1048576"
            echo "root hard nofile 1048576"
        } >> /etc/security/limits.conf
    fi
    systemctl daemon-reexec >/dev/null 2>&1
    ok "File-descriptor limits raised"
}

# =============================================================================
#  MSS CLAMPING  --  the fix for "tunnel works but some sites never load"
# =============================================================================
write_mss_script() {
    local mss="$1" mss6=$(( $1 - 20 ))

    cat > "$MSS_SCRIPT" <<EOF
#!/bin/bash
# managed by frp-tunnel.sh -- MSS clamping / PMTU black-hole fix
MSS4=${mss}
MSS6=${mss6}
EOF

    cat >> "$MSS_SCRIPT" <<'EOF'

rule_set() {           # $1=cmd  $2=chain  $3..=target args
    local cmd="$1" chain="$2"; shift 2
    "$cmd" -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN "$@" >/dev/null 2>&1 && return 0
    "$cmd" -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN "$@" >/dev/null 2>&1
}

rule_del() {
    local cmd="$1" chain="$2"; shift 2
    while "$cmd" -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN "$@" >/dev/null 2>&1; do
        "$cmd" -t mangle -D "$chain" -p tcp --tcp-flags SYN,RST SYN "$@" >/dev/null 2>&1 || break
    done
}

apply() {
    if command -v iptables >/dev/null 2>&1; then
        rule_set iptables OUTPUT     ! -o lo -j TCPMSS --set-mss "$MSS4"
        rule_set iptables PREROUTING ! -i lo -j TCPMSS --set-mss "$MSS4"
        rule_set iptables POSTROUTING ! -o lo -j TCPMSS --set-mss "$MSS4"
        rule_set iptables FORWARD    -j TCPMSS --clamp-mss-to-pmtu
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        rule_set ip6tables OUTPUT     ! -o lo -j TCPMSS --set-mss "$MSS6"
        rule_set ip6tables PREROUTING ! -i lo -j TCPMSS --set-mss "$MSS6"
        rule_set ip6tables POSTROUTING ! -o lo -j TCPMSS --set-mss "$MSS6"
        rule_set ip6tables FORWARD    -j TCPMSS --clamp-mss-to-pmtu
    fi
    return 0
}

remove() {
    if command -v iptables >/dev/null 2>&1; then
        rule_del iptables OUTPUT      ! -o lo -j TCPMSS --set-mss "$MSS4"
        rule_del iptables PREROUTING  ! -i lo -j TCPMSS --set-mss "$MSS4"
        rule_del iptables POSTROUTING ! -o lo -j TCPMSS --set-mss "$MSS4"
        rule_del iptables FORWARD     -j TCPMSS --clamp-mss-to-pmtu
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        rule_del ip6tables OUTPUT      ! -o lo -j TCPMSS --set-mss "$MSS6"
        rule_del ip6tables PREROUTING  ! -i lo -j TCPMSS --set-mss "$MSS6"
        rule_del ip6tables POSTROUTING ! -o lo -j TCPMSS --set-mss "$MSS6"
        rule_del ip6tables FORWARD     -j TCPMSS --clamp-mss-to-pmtu
    fi
    return 0
}

show() {
    echo "--- IPv4 mangle rules (MSS ${MSS4}) ---"
    iptables -t mangle -S 2>/dev/null | grep -i tcpmss || echo "  (none)"
    echo "--- IPv6 mangle rules (MSS ${MSS6}) ---"
    ip6tables -t mangle -S 2>/dev/null | grep -i tcpmss || echo "  (none)"
}

case "$1" in
    apply)  apply  ;;
    remove) remove ;;
    show)   show   ;;
    *) echo "usage: $0 {apply|remove|show}"; exit 1 ;;
esac
EOF
    chmod 0755 "$MSS_SCRIPT"
}

install_mss_fix() {
    local mss="${1:-$DEF_MSS}"
    hdr "Applying the MSS clamp (MSS ${mss} / IP MTU $(( mss + 40 )))"

    modprobe xt_TCPMSS 2>/dev/null
    write_mss_script "$mss"

    cat > "$MSS_UNIT" <<EOF
[Unit]
Description=FRP MSS clamping (PMTU black-hole fix)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${MSS_SCRIPT} apply
ExecStop=${MSS_SCRIPT} remove

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now frp-mss.service >/dev/null 2>&1

    if iptables -t mangle -S 2>/dev/null | grep -qi tcpmss; then
        ok "MSS clamp is active and will survive reboots."
    else
        warn "Could not verify the MSS rules. Is the xt_TCPMSS module available?"
        warn "Kernel MTU probing (tcp_mtu_probing=1) still covers most cases."
    fi
}

remove_mss_fix() {
    systemctl disable --now frp-mss.service >/dev/null 2>&1
    [ -x "$MSS_SCRIPT" ] && "$MSS_SCRIPT" remove >/dev/null 2>&1
    rm -f "$MSS_UNIT" "$MSS_SCRIPT"
    systemctl daemon-reload >/dev/null 2>&1
    ok "MSS clamp removed."
}

probe_mss() {
    local host="$1" payload mtu
    command -v ping >/dev/null 2>&1 || { echo "$DEF_MSS"; return; }
    for payload in 1472 1452 1432 1412 1392 1372 1352 1332 1312 1272 1232 1172; do
        if ping -c 1 -W 2 -M do -s "$payload" "$host" >/dev/null 2>&1; then
            mtu=$(( payload + 28 ))
            echo $(( mtu - 60 ))
            return
        fi
    done
    echo "$DEF_MSS"
}

fix_broken_ipv6() {
    hdr "Checking IPv6 health on this box"

    if ! ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
        ok "No global IPv6 address -- nothing to do."
        return 0
    fi

    if curl -6 -sf --max-time 6 -o /dev/null https://ipv6.google.com 2>/dev/null \
    || curl -6 -sf --max-time 6 -o /dev/null "https://[2606:4700:4700::1111]/" 2>/dev/null; then
        ok "IPv6 is present and actually works."
        return 0
    fi

    warn "This box advertises IPv6 but IPv6 traffic does not work."
    warn "That is a textbook cause of 'some sites never load': anything with an"
    warn "AAAA record (Google, YouTube, Cloudflare-fronted sites) is tried over"
    warn "IPv6 first and times out, while IPv4-only sites open instantly."
    inf  "Fixing by preferring IPv4 in /etc/gai.conf."

    touch /etc/gai.conf
    if ! grep -qE '^\s*precedence\s+::ffff:0:0/96\s+100' /etc/gai.conf; then
        printf '\n# frp-tunnel: broken IPv6 detected, prefer IPv4\nprecedence ::ffff:0:0/96  100\n' >> /etc/gai.conf
    fi
    ok "IPv4 is now preferred for name resolution."
}

check_dns() {
    hdr "Checking DNS on this box"
    local d bad=0
    for d in google.com cloudflare.com github.com; do
        if getent hosts "$d" >/dev/null 2>&1; then
            ok "resolves: $d"
        else
            err "does NOT resolve: $d"
            bad=1
        fi
    done
    if [ $bad -ne 0 ]; then
        warn "Broken DNS on the exit node makes 'some sites' fail while others work."
        warn "Point /etc/resolv.conf (or systemd-resolved) at 1.1.1.1 and 8.8.8.8."
    fi
    return 0
}

open_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 && inf "ufw: opened ${port}/${proto}"
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        inf "firewalld: opened ${port}/${proto}"
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
    fi
}

free_stale_port() {
    local port="$1" pids
    pids="$(ss -lntpH "sport = :${port}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"
    [ -z "$pids" ] && return 0
    warn "Port ${port} is already in use by PID(s): ${pids}"
    read -r -p "Kill them and continue? [y/N]: " a
    if [[ "$a" =~ ^[Yy]$ ]]; then
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null
        sleep 1
        ok "Port ${port} released."
    else
        err "Port ${port} is busy, aborting."
        return 1
    fi
}

server_transport_block() {
    cat <<EOF
# ---- transport (server) ----------------------------------------------------
# tcpMux MUST match the client exactly, otherwise every connection is refused
# after the login succeeds -- that mismatch alone looks like "random drops".
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = ${MUX_KEEPALIVE}
transport.tcpKeepalive = 30
transport.maxPoolCount = 100
# Must be larger than the client's heartbeatInterval, with headroom for a lossy
# link, or the server evicts a client that is perfectly alive.
transport.heartbeatTimeout = ${HB_TIMEOUT_S}
transport.tls.force = true
EOF
}

client_transport_block() {
    local pool="$1"
    cat <<EOF
# ---- transport (client) ----------------------------------------------------
# TCP ONLY. kcp/quic/websocket/wss are intentionally not supported by this
# script: over an Iran <-> abroad path they add jitter and reconnect storms
# without buying anything that TCP+TLS does not already give us.
transport.protocol = "tcp"
transport.tcpMux = ${TCP_MUX}
transport.tcpMuxKeepaliveInterval = ${MUX_KEEPALIVE}
transport.dialServerTimeout = ${DIAL_TIMEOUT}
transport.dialServerKeepalive = ${DIAL_KEEPALIVE}
transport.heartbeatInterval = ${HB_INTERVAL}
transport.heartbeatTimeout = ${HB_TIMEOUT_C}
transport.poolCount = ${pool}
# TLS wraps the control and data streams; with the custom first byte disabled
# the stream starts with a real ClientHello, which is what a DPI box expects.
transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
EOF
}

strip_managed_keys() {
    local file="$1"
    sed -i -E '/^[[:space:]]*(transport\.protocol|transport\.tcpMux|transport\.tcpMuxKeepaliveInterval|transport\.tcpKeepalive|transport\.maxPoolCount|transport\.poolCount|transport\.heartbeatInterval|transport\.heartbeatTimeout|transport\.dialServerTimeout|transport\.dialServerKeepalive|transport\.tls\.enable|transport\.tls\.force|transport\.tls\.disableCustomTLSFirstByte|transport\.quic\.[A-Za-z]+|transport\.kcp\.[A-Za-z]+|kcpBindPort|quicBindPort)[[:space:]]*=/d' "$file"
    sed -i -E '/^# ---- transport \((server|client)\) -+$/d' "$file"
}

current_pool_count() {
    local file="$1" v
    v="$(grep -oE '^[[:space:]]*transport\.poolCount[[:space:]]*=[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+$' | head -1)"
    [ -z "$v" ] && v=5
    echo "$v"
}

write_unit() {
    local role="$1"   # frps | frpc
    cat > "/etc/systemd/system/${role}.service" <<EOF
[Unit]
Description=frp ${role} (TCP-only tunnel)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=5
StartLimitIntervalSec=0
StartLimitBurst=0
ExecStart=${FRP_DIR}/${role} -c ${CONF_DIR}/${role}.toml
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=1048576
LimitNPROC=1048576
TimeoutStopSec=20
KillMode=mixed
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$role" >/dev/null 2>&1
}

generate_proxies() {
    local ports_csv="$1" file="$2" local_ip="$3"
    local p n=0
    IFS=',' read -r -a arr <<< "$ports_csv"
    for p in "${arr[@]}"; do
        p="$(echo "$p" | tr -d '[:space:]')"
        [ -z "$p" ] && continue
        cat >> "$file" <<EOF

[[proxies]]
name = "tcp-${p}"
type = "tcp"
localIP = "${local_ip}"
localPort = ${p}
remotePort = ${p}
transport.useEncryption = false
transport.useCompression = false
EOF
        n=$((n+1))
    done
    echo "$n"
}

install_server() {
    hdr "Iran server -- frps"

    local port token admin_port admin_user admin_pass mss ports
    read -r -p "Tunnel port [${DEF_PORT}]: " port;  port="${port:-$DEF_PORT}"
    read -r -p "Shared token [${DEF_TOKEN}]: " token; token="${token:-$DEF_TOKEN}"
    read -r -p "Dashboard port [${DEF_ADMIN_S}]: " admin_port; admin_port="${admin_port:-$DEF_ADMIN_S}"
    read -r -p "Dashboard user [admin]: " admin_user; admin_user="${admin_user:-admin}"
    read -r -p "Dashboard password [${token}]: " admin_pass; admin_pass="${admin_pass:-$token}"
    read -r -p "Ports to publish, comma separated (e.g. 443,8080,2053): " ports
    read -r -p "Clamped MSS [${DEF_MSS}]: " mss; mss="${mss:-$DEF_MSS}"

    if [ -z "$ports" ]; then err "You must list at least one port."; return 1; fi

    ensure_deps
    download_frp
    tune_tcp
    free_stale_port "$port" || return 1

    mkdir -p "$CONF_DIR" "$LOG_DIR"
    cat > "${CONF_DIR}/frps.toml" <<EOF
# frps.toml -- generated by frp-tunnel.sh v3.0 (frp ${FRP_VERSION}, TCP only)

bindAddr = "0.0.0.0"
bindPort = ${port}

auth.method = "token"
auth.token = "${token}"

webServer.addr = "0.0.0.0"
webServer.port = ${admin_port}
webServer.user = "${admin_user}"
webServer.password = "${admin_pass}"

log.to = "${LOG_DIR}/frps.log"
log.level = "info"
log.maxDays = 3

userConnTimeout = ${USER_CONN_TIMEOUT}
maxPortsPerClient = 0
allowPorts = [{ start = 1, end = 65535 }]

$(server_transport_block)
EOF

    write_unit frps
    open_port "$port" tcp
    open_port "$admin_port" tcp
    local p
    IFS=',' read -r -a arr <<< "$ports"
    for p in "${arr[@]}"; do
        p="$(echo "$p" | tr -d '[:space:]')"; [ -n "$p" ] && { open_port "$p" tcp; open_port "$p" udp; }
    done

    install_mss_fix "$mss"

    systemctl restart frps
    sleep 2
    if systemctl is-active --quiet frps; then
        ok "frps is running."
        echo
        echo "  ${BLD}Dashboard:${NC} http://$(curl -s --max-time 5 ifconfig.me 2>/dev/null):${admin_port}  (${admin_user} / ${admin_pass})"
        echo "  ${BLD}Give the foreign server:${NC} port ${port}, token ${token}, ports ${ports}"
    else
        err "frps failed to start. Last log lines:"
        journalctl -u frps -n 25 --no-pager
    fi
}

install_client() {
    hdr "Foreign server -- frpc"

    local sip port token ports local_ip admin_port pool sni mss ans
    read -r -p "Iran server IP: " sip
    [ -z "$sip" ] && { err "The Iran server IP is required."; return 1; }
    read -r -p "Tunnel port [${DEF_PORT}]: " port; port="${port:-$DEF_PORT}"
    read -r -p "Shared token [${DEF_TOKEN}]: " token; token="${token:-$DEF_TOKEN}"
    read -r -p "Ports to forward, comma separated (same list as the Iran side): " ports
    [ -z "$ports" ] && { err "You must list at least one port."; return 1; }
    read -r -p "Local service IP [127.0.0.1]: " local_ip; local_ip="${local_ip:-127.0.0.1}"
    read -r -p "Local admin port [${DEF_ADMIN_C}]: " admin_port; admin_port="${admin_port:-$DEF_ADMIN_C}"

    echo
    echo "Connection pool: pre-opened work connections. Too many causes a"
    echo "reconnect storm, too few adds a round trip to the first request."
    read -r -p "Pool size [5]: " pool; pool="${pool:-5}"
    [[ "$pool" =~ ^[0-9]+$ ]] || pool=5
    [ "$pool" -gt 20 ] && pool=20

    echo
    echo "TLS SNI (domain fronting). The tunnel is always TCP+TLS; this only"
    echo "changes the server name shown in the ClientHello."
    echo "  1) default (no custom SNI)"
    echo "  2) www.speedtest.net"
    echo "  3) www.cloudflare.com"
    echo "  4) custom"
    read -r -p "Choice [1]: " ans; ans="${ans:-1}"
    case "$ans" in
        2) sni="www.speedtest.net" ;;
        3) sni="www.cloudflare.com" ;;
        4) read -r -p "SNI hostname: " sni ;;
        *) sni="" ;;
    esac

    ensure_deps
    download_frp
    tune_tcp

    echo
    inf "Measuring the path MTU to ${sip} ..."
    local suggested; suggested="$(probe_mss "$sip")"
    inf "Suggested MSS: ${suggested}"
    read -r -p "Clamped MSS [${suggested}]: " mss; mss="${mss:-$suggested}"

    mkdir -p "$CONF_DIR" "$LOG_DIR"
    {
        cat <<EOF
# frpc.toml -- generated by frp-tunnel.sh v3.0 (frp ${FRP_VERSION}, TCP only)

serverAddr = "${sip}"
serverPort = ${port}

auth.method = "token"
auth.token = "${token}"

log.to = "${LOG_DIR}/frpc.log"
log.level = "info"
log.maxDays = 3

webServer.addr = "127.0.0.1"
webServer.port = ${admin_port}

loginFailExit = false

$(client_transport_block "$pool")
EOF
        [ -n "$sni" ] && echo "transport.tls.serverName = \"${sni}\""
    } > "${CONF_DIR}/frpc.toml"

    local n; n="$(generate_proxies "$ports" "${CONF_DIR}/frpc.toml" "$local_ip")"

    write_unit frpc
    install_mss_fix "$mss"
    fix_broken_ipv6
    check_dns

    systemctl restart frpc
    sleep 3
    if systemctl is-active --quiet frpc; then
        ok "frpc is running with ${n} forwarded port(s)."
        if grep -qiE "login to server success" "${LOG_DIR}/frpc.log" 2>/dev/null; then
            ok "Logged in to ${sip}:${port} successfully."
        else
            warn "No successful login in the log yet. Watch it with menu option 7."
        fi
    else
        err "frpc failed to start. Last log lines:"
        journalctl -u frpc -n 25 --no-pager
    fi

    echo
    echo "${YEL}Note on DNS:${NC} frp forwards only the ports you listed. If the service"
    echo "behind this tunnel needs UDP DNS, make sure UDP/53 is handled by that"
    echo "service itself (Xray/sing-box do their own resolution) -- otherwise a"
    echo "filtered local resolver will still poison some domains."
}

repair_install() {
    hdr "Repairing and migrating the existing install to TCP-only"

    local touched=0
    ensure_deps
    tune_tcp

    if [ -f "${CONF_DIR}/frps.toml" ]; then
        cp "${CONF_DIR}/frps.toml" "${CONF_DIR}/frps.toml.bak.$(date +%s)"
        strip_managed_keys "${CONF_DIR}/frps.toml"
        grep -qE '^[[:space:]]*userConnTimeout' "${CONF_DIR}/frps.toml" || \
            echo "userConnTimeout = ${USER_CONN_TIMEOUT}" >> "${CONF_DIR}/frps.toml"
        server_transport_block >> "${CONF_DIR}/frps.toml"
        write_unit frps
        systemctl restart frps
        sleep 2
        systemctl is-active --quiet frps && ok "frps repaired and restarted." || err "frps still failing -- see option 7."
        touched=1
    fi

    if [ -f "${CONF_DIR}/frpc.toml" ]; then
        cp "${CONF_DIR}/frpc.toml" "${CONF_DIR}/frpc.toml.bak.$(date +%s)"
        local pool; pool="$(current_pool_count "${CONF_DIR}/frpc.toml")"
        strip_managed_keys "${CONF_DIR}/frpc.toml"
        grep -qE '^[[:space:]]*loginFailExit' "${CONF_DIR}/frpc.toml" || \
            echo "loginFailExit = false" >> "${CONF_DIR}/frpc.toml"
        local tmp; tmp="$(mktemp)"
        awk -v RS='' 'NR==1' /dev/null >/dev/null 2>&1
        sed -n '1,/^\[\[proxies\]\]/p' "${CONF_DIR}/frpc.toml" | sed '$d' > "$tmp"
        client_transport_block "$pool" >> "$tmp"
        sed -n '/^\[\[proxies\]\]/,$p' "${CONF_DIR}/frpc.toml" >> "$tmp"
        if ! grep -q '\[\[proxies\]\]' "$tmp"; then
            cat "${CONF_DIR}/frpc.toml" > "$tmp"
            client_transport_block "$pool" >> "$tmp"
        fi
        mv "$tmp" "${CONF_DIR}/frpc.toml"
        write_unit frpc
        systemctl restart frpc
        sleep 2
        systemctl is-active --quiet frpc && ok "frpc repaired, migrated to TCP and restarted." || err "frpc still failing -- see option 7."
        fix_broken_ipv6
        touched=1
    fi

    if [ $touched -eq 0 ]; then
        err "No frps.toml or frpc.toml found under ${CONF_DIR}."
        return 1
    fi

    local mss="$DEF_MSS"
    [ -x "$MSS_SCRIPT" ] && mss="$(grep -oE '^MSS4=[0-9]+' "$MSS_SCRIPT" | cut -d= -f2)"
    install_mss_fix "${mss:-$DEF_MSS}"

    echo
    warn "Reminder: tcpMux must be identical on BOTH servers. Run this repair on"
    warn "the other box too, otherwise every connection dies right after login."
}

diagnose() {
    hdr "Diagnosing 'some sites do not load'"

    echo "${BLD}1) MSS clamp${NC}"
    if [ -x "$MSS_SCRIPT" ]; then
        "$MSS_SCRIPT" show
    else
        err "  Not installed. This is the #1 cause -- run menu option 5."
    fi

    echo
    echo "${BLD}2) Kernel MTU / TCP settings${NC}"
    local k
    for k in net.ipv4.tcp_mtu_probing net.ipv4.tcp_congestion_control \
             net.ipv4.tcp_no_metrics_save net.ipv4.tcp_retries2; do
        printf '   %-40s %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
    done
    if [ -f /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal ]; then
        printf '   %-40s %s\n' "nf_conntrack_tcp_be_liberal" "$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal)"
        printf '   %-40s %s / %s\n' "conntrack usage" \
            "$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)" \
            "$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
    fi

    echo
    echo "${BLD}3) Path MTU${NC}"
    local peer=""
    [ -f "${CONF_DIR}/frpc.toml" ] && peer="$(grep -oE '^serverAddr[[:space:]]*=[[:space:]]*"[^"]+"' "${CONF_DIR}/frpc.toml" | cut -d'"' -f2)"
    if [ -n "$peer" ]; then
        inf "   Probing towards ${peer} ..."
        echo "   Recommended MSS for this path: $(probe_mss "$peer")"
    else
        echo "   (run this on the foreign server to probe the tunnel path)"
    fi

    echo
    echo "${BLD}4) IPv6 sanity${NC}"
    fix_broken_ipv6

    echo
    echo "${BLD}5) DNS${NC}"
    check_dns

    echo
    echo "${BLD}6) Reachability of a few heavy sites from this box${NC}"
    local site
    for site in https://www.google.com https://www.cloudflare.com https://www.youtube.com https://github.com; do
        if curl -sf --max-time 8 -o /dev/null -w '' "$site" 2>/dev/null; then
            ok "  $site"
        else
            err "  $site  (timeout or reset)"
        fi
    done

    echo
    echo "${BLD}7) Services${NC}"
    for k in frps frpc; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${k}.service"; then
            printf '   %-6s %s (restarts: %s)\n' "$k" \
                "$(systemctl is-active "$k" 2>/dev/null)" \
                "$(systemctl show -p NRestarts --value "$k" 2>/dev/null)"
        fi
    done

    echo
    inf "If MSS is clamped, IPv6 and DNS are healthy, and heavy sites still hang"
    inf "only through the tunnel, forward the exact port the panel listens on and"
    inf "confirm tcpMux is set the same on both servers."
}

show_status() {
    hdr "Status"
    local role
    for role in frps frpc; do
        systemctl list-unit-files 2>/dev/null | grep -q "^${role}.service" || continue
        echo
        echo "${BLD}${role}${NC}: $(systemctl is-active "$role" 2>/dev/null) / $(systemctl is-enabled "$role" 2>/dev/null)"
        echo "  version : $("${FRP_DIR}/${role}" --version 2>/dev/null)"
        echo "  uptime  : $(systemctl show -p ActiveEnterTimestamp --value "$role" 2>/dev/null)"
        echo "  restarts: $(systemctl show -p NRestarts --value "$role" 2>/dev/null)"
        if [ -f "${CONF_DIR}/${role}.toml" ]; then
            echo "  protocol: $(grep -oE '^transport\.protocol[[:space:]]*=[[:space:]]*"[a-z]+"' "${CONF_DIR}/${role}.toml" | cut -d'"' -f2 || echo tcp)"
            echo "  tcpMux  : $(grep -oE '^transport\.tcpMux[[:space:]]*=[[:space:]]*(true|false)' "${CONF_DIR}/${role}.toml" | awk '{print $3}')"
        fi
    done
    echo
    echo "${BLD}Listening ports${NC}"
    ss -lntp 2>/dev/null | grep -E 'frps|frpc' || echo "  (none)"
    echo
    echo "${BLD}MSS clamp${NC}"
    [ -x "$MSS_SCRIPT" ] && "$MSS_SCRIPT" show || echo "  not installed"
}

show_logs() {
    local role=""
    systemctl is-active --quiet frps && role="frps"
    systemctl is-active --quiet frpc && role="frpc"
    [ -z "$role" ] && { err "Neither frps nor frpc is running."; return 1; }
    inf "Live log for ${role} -- press Ctrl+C to exit."
    journalctl -u "$role" -n 60 -f --no-pager
}

uninstall() {
    read -r -p "Remove frp completely? [y/N]: " a
    [[ "$a" =~ ^[Yy]$ ]] || return 0
    systemctl disable --now frps frpc >/dev/null 2>&1
    rm -f /etc/systemd/system/frps.service /etc/systemd/system/frpc.service
    remove_mss_fix
    rm -rf "$FRP_DIR" "$CONF_DIR" "$LOG_DIR" "$SYSCTL_FILE" "$LIMITS_DROPIN"
    systemctl daemon-reload >/dev/null 2>&1
    sysctl --system >/dev/null 2>&1
    ok "frp removed."
}

menu() {
    clear
    echo "${CYN}${BLD}"
    echo "  ============================================================"
    echo "        FRP Reverse Tunnel Manager  --  v3.0  (TCP only)"
    echo "        frp core: v${FRP_VERSION} (stable)"
    echo "  ============================================================"
    echo "${NC}"
    echo "   1) Install on the ${BLD}IRAN${NC} server        (frps)"
    echo "   2) Install on the ${BLD}FOREIGN${NC} server     (frpc)"
    echo "   3) Status"
    echo "   4) Repair / migrate an existing install to TCP-only"
    echo "   5) Apply the MTU/MSS fix only"
    echo "   6) Diagnose \"some sites don't load\""
    echo "   7) Live logs"
    echo "   8) Uninstall"
    echo "   0) Exit"
    echo
}

main() {
    require_root
    while true; do
        menu
        read -r -p "Choice: " c
        case "$c" in
            1) install_server; pause ;;
            2) install_client; pause ;;
            3) show_status;    pause ;;
            4) repair_install; pause ;;
            5) read -r -p "MSS [${DEF_MSS}]: " m; install_mss_fix "${m:-$DEF_MSS}"; pause ;;
            6) diagnose;       pause ;;
            7) show_logs;      pause ;;
            8) uninstall;      pause ;;
            0) echo "Bye."; exit 0 ;;
            *) err "Invalid choice."; sleep 1 ;;
        esac
    done
}

main "$@"
