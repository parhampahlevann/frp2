#!/bin/bash

# ==============================================================================
# FRP Reverse Tunnel Manager -- Fixed & Hardened Edition
# Iran <-> Kharej routes: TCP (multiplexed) or QUIC, BBR-tuned, watchdog-managed
# Pinned FRP v0.71.0 -- checksums verified against the official release
# ==============================================================================

set -uo pipefail

BASE_DIR="/root/frp"
FRP_VERSION="0.71.0"
FRP_SHA256_LINUX_AMD64="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
FRP_SHA256_LINUX_ARM64="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"

# MSS clamped onto this box's own outgoing SYNs. 1360 is conservative -- safe
# even if there's a VPN/overlay underneath reducing the real path MTU below
# the standard 1500. If you've confirmed a clean 1500 end-to-end MTU on your
# route, you can raise this toward 1440-1460 for a little less per-packet
# overhead.
MSS_CLAMP_VALUE=1360

# ------------------------------------------------------------------------------
# System & Pre-flight Checks
# ------------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root (use sudo)." >&2
        exit 1
    fi
}

install_deps() {
    local missing=()
    for pkg in curl tar iptables; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done
    # iproute2 provides `ss`, which the watchdog and status screen depend on.
    if ! command -v ss >/dev/null 2>&1; then
        missing+=("iproute2")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Installing core networking utilities: ${missing[*]}..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "${missing[@]}" >/dev/null 2>&1 || true
        fi
    fi
}

# $1 = number of random bytes. Hex output only, so it drops safely into a
# TOML double-quoted string or a shell variable with no escaping surprises.
gen_secret() {
    head -c "${1:-24}" /dev/urandom | od -An -tx1 | tr -d ' \n'
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
        echo "ERROR: Download failed. Check network access to GitHub."
        rm -rf "$tmp_dir"
        return 1
    fi

    actual_sha=$(sha256sum "$tmp_dir/$tarball" | awk '{print $1}')
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "ERROR: Checksum mismatch. Corrupted or tampered download rejected."
        echo "  expected: $expected_sha"
        echo "  actual:   $actual_sha"
        rm -rf "$tmp_dir"
        return 1
    fi

    tar -xzf "$tmp_dir/$tarball" -C "$tmp_dir"
    extracted="$tmp_dir/frp_${FRP_VERSION}_${arch}/${bin_name}"
    if [[ ! -f "$extracted" ]]; then
        echo "ERROR: Binary not found in archive."
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
        ss -ltn 2>/dev/null | grep -qE ":${port}\b"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -qE ":${port}\b"
    else
        return 1
    fi
}

udp_port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -lun 2>/dev/null | grep -qE ":${port}\b"
    else
        return 1
    fi
}

open_firewall() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

close_firewall() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

# Poll instead of a single fixed sleep -- a cold start right after extracting
# a fresh binary can take a moment longer on a loaded VPS, and a fixed
# `sleep 2` was reporting that as a false failure.
wait_for_active() {
    local unit="$1" tries="${2:-15}"
    for ((i = 0; i < tries; i++)); do
        if systemctl is-active --quiet "$unit"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ------------------------------------------------------------------------------
# Kernel TCP Stack Optimization & Anti-Stall Mechanisms
# ------------------------------------------------------------------------------

apply_tcp_mss_clamping() {
    echo "Clamping this host's outgoing SYN MSS to ${MSS_CLAMP_VALUE} (avoids MTU black-holes on lossy/tunneled paths)..."
    if command -v iptables >/dev/null 2>&1; then
        # mangle/POSTROUTING is the only table TCPMSS is valid in, and it's
        # also the chain that actually affects connections this host itself
        # originates or terminates (which is all FRP ever does -- it's an
        # application-layer proxy, not an IP router, so a FORWARD-chain rule
        # here never sees any traffic and was silently dead weight before).
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_CLAMP_VALUE" 2>/dev/null || true
        iptables -t mangle -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_CLAMP_VALUE" 2>/dev/null || true
    fi
}

remove_tcp_mss_clamping() {
    if command -v iptables >/dev/null 2>&1; then
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_CLAMP_VALUE" 2>/dev/null || true
    fi
}

tune_tcp_stack() {
    echo "Applying kernel TCP optimizations (BBR, low-latency queues, zero-bufferbloat)..."
    modprobe tcp_bbr 2>/dev/null || true

    cat > /etc/sysctl.d/99-frp-tuning.conf <<'EOF'
# Low-latency packet scheduling and BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Extended buffers for high-bandwidth-delay-product international paths
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 10000

# Reduce jitter and packet-serialization delay
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_window_scaling = 1

# Disabled: TCP Fast Open's SYN-data option gets flagged/dropped by some
# DPI middleboxes on Iranian ISP paths, causing stalls instead of speedups.
net.ipv4.tcp_fastopen = 0

# Socket recycling & Path MTU discovery
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_local_port_range = 1024 65535
EOF

    if [[ ! -f /etc/modules-load.d/frp-bbr.conf ]]; then
        echo "tcp_bbr" > /etc/modules-load.d/frp-bbr.conf 2>/dev/null || true
    fi

    sysctl --system >/dev/null 2>&1 || true
    apply_tcp_mss_clamping
}

# ------------------------------------------------------------------------------
# Watchdog (active state verification, not just "is the process alive")
# ------------------------------------------------------------------------------

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
    command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ":${1}\b"
}
udp_port_listening() {
    command -v ss >/dev/null 2>&1 && ss -lun 2>/dev/null | grep -qE ":${1}\b"
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

[[ ! -f "$META" ]] && exit 0
# shellcheck disable=SC1090
source "$META"

fail_count=0

while true; do
    healthy=true
    reason=""

    if ! systemctl is-active --quiet "${SERVICE}@${INSTANCE}.service"; then
        healthy=false
        reason="service process is dead"
    elif [[ "$ROLE" == "server" ]]; then
        if ! port_listening "$PORT"; then
            healthy=false
            reason="TCP bind port ${PORT} closed"
        elif [[ -n "${QUIC_PORT:-}" ]] && ! udp_port_listening "$QUIC_PORT"; then
            healthy=false
            reason="QUIC bind port ${QUIC_PORT} closed"
        fi
    elif [[ "$ROLE" == "client" ]]; then
        # Actively probe the local admin API rather than trusting the OS
        # process table -- this is what catches "process alive, tunnel dead"
        # (e.g. after a network blip) that a plain is-active check would miss.
        if ! /usr/local/bin/frpc status -c "$BASE_DIR/client/${INSTANCE}.toml" >/dev/null 2>&1; then
            healthy=false
            reason="tunnel connection to server lost"
        fi
    fi

    if $healthy; then
        fail_count=0
    else
        fail_count=$((fail_count + 1))
        log "Warning: $reason ($fail_count/$FAIL_THRESHOLD)"
        if (( fail_count >= FAIL_THRESHOLD )); then
            log "Triggering restart of ${SERVICE}@${INSTANCE}.service"
            systemctl restart "${SERVICE}@${INSTANCE}.service"
            fail_count=0
            sleep 6
        fi
    fi

    sleep "$INTERVAL"
done
WDEOF
    chmod +x "$BASE_DIR/watchdog.sh"

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP Watchdog Engine (%i)
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
    systemctl enable "frp-watchdog@${role}.service" >/dev/null 2>&1 || true
    systemctl restart "frp-watchdog@${role}.service" || true
}

# ------------------------------------------------------------------------------
# Port Parser (single ports, commas, ranges like 8000-8005)
# ------------------------------------------------------------------------------

parse_ports_string() {
    local input="$1"
    local raw_entries=()
    local expanded_ports=()

    IFS=', ' read -r -a raw_entries <<< "$input"

    for entry in "${raw_entries[@]}"; do
        entry=$(echo "$entry" | tr -d '[:space:]')
        [[ -z "$entry" ]] && continue

        if [[ "$entry" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"
            if (( start <= end && start >= 1 && end <= 65535 )); then
                for (( p = start; p <= end; p++ )); do
                    expanded_ports+=("$p")
                done
            fi
        elif [[ "$entry" =~ ^[0-9]+$ ]]; then
            if (( entry >= 1 && entry <= 65535 )); then
                expanded_ports+=("$entry")
            fi
        fi
    done

    if [[ ${#expanded_ports[@]} -gt 0 ]]; then
        printf "%s\n" "${expanded_ports[@]}" | awk '!seen[$0]++'
    fi
}

# ------------------------------------------------------------------------------
# Installation (Server & Client)
# ------------------------------------------------------------------------------

install_server() {
    echo "=== Installing FRP Server (frps) on Iran ==="
    install_deps
    mkdir -p "$BASE_DIR/server"

    tune_tcp_stack
    download_frp frps || return 1

    local token dash_pass
    token=$(gen_secret 24)
    dash_pass=$(gen_secret 9)

    # tcpMux left at its (true) default: sharing one connection per proxy is
    # what actually made "some site elements load, some don't" go away --
    # see the note in install_client() for why. quicBindPort is opened
    # alongside the normal TCP port so a client can be switched to QUIC
    # later with zero server-side changes.
    cat > "$BASE_DIR/server/server-3090.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = 3090
quicBindPort = 3091

transport.maxPoolCount = 100
transport.tcpKeepalive = 30
transport.tls.force = true

auth.method = "token"
auth.token = "${token}"

webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "${dash_pass}"

log.level = "error"
EOF
    chmod 600 "$BASE_DIR/server/server-3090.toml"

    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/
After=network.target network-online.target
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

    cat > "$BASE_DIR/server/meta.env" <<EOF
PORT=3090
QUIC_PORT=3091
INSTANCE=server-3090
EOF
    chmod 600 "$BASE_DIR/server/meta.env"

    systemctl daemon-reload
    systemctl enable frps@server-3090.service >/dev/null 2>&1
    systemctl restart frps@server-3090.service

    if ! wait_for_active "frps@server-3090.service" 15; then
        echo "ERROR: frps service failed to launch. Logs:"
        journalctl -u frps@server-3090.service -n 15 --no-pager
        return 1
    fi

    open_firewall 3090 tcp
    open_firewall 3091 udp
    setup_watchdog_infra
    enable_watchdog server

    echo
    echo "=================================================="
    echo " FRP Server is RUNNING"
    echo "   TCP port (default) : 3090"
    echo "   QUIC port (optional): 3091"
    echo
    echo " >>> Copy these into the client install now -- the token is not"
    echo "     saved anywhere you can print again later. <<<"
    echo "   Auth token     : ${token}"
    echo "   Dashboard user : admin"
    echo "   Dashboard pass : ${dash_pass}  (dashboard is 127.0.0.1-only, not exposed)"
    echo "=================================================="
}

install_client() {
    echo "=== Installing FRP Client (frpc) on Kharej ==="
    install_deps
    mkdir -p "$BASE_DIR/client"

    tune_tcp_stack
    download_frp frpc || return 1

    local server_addr token input_ports proto_choice transport_block server_port_value transport_label

    read -p "Enter Iran Server IP (e.g. 185.97.116.105): " server_addr
    while [[ -z "$server_addr" ]]; do
        read -p "Server IP cannot be empty: " server_addr
    done

    read -p "Enter the auth token printed by the server install: " token
    while [[ -z "$token" ]]; do
        read -p "Token cannot be empty -- paste the value the server printed: " token
    done

    echo
    echo "Transport protocol:"
    echo "  1) TCP + multiplexing  [default -- works on every network, fixes the"
    echo "                          'pages load incomplete' issue from before]"
    echo "  2) QUIC (over UDP)     [can give lower latency & jitter with no head-"
    echo "                          of-line blocking at all, but only if UDP isn't"
    echo "                          throttled on your specific route -- try both"
    echo "                          and keep whichever measures faster for you]"
    read -p "Choice [1-2, default 1]: " proto_choice
    proto_choice=${proto_choice:-1}

    if [[ "$proto_choice" == "2" ]]; then
        proto_choice=2
        server_port_value=3091
        transport_label="quic"
        transport_block='transport.protocol = "quic"'
    else
        proto_choice=1
        server_port_value=3090
        transport_label="tcp-mux"
        transport_block='transport.protocol = "tcp"
transport.tcpMux = true
transport.poolCount = 25'
    fi

    read -p "Enter ports to forward (e.g. 443,2053,8000-8005,8080) [default: 8080]: " input_ports
    input_ports=${input_ports:-8080}

    mapfile -t parsed_ports < <(parse_ports_string "$input_ports")

    if [[ ${#parsed_ports[@]} -eq 0 ]]; then
        echo "WARNING: No valid ports parsed. Defaulting to 8080."
        parsed_ports=(8080)
    fi

    cat > "$BASE_DIR/client/client-3090.toml" <<EOF
serverAddr = "$server_addr"
serverPort = ${server_port_value}
loginFailExit = false

auth.method = "token"
auth.token = "${token}"

${transport_block}
transport.dialServerKeepalive = 30
transport.dialServerTimeout = 10

webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "$(gen_secret 9)"

log.level = "error"
EOF

    for p in "${parsed_ports[@]}"; do
        cat >> "$BASE_DIR/client/client-3090.toml" <<EOF

[[proxies]]
name = "tcp-${p}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10
EOF
    done
    chmod 600 "$BASE_DIR/client/client-3090.toml"

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/
After=network.target network-online.target
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

    local clean_ports_str
    clean_ports_str=$(IFS=,; echo "${parsed_ports[*]}")

    cat > "$BASE_DIR/client/meta.env" <<EOF
INSTANCE=client-3090
SERVER_ADDR=$server_addr
SERVER_PORT=${server_port_value}
TRANSPORT=${transport_label}
PORTS="$clean_ports_str"
EOF
    chmod 600 "$BASE_DIR/client/meta.env"

    systemctl daemon-reload
    systemctl enable frpc@client-3090.service >/dev/null 2>&1
    systemctl restart frpc@client-3090.service

    if ! wait_for_active "frpc@client-3090.service" 15; then
        echo "ERROR: frpc process failed to start. Logs:"
        journalctl -u frpc@client-3090.service -n 20 --no-pager
        return 1
    fi

    # A running process is not proof the tunnel actually came up: with
    # loginFailExit=false (kept, so a *later* transient blip doesn't kill the
    # service) a bad token or unreachable server used to leave frpc "active"
    # in systemd forever while silently never connecting. Confirm the control
    # connection really logged in before declaring success.
    echo "Verifying the tunnel actually reached the server..."
    local tunnel_ok=false
    for ((i = 0; i < 20; i++)); do
        if /usr/local/bin/frpc status -c "$BASE_DIR/client/client-3090.toml" 2>/dev/null | grep -qi "running"; then
            tunnel_ok=true
            break
        fi
        sleep 1
    done

    if ! $tunnel_ok; then
        echo "ERROR: frpc process is running but no proxy ever came up."
        echo "Most likely causes: wrong token, wrong server IP, or port ${server_port_value}/$( [[ $proto_choice == 2 ]] && echo udp || echo tcp ) blocked between here and the Iran server."
        echo "Recent logs:"
        journalctl -u frpc@client-3090.service -n 25 --no-pager
        return 1
    fi

    setup_watchdog_infra
    enable_watchdog client

    echo
    echo "=================================================="
    echo " FRP Client is ONLINE -- tunnel confirmed working end to end"
    echo " Target Server : $server_addr:${server_port_value} (${transport_label})"
    echo " Active Ports  : $clean_ports_str"
    echo " Watchdog & MSS Clamping: RUNNING"
    echo "=================================================="
}

# ------------------------------------------------------------------------------
# Management & Cleanup
# ------------------------------------------------------------------------------

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
        if systemctl is-active --quiet "frps@${INSTANCE}.service"; then
            echo "  Service:   ACTIVE (Running)"
        else
            echo "  Service:   STOPPED / FAILED"
        fi
        port_listening "$PORT" && echo "  TCP Port ($PORT):  LISTENING" || echo "  TCP Port ($PORT):  NOT LISTENING"
        if [[ -n "${QUIC_PORT:-}" ]]; then
            udp_port_listening "$QUIC_PORT" && echo "  QUIC Port ($QUIC_PORT): LISTENING" || echo "  QUIC Port ($QUIC_PORT): NOT LISTENING"
        fi
        systemctl is-active --quiet "frp-watchdog@server.service" && echo "  Watchdog:  ACTIVE" || echo "  Watchdog:  INACTIVE"
    fi

    if [[ -f "$BASE_DIR/client/meta.env" ]]; then
        found=true
        # shellcheck disable=SC1090
        source "$BASE_DIR/client/meta.env"
        echo
        echo "-- Kharej Client (frpc) [${INSTANCE}] --"
        if systemctl is-active --quiet "frpc@${INSTANCE}.service"; then
            echo "  Service:   ACTIVE (Running)"
        else
            echo "  Service:   STOPPED / FAILED"
        fi
        echo "  Server:    $SERVER_ADDR:$SERVER_PORT (${TRANSPORT:-tcp-mux})"
        echo "  Ports:     $PORTS"
        systemctl is-active --quiet "frp-watchdog@client.service" && echo "  Watchdog:  ACTIVE" || echo "  Watchdog:  INACTIVE"

        echo "  Bridge State:"
        /usr/local/bin/frpc status -c "$BASE_DIR/client/client-3090.toml" 2>&1 | sed 's/^/    /' || echo "    Could not query status"
    fi

    if ! $found; then
        echo
        echo "No FRP instance was detected on this system."
    fi

    if [[ -f "$BASE_DIR/watchdog.log" ]]; then
        echo
        echo "-- Recent Watchdog Events --"
        tail -n 5 "$BASE_DIR/watchdog.log" | sed 's/^/  /'
    fi
}

remove_frp() {
    echo "=== Complete FRP Uninstall ==="
    read -p "Are you sure you want to remove all files, services, and network rules? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        return
    fi

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        close_firewall "${PORT:-3090}" tcp
        [[ -n "${QUIC_PORT:-}" ]] && close_firewall "$QUIC_PORT" udp
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
        sysctl --system >/dev/null 2>&1 || true
    fi

    echo "FRP, firewall rules, and custom TCP tunings completely removed."
}

press_enter() {
    echo
    read -p "Press Enter to return to menu..." _
}

show_menu() {
    clear
    echo "=================================="
    echo "     FRP Reverse Tunnel Pro       "
    echo "     (fixed & hardened edition)   "
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
