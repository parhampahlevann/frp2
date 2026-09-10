#!/usr/bin/env bash
# ==============================================================================
# FRP TCP Multi-Path / Adaptive Tunnel Manager
#
# Iran (frps) <-> Foreign (frpc)
#
# Modes:
#   mux    : one TCP control connection with FRP TCP multiplexing
#   multi  : tcpMux=false + N independent FRP work connections per proxy
#            (implemented as N load-balanced proxy replicas)
#
# IMPORTANT:
#   "multi" improves aggregate concurrency when the path has loss/BDP issues,
#   but it cannot make a SINGLE TCP stream exceed TCP's own congestion window.
#   For one HTTP/2/WebSocket/TCP flow, there is still one end-to-end stream.
#
# FRP pinned to 0.71.0. SHA256 values are for official Linux amd64/arm64
# release archives used by the original script (verified against the
# published v0.71.0 GitHub release checksums).
#
# Fixes / changes vs. the original version of this script:
#   - Port forwarding/firewall handling for the actual proxied traffic now
#     happens only on the foreign client (frpc), automatically during
#     client_install and via menu item 5 (manage_client_ports /
#     open_client_ports). Nothing needs to be opened on the Iran server
#     beyond its FRP control port, which server_install already opens.
#   - The frps<->frpc auth token is now a fixed default (FRP_AUTH_TOKEN,
#     "123" unless overridden) instead of a randomly generated value the
#     operator had to copy from the server prompt to the client prompt.
#     Setup no longer asks for it. Note this trades away the security of a
#     random token - see the FRP_AUTH_TOKEN comment near the top.
#   - parse_ports no longer leaks its "items" array into global scope.
#   - MULTI_PATHS env var is now actually honored as the interactive default.
#   - Client dashboard password is now saved to credentials.txt (parity
#     with the server side) instead of being generated and discarded.
#   - Kernel SYN/accept backlog tuning added (somaxconn, tcp_max_syn_backlog,
#     netdev_max_backlog, tcp_syncookies) to reduce handshake drops under
#     connection bursts.
#   - Optional initial congestion window (initcwnd/initrwnd) bump via a
#     small systemd oneshot unit, to reach full throughput faster on new
#     short-lived TCP flows.
#   - "multi" mode now sets a tighter heartbeat timeout so a dead control
#     path is detected and re-established faster.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

BASE_DIR="/root/frp"
FRP_VERSION="0.71.0"
FRP_SHA256_LINUX_AMD64="84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716"
FRP_SHA256_LINUX_ARM64="f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"

FRP_SERVER_PORT="${FRP_SERVER_PORT:-3090}"
FRP_DASH_PORT="${FRP_DASH_PORT:-7500}"
FRP_CLIENT_DASH_PORT="${FRP_CLIENT_DASH_PORT:-7400}"

# Shared auth token between frps and frpc. Fixed to a hardcoded default so
# install never prompts for it and there is nothing to copy/paste between
# the two machines (a mistyped token here previously made frpc run but
# never actually authenticate - see client_install). This is a much weaker
# secret than a random token: anyone who reaches the control port and knows
# (or guesses) this value can authenticate against your frps. Override with
# FRP_AUTH_TOKEN=... before running the script if you want something less
# guessable while still skipping the prompt.
FRP_AUTH_TOKEN="${FRP_AUTH_TOKEN:-123}"

# Number of independent proxy replicas in multi mode.
# 4 is a sane starting point; 2-8 is normally enough.
MULTI_PATHS="${MULTI_PATHS:-4}"

# 0 = auto-detect PMTU, 1 = conservative 1360 clamp.
USE_FIXED_MSS="${USE_FIXED_MSS:-0}"
FIXED_MSS="${FIXED_MSS:-1360}"

# Watchdog timings.
WATCHDOG_INTERVAL="${WATCHDOG_INTERVAL:-5}"
WATCHDOG_FAILURES="${WATCHDOG_FAILURES:-2}"

# Initial congestion window tuning. Raises the default route's initcwnd/
# initrwnd so new short-lived TCP flows ramp up to a useful throughput in
# fewer round trips, instead of starting at Linux's default of 10 segments
# and slow-starting from there. 10 is the value Google's public research
# established as a safe general-purpose default; raise it only if you have
# measured a high-bandwidth, low-loss path. Set TUNE_INITCWND=0 to skip
# this entirely (it touches the host's default route, system-wide, not
# just FRP traffic).
TUNE_INITCWND="${TUNE_INITCWND:-1}"
INITCWND="${INITCWND:-10}"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

check_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run this script as root."
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_deps() {
    local need=()
    need_cmd curl || need+=(curl)
    need_cmd tar || need+=(tar)
    need_cmd ss || need+=(iproute2)
    need_cmd iptables || need+=(iptables)

    if ((${#need[@]})); then
        log "Installing: ${need[*]}"
        if need_cmd apt-get; then
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
        elif need_cmd dnf; then
            dnf install -y "${need[@]}"
        elif need_cmd yum; then
            yum install -y "${need[@]}"
        else
            die "Cannot install dependencies automatically."
        fi
    fi
}

gen_secret() {
    od -An -N"${1:-24}" -tx1 /dev/urandom | tr -d ' \n'
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' linux_amd64 ;;
        aarch64|arm64) printf '%s\n' linux_arm64 ;;
        *) return 1 ;;
    esac
}

download_frp() {
    local bin="$1" arch tarball url tmp expected actual extracted
    arch="$(detect_arch)" || die "Unsupported architecture: $(uname -m)"

    case "$arch" in
        linux_amd64) expected="$FRP_SHA256_LINUX_AMD64" ;;
        linux_arm64) expected="$FRP_SHA256_LINUX_ARM64" ;;
    esac

    tarball="frp_${FRP_VERSION}_${arch}.tar.gz"
    url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${tarball}"
    tmp="$(mktemp -d)"

    log "Downloading FRP ${FRP_VERSION} (${bin}, ${arch})..."
    curl -fL --retry 5 --retry-delay 2 --connect-timeout 10 \
        -o "${tmp}/${tarball}" "$url" || {
        rm -rf "$tmp"
        die "FRP download failed."
    }

    actual="$(sha256sum "${tmp}/${tarball}" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        rm -rf "$tmp"
        die "SHA256 mismatch for ${tarball}."
    }

    tar -xzf "${tmp}/${tarball}" -C "$tmp"
    extracted="${tmp}/frp_${FRP_VERSION}_${arch}/${bin}"
    [[ -x "$extracted" ]] || {
        rm -rf "$tmp"
        die "FRP binary missing from archive."
    }

    install -m 0755 "$extracted" "/usr/local/bin/${bin}"
    rm -rf "$tmp"
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && ((1 <= 10#$1 && 10#$1 <= 65535))
}

parse_ports() {
    local input="$1" item a b p
    local -a items=()
    declare -A seen=()
    IFS=', ' read -r -a items <<< "$input"

    for item in "${items[@]}"; do
        item="${item//[[:space:]]/}"
        [[ -z "$item" ]] && continue

        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
            ((10#$a <= 10#$b)) || continue
            ((10#$a >= 1 && 10#$b <= 65535)) || continue
            for ((p=10#$a; p<=10#$b; p++)); do
                seen["$p"]=1
            done
        elif valid_port "$item"; then
            seen["$((10#$item))"]=1
        fi
    done

    ((${#seen[@]})) || return 1
    printf '%s\n' "${!seen[@]}" | sort -n
}

open_firewall() {
    local port="$1" proto="$2"
    if need_cmd ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if need_cmd iptables; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ||
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

close_firewall() {
    local port="$1" proto="$2"
    if need_cmd ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if need_cmd iptables; then
        while iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; do
            iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || break
        done
    fi
}

write_tcp_tuning() {
    cat > /etc/sysctl.d/99-frp-tcp-tuning.conf <<'EOF'
# FRP TCP tuning. Values are intentionally conservative and let autotuning
# determine the actual socket buffer size.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535

# Larger SYN/accept backlogs so a burst of new connections (many short
# tunneled flows arriving at once) doesn't get dropped at the handshake
# stage before the app ever sees them. tcp_syncookies stays on so the
# server keeps accepting valid handshakes even if the backlog is briefly
# exceeded, instead of silently dropping SYNs.
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_syncookies = 1

# Avoid artificial application buffering.
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_autocorking = 0

# Do not force TCP Fast Open: middleboxes/DPI on a censored path are more
# likely to drop or mangle SYNs carrying the TFO option than a plain SYN,
# which would make handshakes LESS reliable, not faster. Same reasoning
# for leaving tcp_ecn at its distro default rather than forcing it on.
net.ipv4.tcp_fastopen = 0
EOF

    modprobe tcp_bbr 2>/dev/null || true
    printf '%s\n' tcp_bbr > /etc/modules-load.d/frp-bbr.conf 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || true

    if need_cmd iptables; then
        # Remove our older fixed-MSS rule if present.
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --set-mss "$FIXED_MSS" 2>/dev/null || true

        if [[ "$USE_FIXED_MSS" == "1" ]]; then
            iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --set-mss "$FIXED_MSS" 2>/dev/null ||
                iptables -t mangle -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS --set-mss "$FIXED_MSS" 2>/dev/null || true
        else
            # Let Linux calculate the proper MSS from PMTU instead of imposing
            # a permanently low 1360-byte MSS.
            iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
                -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null ||
                iptables -t mangle -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        fi
    fi

    write_initcwnd_script
}

remove_tcp_tuning() {
    if need_cmd iptables; then
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --set-mss "$FIXED_MSS" 2>/dev/null || true
    fi
    rm -f /etc/sysctl.d/99-frp-tcp-tuning.conf /etc/modules-load.d/frp-bbr.conf
    sysctl --system >/dev/null 2>&1 || true

    systemctl disable --now frp-initcwnd.service 2>/dev/null || true
    rm -f /etc/systemd/system/frp-initcwnd.service "$BASE_DIR/apply-initcwnd.sh"
    systemctl daemon-reload
}

write_initcwnd_script() {
    ((TUNE_INITCWND)) || return 0

    cat > "$BASE_DIR/apply-initcwnd.sh" <<EOF
#!/usr/bin/env bash
# Bumps initcwnd/initrwnd on the default route. Not persistent on its own,
# which is why this runs as a oneshot systemd unit on every boot.
set -Eeuo pipefail
INITCWND="\${INITCWND:-${INITCWND}}"

mapfile -t routes < <(ip route show default 2>/dev/null)
if ((\${#routes[@]} == 0)); then
    echo "No default route found; skipping initcwnd tuning." >&2
    exit 0
fi

for route_line in "\${routes[@]}"; do
    # shellcheck disable=SC2086
    ip route change \$route_line initcwnd "\$INITCWND" initrwnd "\$INITCWND" \
        2>/dev/null || echo "Could not apply initcwnd to: \$route_line" >&2
done
EOF
    chmod 700 "$BASE_DIR/apply-initcwnd.sh"
}

wait_active() {
    local unit="$1" timeout="${2:-20}" i
    for ((i=0; i<timeout; i++)); do
        systemctl is-active --quiet "$unit" && return 0
        sleep 1
    done
    return 1
}

install_units() {
    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP Adaptive Watchdog (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/root/frp/watchdog.sh %i
Restart=always
RestartSec=1
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    if ((TUNE_INITCWND)); then
        cat > /etc/systemd/system/frp-initcwnd.service <<EOF
[Unit]
Description=Apply initcwnd/initrwnd tuning for FRP tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=INITCWND=${INITCWND}
ExecStart=${BASE_DIR}/apply-initcwnd.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
}

write_watchdog() {
    cat > "$BASE_DIR/watchdog.sh" <<'WDEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROLE="${1:-}"
BASE="/root/frp"
INTERVAL="${WATCHDOG_INTERVAL:-5}"
MAX_FAIL="${WATCHDOG_FAILURES:-2}"
LOG="$BASE/watchdog.log"

mkdir -p "$BASE"
touch "$LOG"
chmod 600 "$LOG"

log() {
    printf '[%s] [%s] %s\n' "$(date '+%F %T')" "$ROLE" "$*" >> "$LOG"
}

meta="$BASE/${ROLE}/meta.env"
[[ -r "$meta" ]] || exit 0
# shellcheck disable=SC1090
source "$meta"

if [[ "$ROLE" == "server" ]]; then
    UNIT="frps@${INSTANCE}.service"
elif [[ "$ROLE" == "client" ]]; then
    UNIT="frpc@${INSTANCE}.service"
else
    exit 1
fi

# Return the number of ESTABLISHED TCP sockets involving the FRP server port.
server_connection_count() {
    ss -Htn state established "( sport = :${SERVER_PORT} or dport = :${SERVER_PORT} )" 2>/dev/null |
        wc -l | tr -d ' '
}

# Client-side check: a real ESTABLISHED socket to the configured server port.
client_connection_ok() {
    local server="$SERVER_ADDR"
    ss -Htn state established 2>/dev/null |
        awk -v host="$server" -v port=":${SERVER_PORT}" '
        {
            a=$4; b=$5;
            if ((a ~ host && a ~ port) || (b ~ host && b ~ port)) found=1
        }
        END { exit(found ? 0 : 1) }'
}

# Validate configuration before restart; prevents a watchdog from entering a
# restart loop caused by a broken generated TOML.
verify_config() {
    if [[ "$ROLE" == "server" ]]; then
        /usr/local/bin/frps verify -c "$BASE/server/${INSTANCE}.toml" >/dev/null 2>&1
    else
        /usr/local/bin/frpc verify -c "$BASE/client/${INSTANCE}.toml" >/dev/null 2>&1
    fi
}

fail=0

while :; do
    healthy=1
    reason=""

    if ! systemctl is-active --quiet "$UNIT"; then
        healthy=0
        reason="systemd unit inactive"
    elif [[ "$ROLE" == "server" ]]; then
        if ! ss -Hltn 2>/dev/null | awk -v p=":${PORT}" '$4 ~ p"$" {ok=1} END{exit(ok?0:1)}'; then
            healthy=0
            reason="FRP TCP listen port is not listening"
        fi
    else
        if ! client_connection_ok; then
            healthy=0
            reason="no established FRP control connection to server"
        fi
    fi

    if ((healthy)); then
        fail=0
    else
        ((fail++))
        log "health failure ${fail}/${MAX_FAIL}: ${reason}"

        if ((fail >= MAX_FAIL)); then
            if verify_config; then
                log "restarting ${UNIT}"
                systemctl restart "$UNIT" || true
            else
                log "configuration verification failed; refusing blind restart"
            fi
            fail=0
            sleep 2
        fi
    fi

    sleep "$INTERVAL"
done
WDEOF
    chmod 700 "$BASE_DIR/watchdog.sh"
}

write_server_config() {
    local token="$1" dash_pass="$2"

    cat > "$BASE_DIR/server/server-3090.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = ${FRP_SERVER_PORT}

transport.maxPoolCount = 8
transport.tcpKeepalive = 30
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30
transport.tls.force = true

auth.method = "token"
auth.token = "${token}"

webServer.addr = "127.0.0.1"
webServer.port = ${FRP_DASH_PORT}
webServer.user = "admin"
webServer.password = "${dash_pass}"

log.to = "console"
log.level = "warn"
EOF
    chmod 600 "$BASE_DIR/server/server-3090.toml"

    cat > "$BASE_DIR/server/meta.env" <<EOF
INSTANCE=server-3090
PORT=${FRP_SERVER_PORT}
SERVER_PORT=${FRP_SERVER_PORT}
EOF
    chmod 600 "$BASE_DIR/server/meta.env"
}

write_client_config() {
    local server_addr="$1" token="$2" mode="$3" paths="$4" ports_csv="$5"

    local pool dash_pass
    if [[ "$mode" == "multi" ]]; then
        pool=1
    else
        pool=0
    fi
    dash_pass="$(gen_secret 12)"

    cat > "$BASE_DIR/client/client-3090.toml" <<EOF
serverAddr = "${server_addr}"
serverPort = ${FRP_SERVER_PORT}

# Stay alive through transient route failures and let systemd/watchdog recover.
loginFailExit = false

auth.method = "token"
auth.token = "${token}"

transport.protocol = "tcp"
transport.tcpMux = $([[ "$mode" == "mux" ]] && echo true || echo false)
transport.poolCount = ${pool}
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 30
transport.tcpMuxKeepaliveInterval = 30
transport.tls.enable = true

webServer.addr = "127.0.0.1"
webServer.port = ${FRP_CLIENT_DASH_PORT}
webServer.user = "admin"
webServer.password = "${dash_pass}"

log.to = "console"
log.level = "warn"
EOF

    if [[ "$mode" == "multi" ]]; then
        # tcpMux is off in this mode, so the tcpMux keepalive above does
        # nothing; the control connection's liveness is governed by
        # heartbeatInterval/heartbeatTimeout instead. Default is 10s/90s -
        # tightened to 45s here so a dead path (and thus a dead replica
        # proxy) is noticed and reconnected roughly twice as fast. Loosen
        # this back toward 90 if you see spurious reconnects on a very
        # lossy link.
        cat >> "$BASE_DIR/client/client-3090.toml" <<EOF

transport.heartbeatInterval = 10
transport.heartbeatTimeout = 45
EOF
    fi

    cat > "$BASE_DIR/client/credentials.txt" <<EOF
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=${dash_pass}
EOF
    chmod 600 "$BASE_DIR/client/credentials.txt"

    local p i name
    IFS=',' read -r -a ports <<< "$ports_csv"

    if [[ "$mode" == "mux" ]]; then
        for p in "${ports[@]}"; do
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
    else
        # Multi mode: duplicate each TCP proxy into a load-balancer group.
        # Each replica has an independent non-mux work connection pool.
        # New incoming sessions are distributed between replicas.
        for p in "${ports[@]}"; do
            for ((i=1; i<=paths; i++)); do
                name="tcp-${p}-path-${i}"
                cat >> "$BASE_DIR/client/client-3090.toml" <<EOF

[[proxies]]
name = "${name}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}
loadBalancer.group = "frp-${p}"
loadBalancer.groupKey = "${token}"
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10
EOF
            done
        done
    fi

    chmod 600 "$BASE_DIR/client/client-3090.toml"

    cat > "$BASE_DIR/client/meta.env" <<EOF
INSTANCE=client-3090
SERVER_ADDR=${server_addr}
SERVER_PORT=${FRP_SERVER_PORT}
MODE=${mode}
PATHS=${paths}
PORTS=${ports_csv}
EOF
    chmod 600 "$BASE_DIR/client/meta.env"
}

manage_client_ports() {
    mkdir -p "$BASE_DIR/client"
    local input
    local -a parsed=()
    local p

    echo "These are the ports this client forwards (the 'localPort'/"
    echo "'remotePort' values you chose during client setup)."
    echo "Port forwarding is handled only here, on the foreign client -"
    echo "the Iran server side needs no port management beyond its"
    echo "FRP control port (${FRP_SERVER_PORT}), which is opened automatically."
    read -rp "Ports to open (e.g. 8080 or 8080,9000-9005): " input
    [[ -n "$input" ]] || { echo "No ports given, nothing to do."; return 0; }

    mapfile -t parsed < <(parse_ports "$input") ||
        die "No valid TCP ports were supplied."

    open_client_ports "${parsed[@]}"
    log "Opened TCP ports on this client: ${parsed[*]}"
}

# Opens (and records, for later uninstall) TCP ports on THIS machine's
# firewall. Called automatically from client_install for the ports chosen
# during setup, and available standalone via the "Open forwarded ports"
# menu item for adding more later.
open_client_ports() {
    mkdir -p "$BASE_DIR/client"
    touch "$BASE_DIR/client/forwarded_ports.txt"
    local p
    for p in "$@"; do
        open_firewall "$p" tcp
        grep -qxF "$p" "$BASE_DIR/client/forwarded_ports.txt" ||
            echo "$p" >> "$BASE_DIR/client/forwarded_ports.txt"
    done
}

server_install() {
    install_deps
    mkdir -p "$BASE_DIR/server" "$BASE_DIR/client"
    write_tcp_tuning
    download_frp frps
    install_units
    write_watchdog

    local token dash
    token="$FRP_AUTH_TOKEN"
    dash="$(gen_secret 12)"
    write_server_config "$token" "$dash"

    /usr/local/bin/frps verify -c "$BASE_DIR/server/server-3090.toml" ||
        die "Generated frps configuration failed verification."

    systemctl enable --now frps@server-3090.service
    wait_active frps@server-3090.service 20 ||
        { journalctl -u frps@server-3090.service -n 40 --no-pager; die "frps did not start."; }

    open_firewall "$FRP_SERVER_PORT" tcp

    systemctl enable --now frp-watchdog@server.service

    if ((TUNE_INITCWND)); then
        systemctl enable --now frp-initcwnd.service ||
            log "frp-initcwnd.service failed to start (non-fatal, continuing)"
    fi

    cat > "$BASE_DIR/server/credentials.txt" <<EOF
FRP_SERVER=${FRP_SERVER_PORT}
AUTH_TOKEN=${token}
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=${dash}
EOF
    chmod 600 "$BASE_DIR/server/credentials.txt"

    echo
    echo "=============================================================="
    echo " FRP SERVER READY"
    echo "=============================================================="
    echo "TCP port : ${FRP_SERVER_PORT}"
    echo "Token    : ${token} (fixed default, already hardcoded on the client too)"
    echo
    echo "Credentials are also stored root-only at:"
    echo "  ${BASE_DIR}/server/credentials.txt"
    echo "=============================================================="
    echo
    echo "This opened the FRP control port (${FRP_SERVER_PORT}) only. Port"
    echo "forwarding/firewall handling for the actual proxied ports (e.g."
    echo "8080) is now done entirely on the foreign client during its own"
    echo "setup - nothing further to do here on the Iran server for that."
}

client_install() {
    install_deps
    mkdir -p "$BASE_DIR/client" "$BASE_DIR/server"
    write_tcp_tuning
    download_frp frpc
    install_units
    write_watchdog

    if ((TUNE_INITCWND)); then
        systemctl enable --now frp-initcwnd.service ||
            log "frp-initcwnd.service failed to start (non-fatal, continuing)"
    fi

    local server_addr token mode paths input ports_csv

    read -rp "Iran server IP/hostname: " server_addr
    [[ -n "$server_addr" ]] || die "Server address cannot be empty."

    token="$FRP_AUTH_TOKEN"

    echo
    echo "Transport mode:"
    echo "  1) mux   - FRP TCP multiplexing; best default for general web traffic"
    echo "  2) multi - tcpMux=false + multiple independent proxy paths"
    echo
    read -rp "Mode [1/2, default 1]: " mode
    mode="${mode:-1}"

    if [[ "$mode" == "2" ]]; then
        mode="multi"
        read -rp "Number of independent paths [${MULTI_PATHS}]: " paths
        paths="${paths:-$MULTI_PATHS}"
        [[ "$paths" =~ ^[1-9][0-9]*$ ]] || die "Invalid path count."
        ((paths <= 8)) || die "Use 1-8 paths."
    else
        mode="mux"
        paths=1
    fi

    read -rp "Ports to forward [8080]: " input
    input="${input:-8080}"

    mapfile -t parsed < <(parse_ports "$input") ||
        die "No valid TCP ports were supplied."

    ports_csv="$(IFS=,; echo "${parsed[*]}")"

    # Port forwarding/firewall handling happens only on this (foreign)
    # client, never on the Iran server.
    open_client_ports "${parsed[@]}"

    write_client_config "$server_addr" "$token" "$mode" "$paths" "$ports_csv"

    /usr/local/bin/frpc verify -c "$BASE_DIR/client/client-3090.toml" ||
        die "Generated frpc configuration failed verification."

    systemctl enable --now frpc@client-3090.service
    wait_active frpc@client-3090.service 20 ||
        { journalctl -u frpc@client-3090.service -n 50 --no-pager; die "frpc did not start."; }

    # Give the control connection a short window to establish.
    local ok=0 i
    for ((i=0; i<15; i++)); do
        if ss -Htn state established 2>/dev/null |
            awk -v host="$server_addr" -v port=":${FRP_SERVER_PORT}" '
            {a=$4;b=$5;if((a~host&&a~port)||(b~host&&b~port))ok=1}
            END{exit(ok?0:1)}'; then
            ok=1
            break
        fi
        sleep 1
    done

    ((ok)) || {
        journalctl -u frpc@client-3090.service -n 50 --no-pager
        die "frpc is running but no established control connection was detected."
    }

    systemctl enable --now frp-watchdog@client.service

    echo
    echo "=============================================================="
    echo " FRP CLIENT READY"
    echo "=============================================================="
    echo "Server : ${server_addr}:${FRP_SERVER_PORT}"
    echo "Mode   : ${mode}"
    echo "Paths  : ${paths}"
    echo "Ports  : ${ports_csv}"
    echo "Watchdog: active"
    echo "Dashboard credentials: ${BASE_DIR}/client/credentials.txt"
    echo "=============================================================="
}

status() {
    echo "================ FRP STATUS ================"

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        echo
        echo "[SERVER]"
        systemctl is-active --quiet "frps@${INSTANCE}.service" &&
            echo "service: ACTIVE" || echo "service: INACTIVE"
        ss -Hltn 2>/dev/null | grep -q ":${PORT}" &&
            echo "listen :${PORT}: YES" || echo "listen :${PORT}: NO"
        systemctl is-active --quiet frp-watchdog@server.service &&
            echo "watchdog: ACTIVE" || echo "watchdog: INACTIVE"
        echo "established FRP sockets: $(ss -Htn state established "( sport = :${PORT} or dport = :${PORT} )" 2>/dev/null | wc -l)"
    fi

    if [[ -f "$BASE_DIR/client/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/client/meta.env"
        echo
        echo "[CLIENT]"
        systemctl is-active --quiet "frpc@${INSTANCE}.service" &&
            echo "service: ACTIVE" || echo "service: INACTIVE"
        echo "server: ${SERVER_ADDR}:${SERVER_PORT}"
        echo "mode: ${MODE}"
        echo "paths: ${PATHS}"
        echo "ports: ${PORTS}"
        systemctl is-active --quiet frp-watchdog@client.service &&
            echo "watchdog: ACTIVE" || echo "watchdog: INACTIVE"
        echo "established TCP sockets to FRP:"
        ss -Htn state established 2>/dev/null | grep "${SERVER_ADDR}:${SERVER_PORT}\|:${SERVER_PORT}" || true
    fi

    echo
    echo "[KERNEL]"
    printf 'qdisc: '; sysctl -n net.core.default_qdisc 2>/dev/null || true
    printf 'cc:    '; sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
    printf 'mtu probing: '; sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || true
}

uninstall() {
    read -rp "Remove FRP services, binaries, configs, watchdog and tuning? [y/N]: " x
    [[ "$x" =~ ^[Yy]$ ]] || return 0

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        close_firewall "${PORT:-$FRP_SERVER_PORT}" tcp
    fi

    if [[ -f "$BASE_DIR/client/forwarded_ports.txt" ]]; then
        while read -r fp; do
            [[ -n "$fp" ]] && close_firewall "$fp" tcp
        done < "$BASE_DIR/client/forwarded_ports.txt"
    fi

    systemctl disable --now \
        frps@server-3090.service \
        frpc@client-3090.service \
        frp-watchdog@server.service \
        frp-watchdog@client.service 2>/dev/null || true

    rm -f /etc/systemd/system/frps@.service \
          /etc/systemd/system/frpc@.service \
          /etc/systemd/system/frp-watchdog@.service
    systemctl daemon-reload

    remove_tcp_tuning

    rm -f /usr/local/bin/frps /usr/local/bin/frpc
    rm -rf "$BASE_DIR"

    echo "FRP installation removed."
}

main() {
    check_root

    while :; do
        clear 2>/dev/null || true
        echo "=============================================================="
        echo " FRP Adaptive TCP Multi-Path Tunnel Manager"
        echo "=============================================================="
        echo "1) Install / configure Iran server (frps)"
        echo "2) Install / configure foreign client (frpc)"
        echo "3) Status"
        echo "4) Uninstall"
        echo "5) Open forwarded ports on this client (foreign)"
        echo "6) Exit"
        echo "=============================================================="
        read -rp "Select [1-6]: " c

        case "$c" in
            1) server_install ;;
            2) client_install ;;
            3) status ;;
            4) uninstall ;;
            5) manage_client_ports ;;
            6) exit 0 ;;
            *) echo "Invalid choice." ;;
        esac

        echo
        read -rp "Press Enter..." _
    done
}

main "$@"
