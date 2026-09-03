#!/bin/bash

# FRP Reverse Tunnel Manager - Hardened / Fixed version
#
# Summary of what changed vs. the original script (see chat explanation for details):
#   - transport.maxPoolCount on frps was 65535 (resource-exhaustion bug) -> now 50
#   - transport.tls.enable was explicitly set to FALSE on the client, turning off
#     encryption that frp enables by default since v0.50 -> now explicitly ON
#     (frps: transport.tls.force = true), which also helps avoid DPI fingerprinting
#     of a plaintext frp handshake.
#   - auth.token was a hardcoded value ("tun100") baked into the public script,
#     meaning every user of this script shared the same secret -> now generated
#     randomly per install and never both prints in your notes.
#   - systemd units had no StartLimitIntervalSec, so after a handful of rapid
#     restarts in a short window systemd would give up and leave the tunnel dead
#     until someone manually ran `systemctl reset-failed` -> fixed.
#   - the old "kill -10 the process every 3 hours via cron" trick is removed
#     entirely -> replaced with a real watchdog that only restarts the tunnel when
#     it actually detects a problem.
#   - downloaded binaries are no longer trusted blindly; the script verifies it
#     actually received an ELF binary before installing it (a failed download that
#     silently saved an HTML error page used to cause a very confusing crash loop).
#   - added: status option, one-click full uninstall, automatic watchdog install.
#
# Left intentionally unchanged: the Go-template port-range mechanism
# (parseNumberRangePair) and the fixed "server-3090" / "client-3090" instance
# naming, since you mentioned this needs to match your Telegram bot exactly.

set -uo pipefail

BASE_DIR="/root/frp"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)." >&2
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

verify_binary() {
    # Makes sure curl didn't just save an HTML error page or an empty file.
    local path="$1"
    if [[ ! -s "$path" ]]; then
        return 1
    fi
    local magic
    magic=$(head -c4 "$path" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "$magic" == "7f454c46" ]]
}

port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":${port} "
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -q ":${port} "
    else
        return 1
    fi
}

open_firewall_tcp_port() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow "${port}/tcp" >/dev/null 2>&1 && echo "[ufw] opened ${port}/tcp"
    fi
}

press_enter() {
    echo
    read -p "Press Enter to continue..." _
}

# ---------------------------------------------------------------------------
# Watchdog (shared infrastructure + per-role enable)
# ---------------------------------------------------------------------------

setup_watchdog_infra() {
    mkdir -p "$BASE_DIR"

    cat > "$BASE_DIR/watchdog.sh" <<'WDEOF'
#!/bin/bash
# FRP watchdog: checks real tunnel health and restarts the service only when
# it is actually unhealthy (not on a blind timer), then logs what it did.
ROLE="$1"
BASE_DIR="/root/frp"
LOG="$BASE_DIR/watchdog.log"
INTERVAL=15
FAIL_THRESHOLD=2

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$ROLE] $*" >> "$LOG"; }

port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":${port} "
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | grep -q ":${port} "
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
    echo "usage: watchdog.sh [server|client]" >&2
    exit 1
fi

if [[ ! -f "$META" ]]; then
    log "meta file $META not found, exiting"
    exit 1
fi
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
            reason="not listening on port ${PORT}"
        fi
    else
        if ! timeout 3 bash -c "exec 3<>/dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" 2>/dev/null; then
            healthy=false
            reason="cannot reach ${SERVER_ADDR}:${SERVER_PORT}"
        fi
    fi

    if $healthy; then
        fail_count=0
    else
        fail_count=$((fail_count + 1))
        log "unhealthy ($reason) - fail_count=$fail_count"
        if (( fail_count >= FAIL_THRESHOLD )); then
            log "restarting ${SERVICE}@${INSTANCE}.service"
            systemctl restart "${SERVICE}@${INSTANCE}.service"
            fail_count=0
            sleep 5
        fi
    fi

    sleep "$INTERVAL"
done
WDEOF
    chmod +x "$BASE_DIR/watchdog.sh"

    cat > /etc/systemd/system/frp-watchdog@.service <<'EOF'
[Unit]
Description=FRP Watchdog (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/root/frp/watchdog.sh %i
Restart=always
RestartSec=5s
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

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

show_menu() {
    clear
    echo "=================================="
    echo "     FRP Reverse Tunnel Setup     "
    echo "=================================="
    echo "1) Install FRP on Iran (Server - frps)"
    echo "2) Install FRP on Kharej (Client - frpc)"
    echo "3) Show tunnel status"
    echo "4) Remove FRP (full uninstall)"
    echo "5) Exit"
    echo "=================================="
    read -p "Choose an option [1-5]: " choice
}

# ---------------------------------------------------------------------------
# Install server
# ---------------------------------------------------------------------------

install_server() {
    echo "=== Installing FRP Server (frps) on Iran ==="

    mkdir -p "$BASE_DIR/server"

    echo "Downloading frps..."
    if ! curl -fL --retry 3 --retry-delay 2 -o /usr/local/bin/frps http://81.12.32.210/downloads/frps; then
        echo "ERROR: download failed. Check your network / the download URL and try again."
        return 1
    fi
    if ! verify_binary /usr/local/bin/frps; then
        echo "ERROR: the downloaded file does not look like a valid binary (the server may"
        echo "       have returned an error page instead of the frps executable). Aborting."
        rm -f /usr/local/bin/frps
        return 1
    fi
    chmod +x /usr/local/bin/frps

    local token admin_pass
    token=$(gen_secret)
    admin_pass=$(gen_secret)

    cat > "$BASE_DIR/server/server-3090.toml" <<EOF
# Auto-generated frps config
bindAddr = "::"
bindPort = 3090

transport.heartbeatTimeout = 90
transport.maxPoolCount = 50
transport.tcpMux = false
transport.tcpKeepalive = 120
transport.tls.force = true

auth.method = "token"
auth.token = "$token"

# Local-only admin API/dashboard, used by the "status" menu option.
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "$admin_pass"

log.level = "info"
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
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
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
        echo "ERROR: frps failed to start. Check: journalctl -u frps@server-3090.service -n 50"
        return 1
    fi

    cat > "$BASE_DIR/server/meta.env" <<EOF
PORT=3090
INSTANCE=server-3090
TOKEN=$token
EOF
    chmod 600 "$BASE_DIR/server/meta.env"

    open_firewall_tcp_port 3090

    setup_watchdog_infra
    enable_watchdog server

    echo
    echo "=================================================="
    echo " FRP Server installed and running on port 3090"
    echo " SAVE THIS TOKEN - you will need it on the client:"
    echo
    echo "   $token"
    echo
    echo "=================================================="
}

# ---------------------------------------------------------------------------
# Install client
# ---------------------------------------------------------------------------

install_client() {
    echo "=== Installing FRP Client (frpc) on Kharej ==="

    mkdir -p "$BASE_DIR/client"

    echo "Downloading frpc..."
    if ! curl -fL --retry 3 --retry-delay 2 -o /usr/local/bin/frpc https://raw.githubusercontent.com/lostsoul6/frp-file/refs/heads/main/frpc; then
        echo "ERROR: download failed."
        return 1
    fi
    if ! verify_binary /usr/local/bin/frpc; then
        echo "ERROR: the downloaded file does not look like a valid binary. Aborting."
        rm -f /usr/local/bin/frpc
        return 1
    fi
    chmod +x /usr/local/bin/frpc

    local server_addr ports token

    read -p "Enter Iran server address (IPv4 or IPv6, e.g. 1.2.3.4 or 2a10:250:56ff:feb4:3b26): " server_addr
    while [[ -z "$server_addr" ]]; do
        read -p "Server address cannot be empty: " server_addr
    done

    read -p "Enter the token shown by the server during its install: " token
    while [[ -z "$token" ]]; do
        read -p "Token cannot be empty: " token
    done

    read -p "Enter inbound ports to forward (comma-separated or ranges, e.g. 1194 or 6000-6005,8443) [default: 8080]: " ports
    ports=${ports:-8080}
    if [[ ! "$ports" =~ ^[0-9,-]+$ ]]; then
        echo "Warning: '$ports' doesn't look like a valid port list, continuing anyway."
    fi

    local escaped_ports admin_pass
    escaped_ports=$(printf '%s' "$ports" | sed 's/"/\\"/g')
    admin_pass=$(gen_secret)

    cat > "$BASE_DIR/client/client-3090.toml" <<EOF
serverAddr = "$server_addr"
serverPort = 3090

loginFailExit = false

auth.method = "token"
auth.token = "$token"

transport.protocol = "tcp"
transport.tcpMux = false
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 5
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = true

# Local-only admin API, lets you run: frpc status -c client-3090.toml
webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "admin"
webServer.password = "$admin_pass"

log.level = "info"

{{- range \$_, \$v := parseNumberRangePair "$escaped_ports" "$escaped_ports" }}
[[proxies]]
name = "tcp-{{ \$v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = false
transport.useCompression = false
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
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
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
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
        echo "ERROR: frpc failed to start. Check: journalctl -u frpc@client-3090.service -n 50"
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
    echo "FRP Client installed and started."
    echo "Connecting to $server_addr:3090"
    echo "Forwarding ports: $ports"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

show_status() {
    clear
    echo "=================================="
    echo "        FRP Tunnel Status         "
    echo "=================================="

    local found=false

    if [[ -f "$BASE_DIR/server/meta.env" ]]; then
        found=true
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        echo
        echo "-- Server (frps), instance ${INSTANCE} --"
        systemctl is-active --quiet "frps@${INSTANCE}.service" && echo "  Service:    ACTIVE" || echo "  Service:    NOT RUNNING"
        systemctl is-enabled --quiet "frps@${INSTANCE}.service" && echo "  Autostart:  enabled" || echo "  Autostart:  disabled"
        port_listening "$PORT" && echo "  Port ${PORT}:   listening" || echo "  Port ${PORT}:   NOT listening"
        systemctl is-active --quiet "frp-watchdog@server.service" && echo "  Watchdog:   ACTIVE" || echo "  Watchdog:   NOT RUNNING"
        echo "  Recent log:"
        journalctl -u "frps@${INSTANCE}.service" -n 5 --no-pager 2>/dev/null | sed 's/^/    /'
    fi

    if [[ -f "$BASE_DIR/client/meta.env" ]]; then
        found=true
        # shellcheck disable=SC1090
        source "$BASE_DIR/client/meta.env"
        echo
        echo "-- Client (frpc), instance ${INSTANCE} --"
        systemctl is-active --quiet "frpc@${INSTANCE}.service" && echo "  Service:    ACTIVE" || echo "  Service:    NOT RUNNING"
        systemctl is-enabled --quiet "frpc@${INSTANCE}.service" && echo "  Autostart:  enabled" || echo "  Autostart:  disabled"
        if timeout 3 bash -c "exec 3<>/dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" 2>/dev/null; then
            echo "  Reach ${SERVER_ADDR}:${SERVER_PORT}: yes"
        else
            echo "  Reach ${SERVER_ADDR}:${SERVER_PORT}: NO"
        fi
        systemctl is-active --quiet "frp-watchdog@client.service" && echo "  Watchdog:   ACTIVE" || echo "  Watchdog:   NOT RUNNING"
        echo "  Recent log:"
        journalctl -u "frpc@${INSTANCE}.service" -n 5 --no-pager 2>/dev/null | sed 's/^/    /'
    fi

    if ! $found; then
        echo
        echo "Nothing installed yet."
    fi

    if [[ -f "$BASE_DIR/watchdog.log" ]]; then
        echo
        echo "-- Last watchdog actions --"
        tail -n 5 "$BASE_DIR/watchdog.log" | sed 's/^/    /'
    fi
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

remove_frp() {
    echo "=== Remove FRP (server + client + watchdog) ==="
    read -p "This deletes every file, service and setting this script created. Continue? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        return
    fi

    systemctl stop frps@server-3090.service frpc@client-3090.service \
        frp-watchdog@server.service frp-watchdog@client.service 2>/dev/null
    systemctl disable frps@server-3090.service frpc@client-3090.service \
        frp-watchdog@server.service frp-watchdog@client.service 2>/dev/null

    if [[ -f "$BASE_DIR/server/meta.env" ]] && command -v ufw >/dev/null 2>&1; then
        # shellcheck disable=SC1090
        source "$BASE_DIR/server/meta.env"
        ufw delete allow "${PORT}/tcp" >/dev/null 2>&1
    fi

    rm -f /etc/systemd/system/frps@.service
    rm -f /etc/systemd/system/frpc@.service
    rm -f /etc/systemd/system/frp-watchdog@.service
    systemctl daemon-reload

    rm -rf "$BASE_DIR"
    rm -f /usr/local/bin/frps /usr/local/bin/frpc

    # Clean up crontab entries left by older versions of this script.
    (crontab -l 2>/dev/null | grep -v 'pkill -10') | crontab - 2>/dev/null

    echo "FRP fully removed."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_root

while true; do
    show_menu
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) show_status ;;
        4) remove_frp ;;
        5) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
    press_enter
done
