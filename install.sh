#!/bin/bash

# FRP Installation Script (Fixed, multi-protocol)
#
# Uses OFFICIAL frp v0.69.1 releases from github.com/fatedier/frp.
# v0.69.1 was picked deliberately, not just "the newest tag":
#   - It's the latest PATCH on top of v0.69.0, which is the release that
#     started frp's new compatibility-window policy (frpc/frps stay
#     interoperable across 9 minor versions), so it's the most
#     "battle-tested + still receiving fixes" point right now.
#   - Binary size is essentially the same across recent frp versions
#     (~12-14MB per platform) - version choice does not meaningfully
#     change footprint; there is no meaningfully "lighter" official build.
#
# What changed vs the previous version of this script:
#   - No untrusted third-party binaries; downloads official GitHub releases.
#   - Minimal systemd capabilities (only CAP_NET_BIND_SERVICE).
#   - Proper reload via SIGHUP (systemctl reload), not SIGUSR1.
#   - Download failure checks + architecture detection.
#   - frps now enables tcp, kcp AND websocket/wss simultaneously, so you
#     can switch frpc's protocol later without reinstalling the server.
#   - frpc lets you pick tcp / wss / kcp at install time.
#   - Heartbeat/keepalive re-tuned: the previous script had heartbeatTimeout
#     set too aggressively (60s). On a lossy international link that's
#     often *itself* the cause of "connects then drops almost immediately"
#     - the client gets marked dead on any brief latency spike. This
#     version uses frp's own tested defaults (heartbeatInterval=10,
#     heartbeatTimeout=90) instead of a hand-tuned, tighter value.

set -o pipefail

FRP_VERSION="0.69.1"
FRP_TOKEN="tun100"
FRP_PORT="3090"

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "این اسکریپت باید با root اجرا بشه (sudo)."
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

# Downloads and extracts frps/frpc from the official GitHub release.
# $1 = binary name ("frps" or "frpc")
download_frp_binary() {
    local bin_name="$1"
    local arch
    arch=$(detect_arch)
    if [ "$arch" = "unsupported" ]; then
        echo "معماری سیستم پشتیبانی نمی‌شه: $(uname -m)"
        exit 1
    fi

    local pkg="frp_${FRP_VERSION}_linux_${arch}"
    local url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${pkg}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo "در حال دانلود ${bin_name} (frp v${FRP_VERSION}, ${arch}) از ریلیز رسمی..."
    if ! curl -fL --retry 3 -o "${tmp_dir}/frp.tar.gz" "$url"; then
        echo "دانلود ناموفق بود: $url"
        rm -rf "$tmp_dir"
        exit 1
    fi

    if ! tar -xzf "${tmp_dir}/frp.tar.gz" -C "$tmp_dir"; then
        echo "استخراج آرشیو ناموفق بود."
        rm -rf "$tmp_dir"
        exit 1
    fi

    if [ ! -f "${tmp_dir}/${pkg}/${bin_name}" ]; then
        echo "باینری ${bin_name} داخل آرشیو پیدا نشد."
        rm -rf "$tmp_dir"
        exit 1
    fi

    install -m 755 "${tmp_dir}/${pkg}/${bin_name}" "/usr/local/bin/${bin_name}"
    rm -rf "$tmp_dir"
    echo "${bin_name} با موفقیت نصب شد در /usr/local/bin/${bin_name}"
}

show_menu() {
    clear
    echo "=================================="
    echo "     FRP Reverse Tunnel Setup     "
    echo "         (frp v${FRP_VERSION})          "
    echo "=================================="
    echo "1) Install FRP on Iran (Server - frps)"
    echo "2) Install FRP on Kharej (Client - frpc)"
    echo "3) Remove FRP"
    echo "4) Exit"
    echo "=================================="
    read -p "Choose an option [1-4]: " choice
}

install_server() {
    echo "=== Installing FRP Server (frps) on Iran ==="

    download_frp_binary "frps"

    mkdir -p /root/frp/server

    # tcp/wss/websocket all share bindPort automatically.
    # kcpBindPort opens the same port number over UDP for the kcp protocol.
    # This means frpc can switch protocol later without touching the server.
    cat > /root/frp/server/server-3090.toml <<EOF
# Auto-generated frps config
bindAddr = "::"
bindPort = ${FRP_PORT}
kcpBindPort = ${FRP_PORT}

# frp's own tested defaults - a tighter custom timeout was causing the
# connection to be dropped on brief latency spikes instead of surviving them.
transport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.tcpKeepalive = 30

# Must match frpc. Unencrypted/unwrapped frp traffic has a recognizable
# handshake signature that gets fingerprinted and reset quickly by
# DPI/firewalls - this is the main reason plain tcp was dropping fast.
transport.tls.force = true

auth.method = "token"
auth.token = "${FRP_TOKEN}"
EOF

    cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
# Only what's actually needed: binding to privileged ports (<1024).
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frps@server-3090.service
    systemctl restart frps@server-3090.service

    # Reload every 3 hours via proper SIGHUP (systemctl reload), not a raw kill signal.
    (crontab -l 2>/dev/null | grep -v 'frps@server-3090\|frpc@client-3090' ; \
     echo '0 */3 * * * systemctl reload frps@server-3090.service >/dev/null 2>&1') | crontab -

    echo "FRP Server installed and started!"
    echo "Listening on TCP/WSS/WS port ${FRP_PORT} and KCP(UDP) port ${FRP_PORT}, token '${FRP_TOKEN}'"
}

install_client() {
    echo "=== Installing FRP Client (frpc) on Kharej ==="

    download_frp_binary "frpc"

    mkdir -p /root/frp/client

    read -p "Enter Iran server address (IPv4 or IPv6, e.g. 1.2.3.4 or 2a10:250:56ff:feb4:3b26): " server_addr
    read -p "Enter inbound ports to forward (comma-separated or ranges, e.g. 1194 or 6000-6005,8443) [default: 8080]: " ports
    ports=${ports:-8080}

    echo ""
    echo "پروتکل اتصال به سرور رو انتخاب کن:"
    echo "  1) tcp  - ساده‌ترین حالت، روی اکثر شبکه‌ها کار می‌کنه"
    echo "  2) wss  - وب‌سوکت روی TLS، شبیه ترافیک HTTPS عادی، بیشترین پایداری در برابر فیلترینگ/DPI"
    echo "  3) kcp  - روی UDP، بهترین گزینه برای لینک‌های پرلاس/جیتری (پکت‌لاس بالا)"
    read -p "انتخاب [1-3, پیش‌فرض 2]: " proto_choice
    proto_choice=${proto_choice:-2}

    case "$proto_choice" in
        1)
            transport_protocol="tcp"
            pool_count=5
            ;;
        3)
            transport_protocol="kcp"
            pool_count=1
            ;;
        *)
            transport_protocol="wss"
            pool_count=5
            ;;
    esac

    # Escape quotes for safe insertion into the template
    escaped_ports=$(printf '%s' "$ports" | sed 's/"/\\"/g')

    cat > /root/frp/client/client-3090.toml <<EOF
serverAddr = "$server_addr"
serverPort = ${FRP_PORT}

loginFailExit = false

auth.method = "token"
auth.token = "${FRP_TOKEN}"

transport.protocol = "${transport_protocol}"
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 30
transport.poolCount = ${pool_count}

# frp's own tested defaults (see comment at top of the script for why the
# earlier tighter timeout was making the disconnect problem worse, not better).
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 90

# Must match frps.
transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = false

{{- range \$_, \$v := parseNumberRangePair "$escaped_ports" "$escaped_ports" }}
[[proxies]]
name = "tcp-{{ \$v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = true
transport.useCompression = true
{{- end }}
EOF

    cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frpc@client-3090.service
    systemctl restart frpc@client-3090.service

    (crontab -l 2>/dev/null | grep -v 'frps@server-3090\|frpc@client-3090' ; \
     echo '0 */3 * * * systemctl reload frpc@client-3090.service >/dev/null 2>&1') | crontab -

    echo "FRP Client installed and started!"
    echo "Connecting to $server_addr:${FRP_PORT} over ${transport_protocol}"
    echo "Forwarding ports: $ports"
    echo "Config uses Go template - frpc renders the proxy sections at runtime."
    echo ""
    echo "برای دیدن وضعیت اتصال: journalctl -u frpc@client-3090 -f"
}

remove_frp() {
    echo "=== Removing FRP ==="

    systemctl stop frps@server-3090.service frpc@client-3090.service 2>/dev/null || true
    systemctl disable frps@server-3090.service frpc@client-3090.service 2>/dev/null || true
    rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
    rm -rf /root/frp
    rm -f /usr/local/bin/frps /usr/local/bin/frpc
    systemctl daemon-reload

    # Remove only the reload cron entries this script added
    (crontab -l 2>/dev/null | grep -v 'frps@server-3090\|frpc@client-3090') | crontab -

    echo "FRP removed successfully!"
}

require_root

while true; do
    show_menu
    case $choice in
        1) install_server ;;
        2) install_client ;;
        3) remove_frp ;;
        4) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
    echo
    read -p "Press Enter to continue..."
done
