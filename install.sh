#!/bin/bash
set -o pipefail

FRP_VERSION="0.71.0"
FRP_TOKEN="tun100"
FRP_PORT="8443"
ADMIN_PORT_S="7500"
ADMIN_PORT_C="7400"

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

tune_tcp_for_frp() {
   log_step "Applying TCP kernel tuning for tunnel stability/performance..."

   local cc_line="net.ipv4.tcp_congestion_control = cubic"
   local qdisc_line="# net.core.default_qdisc = fq (bbr module unavailable, staying on cubic)"

   modprobe tcp_bbr >/dev/null 2>&1 || true
   if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
       cc_line="net.ipv4.tcp_congestion_control = bbr"
       qdisc_line="net.core.default_qdisc = fq"
       log_perf "BBR congestion control available, enabling it."
   else
       log_warn "BBR module not available on this kernel, staying on cubic."
   fi

   cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
# FRP Long-Haul TCP Optimization
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65535
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

check_port_in_use() {
   local port="$1"
   if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
       return 0
   elif netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
       return 0
   fi
   return 1
}

install_watchdog() {
   log_step "Installing watchdog for health monitoring..."

   cat > /usr/local/bin/frp-watchdog.sh <<HEADER_EOF
#!/bin/bash
FRP_PORT="${FRP_PORT}"
ADMIN_PORT_S="${ADMIN_PORT_S}"
ADMIN_PORT_C="${ADMIN_PORT_C}"
FRP_TOKEN="${FRP_TOKEN}"
HEADER_EOF

   cat >> /usr/local/bin/frp-watchdog.sh <<'WATCHDOG_EOF'
LOG_FILE="/var/log/frp-watchdog.log"
MAX_LOG_SIZE=1048576
STATE_DIR="/var/run/frp-watchdog"
FAIL_THRESHOLD=3
RESTART_COOLDOWN=300
API_TIMEOUT=8

mkdir -p "$STATE_DIR"

log_msg() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

rotate_log() {
   if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt "$MAX_LOG_SIZE" ]; then
       mv "$LOG_FILE" "${LOG_FILE}.old"
       touch "$LOG_FILE"
   fi
}

check_admin_api() {
   local port="$1" user="$2" pass="$3"
   curl -sf --max-time "$API_TIMEOUT" -u "${user}:${pass}" "http://127.0.0.1:${port}/api/status" >/dev/null 2>&1
}

read_count() {
   local f="${STATE_DIR}/$1.fails"
   [ -f "$f" ] && cat "$f" || echo 0
}

write_count() {
   echo "$2" > "${STATE_DIR}/$1.fails"
}

can_restart_now() {
   local svc="$1"
   local ts_file="${STATE_DIR}/${svc}.last_restart"
   local now
   now=$(date +%s)
   if [ -f "$ts_file" ]; then
       local last
       last=$(cat "$ts_file")
       if [ $(( now - last )) -lt "$RESTART_COOLDOWN" ]; then
           return 1
       fi
   fi
   echo "$now" > "$ts_file"
   return 0
}

do_restart() {
   local proc="$1" unit="$2" svc_key="$3"
   if ! can_restart_now "$svc_key"; then
       log_msg "WATCHDOG: ${proc} needs restart but cooldown is active, skipping to avoid a restart storm"
       return
   fi
   log_msg "WATCHDOG: RESTARTING ${unit}.service..."
   systemctl restart "${unit}.service" >/dev/null 2>&1
   sleep 5
   if pgrep -x "$proc" >/dev/null 2>&1; then
       log_msg "WATCHDOG: ${proc} restarted OK"
       write_count "$svc_key" 0
   else
       log_msg "WATCHDOG: CRITICAL - ${proc} restart FAILED"
   fi
}

check_frps() {
   local svc_key="frps"
   if ! pgrep -x "frps" >/dev/null 2>&1; then
       log_msg "WATCHDOG: frps process NOT RUNNING"
       do_restart "frps" "frps@server-${FRP_PORT}" "$svc_key"
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
       do_restart "frps" "frps@server-${FRP_PORT}" "$svc_key"
       return
   fi
   if check_admin_api "$ADMIN_PORT_S" "admin" "$FRP_TOKEN"; then
       write_count "$svc_key" 0
   else
       local n=$(( $(read_count "$svc_key") + 1 ))
       write_count "$svc_key" "$n"
       log_msg "WATCHDOG: frps admin API not responding (${n}/${FAIL_THRESHOLD})"
       if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
           do_restart "frps" "frps@server-${FRP_PORT}" "$svc_key"
       fi
   fi
}

check_frpc() {
   local svc_key="frpc"
   if ! pgrep -x "frpc" >/dev/null 2>&1; then
       log_msg "WATCHDOG: frpc process NOT RUNNING"
       do_restart "frpc" "frpc@client-${FRP_PORT}" "$svc_key"
       return
   fi
   if check_admin_api "$ADMIN_PORT_C" "admin" "$FRP_TOKEN"; then
       local status
       status=$(curl -sf --max-time "$API_TIMEOUT" -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
       if [ -n "$status" ] && echo "$status" | grep -q '"online":false'; then
           local n=$(( $(read_count "$svc_key") + 1 ))
           write_count "$svc_key" "$n"
           log_msg "WATCHDOG: frpc reports OFFLINE status (${n}/${FAIL_THRESHOLD})"
           if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
               do_restart "frpc" "frpc@client-${FRP_PORT}" "$svc_key"
           fi
       else
           write_count "$svc_key" 0
       fi
   else
       local n=$(( $(read_count "$svc_key") + 1 ))
       write_count "$svc_key" "$n"
       log_msg "WATCHDOG: frpc admin API not responding (${n}/${FAIL_THRESHOLD})"
       if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
           do_restart "frpc" "frpc@client-${FRP_PORT}" "$svc_key"
       fi
   fi
}

rotate_log
mkdir -p "$STATE_DIR"
(
   flock -n 200 || { log_msg "WATCHDOG: previous check for '$1' still running, skipping this tick"; exit 0; }
   case "$1" in
       frps) check_frps ;;
       frpc) check_frpc ;;
       *)    log_msg "Usage: $0 {frps|frpc}" ;;
   esac
) 200>"${STATE_DIR}/$1.lock"
WATCHDOG_EOF

   chmod 755 /usr/local/bin/frp-watchdog.sh
   mkdir -p /var/run/frp-watchdog

   (crontab -l 2>/dev/null | grep -v 'frp-watchdog' ; \
    echo "* * * * * /usr/local/bin/frp-watchdog.sh frps >/dev/null 2>&1" ; \
    echo "* * * * * /usr/local/bin/frp-watchdog.sh frpc >/dev/null 2>&1") | crontab -

   log_info "Watchdog installed."
}

remove_watchdog() {
   rm -f /usr/local/bin/frp-watchdog.sh
   (crontab -l 2>/dev/null | grep -v 'frp-watchdog') | crontab -
   rm -f /var/log/frp-watchdog.log /var/log/frp-watchdog.log.old
   rm -rf /var/run/frp-watchdog
}

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

generate_tcp_proxies() {
   local ports="$1"
   local config_file="$2"
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
name = "tcp-${p}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}

PROXY
           done
       else
           cat >> "$config_file" <<PROXY
[[proxies]]
name = "tcp-${entry}"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}

PROXY
       fi
   done
}

generate_udp_proxies() {
   local ports="$1"
   local config_file="$2"
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
name = "udp-${p}"
type = "udp"
localIP = "127.0.0.1"
localPort = ${p}
remotePort = ${p}

PROXY
           done
       else
           cat >> "$config_file" <<PROXY
[[proxies]]
name = "udp-${entry}"
type = "udp"
localIP = "127.0.0.1"
localPort = ${entry}
remotePort = ${entry}

PROXY
       fi
   done
}

show_menu() {
   clear
   echo "============================================"
   echo "     FRP Iran-Optimized Tunnel Setup        "
   echo "         (frp v${FRP_VERSION})                "
   echo "============================================"
   echo "1) Install FRP Server (frps) - IRAN"
   echo "2) Install FRP Client (frpc) - OUTSIDE"
   echo "3) Check Status / Health"
   echo "4) Remove FRP"
   echo "5) Exit"
   echo "============================================"
   read -p "Choose an option [1-5]: " choice
}

install_server() {
   log_step "=== Installing FRP Server (frps) on IRAN ==="
   log_ir "Reverse tunnel: frpc (outside) -> frps (Iran)"

   if check_port_in_use "$FRP_PORT"; then
       log_error "Port ${FRP_PORT} is already in use!"
       ss -tlnp | grep ":${FRP_PORT} " || netstat -tlnp | grep ":${FRP_PORT} "
       read -p "Press Enter to continue anyway, or Ctrl+C to abort..."
   fi

   download_frp_binary "frps"
   mkdir -p /root/frp/server /var/log

   open_firewall_port "$FRP_PORT" "tcp"
   open_firewall_port "$ADMIN_PORT_S" "tcp"

   cat > /root/frp/server/server-${FRP_PORT}.toml <<EOF
bindAddr = "0.0.0.0"
bindPort = ${FRP_PORT}
proxyBindAddr = "0.0.0.0"

webServer.addr = "0.0.0.0"
webServer.port = ${ADMIN_PORT_S}
webServer.user = "admin"
webServer.password = "${FRP_TOKEN}"

log.to = "/var/log/frps.log"
log.level = "info"
log.maxDays = 30
log.disablePrintColor = true

transport.tcpMux = false
transport.tcpKeepalive = 30
transport.maxPoolCount = 100
transport.tls.force = true

auth.method = "token"
auth.token = "${FRP_TOKEN}"

maxPortsPerClient = 0
detailedErrorsToClient = false
EOF

   cat > /etc/systemd/system/frps@.service <<'EOF'
[Unit]
Description=FRP Server Service (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

   systemctl daemon-reload
   systemctl enable frps@server-${FRP_PORT}.service
   systemctl restart frps@server-${FRP_PORT}.service

   tune_tcp_for_frp
   install_watchdog

   sleep 3

   if systemctl is-active --quiet frps@server-${FRP_PORT}.service; then
       log_info "FRP Server installed and running!"
       echo ""
       echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
       echo -e "${GREEN}║  Server (IRAN) Status: RUNNING                       ║${NC}"
       echo -e "${GREEN}║  Bind Port:     ${FRP_PORT} (TCP Only)                      ║${NC}"
       echo -e "${GREEN}║  Dashboard:    http://IRAN_IP:${ADMIN_PORT_S}              ║${NC}"
       echo -e "${GREEN}║  Token:        ${FRP_TOKEN}                          ║${NC}"
       echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
       echo ""
       log_warn "IMPORTANT: Make sure port ${FRP_PORT} is open in your cloud firewall!"
       log_warn "Test from outside: nc -vz IRAN_IP ${FRP_PORT}"
   else
       log_error "Failed to start server!"
       journalctl -u frps@server-${FRP_PORT} --no-pager -n 30
   fi
}

install_client() {
   log_step "=== Installing FRP Client (frpc) on OUTSIDE server ==="
   log_ir "Connecting to Iran server via WSS/TLS"

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
       log_warn "Solution: use proxy chaining (Shadowsocks/V2Ray) during install."
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

   local base_pool
   case "$load_choice" in
       1) base_pool=8 ;;
       3) base_pool=40 ;;
       *) base_pool=20 ;;
   esac

   local n_ports
   n_ports=$(count_ports "$ports")
   [ "$n_ports" -lt 1 ] && n_ports=1

   local pool_count=$base_pool
   local total_pool=$(( n_ports * base_pool ))
   local POOL_CAP=400
   if [ "$total_pool" -gt "$POOL_CAP" ]; then
       pool_count=$(( POOL_CAP / n_ports ))
       [ "$pool_count" -lt 2 ] && pool_count=2
       log_warn "Capping pool to ${pool_count} per port (~${POOL_CAP} total)."
   fi

   echo ""
   echo "Select connection protocol:"
   echo "  1) wss       - RECOMMENDED: WebSocket over TLS, looks like HTTPS"
   echo "  2) websocket - WebSocket without TLS"
   echo "  3) tcp       - Plain TLS (NOT recommended for Iran)"
   echo "  4) kcp       - UDP-based, usually BLOCKED in Iran"
   echo "  5) quic      - UDP-based, usually BLOCKED in Iran"
   read -p "Select [1-5, default 1]: " proto_choice
   proto_choice=${proto_choice:-1}

   local transport_protocol
   local kcp_config=""
   local iran_warn=""

   case "$proto_choice" in
       3)
           transport_protocol="tcp"
           iran_warn="WARNING: Plain TCP is detectable in Iran."
           ;;
       4)
           transport_protocol="kcp"
           iran_warn="WARNING: KCP uses UDP, heavily filtered in Iran."
           kcp_config='
transport.kcp.mtu = 1350
transport.kcp.sndwnd = 128
transport.kcp.rcvwnd = 1024
transport.kcp.datashard = 10
transport.kcp.parityshard = 3
'
           ;;
       5)
           transport_protocol="quic"
           iran_warn="WARNING: QUIC uses UDP, heavily filtered in Iran."
           ;;
       2)
           transport_protocol="websocket"
           ;;
       *)
           transport_protocol="wss"
           ;;
   esac

   [ -n "$iran_warn" ] && log_warn "$iran_warn"

   echo ""
   echo "TLS / Domain Fronting:"
   echo "  1) Basic TLS (default)"
   echo "  2) Domain Fronting - Fake SNI"
   echo "  3) Real Domain - Your own domain"
   read -p "Select [1-3, default 1]: " tls_choice
   tls_choice=${tls_choice:-1}

   local tls_config=""
   local sni_note=""

   case "$tls_choice" in
       2)
           read -p "Enter fake SNI domain [default: www.microsoft.com]: " fake_sni
           fake_sni=${fake_sni:-www.microsoft.com}
           tls_config="transport.tls.serverName = \"${fake_sni}\""
           sni_note="SNI: ${fake_sni} (domain fronting)"
           log_ir "Domain fronting active: SNI will show ${fake_sni}"
           ;;
       3)
           read -p "Enter your real domain: " real_domain
           while [ -z "$real_domain" ]; do
               log_warn "Domain cannot be empty!"
               read -p "Enter your real domain: " real_domain
           done
           tls_config="transport.tls.serverName = \"${real_domain}\""
           sni_note="SNI: ${real_domain} (real domain)"
           ;;
       *)
           sni_note="SNI: ${server_addr} (basic TLS)"
           ;;
   esac

   echo ""
   echo "Proxy Chaining (optional):"
   echo "  If you have a working proxy (Shadowsocks/V2Ray/Xray),"
   echo "  FRP can tunnel through it."
   read -p "Use existing proxy? (y/n) [default: n]: " use_proxy

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

   # -----------------------------------------------------------------------
   # FIXED CLIENT CONFIG:
   # - Removed transport.tcpKeepalive (SERVER-ONLY field, caused crash)
   # - Removed heartbeatInterval/Timeout/dialServerTimeout/Keepalive 
   #   to avoid potential unknown-field errors in v0.71.0
   # - Kept only validated fields: protocol, tcpMux, poolCount
   # -----------------------------------------------------------------------
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
transport.tcpMux = false
transport.poolCount = ${pool_count}

${tls_config}
${proxy_config}
${kcp_config}
EOF

   generate_tcp_proxies "$ports" "/root/frp/client/client-${FRP_PORT}.toml"

   if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
       log_warn "Adding UDP forwarding..."
       generate_udp_proxies "$ports" "/root/frp/client/client-${FRP_PORT}.toml"
   fi

   # DEBUG: Test frpc directly BEFORE systemd to catch parse errors
   log_step "Testing frpc config validity (10 seconds)..."
   echo ""
   echo -e "${CYAN}========== DIRECT FRPC TEST ==========${NC}"
   timeout 10 /usr/local/bin/frpc -c /root/frp/client/client-${FRP_PORT}.toml 2>&1 || true
   echo -e "${CYAN}========== END OF TEST ==========${NC}"
   echo ""
   read -p "If you see an error above, press Ctrl+C to fix it. Otherwise press Enter to continue..."

   cat > /etc/systemd/system/frpc@.service <<'EOF'
[Unit]
Description=FRP Client Service (%i)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10s
LimitNOFILE=1048576
LimitNPROC=65535
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

   systemctl daemon-reload
   systemctl enable frpc@client-${FRP_PORT}.service
   systemctl restart frpc@client-${FRP_PORT}.service

   tune_tcp_for_frp
   install_watchdog

   log_step "Waiting for connection..."
   sleep 5

   local connected=false
   for i in {1..10}; do
       if pgrep -x "frpc" >/dev/null 2>&1; then
           local status
           status=$(curl -sf --max-time 3 -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
           if [ -n "$status" ] && echo "$status" | grep -q '"online":true'; then
               connected=true
               break
           fi
       fi
       sleep 2
   done

   echo ""
   if [ "$connected" = true ]; then
       log_info "FRP Client installed and connected to Iran!"
       echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
       echo -e "${GREEN}║  Client (OUTSIDE) Status: CONNECTED                  ║${NC}"
       echo -e "${GREEN}║  Iran Server:   ${server_addr}:${FRP_PORT}                  ║${NC}"
       echo -e "${GREEN}║  Protocol:     ${transport_protocol}                          ║${NC}"
       echo -e "${GREEN}║  ${sni_note}                    ║${NC}"
       echo -e "${GREEN}║  Pool:         ${pool_count} pre-opened connections            ║${NC}"
       echo -e "${GREEN}║  TCP Ports:    ${ports}                              ║${NC}"
       if [[ "$forward_udp" =~ ^[Yy]$ ]]; then
       echo -e "${GREEN}║  UDP Ports:    ${ports} (also forwarded)              ║${NC}"
       fi
       if [ -n "$proxy_config" ]; then
       echo -e "${GREEN}║  Proxy:        ENABLED                               ║${NC}"
       fi
       echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
   else
       log_warn "Connection not established."
       log_warn "Common causes for reverse tunnel (outside -> Iran):"
       log_warn "  1. Iran IP is blocked from your datacenter"
       log_warn "  2. Iran cloud firewall blocks port ${FRP_PORT}"
       log_warn "  3. TLS/SNI fingerprint detected"
       echo -e "${YELLOW}Check logs: journalctl -u frpc@client-${FRP_PORT} -f${NC}"
       echo -e "${YELLOW}Check config: cat /root/frp/client/client-${FRP_PORT}.toml${NC}"
       echo ""
       log_info "Debug commands:"
       echo "  nc -vz ${server_addr} ${FRP_PORT}"
       echo "  curl -v --max-time 10 https://${server_addr}:${FRP_PORT}"
       echo "  journalctl -u frpc@client-${FRP_PORT} --no-pager -n 30"
   fi

   echo ""
   log_info "View logs: journalctl -u frpc@client-${FRP_PORT} -f"
}

check_status() {
   echo "============================================"
   echo "           FRP Health Status                "
   echo "============================================"

   local has_service=false

   if systemctl list-units --type=service | grep -q 'frps@'; then
       has_service=true
       echo ""
       echo "--- FRP Server (frps) - IRAN ---"
       systemctl status frps@server-${FRP_PORT}.service --no-pager 2>/dev/null || echo "Not installed"

       if [ -f /var/log/frp-watchdog.log ]; then
           echo ""
           echo "--- Recent Watchdog Logs ---"
           tail -n 5 /var/log/frp-watchdog.log 2>/dev/null
       fi
   fi

   if systemctl list-units --type=service | grep -q 'frpc@'; then
       has_service=true
       echo ""
       echo "--- FRP Client (frpc) - OUTSIDE ---"
       systemctl status frpc@client-${FRP_PORT}.service --no-pager 2>/dev/null || echo "Not installed"

       echo ""
       echo "--- Connection Status ---"
       local status
       status=$(curl -sf --max-time 3 -u "admin:${FRP_TOKEN}" "http://127.0.0.1:${ADMIN_PORT_C}/api/status" 2>/dev/null)
       if [ -n "$status" ]; then
           if echo "$status" | grep -q '"online":true'; then
               echo -e "${GREEN}Client is ONLINE and connected to Iran server.${NC}"
           else
               echo -e "${RED}Client is RUNNING but OFFLINE (cannot reach Iran).${NC}"
               echo "Raw: $status"
           fi
       else
           echo "Admin API not available."
       fi
   fi

   if [ "$has_service" = false ]; then
       log_warn "No active FRP service found."
   fi

   echo ""
   echo "--- TCP Kernel Settings ---"
   sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_keepalive_time 2>/dev/null || true
}

remove_frp() {
   log_step "=== Removing FRP ==="

   systemctl stop frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true
   systemctl disable frps@server-${FRP_PORT}.service frpc@client-${FRP_PORT}.service 2>/dev/null || true

   rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
   rm -rf /root/frp
   rm -f /usr/local/bin/frps /usr/local/bin/frpc

   remove_watchdog
   remove_tcp_tuning

   systemctl daemon-reload

   log_info "FRP removed completely."
}

require_root

while true; do
   show_menu
   case $choice in
       1) install_server ;;
       2) install_client ;;
       3) check_status ;;
       4) remove_frp ;;
       5) echo "Goodbye!"; exit 0 ;;
       *) log_warn "Invalid option. Please try again." ;;
   esac
   echo
   read -p "Press Enter to continue..."
done
