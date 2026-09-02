#!/bin/bash
#==============================================================
#  FRP TUNNEL MANAGER v4.0 (Server + Client) — One Script
#  For: x-ui (VLESS / Shadowsocks) | Transport: TCP
#  Features: Smart Watchdog | Google/QUIC Fix | MTU Fix | Monitor
#
#  ⚠️ نکات مهم:
#  - فرپ فقط TCP و UDP فوروارد میکند. ICMP (پینگ) از داخل تانل
#    رد نمیشود. پینگ واچ‌داگ، پینگ مستقیم بین دو سرور برای سنجش
#    سلامت لینک است (چون از ICMP استفاده میکنی، این کار میکند).
#  - x-ui داخل این اسکریپت نصب نمیشود — خودت نصب کن.
#==============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

FRP_VERSION="0.58.1"
INSTALL_DIR="/opt/frp"
BIN_DIR="$INSTALL_DIR/bin"
CONFIG_DIR="/etc/frp"
LOG_DIR="/var/log/frp"
SCRIPTS_DIR="$INSTALL_DIR/scripts"

#---------------- helpers ----------------
msg()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

check_root() {
    [ "$EUID" -ne 0 ] && { err "با root اجرا کن → sudo bash $0"; exit 1; }
}

detect_arch() {
    case $(uname -m) in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "arm" ;;
        *) err "معماری پشتیبانی نمیشود: $(uname -m)"; exit 1 ;;
    esac
}

is_port() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q wget curl tar openssl iptables iproute2 procps >/dev/null 2>&1
    fi
    command -v wget >/dev/null 2>&1 || { err "نصب wget ناموفق بود"; exit 1; }
}

# دانلود با میرور فال‌بک (برای سرورهایی که دسترسی مستقیم به گیت‌هاب ندارند)
fetch_file() {
    local url="$1" out="$2"
    local mirrors=("" "https://ghfast.top/" "https://ghproxy.net/" "https://mirror.ghproxy.com/")
    local m
    for m in "${mirrors[@]}"; do
        wget -q --timeout=25 "${m}${url}" -O "$out" 2>/dev/null && [ -s "$out" ] && return 0
    done
    curl -sL --max-time 90 "$url" -o "$out" 2>/dev/null && [ -s "$out" ] && return 0
    return 1
}

install_frp_binaries() {
    local need="$1"   # frps | frpc | both
    local arch; arch=$(detect_arch)
    local file="frp_${FRP_VERSION}_linux_${arch}.tar.gz"
    local url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${file}"
    local ext="frp_${FRP_VERSION}_linux_${arch}"

    mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR"

    msg "دانلود FRP v${FRP_VERSION} (${arch})..."
    fetch_file "$url" "/tmp/$file" || { err "دانلود ناموفق (گیت‌هاب + میرورها)"; exit 1; }
    tar -xzf "/tmp/$file" -C /tmp || { err "اکسترکت ناموفق"; exit 1; }

    [ "$need" != "frpc" ] && cp "/tmp/$ext/frps" "$BIN_DIR/" && chmod +x "$BIN_DIR/frps"
    [ "$need" != "frps" ] && cp "/tmp/$ext/frpc" "$BIN_DIR/" && chmod +x "$BIN_DIR/frpc"
    rm -rf "/tmp/$ext" "/tmp/$file"
    msg "باینری FRP نصب شد → $BIN_DIR"
}

sys_optimize() {
    msg "بهینه‌سازی سیستم (BBR، بافرها، MTU probing)..."
    modprobe tcp_bbr 2>/dev/null
    modprobe nf_conntrack 2>/dev/null

    cat > /etc/sysctl.d/99-frp-tuning.conf <<EOF
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 536
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.udp_mem = 786432 1048576 1572864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.ipfrag_high_thresh = 4194304
net.ipv4.ipfrag_low_thresh = 3145728
net.ipv4.ipfrag_time = 30
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
vm.swappiness = 10
fs.file-max = 1000000
EOF
    sysctl -p /etc/sysctl.d/99-frp-tuning.conf >/dev/null 2>&1 || true

    cat > /etc/security/limits.d/frp-limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF
}

open_firewall() {
    local p
    for p in $1; do
        if command -v ufw >/dev/null 2>&1; then
            ufw allow "${p//-/:}" >/dev/null 2>&1
        elif command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="$p" >/dev/null 2>&1
        fi
    done
    command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1
    return 0
}

#==============================================================
#  گزینه 1 — نصب FRP SERVER (frps)  ← روی سرور فرپ اجرا شود
#==============================================================
install_server() {
    echo ""
    msg "═══ نصب FRP SERVER (frps) ═══"

    if [ -f /etc/systemd/system/frps.service ]; then
        read -rp "frps قبلا نصب شده. نصب مجدد انجام شود؟ (y/N): " R
        [ "$R" = "y" ] || return 0
        systemctl stop frps 2>/dev/null
    fi

    install_deps
    sys_optimize
    install_frp_binaries frps

    read -rp "پورت FRP [7000]: " P;      P=${P:-7000};      is_port "$P"  || { err "پورت نامعتبر"; return 1; }
    read -rp "پورت Dashboard [7500]: " DP; DP=${DP:-7500};  is_port "$DP" || { err "پورت نامعتبر"; return 1; }
    read -rp "بازه پورت‌های Remote برای کلاینت‌ها [1024-65535]: " RANGE
    RANGE=${RANGE:-1024-65535}
    RSTART=${RANGE%-*}; REND=${RANGE#*-}
    is_port "$RSTART" && is_port "$REND" || { err "بازه نامعتبر"; return 1; }

    TOKEN=$(openssl rand -hex 16)
    DASH_USER="admin"
    DASH_PASS=$(openssl rand -hex 8)
    SRV_IP=$(curl -s4 --max-time 6 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    cat > "$CONFIG_DIR/frps.toml" <<EOF
bindAddr = "0.0.0.0"
bindPort = ${P}
kcpBindPort = ${P}
quicBindPort = ${P}

auth.method = "token"
auth.token = "${TOKEN}"

webServer.addr = "0.0.0.0"
webServer.port = ${DP}
webServer.user = "${DASH_USER}"
webServer.password = "${DASH_PASS}"

allowPorts = [ { start = ${RSTART}, end = ${REND} } ]
maxPortsPerClient = 0

transport.heartbeatTimeout = 90
transport.maxPoolCount = 50
transport.tcpMuxKeepaliveInterval = 30

log.to = "${LOG_DIR}/frps.log"
log.level = "warn"
log.maxDays = 3

udpPacketSize = 1500
EOF

    # ✅ اعتبارسنجی کانفیگ قبل از استارت
    if ! "$BIN_DIR/frps" verify -c "$CONFIG_DIR/frps.toml" >/dev/null 2>&1; then
        err "کانفیگ frps نامعتبر است!"; return 1
    fi

    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server (frps)
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=${BIN_DIR}/frps -c ${CONFIG_DIR}/frps.toml
LimitNOFILE=1000000
LimitNPROC=500000
KillMode=process
TimeoutStopSec=5
Environment="GOMAXPROCS=$(nproc)"

[Install]
WantedBy=multi-user.target
EOF

    open_firewall "${P}/tcp ${P}/udp ${DP}/tcp ${RSTART}-${REND}/tcp ${RSTART}-${REND}/udp"

    systemctl daemon-reload
    systemctl enable frps >/dev/null 2>&1
    systemctl restart frps
    sleep 3

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/server-info.txt" <<EOF
Server IP   : ${SRV_IP}
FRP Port    : ${P} (tcp/kcp/quic)
Token       : ${TOKEN}
Dashboard   : http://${SRV_IP}:${DP}  (${DASH_USER} / ${DASH_PASS})
EOF

    echo ""
    if systemctl is-active --quiet frps; then
        echo -e "${GREEN}╔══════════════ FRP SERVER آماده است ══════════════╗${NC}"
        echo -e "${GREEN}║ Server IP : ${SRV_IP}${NC}"
        echo -e "${GREEN}║ FRP Port  : ${P} (tcp/kcp/quic)${NC}"
        echo -e "${YELLOW}║ TOKEN     : ${TOKEN}${NC}"
        echo -e "${GREEN}║ Dashboard : http://${SRV_IP}:${DP}${NC}"
        echo -e "${GREEN}║             user=${DASH_USER}  pass=${DASH_PASS}${NC}"
        echo -e "${GREEN}║ (اطلاعات در ${CONFIG_DIR}/server-info.txt ذخیره شد)${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
        warn "قدم بعدی: روی سرور x-ui (کلاینت) → گزینه 2، بعد 4، بعد 5"
    else
        err "frps استارت نشد:"; journalctl -u frps --no-pager -n 15
    fi
}

#==============================================================
#  پروکسی‌نویس‌ها (کلاینت)
#==============================================================
write_tcp_proxy() {  # $1=name $2=lport $3=rport
cat >> "$CONFIG_DIR/frpc.toml" <<EOF

[[proxies]]
name = "$1"
type = "tcp"
localIP = "127.0.0.1"
localPort = $2
remotePort = $3
transport.useEncryption = false
transport.useCompression = false
healthCheck.enable = true
healthCheck.type = "tcp"
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
healthCheck.intervalSeconds = 10
EOF
}

write_udp_proxy() {  # $1=name $2=lport $3=rport
cat >> "$CONFIG_DIR/frpc.toml" <<EOF

[[proxies]]
name = "$1"
type = "udp"
localIP = "127.0.0.1"
localPort = $2
remotePort = $3
transport.useEncryption = false
transport.useCompression = false
EOF
}

proxy_count() {
    local n
    n=$(grep -c '^\[\[proxies\]\]' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    [ -z "$n" ] && n=0
    echo "$n"
}

#==============================================================
#  گزینه 2 — نصب FRP CLIENT (frpc)  ← روی سرور x-ui اجرا شود
#==============================================================
install_client() {
    echo ""
    msg "═══ نصب FRP CLIENT (frpc) ═══"

    if [ -f "$CONFIG_DIR/frpc.toml" ]; then
        read -rp "frpc قبلا کانفیگ شده. از نو کانفیگ شود؟ (y/N): " R
        [ "$R" = "y" ] || return 0
        systemctl stop frpc 2>/dev/null
    fi

    install_deps
    sys_optimize
    install_frp_binaries frpc

    read -rp "IP سرور فرپ (frps): " SERVER_IP
    [ -z "$SERVER_IP" ] && { err "IP الزامی است"; return 1; }
    read -rp "پورت FRP [7000]: " P; P=${P:-7000}; is_port "$P" || { err "پورت نامعتبر"; return 1; }
    read -rp "Token: " TOKEN
    [ -z "$TOKEN" ] && { err "Token الزامی است"; return 1; }

    echo ""
    echo "پروتکل ارتباط فرپ با سرور:"
    echo "  1) tcp       ← پیش‌فرض و پایدار (انتخاب اصلی تو)"
    echo "  2) kcp       ← سرعت بهتر روی لینک پکت‌لاس (نیاز UDP باز بین دو سرور)"
    echo "  3) quic      ← مشابه kcp"
    echo "  4) websocket ← برای عبور از فایروال‌های سخت‌گیر"
    read -rp "انتخاب [1]: " T
    case $T in
        2) TP="kcp" ;; 3) TP="quic" ;; 4) TP="websocket" ;; *) TP="tcp" ;;
    esac

    # ---------- پورت مپ‌ها (اینباندهای x-ui: VLESS / Shadowsocks) ----------
    MAPPINGS=()
    while true; do
        echo ""
        echo -e "${CYAN}── پورت مپ جدید (پورت اینباند پنل x-ui) ──${NC}"
        read -rp "پورت لوکال روی همین سرور (اینباند پنل، مثلا 443 یا 8443): " LP
        is_port "$LP" || { err "پورت نامعتبر"; continue; }
        read -rp "پورت Remote روی سرور فرپ (کاربر به این وصل میشود): " RP
        is_port "$RP" || { err "پورت نامعتبر"; continue; }
        read -rp "پروتکل مپ: tcp/udp/both [both]: " PP; PP=${PP:-both}
        case $PP in tcp|udp|both) ;; *) PP="both" ;; esac

        # هشدار اگر پورت لوکال هیچ سرویسی روش گوش نمیدهد
        if command -v ss >/dev/null 2>&1; then
            if ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":${LP}$"; then
                warn "پورت ${LP} هنوز روی این سرور Listen نیست — اینباند x-ui را بساز"
            fi
        fi

        MAPPINGS+=("${LP}:${RP}:${PP}")
        read -rp "پورت دیگری اضافه میکنی؟ (Y/n): " M
        [ "$M" = "n" ] && break
    done

    [ ${#MAPPINGS[@]} -eq 0 ] && { err "حداقل یک پورت مپ لازم است"; return 1; }

    # ---------- کانفیگ اصلی ----------
    cat > "$CONFIG_DIR/frpc.toml" <<EOF
serverAddr = "${SERVER_IP}"
serverPort = ${P}

auth.method = "token"
auth.token = "${TOKEN}"

transport.protocol = "${TP}"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
transport.poolCount = 10
transport.tcpKeepalive = 30
transport.dialServerTimeout = 10

loginFailExit = false

log.to = "${LOG_DIR}/frpc.log"
log.level = "info"
log.maxDays = 3

udpPacketSize = 1500
EOF

    # ---------- پروکسی‌ها ----------
    i=0
    for m in "${MAPPINGS[@]}"; do
        i=$((i+1))
        LP=${m%%:*}; rest=${m#*:}; RP=${rest%%:*}; PP=${rest#*:}
        case $PP in
            tcp)  write_tcp_proxy "xui-tcp-$i" "$LP" "$RP" ;;
            udp)  write_udp_proxy "xui-udp-$i" "$LP" "$RP" ;;
            both) write_tcp_proxy "xui-tcp-$i" "$LP" "$RP"
                  write_udp_proxy "xui-udp-$i" "$LP" "$RP" ;;
        esac
    done

    # ---------- اعتبارسنجی ----------
    if ! "$BIN_DIR/frpc" verify -c "$CONFIG_DIR/frpc.toml" >/dev/null 2>&1; then
        err "کانفیگ frpc نامعتبر است! لاگ: $LOG_DIR/frpc.log"; return 1
    fi

    # ---------- سرویس ----------
    cat > /etc/systemd/system/frpc.service <<EOF
[Unit]
Description=FRP Client (frpc)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Restart=always
RestartSec=3
ExecStart=${BIN_DIR}/frpc -c ${CONFIG_DIR}/frpc.toml
LimitNOFILE=1000000
LimitNPROC=500000
KillMode=process
TimeoutStopSec=5
Environment="GOMAXPROCS=$(nproc)"

[Install]
WantedBy=multi-user.target
EOF

    open_firewall "${P}/tcp ${P}/udp"

    systemctl daemon-reload
    systemctl enable frpc >/dev/null 2>&1
    systemctl restart frpc
    sleep 4

    echo ""
    if systemctl is-active --quiet frpc; then
        msg "frpc در حال اجراست"
        if tail -20 "$LOG_DIR/frpc.log" 2>/dev/null | grep -q "login to server success"; then
            msg "اتصال تانل به ${SERVER_IP}:${P} برقرار است ✅"
        else
            warn "اتصال هنوز برقرار نشده — IP/Token را چک کن، لاگ: منو → گزینه 9"
        fi
    else
        err "frpc استارت نشد:"; journalctl -u frpc --no-pager -n 15
        return 1
    fi

    echo ""
    echo -e "${CYAN}پورت مپ‌ها:${NC}"
    for m in "${MAPPINGS[@]}"; do
        LP=${m%%:*}; rest=${m#*:}; RP=${rest%%:*}; PP=${rest#*:}
        echo -e "  local ${LP} → remote ${RP} (${PP})"
    done
    warn "قدم بعدی: گزینه 4 (واچ‌داگ) و گزینه 5 (فیکس گوگل — روی همین سرور چون خروجی اینترنت اینجاست)"
}

#==============================================================
#  گزینه 3 — افزودن پورت مپ جدید بدون نصب مجدد
#==============================================================
add_mapping() {
    [ -f "$CONFIG_DIR/frpc.toml" ] || { err "اول گزینه 2 (نصب کلاینت) را اجرا کن"; return 1; }

    read -rp "پورت لوکال (اینباند x-ui): " LP
    is_port "$LP" || { err "پورت نامعتبر"; return 1; }
    read -rp "پورت Remote روی سرور فرپ: " RP
    is_port "$RP" || { err "پورت نامعتبر"; return 1; }
    read -rp "پروتکل مپ: tcp/udp/both [both]: " PP; PP=${PP:-both}
    case $PP in tcp|udp|both) ;; *) PP="both" ;; esac

    if command -v ss >/dev/null 2>&1; then
        if ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":${LP}$"; then
            warn "پورت ${LP} هنوز Listen نیست — اینباند را در x-ui بساز"
        fi
    fi

    N=$(proxy_count)
    case $PP in
        tcp)  write_tcp_proxy "xui-tcp-$((N+1))" "$LP" "$RP" ;;
        udp)  write_udp_proxy "xui-udp-$((N+1))" "$LP" "$RP" ;;
        both) write_tcp_proxy "xui-tcp-$((N+1))" "$LP" "$RP"
              write_udp_proxy "xui-udp-$((proxy_count+1))" "$LP" "$RP" ;;
    esac

    if ! "$BIN_DIR/frpc" verify -c "$CONFIG_DIR/frpc.toml" >/dev/null 2>&1; then
        err "کانفیگ جدید نامعتبر! به نسخه قبل برنگشته — لاگ را ببین"; return 1
    fi

    systemctl restart frpc 2>/dev/null
    msg "پورت مپ اضافه و frpc ری‌استارت شد (local ${LP} → remote ${RP})"
    warn "اگر روی سرور فرپ فایروال (ufw/firewalld) فعاله، پورت ${RP} را آنجا هم باز کن"
}

#==============================================================
#  گزینه 4 — واچ‌داگ هوشمند
#==============================================================
install_watchdog() {
    [ -f "$CONFIG_DIR/frpc.toml" ] || { err "اول گزینه 2 (نصب کلاینت) را اجرا کن"; return 1; }

    msg "نصب واچ‌داگ هوشمند..."

    cat > "$SCRIPTS_DIR/frp-watchdog.sh" <<'WEOF'
#!/bin/bash
# ============ Smart FRP Watchdog v4.0 ============
# هر 5 ثانیه چک | بعد از 2 خطا (10s) اقدام | کول‌داون ضدلوپ
LOG_DIR="/var/log/frp"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
CONFIG="/etc/frp/frpc.toml"

SERVER_ADDR=$(grep -oP '^\s*serverAddr\s*=\s*"\K[^"]+' "$CONFIG" 2>/dev/null)
SERVER_PORT=$(grep -oP '^\s*serverPort\s*=\s*\K[0-9]+' "$CONFIG" 2>/dev/null)

CHECK_INTERVAL=5
FAIL_THRESHOLD=2
RESTART_COOLDOWN=30
fail_count=0
last_restart=0
total_restarts=0
cycle=0

log(){ echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$WATCHDOG_LOG"; }

# جلوگیری از بزرگ شدن لاگ (بیش از 1MB → خالی)
if [ -f "$WATCHDOG_LOG" ]; then
    sz=$(stat -c%s "$WATCHDOG_LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 1048576 ] && : > "$WATCHDOG_LOG"
fi

[ -z "$SERVER_ADDR" ] && { echo "$(date) ERROR: frpc.toml not found" >> "$WATCHDOG_LOG"; exit 1; }

proc_ok(){ pgrep -x frpc >/dev/null 2>&1; }

tcp_ok(){ timeout 3 bash -c "exec 3<>/dev/tcp/$SERVER_ADDR/$SERVER_PORT" 2>/dev/null; }

log_ok(){
    [ -f "$LOG_DIR/frpc.log" ] || return 0
    recent=$(tail -n 15 "$LOG_DIR/frpc.log" 2>/dev/null)
    echo "$recent" | grep -qE 'login to server success|start proxy success' && return 0
    echo "$recent" | grep -qiE 'connect to server error|dial tcp.*(refused|timeout|i/o timeout)' && return 1
    return 0
}

mem_kb(){ ps -C frpc -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}'; }

restart_frpc(){
    now=$(date +%s)
    if [ $((now - last_restart)) -lt $RESTART_COOLDOWN ]; then
        log "COOLDOWN — ری‌استارت رد شد (جلوگیری از لوپ)"
        return 1
    fi
    log "ACTION: ری‌استارت frpc..."
    systemctl stop frpc 2>/dev/null
    pkill -9 -x frpc 2>/dev/null
    sleep 1
    # پاکسازی سوکت‌های نیمه‌مُرده به سمت سرور
    ss -K dst "$SERVER_ADDR" 2>/dev/null
    systemctl reset-failed frpc 2>/dev/null
    systemctl start frpc 2>/dev/null
    sleep 3
    last_restart=$(date +%s)
    total_restarts=$((total_restarts+1))
    if proc_ok; then
        log "OK: frpc ری‌استارت شد (مجموع=$total_restarts)"
        fail_count=0
    else
        log "ERROR: ری‌استارت ناموفق!"
    fi
}

net_repair(){
    log "ACTION: تعمیر شبکه (سوکت‌های مُرده / ARP / sysctl)"
    ss -K dst "$SERVER_ADDR" 2>/dev/null
    ip neigh flush "$SERVER_ADDR" 2>/dev/null
    sysctl -p /etc/sysctl.d/99-frp-tuning.conf >/dev/null 2>&1
}

log "==================================================="
log "START watchdog → server=$SERVER_ADDR:$SERVER_PORT interval=${CHECK_INTERVAL}s threshold=$FAIL_THRESHOLD"

while true; do
    sleep "$CHECK_INTERVAL"
    cycle=$((cycle+1))

    # --- 1) پروسه زنده است؟ ---
    if ! proc_ok; then
        fail_count=$((fail_count+1))
        log "WARN: پروسه frpc مرده است ($fail_count/$FAIL_THRESHOLD)"
        [ $fail_count -ge $FAIL_THRESHOLD ] && restart_frpc
        continue
    fi

    # --- 2) کانکشن TCP واقعی به سرور برقرار است؟ (سریع‌ترین تست) ---
    if ! tcp_ok; then
        fail_count=$((fail_count+1))
        log "WARN: سرور در دسترس نیست ($fail_count/$FAIL_THRESHOLD)"
        if [ $fail_count -ge $FAIL_THRESHOLD ]; then
            net_repair
            sleep 2
            tcp_ok || restart_frpc
            fail_count=0
        fi
        continue
    fi

    # --- 3) لاگ frpc سالم است؟ ---
    if ! log_ok; then
        fail_count=$((fail_count+1))
        log "WARN: لاگ frpc خطا نشان میدهد ($fail_count/$FAIL_THRESHOLD)"
        [ $fail_count -ge $FAIL_THRESHOLD ] && restart_frpc
        continue
    fi

    if [ $fail_count -gt 0 ]; then
        log "OK: اتصال برقرار شد ✔"
        fail_count=0
    fi

    # --- 4) هر 60 ثانیه: پینگ ICMP مستقیم + حافظه ---
    if [ $((cycle % 12)) -eq 0 ]; then
        lat=$(ping -c1 -W2 "$SERVER_ADDR" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2 | cut -d. -f1)
        [ -n "$lat" ] && log "INFO: پینگ مستقیم ${lat}ms"
        m=$(mem_kb)
        if [ "$m" -gt 524288 ]; then
            log "WARN: مصرف حافظه frpc بالا ($((m/1024))MB) → ری‌استارت"
            restart_frpc
        fi
    fi
done
WEOF
    chmod +x "$SCRIPTS_DIR/frp-watchdog.sh"

    cat > /etc/systemd/system/frp-watchdog.service <<EOF
[Unit]
Description=FRP Smart Watchdog
After=frpc.service

[Service]
Type=simple
User=root
Restart=always
RestartSec=5
ExecStart=${SCRIPTS_DIR}/frp-watchdog.sh
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frp-watchdog >/dev/null 2>&1
    systemctl restart frp-watchdog

    if systemctl is-active --quiet frp-watchdog; then
        msg "واچ‌داگ فعال شد (چک هر 5s — اقدام بعد از 10s — کول‌داون 30s)"
    else
        err "واچ‌داگ استارت نشد:"; journalctl -u frp-watchdog --no-pager -n 10
    fi
}

#==============================================================
#  گزینه 5 و 6 — فیکس گوگل + MTU
#==============================================================
ensure_fix_rules() {
    cat > "$SCRIPTS_DIR/apply-fix-rules.sh" <<'FEOF'
#!/bin/bash
# بلاک QUIC/UDP-443 → کروم فوراً روی TCP فال‌بک میکند (فیکس سرچ گوگل)
iptables  -C OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null || iptables  -I OUTPUT  1 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
ip6tables -C OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null || ip6tables -I OUTPUT  1 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable
iptables  -C FORWARD -p udp --dport 443 -j REJECT 2>/dev/null || iptables  -I FORWARD 1 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
ip6tables -C FORWARD -p udp --dport 443 -j REJECT 2>/dev/null || ip6tables -I FORWARD 1 -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable

# MSS Clamp → فیکس صفحات نیمه‌لود / هنگ روی محتوای سنگین
iptables  -t mangle -C OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables  -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables  -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables  -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip6tables -t mangle -C OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# اعمال MTU ذخیره‌شده از منوی بهینه‌ساز
MTU_FILE=/etc/frp/mtu.conf
if [ -f "$MTU_FILE" ]; then
    MTU=$(cat "$MTU_FILE")
    for i in /sys/class/net/*; do
        iface=${i##*/}
        [ "$iface" = "lo" ] && continue
        cur=$(cat "$i/mtu" 2>/dev/null)
        [ -n "$cur" ] && [ "$cur" -gt "$MTU" ] && ip link set dev "$iface" mtu "$MTU" 2>/dev/null
    done
fi
exit 0
FEOF
    chmod +x "$SCRIPTS_DIR/apply-fix-rules.sh"

    cat > /etc/systemd/system/frp-fix-rules.service <<EOF
[Unit]
Description=FRP Fix Rules (QUIC/MSS/MTU) — persistent
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/apply-fix-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frp-fix-rules >/dev/null 2>&1
}

google_fix() {
    msg "اعمال فیکس گوگل (بلاک QUIC + MSS Clamp)..."
    install_deps
    ensure_fix_rules
    "$SCRIPTS_DIR/apply-fix-rules.sh"
    msg "انجام شد — کروم دیگر منتظر QUIC نمیماند و سریع روی TCP سرچ میکند"
    warn "این گزینه باید روی سروری اجرا شود که x-ui و خروجی اینترنت روی آن است (کلاینت فرپ)"
    warn "اگر باز مشکل DNS داشتی: در x-ui خروجی، DNS را روی tcp://8.8.8.8 بگذار"
}

mtu_opt() {
    read -rp "IP برای تست MTU (IP سرور فرپ): " TIP
    [ -z "$TIP" ] && { err "IP الزامی است"; return 1; }

    msg "تشخیص خودکار بهترین MTU (جستجوی باینری)..."
    size=1472; optimal=1500
    while [ "$size" -gt 500 ]; do
        if ping -M do -s "$size" -c1 -W2 "$TIP" >/dev/null 2>&1; then
            optimal=$((size+28)); break
        fi
        size=$((size-10))
    done

    mkdir -p "$CONFIG_DIR"
    echo "$optimal" > "$CONFIG_DIR/mtu.conf"
    install_deps
    ensure_fix_rules
    "$SCRIPTS_DIR/apply-fix-rules.sh"
    msg "بهترین MTU: $optimal → روی همه اینترفیس‌ها اعمال شد (دائمی — بعد از ریبوت هم خودکار اعمال میشود)"
}

#==============================================================
#  گزینه 7 — وضعیت
#==============================================================
show_status() {
    echo ""
    echo -e "${CYAN}══════════ وضعیت FRP ══════════${NC}"
    for svc in frps frpc frp-watchdog frp-fix-rules; do
        [ -f "/etc/systemd/system/$svc.service" ] || continue
        if systemctl is-active --quiet "$svc"; then
            echo -e "  $svc : ${GREEN}● RUNNING${NC}"
        else
            echo -e "  $svc : ${RED}● STOPPED${NC}"
        fi
    done

    if [ -f "$CONFIG_DIR/frpc.toml" ]; then
        SA=$(grep -oP 'serverAddr\s*=\s*"\K[^"]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
        SP=$(grep -oP 'serverPort\s*=\s*\K[0-9]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
        if [ -n "$SA" ]; then
            if timeout 2 bash -c "exec 3<>/dev/tcp/$SA/$SP" 2>/dev/null; then
                echo -e "  Server $SA:$SP : ${GREEN}● در دسترس${NC}"
            else
                echo -e "  Server $SA:$SP : ${RED}● قطع${NC}"
            fi
            P=$(ping -c1 -W2 "$SA" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            [ -n "$P" ] && echo -e "  Latency: ${YELLOW}${P}ms${NC}"
            C=$(ss -tn 2>/dev/null | grep -c "$SA")
            echo -e "  کانکشن‌های فعال: ${YELLOW}$C${NC}"
        fi
    fi

    PID=$(pgrep -x frpc | head -1)
    [ -n "$PID" ] && echo -e "  frpc MEM: $(ps -p $PID -o rss= | awk '{printf "%.0f MB", $1/1024}')  CPU: $(ps -p $PID -o %cpu= | tr -d ' ')%"

    echo ""
    echo -e "${CYAN}── آخرین رویدادهای واچ‌داگ ──${NC}"
    tail -5 "$LOG_DIR/watchdog.log" 2>/dev/null || echo "  (رویدادی نیست)"
    echo ""
}

#==============================================================
#  گزینه 8 — مانیتور زنده
#==============================================================
show_monitor() {
    SA=$(grep -oP 'serverAddr\s*=\s*"\K[^"]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    SP=$(grep -oP 'serverPort\s*=\s*\K[0-9]+' "$CONFIG_DIR/frpc.toml" 2>/dev/null)
    trap 'trap - INT; echo; return' INT
    while true; do
        clear
        echo -e "${CYAN}════ FRP LIVE MONITOR — $(date '+%H:%M:%S') ════${NC}  (Ctrl+C = بازگشت)"
        systemctl is-active --quiet frpc 2>/dev/null && echo -e " frpc      : ${GREEN}● RUNNING${NC}" || echo -e " frpc      : ${RED}● STOPPED${NC}"
        systemctl is-active --quiet frp-watchdog 2>/dev/null && echo -e " watchdog  : ${GREEN}● RUNNING${NC}" || echo -e " watchdog  : ${RED}● STOPPED${NC}"
        if [ -n "$SA" ]; then
            if timeout 2 bash -c "exec 3<>/dev/tcp/$SA/$SP" 2>/dev/null; then
                echo -e " server    : ${GREEN}● CONNECTED${NC} ($SA:$SP)"
            else
                echo -e " server    : ${RED}● DISCONNECTED${NC} ($SA:$SP)"
            fi
            P=$(ping -c1 -W2 "$SA" 2>/dev/null | grep -o 'time=[0-9.]*' | head -1 | cut -d= -f2)
            [ -n "$P" ] && echo -e " latency   : ${YELLOW}${P}ms${NC}"
            echo -e " conns     : $(ss -tn 2>/dev/null | grep -c "$SA")"
        fi
        PID=$(pgrep -x frpc | head -1)
        [ -n "$PID" ] && echo -e " frpc mem  : $(ps -p $PID -o rss= | awk '{printf "%.0f MB", $1/1024}') | uptime: $(ps -p $PID -o etime= | tr -d ' ')"
        echo "──────────────────────────────"
        tail -3 "$LOG_DIR/watchdog.log" 2>/dev/null
        sleep 3
    done
}

#==============================================================
#  گزینه 9 / 10 / 11 / 12
#==============================================================
view_logs() {
    echo "  1) frpc log   2) frps log   3) watchdog log   4) journal frpc"
    read -rp "انتخاب: " L
    case $L in
        1) tail -f "$LOG_DIR/frpc.log" 2>/dev/null ;;
        2) tail -f "$LOG_DIR/frps.log" 2>/dev/null ;;
        3) tail -f "$LOG_DIR/watchdog.log" 2>/dev/null ;;
        4) journalctl -u frpc -f --no-pager ;;
    esac
}

restart_services() {
    for svc in frpc frps frp-watchdog frp-fix-rules; do
        if [ -f "/etc/systemd/system/$svc.service" ]; then
            systemctl restart "$svc" 2>/dev/null && msg "$svc ری‌استارت شد"
        fi
    done
    sleep 2
    show_status
}

uninstall() {
    read -rp "مطمئنی همه‌چیز حذف شود؟ (yes/no): " C
    [ "$C" = "yes" ] || return 0
    for svc in frp-watchdog frpc frps frp-fix-rules; do
        systemctl disable --now "$svc" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$svc.service"
    done
    # حذف رول‌های iptables
    iptables  -D OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null
    ip6tables -D OUTPUT  -p udp --dport 443 -j REJECT 2>/dev/null
    iptables  -D FORWARD -p udp --dport 443 -j REJECT 2>/dev/null
    ip6tables -D FORWARD -p udp --dport 443 -j REJECT 2>/dev/null
    iptables  -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    iptables  -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    pkill -9 -x frpc 2>/dev/null; pkill -9 -x frps 2>/dev/null
    rm -rf "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    rm -f /etc/sysctl.d/99-frp-tuning.conf /etc/security/limits.d/frp-limits.conf
    msg "حذف کامل انجام شد."
}

#==============================================================
#  منوی اصلی
#==============================================================
show_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   FRP TUNNEL MANAGER v4.0 (x-ui / VLESS / SS)    ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  1) نصب FRP Server (frps)        ← سرور فرپ     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  2) نصب FRP Client (frpc)        ← سرور x-ui    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  3) افزودن پورت مپ جدید (کلاینت)                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  4) واچ‌داگ هوشمند                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  5) فیکس گوگل (QUIC block + MSS clamp)          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  6) بهینه‌ساز MTU                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  7) وضعیت (Status)                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  8) مانیتور زنده                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  9) مشاهده لاگ‌ها                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  10) ری‌استارت سرویس‌ها                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  11) اعمال مجدد تیونینگ سیستم                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  12) حذف کامل (Uninstall)                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  0) خروج                                        ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
}

check_root
while true; do
    show_menu
    read -rp "انتخاب: " CH
    case $CH in
        1)  install_server ;;
        2)  install_client ;;
        3)  add_mapping ;;
        4)  install_watchdog ;;
        5)  google_fix ;;
        6)  mtu_opt ;;
        7)  show_status ;;
        8)  show_monitor ;;
        9)  view_logs ;;
        10) restart_services ;;
        11) sys_optimize ;;
        12) uninstall ;;
        0)  exit 0 ;;
        *)  warn "انتخاب نامعتبر" ;;
    esac
    read -rp $'\nبرای بازگشت به منو Enter بزن...'
done
