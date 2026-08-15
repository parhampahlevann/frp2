#!/usr/bin/env bash
# =====================================================================
#  FRP HIGH-THROUGHPUT INSTALLER / UPDATER
#  frps + frpc | FRP v0.60.0 | NO TLS | NO BANDWIDTH LIMIT
#
#  اهداف:
#    - حذف کامل bandwidth limit
#    - حداکثر throughput عملی در حد ظرفیت واقعی شبکه
#    - TCP-RAW برای بیشترین aggregate throughput
#    - TCP-MUXED برای پایداری و کاهش connection overhead
#    - QUIC برای مسیرهای مناسب UDP
#    - KCP به عنوان UDP fallback
#    - sysctl محافظه‌کارانه ولی مناسب throughput
#    - BBR فقط در صورت پشتیبانی کرنل
#    - systemd auto restart
#    - config verification قبل از restart
#
#  IMPORTANT:
#    این اسکریپت محدودیت ISP، VPS، provider، NIC، مسیر اینترنت یا
#    congestion شبکه را حذف نمی‌کند؛ فقط محدودیت مصنوعی FRP را حذف می‌کند.
# =====================================================================

set -euo pipefail

# ============================= Colors ===============================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info() {
    echo -e "${CYAN}==>${NC} $1"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

fail() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# ========================= Fixed Settings ===========================

FRP_VERSION="0.60.0"
FRP_TAG="v${FRP_VERSION}"

# استفاده از همان token که در نسخه قبلی خودتان قرار داده بودید.
FIXED_AUTH_TOKEN="7ZuESw25FFWCZQmrroruUEy4qVVB9dbmkG1BMSMD6WHx"

FRP_DIR="/etc/frp"
LOG_DIR="/var/log/frp"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

SYSCTL_FILE="/etc/sysctl.d/99-frp-tune.conf"

# ============================= Root =================================

[[ "${EUID}" -eq 0 ]] || fail "Run this script as root (sudo)."

# ============================= Functions =============================

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_dns() {
    getent hosts github.com >/dev/null 2>&1
}

fix_dns_if_needed() {
    if check_dns; then
        ok "DNS is working."
        return 0
    fi

    warn "DNS resolution is broken. Attempting repair..."

    if [[ -e /etc/resolv.conf ]] && command_exists chattr; then
        chattr -i /etc/resolv.conf 2>/dev/null || true
    fi

    if [[ -L /etc/resolv.conf ]]; then
        warn "/etc/resolv.conf is a symlink. Temporary resolver override will be used."
    fi

    rm -f /etc/resolv.conf

    cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

    sleep 1

    if check_dns; then
        ok "DNS repaired."
    else
        warn "DNS is still unavailable."
    fi
}

port_in_use() {
    local PORT="$1"

    if command_exists ss; then
        ss -H -tuln 2>/dev/null |
            awk '{print $5}' |
            grep -qE "([.:]|^|\])${PORT}$"
    else
        return 1
    fi
}

valid_port() {
    local P="$1"

    [[ "$P" =~ ^[0-9]+$ ]] &&
    (( P >= 1 && P <= 65535 ))
}

pick_free_port() {
    local DEFAULT_PORT="$1"
    local LABEL="$2"

    local CHOSEN="$DEFAULT_PORT"
    local INPUT_PORT=""

    while true; do
        read -rp "${LABEL} [${CHOSEN}]: " INPUT_PORT
        CHOSEN="${INPUT_PORT:-$CHOSEN}"

        if ! valid_port "$CHOSEN"; then
            warn "Invalid port: ${CHOSEN}"
            CHOSEN="$DEFAULT_PORT"
            continue
        fi

        if port_in_use "$CHOSEN"; then
            warn "TCP/UDP port ${CHOSEN} is already in use."
            CHOSEN=$((CHOSEN + 1))
            continue
        fi

        echo "$CHOSEN"
        return 0
    done
}

# ============================= Sysctl ================================

apply_sysctl() {
    info "Applying high-throughput conservative network profile..."

    cat > "$SYSCTL_FILE" <<'EOF'
# ====================================================================
# FRP High Throughput Network Profile
# ====================================================================

# Socket buffers
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# Queueing / connection handling
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# TCP autotuning
net.ipv4.tcp_rmem = 4096 262144 67108864
net.ipv4.tcp_wmem = 4096 262144 67108864
net.ipv4.tcp_moderate_rcvbuf = 1

# Keep throughput after idle periods
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# TCP Fast Open
net.ipv4.tcp_fastopen = 3

# Connection backlog
net.ipv4.tcp_max_syn_backlog = 65536

# Reasonable FIN timeout
net.ipv4.tcp_fin_timeout = 15

# TIME_WAIT handling
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000

# Keepalive
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# Retries
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_syn_retries = 3

# Large ephemeral range
net.ipv4.ip_local_port_range = 1024 65535
EOF

    # Try to enable BBR only if supported.
    if [[ -r /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then
        if grep -qw "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
            cat >> "$SYSCTL_FILE" <<'EOF'

# BBR congestion control
net.ipv4.tcp_congestion_control = bbr
EOF
            ok "BBR is supported by the kernel and will be enabled."
        else
            warn "BBR is not available on this kernel. Keeping the kernel default congestion control."
        fi
    fi

    if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        ok "Network tuning applied."
    else
        warn "Some sysctl parameters were rejected by this kernel."
    fi

    # Try fq qdisc because BBR works best with fq on many Linux systems.
    if command_exists tc; then
        local DEFAULT_QDISC=""
        DEFAULT_QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"

        if [[ -e /sys/module/sch_fq ]]; then
            sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
            ok "fq queue discipline enabled where supported."
        elif [[ -n "$DEFAULT_QDISC" ]]; then
            warn "fq module is unavailable; keeping existing qdisc."
        fi
    fi
}

# ========================== Config Helpers ===========================

toml_set() {
    local FILE="$1"
    local KEY="$2"
    local VALUE="$3"

    local KEY_ESCAPED

    KEY_ESCAPED="$(printf '%s' "$KEY" | sed 's/\./\\./g')"

    if grep -qE "^${KEY_ESCAPED}[[:space:]]*=" "$FILE" 2>/dev/null; then
        sed -i -E "s/^(${KEY_ESCAPED}[[:space:]]*=).*/\1 ${VALUE}/" "$FILE"
    else
        echo "${KEY} = ${VALUE}" >> "$FILE"
    fi
}

remove_key() {
    local FILE="$1"
    local KEY="$2"

    local KEY_ESCAPED
    KEY_ESCAPED="$(printf '%s' "$KEY" | sed 's/\./\\./g')"

    sed -i -E "/^${KEY_ESCAPED}[[:space:]]*=/d" "$FILE"
}

strip_problematic_keys() {
    local FILE="$1"

    # Legacy / unwanted TLS keys
    sed -i '/^tls_enable[[:space:]]*=/d' "$FILE"
    sed -i '/^transport\.tls\./d' "$FILE"

    # ABSOLUTELY NO BANDWIDTH LIMIT
    sed -i '/^transport\.bandwidthLimit[[:space:]]*=/d' "$FILE"
    sed -i '/^transport\.bandwidthLimitMode[[:space:]]*=/d' "$FILE"

    # Old / unnecessary transport settings
    sed -i '/^transport\.udpPacketSize[[:space:]]*=/d' "$FILE"
    sed -i '/^transport\.kcp\./d' "$FILE"

    # Remove deprecated/previously injected values
    sed -i '/^transport\.useCompression[[:space:]]*=/d' "$FILE"
    sed -i '/^transport\.useEncryption[[:space:]]*=/d' "$FILE"
}

ensure_no_bandwidth_limit() {
    local FILE="$1"

    # Delete any bandwidthLimit left by an older installation.
    sed -i '/bandwidthLimit/d' "$FILE"

    # Extra sanity check:
    if grep -q "bandwidthLimit" "$FILE" 2>/dev/null; then
        warn "Could not completely remove bandwidthLimit from ${FILE}"
    fi
}

fix_proxy_transport() {
    local FILE="$1"

    # Disable compression/encryption inside every proxy block.
    sed -i -E \
        's/^[[:space:]]*transport\.useCompression[[:space:]]*=.*/transport.useCompression = false/' \
        "$FILE" || true

    sed -i -E \
        's/^[[:space:]]*transport\.useEncryption[[:space:]]*=.*/transport.useEncryption = false/' \
        "$FILE" || true

    # Never permit a per-proxy bandwidth limiter.
    sed -i '/^[[:space:]]*transport\.bandwidthLimit[[:space:]]*=/d' "$FILE"
    sed -i '/^[[:space:]]*transport\.bandwidthLimitMode[[:space:]]*=/d' "$FILE"
}

backup_config() {
    local FILE="$1"

    if [[ -f "$FILE" ]]; then
        local BACKUP
        BACKUP="${FILE}.backup.$(date +%Y%m%d-%H%M%S)"

        cp -a "$FILE" "$BACKUP"
        ok "Existing config backed up: ${BACKUP}"
    fi
}

verify_config() {
    local BIN="$1"
    local CFG="$2"

    info "Validating ${CFG}..."

    local OUT="/tmp/${BIN}-verify.out"

    if "$BIN" verify -c "$CFG" >"$OUT" 2>&1; then
        ok "${BIN} configuration is valid."
        return 0
    fi

    cat "$OUT"
    return 1
}

# ============================= Logs =================================

diagnose_logs() {
    local SERVICE="$1"

    local LOG
    LOG="$(journalctl -u "$SERVICE" -n 100 --no-pager 2>/dev/null || true)"

    if echo "$LOG" |
        grep -qiE "authorization failed|auth.*fail|token.*(invalid|mismatch)"; then
        warn "Authentication failure detected. Check auth.token on both sides."
    fi

    if echo "$LOG" |
        grep -qiE "i/o timeout|dial tcp.*timeout|no route to host"; then
        warn "Network timeout detected. Check routing, firewall and provider security group."
    fi

    if echo "$LOG" |
        grep -qiE "address already in use|bind: address already in use"; then
        warn "Port conflict detected."
    fi

    if echo "$LOG" |
        grep -qiE "connection refused"; then
        warn "Connection refused. Check server bind port and firewall."
    fi

    if echo "$LOG" |
        grep -qiE "bandwidthLimit"; then
        warn "A bandwidthLimit string was found in logs/config."
    fi
}

tunnel_verdict() {
    local SERVICE="$1"

    local LOG
    LOG="$(journalctl -u "$SERVICE" -n 100 --no-pager 2>/dev/null || true)"

    if [[ "$SERVICE" == "frpc" ]]; then
        if echo "$LOG" | grep -qi "login to server success"; then
            ok "FRPC tunnel: CONNECTED"
        else
            warn "FRPC tunnel: no successful login detected yet."
        fi
    fi

    if [[ "$SERVICE" == "frps" ]]; then
        if echo "$LOG" | grep -qi "client login info"; then
            ok "FRPS tunnel: at least one client logged in."
        else
            warn "FRPS tunnel: no client login detected yet."
        fi
    fi
}

# =========================== Uninstall ===============================

uninstall_frp() {
    warn "This will remove frps/frpc installed by this script."

    read -rp "Type 'yes' to confirm: " CONFIRM

    [[ "$CONFIRM" == "yes" ]] || {
        echo "Cancelled."
        exit 0
    }

    for SERVICE in frps frpc; do
        systemctl stop "$SERVICE" 2>/dev/null || true
        systemctl disable "$SERVICE" 2>/dev/null || true
        rm -f "${SYSTEMD_DIR}/${SERVICE}.service"
    done

    systemctl daemon-reload

    rm -f "${BIN_DIR}/frps"
    rm -f "${BIN_DIR}/frpc"

    rm -rf "$FRP_DIR"
    rm -rf "$LOG_DIR"

    rm -f "$SYSCTL_FILE"

    # Re-apply sysctl after deleting the FRP profile.
    sysctl --system >/dev/null 2>&1 || true

    if command_exists ufw; then
        ufw delete allow 7001/tcp >/dev/null 2>&1 || true
        ufw delete allow 7001/udp >/dev/null 2>&1 || true
        ufw delete allow 8080/tcp >/dev/null 2>&1 || true
        ufw delete allow 8443/tcp >/dev/null 2>&1 || true
        ufw delete allow 7005/tcp >/dev/null 2>&1 || true
    fi

    ok "FRP installation removed."
    exit 0
}

# ============================= Status ================================

show_status() {
    for SERVICE in frps frpc; do
        echo ""
        echo -e "${CYAN}================================================${NC}"
        echo -e "${CYAN}${SERVICE}${NC}"
        echo -e "${CYAN}================================================${NC}"

        if systemctl list-unit-files 2>/dev/null |
            grep -q "^${SERVICE}\.service"; then

            if systemctl is-active --quiet "$SERVICE"; then
                ok "Service RUNNING"
            else
                warn "Service NOT RUNNING"
            fi

            systemctl status "$SERVICE" \
                --no-pager \
                -l 2>&1 |
                head -20 || true

            echo ""
            echo "Config: ${FRP_DIR}/${SERVICE}.toml"

            if [[ -f "${FRP_DIR}/${SERVICE}.toml" ]]; then
                ok "Config exists."

                if grep -q "bandwidthLimit" "${FRP_DIR}/${SERVICE}.toml"; then
                    warn "WARNING: bandwidthLimit exists in config!"
                else
                    ok "No bandwidthLimit found."
                fi
            else
                warn "Config missing."
            fi

            echo ""
            echo "Recent logs:"
            journalctl -u "$SERVICE" -n 10 --no-pager 2>/dev/null || true

            echo ""
            tunnel_verdict "$SERVICE"
            diagnose_logs "$SERVICE"

        else
            warn "${SERVICE} is not installed."
        fi
    done

    exit 0
}

# =========================== Architecture ============================

detect_arch() {
    local ARCH
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64)
            FRP_ARCH="amd64"
            ;;
        aarch64|arm64)
            FRP_ARCH="arm64"
            ;;
        armv7l|armv7)
            FRP_ARCH="arm"
            ;;
        *)
            fail "Unsupported architecture: ${ARCH}"
            ;;
    esac

    ok "Architecture: ${FRP_ARCH}"
}

# =========================== Dependencies ============================

install_dependencies() {
    info "Installing required packages..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq

    apt-get install -y -qq \
        curl \
        tar \
        jq \
        openssl \
        iproute2 \
        ca-certificates \
        netcat-openbsd \
        procps \
        sed \
        grep \
        gawk

    ok "Dependencies installed."
}

# =========================== Download ================================

download_frp() {
    local FILENAME
    FILENAME="frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"

    DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${FRP_TAG}/${FILENAME}"

    TMP_DIR="$(mktemp -d)"

    trap 'rm -rf "${TMP_DIR}"' EXIT

    info "Downloading FRP ${FRP_TAG}..."

    curl \
        -fL \
        --retry 5 \
        --retry-delay 2 \
        --connect-timeout 15 \
        --max-time 300 \
        -o "${TMP_DIR}/${FILENAME}" \
        "$DOWNLOAD_URL" ||
        fail "FRP download failed."

    tar -xzf \
        "${TMP_DIR}/${FILENAME}" \
        -C "${TMP_DIR}" ||
        fail "Could not extract FRP archive."

    EXTRACTED_DIR="${TMP_DIR}/frp_${FRP_VERSION}_linux_${FRP_ARCH}"

    [[ -d "$EXTRACTED_DIR" ]] ||
        fail "FRP extracted directory not found."

    ok "FRP ${FRP_TAG} downloaded."
}

# ============================= Menu =================================

clear 2>/dev/null || true

echo -e "${CYAN}"
echo "=================================================================="
echo "        FRP HIGH-THROUGHPUT INSTALLER"
echo "             v${FRP_VERSION} | NO TLS"
echo "         NO ARTIFICIAL BANDWIDTH LIMIT"
echo "=================================================================="
echo -e "${NC}"

echo "Select action:"
echo ""
echo "  1) Install / Update Server (frps)"
echo "  2) Install / Update Client (frpc)"
echo "  3) Status"
echo "  4) Uninstall"
echo ""

read -rp "Choose [1-4]: " ROLE_CHOICE

case "$ROLE_CHOICE" in
    1)
        ROLE="server"
        BIN_NAME="frps"
        ;;
    2)
        ROLE="client"
        BIN_NAME="frpc"
        ;;
    3)
        show_status
        ;;
    4)
        uninstall_frp
        ;;
    *)
        fail "Invalid choice."
        ;;
esac

# ======================== Preflight =================================

fix_dns_if_needed

install_dependencies

detect_arch

mkdir -p "$FRP_DIR"
mkdir -p "$LOG_DIR"

chmod 700 "$FRP_DIR"

# ========================== Download ================================

download_frp

install -m 0755 \
    "${EXTRACTED_DIR}/${BIN_NAME}" \
    "${BIN_DIR}/${BIN_NAME}"

ok "${BIN_NAME} installed at ${BIN_DIR}/${BIN_NAME}"

# ======================== Select Protocol ============================

echo ""
echo "=================================================================="
echo "Transport mode"
echo "=================================================================="
echo ""
echo "  1) TCP-RAW"
echo "     tcpMux=false"
echo "     poolCount=50"
echo "     Recommended for maximum aggregate throughput"
echo ""
echo "  2) TCP-MUXED"
echo "     tcpMux=true"
echo "     poolCount=20"
echo "     Recommended for stability / fewer underlying connections"
echo ""
echo "  3) QUIC"
echo "     UDP transport"
echo "     Useful when UDP path performs better"
echo ""
echo "  4) KCP"
echo "     UDP transport"
echo "     Fallback for difficult TCP paths"
echo ""

read -rp "Choose [1-4]: " PROTO_CHOICE

case "$PROTO_CHOICE" in
    1)
        PROTOCOL="tcp"
        TCPMUX="false"
        PROTOCOL_LABEL="TCP-RAW"
        ;;
    2)
        PROTOCOL="tcp"
        TCPMUX="true"
        PROTOCOL_LABEL="TCP-MUXED"
        ;;
    3)
        PROTOCOL="quic"
        TCPMUX="n/a"
        PROTOCOL_LABEL="QUIC"
        ;;
    4)
        PROTOCOL="kcp"
        TCPMUX="n/a"
        PROTOCOL_LABEL="KCP"
        ;;
    *)
        fail "Invalid protocol choice."
        ;;
esac

echo ""
ok "Selected protocol: ${PROTOCOL_LABEL}"

warn "Server and client must use the same transport protocol."

# ========================== SERVER ==================================

if [[ "$ROLE" == "server" ]]; then

    CONFIG_PATH="${FRP_DIR}/frps.toml"

    backup_config "$CONFIG_PATH"

    BIND_PORT=""

    if [[ -f "$CONFIG_PATH" ]]; then
        OLD_PORT="$(grep -E '^bindPort[[:space:]]*=' "$CONFIG_PATH" |
            grep -oE '[0-9]+' |
            head -1 || true)"

        if valid_port "${OLD_PORT:-}"; then
            BIND_PORT="$OLD_PORT"
        fi
    fi

    if [[ -z "$BIND_PORT" ]]; then
        BIND_PORT="$(pick_free_port "7001" "Server bind port")"
    fi

    # --------------------------------------------------------------
    # Build a clean server config.
    # --------------------------------------------------------------

    cat > "$CONFIG_PATH" <<EOF
# ==================================================================
# frps.toml
# FRP ${FRP_TAG}
# HIGH THROUGHPUT / NO BANDWIDTH LIMIT
# TLS DISABLED
# ==================================================================

bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}

# HTTP/HTTPS reverse proxy ports
vhostHTTPPort = 8080
vhostHTTPSPort = 8443

# TCP mux HTTP CONNECT port
tcpmuxHTTPConnectPort = 7005

# Authentication
auth.method = "token"
auth.token = "${FIXED_AUTH_TOKEN}"

# ================================================================
# SERVER TRANSPORT
# ================================================================

# Large maximum so the server does not artificially reduce the
# client's requested connection pool.
transport.maxPoolCount = 500

# Stable heartbeat timeout.
transport.heartbeatTimeout = 120

# Keep proxy ports unrestricted.
allowPorts = [ { start = 1, end = 65535 } ]

# No artificial proxy count restriction.
maxPortsPerClient = 0

# Logging
log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7

detailedErrorsToClient = true
EOF

    # --------------------------------------------------------------
    # TCP settings
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "false" ]]; then

        cat >> "$CONFIG_PATH" <<'EOF'

# ================================================================
# TCP-RAW
# ================================================================

transport.tcpMux = false
transport.tcpKeepalive = 60
EOF

    fi

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "true" ]]; then

        cat >> "$CONFIG_PATH" <<'EOF'

# ================================================================
# TCP-MUXED
# ================================================================

transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30
transport.tcpKeepalive = 60
EOF

    fi

    # --------------------------------------------------------------
    # QUIC
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "quic" ]]; then

        cat >> "$CONFIG_PATH" <<EOF

# ================================================================
# QUIC
# ================================================================

quicBindPort = ${BIND_PORT}

transport.quic.keepalivePeriod = 30
transport.quic.maxIdleTimeout = 120
transport.quic.maxIncomingStreams = 100000
EOF

    fi

    # --------------------------------------------------------------
    # KCP
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "kcp" ]]; then

        cat >> "$CONFIG_PATH" <<EOF

# ================================================================
# KCP
# ================================================================

kcpBindPort = ${BIND_PORT}
EOF

    fi

    # Absolute sanity check.
    strip_problematic_keys "$CONFIG_PATH"

    # Re-add required auth/protocol-independent values after cleanup.
    toml_set "$CONFIG_PATH" "auth.method" "\"token\""
    toml_set "$CONFIG_PATH" "auth.token" "\"${FIXED_AUTH_TOKEN}\""
    toml_set "$CONFIG_PATH" "transport.maxPoolCount" "500"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "120"

    ensure_no_bandwidth_limit "$CONFIG_PATH"

    ok "Server config generated."
    echo ""
    cat "$CONFIG_PATH"
    echo ""

    # --------------------------------------------------------------
    # Firewall
    # --------------------------------------------------------------

    if command_exists ufw; then

        ufw allow "${BIND_PORT}/tcp" >/dev/null 2>&1 || true

        if [[ "$PROTOCOL" == "quic" || "$PROTOCOL" == "kcp" ]]; then
            ufw allow "${BIND_PORT}/udp" >/dev/null 2>&1 || true
        fi

        ufw allow 8080/tcp >/dev/null 2>&1 || true
        ufw allow 8443/tcp >/dev/null 2>&1 || true
        ufw allow 7005/tcp >/dev/null 2>&1 || true

        ok "UFW rules applied."
    else
        warn "UFW is not installed. Open ${BIND_PORT}/tcp manually."

        if [[ "$PROTOCOL" == "quic" || "$PROTOCOL" == "kcp" ]]; then
            warn "Also open ${BIND_PORT}/udp."
        fi
    fi

    # --------------------------------------------------------------
    # Verify
    # --------------------------------------------------------------

    verify_config "frps" "$CONFIG_PATH" ||
        fail "frps config validation failed. Service was NOT restarted."

fi

# =========================== CLIENT =================================

if [[ "$ROLE" == "client" ]]; then

    CONFIG_PATH="${FRP_DIR}/frpc.toml"

    backup_config "$CONFIG_PATH"

    SERVER_ADDR=""
    SERVER_PORT=""

    if [[ -f "$CONFIG_PATH" ]]; then

        SERVER_ADDR="$(grep -E '^serverAddr[[:space:]]*=' "$CONFIG_PATH" |
            sed -E 's/^[^=]+=[[:space:]]*"(.*)".*/\1/' |
            head -1 || true)"

        SERVER_PORT="$(grep -E '^serverPort[[:space:]]*=' "$CONFIG_PATH" |
            grep -oE '[0-9]+' |
            head -1 || true)"
    fi

    if [[ -z "$SERVER_ADDR" ]]; then
        read -rp "Server IP or domain: " SERVER_ADDR
    else
        echo "Existing server address: ${SERVER_ADDR}"
        read -rp "Press ENTER to keep it, or enter new address: " NEW_SERVER_ADDR

        if [[ -n "$NEW_SERVER_ADDR" ]]; then
            SERVER_ADDR="$NEW_SERVER_ADDR"
        fi
    fi

    if ! valid_port "${SERVER_PORT:-}"; then
        read -rp "Server bind port [7001]: " SERVER_PORT
        SERVER_PORT="${SERVER_PORT:-7001}"
    else
        echo "Existing server port: ${SERVER_PORT}"
        read -rp "Press ENTER to keep it, or enter new port: " NEW_SERVER_PORT

        if [[ -n "$NEW_SERVER_PORT" ]]; then
            if valid_port "$NEW_SERVER_PORT"; then
                SERVER_PORT="$NEW_SERVER_PORT"
            else
                fail "Invalid server port."
            fi
        fi
    fi

    # --------------------------------------------------------------
    # Proxy ports
    # --------------------------------------------------------------

    read -rp \
        "TCP ports to forward (comma-separated, e.g. 80,443,22) [keep existing if empty]: " \
        PORTS_INPUT

    if [[ -z "$PORTS_INPUT" && -f "$CONFIG_PATH" ]]; then

        EXISTING_PROXY_BLOCK="$(sed -n '/^\[\[proxies\]\]/,$p' "$CONFIG_PATH" || true)"

        if [[ -n "$EXISTING_PROXY_BLOCK" ]]; then
            PROXIES_BLOCK="$EXISTING_PROXY_BLOCK"
        else
            warn "No existing proxy blocks found."
            PORTS_INPUT=""
        fi

    else
        PROXIES_BLOCK=""

        IFS=',' read -ra PORTS <<< "$PORTS_INPUT"

        for PORT in "${PORTS[@]}"; do

            PORT="$(echo "$PORT" | tr -d '[:space:]')"

            [[ -z "$PORT" ]] && continue

            if ! valid_port "$PORT"; then
                warn "Skipping invalid port: ${PORT}"
                continue
            fi

            PROXIES_BLOCK+="
[[proxies]]
name = \"tcp-${PORT}\"
type = \"tcp\"
localIP = \"127.0.0.1\"
localPort = ${PORT}
remotePort = ${PORT}
transport.useCompression = false
transport.useEncryption = false
"
        done
    fi

    [[ -n "$PROXIES_BLOCK" ]] ||
        fail "No valid proxy configuration was provided."

    # --------------------------------------------------------------
    # Generate CLEAN frpc config
    # --------------------------------------------------------------

    cat > "$CONFIG_PATH" <<EOF
# ==================================================================
# frpc.toml
# FRP ${FRP_TAG}
# HIGH THROUGHPUT / NO BANDWIDTH LIMIT
# TLS DISABLED
# ==================================================================

serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}

# Keep reconnecting instead of exiting after an initial failure.
loginFailExit = false

# ================================================================
# AUTHENTICATION
# ================================================================

auth.method = "token"
auth.token = "${FIXED_AUTH_TOKEN}"

# ================================================================
# GLOBAL TRANSPORT
# ================================================================

transport.protocol = "${PROTOCOL}"

transport.heartbeatInterval = 30
transport.heartbeatTimeout = 120

transport.dialServerTimeout = 60
transport.dialServerKeepalive = 60
EOF

    # --------------------------------------------------------------
    # TCP RAW
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "false" ]]; then

        cat >> "$CONFIG_PATH" <<'EOF'

# ================================================================
# TCP-RAW
# Maximum aggregate throughput mode.
# ================================================================

transport.tcpMux = false

# Warm independent connections.
transport.poolCount = 50

transport.tcpKeepalive = 60
EOF

    fi

    # --------------------------------------------------------------
    # TCP MUX
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "true" ]]; then

        cat >> "$CONFIG_PATH" <<'EOF'

# ================================================================
# TCP-MUXED
# ================================================================

transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30

# Do not artificially starve work connections.
transport.poolCount = 20

transport.tcpKeepalive = 60
EOF

    fi

    # --------------------------------------------------------------
    # QUIC
    # --------------------------------------------------------------

    if [[ "$PROTOCOL" == "quic" ]]; then

        cat >> "$CONFIG_PATH" <<'EOF'

# ================================================================
# QUIC
# ================================================================

transport.quic.keepalivePeriod = 30
transport.quic.maxIdleTimeout = 120
EOF

    fi

    # --------------------------------------------------------------
    # Logging
    # --------------------------------------------------------------

    cat >> "$CONFIG_PATH" <<EOF

# ================================================================
# LOGGING
# ================================================================

log.to = "console"
log.level = "info"
log.maxDays = 7

# ================================================================
# PROXIES
# NO bandwidthLimit
# NO compression
# NO proxy encryption
# ================================================================

${PROXIES_BLOCK}
EOF

    # --------------------------------------------------------------
    # Clean old problematic keys
    # --------------------------------------------------------------

    strip_problematic_keys "$CONFIG_PATH"

    # Re-assert mandatory values.
    toml_set "$CONFIG_PATH" "serverAddr" "\"${SERVER_ADDR}\""
    toml_set "$CONFIG_PATH" "serverPort" "${SERVER_PORT}"

    toml_set "$CONFIG_PATH" "auth.method" "\"token\""
    toml_set "$CONFIG_PATH" "auth.token" "\"${FIXED_AUTH_TOKEN}\""

    toml_set "$CONFIG_PATH" "transport.protocol" "\"${PROTOCOL}\""
    toml_set "$CONFIG_PATH" "transport.heartbeatInterval" "30"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "120"
    toml_set "$CONFIG_PATH" "transport.dialServerTimeout" "60"
    toml_set "$CONFIG_PATH" "transport.dialServerKeepalive" "60"

    # Protocol-specific values after cleanup.
    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "false" ]]; then
        toml_set "$CONFIG_PATH" "transport.tcpMux" "false"
        toml_set "$CONFIG_PATH" "transport.poolCount" "50"
        toml_set "$CONFIG_PATH" "transport.tcpKeepalive" "60"
    fi

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "true" ]]; then
        toml_set "$CONFIG_PATH" "transport.tcpMux" "true"
        toml_set "$CONFIG_PATH" "transport.poolCount" "20"
        toml_set "$CONFIG_PATH" "transport.tcpMuxKeepaliveInterval" "30"
        toml_set "$CONFIG_PATH" "transport.tcpKeepalive" "60"
    fi

    if [[ "$PROTOCOL" == "quic" ]]; then
        toml_set "$CONFIG_PATH" "transport.quic.keepalivePeriod" "30"
        toml_set "$CONFIG_PATH" "transport.quic.maxIdleTimeout" "120"
    fi

    # Make absolutely sure no artificial bandwidth limiter remains.
    ensure_no_bandwidth_limit "$CONFIG_PATH"

    # Make sure every proxy has compression/encryption disabled.
    fix_proxy_transport "$CONFIG_PATH"

    ok "Client config generated."
    echo ""
    cat "$CONFIG_PATH"
    echo ""

    # --------------------------------------------------------------
    # Reachability test
    # --------------------------------------------------------------

    info "Testing server reachability: ${SERVER_ADDR}:${SERVER_PORT}"

    if [[ "$PROTOCOL" == "tcp" ]]; then

        if timeout 5 bash -c \
            "cat < /dev/null > /dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" \
            2>/dev/null; then

            ok "TCP server port is reachable."

        else
            warn "TCP server port is NOT reachable."
            warn "Check firewall/security-group and server service."
        fi

    else

        if command_exists nc; then

            if nc -uzw3 \
                "$SERVER_ADDR" \
                "$SERVER_PORT" \
                >/dev/null 2>&1; then

                ok "UDP probe completed successfully."

            else
                warn "UDP reachability could not be confirmed."
                warn "UDP probes are inherently best-effort."
            fi

        else
            warn "nc is unavailable; UDP test skipped."
        fi
    fi

    # --------------------------------------------------------------
    # Verify
    # --------------------------------------------------------------

    verify_config "frpc" "$CONFIG_PATH" ||
        fail "frpc configuration validation failed. Service was NOT restarted."

fi

# =========================== Systemd ================================

SERVICE_FILE="${SYSTEMD_DIR}/${BIN_NAME}.service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=FRP ${ROLE} ${FRP_TAG} - High Throughput No Bandwidth Limit
After=network-online.target
Wants=network-online.target

StartLimitIntervalSec=0

[Service]
Type=simple

User=root

ExecStart=${BIN_DIR}/${BIN_NAME} -c ${CONFIG_PATH}

Restart=always
RestartSec=5

LimitNOFILE=2097152
LimitNPROC=infinity

NoNewPrivileges=true

# Give FRP ample scheduling priority without making it real-time.
Nice=-5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ========================= Final Verify =============================

if ! verify_config "$BIN_NAME" "$CONFIG_PATH"; then
    fail "Configuration validation failed. Service was NOT restarted."
fi

# ============================ Start =================================

systemctl enable "$BIN_NAME" >/dev/null 2>&1 || true

systemctl restart "$BIN_NAME"

sleep 4

if systemctl is-active --quiet "$BIN_NAME"; then

    ok "${BIN_NAME} service is RUNNING."

else

    warn "${BIN_NAME} failed to start."

    journalctl \
        -u "$BIN_NAME" \
        -n 50 \
        --no-pager \
        2>/dev/null || true

    diagnose_logs "$BIN_NAME"

    exit 1
fi

# ========================= Network Tune =============================

apply_sysctl

# =========================== Post Check =============================

echo ""

if grep -q "bandwidthLimit" "$CONFIG_PATH" 2>/dev/null; then
    warn "WARNING: bandwidthLimit is still present!"
else
    ok "Confirmed: no bandwidthLimit in ${CONFIG_PATH}"
fi

if grep -q "bandwidthLimitMode" "$CONFIG_PATH" 2>/dev/null; then
    warn "WARNING: bandwidthLimitMode is still present!"
else
    ok "Confirmed: no bandwidthLimitMode in ${CONFIG_PATH}"
fi

tunnel_verdict "$BIN_NAME"
diagnose_logs "$BIN_NAME"

# ======================= Server Summary =============================

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}        FRP ${FRP_TAG} INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo "Role        : ${ROLE}"
echo "Binary      : ${BIN_NAME}"
echo "Version     : ${FRP_TAG}"
echo "Protocol    : ${PROTOCOL_LABEL}"
echo "TLS         : DISABLED"
echo "Bandwidth   : NO FRP LIMIT"
echo "Compression : DISABLED"
echo "Proxy Crypto: DISABLED"
echo ""
echo "Config      : ${CONFIG_PATH}"
echo "Service     : ${BIN_NAME}"
echo "Logs        : journalctl -u ${BIN_NAME} -f"
echo "Restart     : systemctl restart ${BIN_NAME}"
echo "Status      : systemctl status ${BIN_NAME}"
echo ""

# ========================= Client Summary ===========================

if [[ "$ROLE" == "client" ]]; then

    echo -e "${CYAN}================ CLIENT SETTINGS =================${NC}"
    echo "Server address : ${SERVER_ADDR}"
    echo "Server port    : ${SERVER_PORT}"
    echo "Protocol       : ${PROTOCOL_LABEL}"
    echo "TLS            : DISABLED"
    echo "Bandwidth      : UNLIMITED by FRP"
    echo ""

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "false" ]]; then
        echo "TCP mux        : false"
        echo "Pool count     : 50"
    elif [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "true" ]]; then
        echo "TCP mux        : true"
        echo "Pool count     : 20"
    fi

    echo -e "${CYAN}==================================================${NC}"
fi

# ========================= Server Summary ===========================

if [[ "$ROLE" == "server" ]]; then

    PUB_IP="$(
        curl \
            -4 \
            -fsSL \
            --max-time 5 \
            https://ifconfig.me \
            2>/dev/null ||
        echo "<detect manually>"
    )"

    echo -e "${CYAN}================ SERVER SETTINGS =================${NC}"
    echo "Server address : ${PUB_IP}"
    echo "Server port    : ${BIND_PORT}"
    echo "Protocol       : ${PROTOCOL_LABEL}"
    echo "TLS            : DISABLED"
    echo "Bandwidth      : UNLIMITED by FRP"
    echo "Auth token     : ${FIXED_AUTH_TOKEN}"
    echo ""

    if [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "false" ]]; then
        echo "TCP mux        : false"
        echo "Server pool    : max 500"
        echo "Client pool    : recommended 50"
    elif [[ "$PROTOCOL" == "tcp" && "$TCPMUX" == "true" ]]; then
        echo "TCP mux        : true"
        echo "Server pool    : max 500"
        echo "Client pool    : recommended 20"
    elif [[ "$PROTOCOL" == "quic" ]]; then
        echo "UDP port       : ${BIND_PORT}"
        echo "QUIC streams   : 100000"
    elif [[ "$PROTOCOL" == "kcp" ]]; then
        echo "UDP port       : ${BIND_PORT}"
    fi

    echo -e "${CYAN}==================================================${NC}"
fi

echo ""
ok "Installation finished."
echo ""

# =====================================================================
# END
# =====================================================================
