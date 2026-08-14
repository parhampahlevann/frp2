#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Version: v0.61.0 (latest stable)
#  - TLS COMPLETELY REMOVED
#  - TCP (tcpMux=false), QUIC, and KCP supported
#  - KCP NOTE: v0.61.0 does NOT expose internal KCP tuning parameters
#    (sndwnd, rcvwnd, nodelay, etc). KCP runs with built-in defaults.
#    For maximum bandwidth, use TCP or QUIC instead.
#  - Auto-fixes DNS, port conflicts, and applies aggressive sysctl tuning
#  - Menu: server, client, status, uninstall
#
#  USAGE: sudo bash frp_setup.sh
# =====================================================================
set -euo pipefail

# ----------------------------- colors -------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --------------------------- fixed shared token ----------------------
FIXED_AUTH_TOKEN="7ZuESw25FFWCZQmrroruUEy4qVVB9dbmkG1BMSMD6WHx"

# --------------------------- pre-flight -----------------------------
[[ $EUID -eq 0 ]] || fail "Run as root (sudo)."

if [[ -e /etc/resolv.conf ]] && command -v chattr >/dev/null 2>&1; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
fi
dpkg --configure -a >/dev/null 2>&1 || true

# ---- DNS self-check / auto-repair --------------------------------
check_dns() { getent hosts github.com >/dev/null 2>&1; }
fix_dns_if_needed() {
  if check_dns; then return 0; fi
  warn "DNS broken. Fixing..."
  if [[ -L /etc/resolv.conf ]]; then
    warn "/etc/resolv.conf is a symlink (systemd-resolved). Overriding temporarily."
  fi
  chattr -i /etc/resolv.conf 2>/dev/null || true
  rm -f /etc/resolv.conf
  cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
  sleep 1
  check_dns && ok "DNS fixed." || warn "DNS still broken. Fix manually."
}
fix_dns_if_needed

# ---- Port conflict helper -----------------------------------------
port_in_use() {
  local PORT="$1"
  ss -tuln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$"
}

pick_free_port() {
  local DEFAULT_PORT="$1"
  local LABEL="$2"
  local CHOSEN="${DEFAULT_PORT}"
  while true; do
    read -rp "${LABEL} [${CHOSEN}]: " INPUT_PORT
    CHOSEN="${INPUT_PORT:-$CHOSEN}"
    if port_in_use "${CHOSEN}"; then
      warn "Port ${CHOSEN} in use. Choose another."
      CHOSEN=$((CHOSEN + 1))
    else
      break
    fi
  done
  echo "${CHOSEN}"
}

# ---- Apply sysctl tuning for maximum throughput ------------------
apply_sysctl() {
  info "Applying sysctl network tuning (throughput optimized)..."
  cat > /etc/sysctl.d/99-frp-tune.conf <<'EOF'
# Core buffers
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# TCP memory & congestion (BBR)
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_moderate_rcvbuf = 1

# Prevent speed collapse after idle / stale cwnd cache
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# Fast open & backlog
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_tw_buckets = 2000000

# Keepalive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# Port range & reuse
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
EOF
  sysctl -p /etc/sysctl.d/99-frp-tune.conf >/dev/null 2>&1 || warn "Sysctl apply failed (ignore if not supported)."
  ok "Sysctl tuning applied."
}

# ---- Diagnose common connection failures from logs ------------------
diagnose_logs() {
  local SVC="$1"
  local LOG
  LOG="$(journalctl -u "$SVC" -n 80 --no-pager 2>/dev/null || true)"

  if echo "$LOG" | grep -qiE "authorization failed|auth.*fail|token.*(invalid|mismatch)"; then
    warn "Hint: authentication failed -> auth.token in frps.toml and frpc.toml do not match."
  fi
  if echo "$LOG" | grep -qiE "i/o timeout|dial tcp.*timeout|no route to host"; then
    warn "Hint: network/timeout -> server unreachable on this port. Check firewall/security-group."
  fi
  if echo "$LOG" | grep -qiE "address already in use|bind: address already in use"; then
    warn "Hint: port already in use -> another process is holding the bind port."
  fi
  if echo "$LOG" | grep -qiE "connection refused"; then
    warn "Hint: connection refused -> frps is not listening on that IP/port yet, or a firewall is dropping it."
  fi
  if echo "$LOG" | grep -qiE "bandwidth limit|bandwidthLimit"; then
    warn "Hint: bandwidth limit detected in config -> remove transport.bandwidthLimit from proxy blocks."
  fi
  return 0
}

# ---- Explicit tunnel-connected verdict -----------------------------
tunnel_verdict() {
  local SVC="$1"
  local LOG
  LOG="$(journalctl -u "$SVC" -n 80 --no-pager 2>/dev/null || true)"
  if [[ "$SVC" == "frpc" ]]; then
    if echo "$LOG" | grep -qi "login to server success"; then
      ok "Tunnel status: CONNECTED (client successfully logged in to server)."
    else
      warn "Tunnel status: NOT CONNECTED (no successful login found in recent logs)."
    fi
  elif [[ "$SVC" == "frps" ]]; then
    if echo "$LOG" | grep -qi "client login info"; then
      ok "Tunnel status: at least one client has logged in successfully."
    else
      warn "Tunnel status: no client has successfully logged in yet."
    fi
  fi
  return 0
}

# ---- Validate existing config; backup & rebuild if invalid --------
validate_or_backup_config() {
  local BIN="$1"
  local CFG="$2"
  if [[ ! -f "$CFG" ]]; then
    return 0
  fi
  info "Validating existing config ${CFG} ..."
  if "$BIN" verify -c "$CFG" >/tmp/${BIN}-verify-old.out 2>&1; then
    ok "Existing config is valid."
    return 0
  else
    warn "Existing config is INVALID. Backing up..."
    mv "$CFG" "${CFG}.bak.$(date +%s)"
    return 1
  fi
}

# ---- Inject or replace a key in a TOML file -----------------------
toml_set() {
  local FILE="$1"
  local KEY="$2"
  local VAL="$3"
  local KEY_ESCAPED
  KEY_ESCAPED="$(echo "$KEY" | sed 's/\./\\./g')"
  if grep -qE "^${KEY_ESCAPED} *=" "$FILE" 2>/dev/null; then
    sed -i -E "s/^(${KEY_ESCAPED} *=).*/\1 ${VAL}/" "$FILE"
  else
    echo "${KEY} = ${VAL}" >> "$FILE"
  fi
}

# ---- Strip ALL problematic keys from existing configs ---------------
strip_problematic_keys() {
  local FILE="$1"
  sed -i '/^tls_enable/d' "$FILE"
  sed -i '/^transport\.tls\./d' "$FILE"
  sed -i '/^transport\.bandwidthLimit/d' "$FILE"
  sed -i '/bandwidthLimit/d' "$FILE"
  sed -i '/^transport\.useCompression/d' "$FILE"
  sed -i '/^transport\.useEncryption/d' "$FILE"
  sed -i '/^transport\.udpPacketSize/d' "$FILE"
  # Remove any leftover KCP tuning keys (not supported in v0.61.0)
  sed -i '/^transport\.kcp\./d' "$FILE"
}

# ---- Ensure proxy blocks have compression=false, encryption=false --
fix_proxy_blocks() {
  local FILE="$1"
  sed -i -E 's/^transport\.useCompression\s*=\s*.*/transport.useCompression = false/' "$FILE"
  sed -i -E 's/^transport\.useEncryption\s*=\s*.*/transport.useEncryption = false/' "$FILE"
}

# ===================== Main Menu ===================================
echo -e "${CYAN}"
echo "==================================================="
echo "   FRP Reverse Tunnel - One-Click Setup"
echo "        (v0.61.0 | NO-TLS | Bandwidth+)"
echo "==================================================="
echo -e "${NC}"

echo "What do you want to do?"
echo "  1) Install / Update Server (frps)"
echo "  2) Install / Update Client (frpc)"
echo "  3) Status"
echo "  4) Uninstall"
read -rp "Choose [1-4]: " ROLE_CHOICE
case "$ROLE_CHOICE" in
  1) ROLE="server"; BIN_NAME="frps" ;;
  2) ROLE="client"; BIN_NAME="frpc" ;;
  3) ROLE="status" ;;
  4) ROLE="uninstall" ;;
  *) fail "Invalid choice." ;;
esac

# ------------------------------------------------------------------
if [[ "$ROLE" == "status" ]]; then
  for SVC in frps frpc; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${SVC}\.service"; then
      echo -e "\n${CYAN}=== $SVC ===${NC}"
      systemctl is-active --quiet "$SVC" && ok "process RUNNING" || warn "process NOT RUNNING"
      systemctl status "$SVC" --no-pager -l 2>&1 | head -10 || true
      echo "Config: /etc/frp/$SVC.toml"
      [[ -f "/etc/frp/$SVC.toml" ]] && ok "Config present" || warn "Config missing"
      echo "Last logs:"
      journalctl -u "$SVC" -n 5 --no-pager 2>/dev/null || true
      tunnel_verdict "$SVC"
      diagnose_logs "$SVC"
    else
      echo -e "\n${CYAN}=== $SVC ===${NC}"
      warn "Not installed (no systemd unit found)."
    fi
  done
  exit 0
fi

if [[ "$ROLE" == "uninstall" ]]; then
  warn "This will remove frps & frpc installed by this script."
  read -rp "Type 'yes' to confirm: " CONFIRM
  [[ "$CONFIRM" == "yes" ]] || exit 0
  for SVC in frps frpc; do
    systemctl stop "$SVC" 2>/dev/null || true
    systemctl disable "$SVC" 2>/dev/null || true
    rm -f /etc/systemd/system/${SVC}.service
  done
  systemctl daemon-reload
  rm -f /usr/local/bin/frps /usr/local/bin/frpc
  rm -rf /etc/frp /var/log/frp
  rm -f /etc/sysctl.d/99-frp-tune.conf
  ufw delete allow 7001/tcp 2>/dev/null || true
  ufw delete allow 7001/udp 2>/dev/null || true
  ufw delete allow 8080/tcp 2>/dev/null || true
  ufw delete allow 8443/tcp 2>/dev/null || true
  ufw delete allow 7005/tcp 2>/dev/null || true
  echo -e "${GREEN}Removed.${NC}"
  exit 0
fi

# -------------------- Install dependencies -------------------------
info "Installing dependencies (curl, tar, jq)..."
apt-get update -qq
apt-get install -y -qq curl tar jq openssl || fail "Install failed."
ok "Dependencies ready."

UFW_AVAIL=$(command -v ufw >/dev/null && echo 1 || echo 0)

# -------------------- Detect architecture --------------------------
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)   FRP_ARCH="amd64" ;;
  aarch64)  FRP_ARCH="arm64" ;;
  armv7l)   FRP_ARCH="arm" ;;
  *) fail "Unsupported arch: $ARCH" ;;
esac
ok "Arch: $FRP_ARCH"

# -------------------- Version v0.61.0 -------------------------------
FRP_VERSION="0.61.0"
FRP_TAG="v${FRP_VERSION}"
FILENAME="frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${FRP_TAG}/${FILENAME}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${FRP_TAG}..."
curl -fL --retry 3 -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL" || fail "Download failed."
tar -xzf "${TMP_DIR}/${FILENAME}" -C "$TMP_DIR"
EXTRACTED="${TMP_DIR}/frp_${FRP_VERSION}_linux_${FRP_ARCH}"

mkdir -p /etc/frp /var/log/frp
install -m 755 "${EXTRACTED}/${BIN_NAME}" "/usr/local/bin/${BIN_NAME}"
ok "Binary installed."

CONFIG_PATH="/etc/frp/${BIN_NAME}.toml"

# -------------------- Protocol choice (NO TLS) ----------------------
echo ""
echo "Select transport protocol:"
echo "  1) TCP  — tcpMux = false, each proxy = independent connection (MAX throughput)"
echo "  2) QUIC — UDP multi-stream, no HOL blocking (recommended)"
echo "  3) KCP  — UDP-based fallback (v0.61.0 has NO internal tuning params)"
read -rp "Choose [1-3]: " PROTO_CHOICE
case "$PROTO_CHOICE" in
  1) PROTOCOL="tcp" ;;
  2) PROTOCOL="quic" ;;
  3) PROTOCOL="kcp" ;;
  *) fail "Invalid protocol choice." ;;
esac

warn "IMPORTANT: Protocol (${PROTOCOL}) must be set IDENTICALLY on server and client."

# ------------------------------------------------------------------
if [[ "$ROLE" == "server" ]]; then
  AUTH_TOKEN="$FIXED_AUTH_TOKEN"

  validate_or_backup_config "frps" "$CONFIG_PATH"

  if [[ -f "$CONFIG_PATH" ]]; then
    ok "Updating config for ${PROTOCOL} mode..."
    strip_problematic_keys "$CONFIG_PATH"
    toml_set "$CONFIG_PATH" "auth.token" "\"${AUTH_TOKEN}\""
    toml_set "$CONFIG_PATH" "transport.maxPoolCount" "200"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "30"
    fix_proxy_blocks "$CONFIG_PATH"

    BIND_PORT=$(grep -E '^bindPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || true)
    BIND_PORT="${BIND_PORT:-7001}"
  else
    BIND_PORT=$(pick_free_port "7001" "Bind port for tunnel control")

    cat > "$CONFIG_PATH" <<EOF
# ===================== frps.toml (server) =====================
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
tcpmuxHTTPConnectPort = 7005

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- Transport (bandwidth + stability) ----
transport.maxPoolCount = 200
transport.heartbeatTimeout = 30

allowPorts = [ { start = 1, end = 65535 } ]
maxPortsPerClient = 0

log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7
detailedErrorsToClient = true
EOF

    if [[ "$PROTOCOL" == "tcp" ]]; then
      cat >> "$CONFIG_PATH" <<'EOF'
transport.tcpMux = false
transport.tcpKeepalive = 30
EOF
    fi

    if [[ "$PROTOCOL" == "quic" ]]; then
      cat >> "$CONFIG_PATH" <<EOF
quicBindPort = ${BIND_PORT}
transport.quic.keepalivePeriod = 5
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000
EOF
    fi

    if [[ "$PROTOCOL" == "kcp" ]]; then
      cat >> "$CONFIG_PATH" <<EOF
kcpBindPort = ${BIND_PORT}
EOF
    fi

    ok "Server config created for ${PROTOCOL}."
  fi

  if [[ "$UFW_AVAIL" -eq 1 ]]; then
    ufw allow "${BIND_PORT}"/tcp >/dev/null 2>&1 || true
    if [[ "$PROTOCOL" == "quic" || "$PROTOCOL" == "kcp" ]]; then
      ufw allow "${BIND_PORT}"/udp >/dev/null 2>&1 || true
      ok "Opened ${BIND_PORT}/udp for ${PROTOCOL}."
    fi
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 8443/tcp >/dev/null 2>&1 || true
    ufw allow 7005/tcp >/dev/null 2>&1 || true
    ok "Firewall (ufw) rules applied."
  else
    warn "ufw not installed – open ports manually (including UDP ${BIND_PORT} if using QUIC/KCP)."
  fi
fi

# ------------------------------------------------------------------
if [[ "$ROLE" == "client" ]]; then
  AUTH_TOKEN="$FIXED_AUTH_TOKEN"

  validate_or_backup_config "frpc" "$CONFIG_PATH"

  if [[ -f "$CONFIG_PATH" ]]; then
    ok "Updating config for ${PROTOCOL} mode..."
    strip_problematic_keys "$CONFIG_PATH"
    toml_set "$CONFIG_PATH" "auth.token" "\"${AUTH_TOKEN}\""
    toml_set "$CONFIG_PATH" "transport.protocol" "\"${PROTOCOL}\""
    toml_set "$CONFIG_PATH" "transport.heartbeatInterval" "5"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "30"
    toml_set "$CONFIG_PATH" "transport.dialServerTimeout" "30"
    toml_set "$CONFIG_PATH" "transport.dialServerKeepalive" "30"
    fix_proxy_blocks "$CONFIG_PATH"

    if [[ "$PROTOCOL" == "tcp" ]]; then
      toml_set "$CONFIG_PATH" "transport.tcpMux" "false"
      toml_set "$CONFIG_PATH" "transport.poolCount" "10"
    fi

    if [[ "$PROTOCOL" == "quic" ]]; then
      toml_set "$CONFIG_PATH" "transport.quic.keepalivePeriod" "5"
      toml_set "$CONFIG_PATH" "transport.quic.maxIdleTimeout" "30"
    fi

    SERVER_ADDR=$(grep -E '^serverAddr' "$CONFIG_PATH" | sed -E 's/.*"(.*)".*/\1/' || echo "")
    SERVER_PORT=$(grep -E '^serverPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || echo "")
  else
    read -rp "Server IP or domain: " SERVER_ADDR
    read -rp "Server bind port [7001]: " SERVER_PORT
    SERVER_PORT="${SERVER_PORT:-7001}"

    echo "Enter TCP ports to forward (comma-separated, e.g. 80,443):"
    read -rp "Ports: " PORTS_INPUT

    PROXIES_BLOCK=""
    IFS=',' read -ra PORTS <<< "$PORTS_INPUT"
    for PORT in "${PORTS[@]}"; do
      PORT=$(echo "$PORT" | tr -d ' ')
      [[ -z "$PORT" ]] && continue
      [[ ! "$PORT" =~ ^[0-9]+$ ]] && warn "Skipping invalid port: $PORT" && continue
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

    cat > "$CONFIG_PATH" <<EOF
# ===================== frpc.toml (client) =====================
serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}
loginFailExit = false

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- Transport (bandwidth + stability) ----
transport.protocol = "${PROTOCOL}"
transport.heartbeatInterval = 5
transport.heartbeatTimeout = 30
transport.dialServerTimeout = 30
transport.dialServerKeepalive = 30
EOF

    if [[ "$PROTOCOL" == "tcp" ]]; then
      cat >> "$CONFIG_PATH" <<'EOF'
transport.tcpMux = false
transport.poolCount = 10
EOF
    fi

    if [[ "$PROTOCOL" == "quic" ]]; then
      cat >> "$CONFIG_PATH" <<'EOF'
transport.quic.keepalivePeriod = 5
transport.quic.maxIdleTimeout = 30
EOF
    fi

    cat >> "$CONFIG_PATH" <<EOF

log.to = "console"
log.level = "info"

# ============= Auto-generated proxies (NO bandwidth limit) =============
${PROXIES_BLOCK}
EOF

    if [[ ! -f "$CONFIG_PATH" ]]; then
      fail "Failed to write config file at $CONFIG_PATH. Check disk space or permissions."
    fi
    ok "Client config created at $CONFIG_PATH."

    info "Testing reachability to ${SERVER_ADDR}:${SERVER_PORT} (${PROTOCOL})..."
    if [[ "$PROTOCOL" == "quic" || "$PROTOCOL" == "kcp" ]]; then
      if command -v nc >/dev/null 2>&1; then
        if nc -uzw3 "${SERVER_ADDR}" "${SERVER_PORT}" 2>/dev/null; then
          ok "UDP port appears reachable (best-effort; UDP checks are not fully reliable)."
        else
          warn "Could not confirm UDP reachability — this is normal for UDP."
        fi
      else
        warn "nc not found — skipping UDP reachability test."
      fi
    else
      if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" 2>/dev/null; then
        ok "Server reachable."
      else
        warn "Server NOT reachable – tunnel will fail. Check the server's firewall/security group for TCP ${SERVER_PORT}."
      fi
    fi
  fi
fi

# -------------------- Systemd Service -----------------------------
SERVICE_FILE="/etc/systemd/system/${BIN_NAME}.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=frp ${ROLE} (${BIN_NAME}) - ${FRP_TAG}
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Restart=always
RestartSec=1
ExecStart=/usr/local/bin/${BIN_NAME} -c ${CONFIG_PATH}
LimitNOFILE=2097152
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# Validate the generated configuration before restarting the service.
if ! "${BIN_NAME}" verify -c "${CONFIG_PATH}" >/tmp/${BIN_NAME}-verify.out 2>&1; then
  cat /tmp/${BIN_NAME}-verify.out
  fail "${BIN_NAME} configuration validation failed. Service was NOT restarted."
fi
systemctl enable "${BIN_NAME}" >/dev/null 2>&1 || true
systemctl restart "${BIN_NAME}"
sleep 3

# ---- Verify service ----
if systemctl is-active --quiet "${BIN_NAME}"; then
  ok "${BIN_NAME} process is RUNNING"
  tunnel_verdict "${BIN_NAME}"
  diagnose_logs "${BIN_NAME}"
else
  warn "${BIN_NAME} failed to start. Showing logs:"
  journalctl -u "${BIN_NAME}" -n 20 --no-pager 2>/dev/null || true
  diagnose_logs "${BIN_NAME}"
  exit 1
fi

# ---- Apply sysctl tuning after successful start ----
apply_sysctl

echo ""
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} ${BIN_NAME} installed (${FRP_TAG})${NC}"
echo -e "${GREEN} Protocol: ${PROTOCOL}   TLS: DISABLED${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo "Config : ${CONFIG_PATH}"
echo "Logs   : journalctl -u ${BIN_NAME} -f"
echo "Restart: systemctl restart ${BIN_NAME}"

if [[ "$ROLE" == "server" ]]; then
  PUB_IP="$(curl -fsSL --max-time 3 https://ifconfig.me 2>/dev/null || echo "<could not detect - use your known server IP>")"
  echo ""
  echo -e "${CYAN}================ CONNECTION SUMMARY =================${NC}"
  echo -e "Give these EXACT values when setting up the client (frpc):"
  echo -e "  Server address : ${GREEN}${PUB_IP}${NC}"
  echo -e "  Server port    : ${GREEN}${BIND_PORT}${NC}"
  echo -e "  Auth token     : ${GREEN}${AUTH_TOKEN}${NC}"
  echo -e "  Protocol       : ${GREEN}${PROTOCOL}${NC}"
  echo -e "  TLS            : ${GREEN}DISABLED${NC}"
  echo -e "${CYAN}=======================================================${NC}"
fi
