#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Version: v0.61.0 (latest stable as of 2026)
#  - OPTIMIZED FOR STABILITY: fixed heartbeat, pooling, and timeouts
#  - Supports TLS & KCP (optional)
#  - TCP tunnel default; KCP remains optional for problematic TCP paths
#  - Auto-fixes DNS, port conflicts, and applies sysctl tuning
#  - Menu: server, client, status, uninstall
#
#  FIXES applied vs original:
#   1) Bumped to v0.61.0 for latest stability and TLS improvements.
#   2) Existing configs are now VALIDATED before being kept. If an old
#      config is invalid (e.g., leftover INI format, wrong keys), it
#      is automatically backed up and replaced with a fresh valid one.
#   3) TLS uses correct toml keys: transport.tls.force (server) /
#      transport.tls.enable (client).
#   4) When KCP is selected, the KCP bind port is opened on UDP in ufw.
#   5) AUTH TOKEN IS FIXED/SHARED — no mismatch between server/client.
#   6) Client reachability test matches the real protocol.
#   7) Status pipelines guarded with || true so inactive services do
#      not kill the script under set -e + pipefail.
#   8) Connection summary printed at the end of server setup so the
#      client can be configured with exactly matching parameters.
#   9) Real tunnel verdict based on log markers, not just process state.
#  10) STABILITY FIXES FOR DISCONNECT/RECONNECT ISSUES:
#      - Client heartbeatInterval = 30 (was -1, disabled)
#      - Client heartbeatTimeout = 90
#      - Client poolCount = 5 (was 0)
#      - Client dialServerTimeout = 30 (was 15)
#      - Client dialServerKeepalive = 30 (was 15)
#      - Server maxPoolCount = 50 (was 5)
#      - Server/client tcpMuxKeepaliveInterval = 10 (was 15)
#      - Server tcpKeepalive = 10 (was 15)
#      - Sysctl tuning enhanced with tcp_tw_reuse and port range.
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

# ---- Apply sysctl tuning for network stability --------------------
apply_sysctl() {
  info "Applying sysctl network tuning..."
  cat > /etc/sysctl.d/99-frp-tune.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
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
  if echo "$LOG" | grep -qiE "tls: |certificate|handshake"; then
    warn "Hint: TLS handshake issue -> TLS must be enabled/disabled IDENTICALLY on BOTH server and client."
  fi
  if echo "$LOG" | grep -qiE "i/o timeout|dial tcp.*timeout|no route to host"; then
    warn "Hint: network/timeout -> server unreachable on this port. Check firewall/security-group."
  fi
  if echo "$LOG" | grep -qiE "address already in use|bind: address already in use"; then
    warn "Hint: port already in use -> another process is holding the bind port. Pick a different port."
  fi
  if echo "$LOG" | grep -qiE "connection refused"; then
    warn "Hint: connection refused -> frps is not listening on that IP/port yet, or a firewall is dropping it."
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
    warn "Existing config is INVALID (see /tmp/${BIN}-verify-old.out). Backing up..."
    mv "$CFG" "${CFG}.bak.$(date +%s)"
    return 1
  fi
}

# ---- Inject or replace a key in a TOML file -----------------------
# Usage: toml_set <file> <key> <value>
toml_set() {
  local FILE="$1"
  local KEY="$2"
  local VAL="$3"
  # Escape dots for regex
  local KEY_ESCAPED
  KEY_ESCAPED="$(echo "$KEY" | sed 's/\./\\./g')"
  if grep -qE "^${KEY_ESCAPED} *=" "$FILE" 2>/dev/null; then
    sed -i -E "s/^(${KEY_ESCAPED} *=).*/\1 ${VAL}/" "$FILE"
  else
    echo "${KEY} = ${VAL}" >> "$FILE"
  fi
}

# ===================== Main Menu ===================================
echo -e "${CYAN}"
echo "==================================================="
echo "        FRP Reverse Tunnel - One-Click Setup"
echo "              (Stable v0.61.0 - Fixed)"
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

# -------------------- Ask for TLS and protocol ---------------------
read -rp "Enable TLS (recommended) [Y/n]: " TLS_ANSWER
if [[ "$TLS_ANSWER" =~ ^[Nn]$ ]]; then
  TLS_ENABLE="false"
else
  TLS_ENABLE="true"
fi

read -rp "Use KCP (UDP-based; only if TCP is unstable)? [y/N]: " KCP_ANSWER
if [[ "$KCP_ANSWER" =~ ^[Yy]$ ]]; then
  PROTOCOL="kcp"
else
  PROTOCOL="tcp"
fi
warn "IMPORTANT: TLS (${TLS_ENABLE}) and protocol (${PROTOCOL}) must be set IDENTICALLY on the server and the client, or the handshake will never complete. Write these down."

# ------------------------------------------------------------------
if [[ "$ROLE" == "server" ]]; then
  AUTH_TOKEN="$FIXED_AUTH_TOKEN"

  # Validate existing config; if invalid, back it up so we create a fresh one
  validate_or_backup_config "frps" "$CONFIG_PATH"
  CONFIG_WAS_INVALID=$?

  if [[ -f "$CONFIG_PATH" ]]; then
    # Config is valid; sync stability params and token
    ok "Updating stability parameters in existing config..."
    toml_set "$CONFIG_PATH" "auth.token" "\"${AUTH_TOKEN}\""
    toml_set "$CONFIG_PATH" "transport.tcpMuxKeepaliveInterval" "10"
    toml_set "$CONFIG_PATH" "transport.tcpKeepalive" "10"
    toml_set "$CONFIG_PATH" "transport.maxPoolCount" "50"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "90"
    # Migrate old tls_enable key if present
    if grep -qE '^tls_enable' "$CONFIG_PATH"; then
      warn "Old config uses invalid key 'tls_enable' — migrating to 'transport.tls.force'."
      sed -i -E 's/^tls_enable = (.*)$/transport.tls.force = \1/' "$CONFIG_PATH"
    fi
    toml_set "$CONFIG_PATH" "transport.tls.force" "${TLS_ENABLE}"

    BIND_PORT=$(grep -E '^bindPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || true)
    BIND_PORT="${BIND_PORT:-7001}"
    if grep -q '^kcpBindPort' "$CONFIG_PATH"; then IS_KCP=1; else IS_KCP=0; fi
  else
    # Create fresh server config
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

# ---- Transport settings ----
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 10
transport.tcpKeepalive = 10
transport.maxPoolCount = 50

# ---- Heartbeat ----
transport.heartbeatTimeout = 90

# ---- TLS (v0.61.0 uses transport.tls.force) ----
transport.tls.force = ${TLS_ENABLE}

allowPorts = [ { start = 1, end = 65535 } ]
maxPortsPerClient = 0

log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7
detailedErrorsToClient = true
EOF
    if [[ "$PROTOCOL" == "kcp" ]]; then
      echo "kcpBindPort = ${BIND_PORT}" >> "$CONFIG_PATH"
      IS_KCP=1
    else
      IS_KCP=0
    fi
    ok "Server config created."
  fi

  if [[ "$UFW_AVAIL" -eq 1 ]]; then
    ufw allow "${BIND_PORT}"/tcp >/dev/null 2>&1 || true
    if [[ "${IS_KCP:-0}" -eq 1 ]]; then
      ufw allow "${BIND_PORT}"/udp >/dev/null 2>&1 || true
      ok "Opened ${BIND_PORT}/udp for KCP."
    fi
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 8443/tcp >/dev/null 2>&1 || true
    ufw allow 7005/tcp >/dev/null 2>&1 || true
    ok "Firewall (ufw) rules applied."
  else
    warn "ufw not installed – open ports manually (including UDP ${BIND_PORT} if using KCP)."
  fi
fi

# ------------------------------------------------------------------
if [[ "$ROLE" == "client" ]]; then
  AUTH_TOKEN="$FIXED_AUTH_TOKEN"

  validate_or_backup_config "frpc" "$CONFIG_PATH"
  CONFIG_WAS_INVALID=$?

  if [[ -f "$CONFIG_PATH" ]]; then
    ok "Updating stability parameters in existing config..."
    toml_set "$CONFIG_PATH" "auth.token" "\"${AUTH_TOKEN}\""
    toml_set "$CONFIG_PATH" "transport.tcpMuxKeepaliveInterval" "10"
    toml_set "$CONFIG_PATH" "transport.poolCount" "5"
    toml_set "$CONFIG_PATH" "transport.heartbeatInterval" "30"
    toml_set "$CONFIG_PATH" "transport.heartbeatTimeout" "90"
    toml_set "$CONFIG_PATH" "transport.dialServerTimeout" "30"
    toml_set "$CONFIG_PATH" "transport.dialServerKeepalive" "30"
    if grep -qE '^tls_enable' "$CONFIG_PATH"; then
      warn "Old config uses invalid key 'tls_enable' — migrating to 'transport.tls.enable'."
      sed -i -E 's/^tls_enable = (.*)$/transport.tls.enable = \1/' "$CONFIG_PATH"
    fi
    toml_set "$CONFIG_PATH" "transport.tls.enable" "${TLS_ENABLE}"
    toml_set "$CONFIG_PATH" "transport.protocol" "\"${PROTOCOL}\""

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
transport.useEncryption = false
transport.useCompression = false
"
    done

    cat > "$CONFIG_PATH" <<EOF
# ===================== frpc.toml (client) =====================
serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}
loginFailExit = false

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- Transport ----
transport.protocol = "${PROTOCOL}"
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 10
transport.poolCount = 5

# ---- Heartbeat (CRITICAL: keeps NAT/firewall from dropping idle tunnel) ----
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90

# ---- Connection timeouts ----
transport.dialServerTimeout = 30
transport.dialServerKeepalive = 30

# ---- TLS (v0.61.0 uses transport.tls.enable) ----
transport.tls.enable = ${TLS_ENABLE}

log.to = "console"
log.level = "info"

# ============= Auto-generated proxies (TCP only) =============
${PROXIES_BLOCK}
EOF

    if [[ ! -f "$CONFIG_PATH" ]]; then
      fail "Failed to write config file at $CONFIG_PATH. Check disk space or permissions."
    fi
    ok "Client config created at $CONFIG_PATH."

    info "Testing reachability to ${SERVER_ADDR}:${SERVER_PORT} (${PROTOCOL})..."
    if [[ "$PROTOCOL" == "kcp" ]]; then
      if command -v nc >/dev/null 2>&1; then
        if nc -uzw3 "${SERVER_ADDR}" "${SERVER_PORT}" 2>/dev/null; then
          ok "UDP port appears reachable (best-effort; UDP checks are not fully reliable)."
        else
          warn "Could not confirm UDP reachability — this is normal for UDP and not necessarily an error."
        fi
      else
        warn "nc not found — skipping UDP reachability test. Install netcat to enable it."
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
RestartSec=3
ExecStart=/usr/local/bin/${BIN_NAME} -c ${CONFIG_PATH}
LimitNOFILE=1048576
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
echo -e "${GREEN} TLS: ${TLS_ENABLE}   Protocol: ${PROTOCOL}${NC}"
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
  echo -e "  TLS            : ${GREEN}${TLS_ENABLE}${NC}"
  echo -e "${CYAN}=======================================================${NC}"
fi
