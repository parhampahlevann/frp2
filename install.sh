#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Fixed version: v0.57.0 (stable)
#  - Optimized for low latency and jitter
#  - Supports TLS & KCP (optional)
#  - Pure TCP tunnel default — UDP completely removed
#  - Health Check completely disabled
#  - Auto-fixes DNS, port conflicts, and applies sysctl tuning
#  - Menu: server, client, status, uninstall
#
#  FIXES applied vs original:
#   1) TLS now uses correct toml keys: transport.tls.force (server) /
#      transport.tls.enable (client) instead of the non-existent
#      top-level "tls_enable" key (which frp silently ignored).
#   2) When KCP is selected, the KCP bind port is now opened on UDP
#      in ufw as well (previously only TCP was opened, so the KCP
#      control channel could never establish -> "tunnel never connects").
#   3) Auth token is no longer hardcoded to "123": frps generates a
#      strong random token and prints it clearly; frpc asks you to
#      paste that exact token, preventing silent auth mismatches.
#   4) Client reachability test now matches the real protocol
#      (TCP test for tcp/websocket, UDP probe for kcp) instead of
#      always doing a TCP-only check that falsely "fails" under KCP.
#   5) After starting frps/frpc, logs are scanned for the most common
#      failure signatures (auth mismatch, TLS handshake, timeout,
#      port already in use) and a plain-language hint is printed.
#  USAGE: sudo bash frp_setup.sh
# =====================================================================
set -euo pipefail

# ----------------------------- colors -------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --------------------------- pre-flight -----------------------------
[[ $EUID -eq 0 ]] || fail "Run as root (sudo)."

# Fix immutable resolv.conf
if [[ -e /etc/resolv.conf ]] && command -v chattr >/dev/null 2>&1; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
fi
dpkg --configure -a >/dev/null 2>&1 || true

# ---- DNS self-check / auto-repair --------------------------------
check_dns() { getent hosts github.com >/dev/null 2>&1; }
fix_dns_if_needed() {
  if check_dns; then return 0; fi
  warn "DNS broken. Fixing..."
  # If systemd-resolved manages resolv.conf as a symlink, replacing it
  # with a plain file works but will be reverted on next resolved
  # restart; warn instead of silently fighting it forever.
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

# ---- Random token generator ----------------------------------------
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32
  fi
}

# ---- Apply sysctl tuning for network stability --------------------
apply_sysctl() {
  info "Applying sysctl network tuning..."
  cat > /etc/sysctl.d/99-frp-tune.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOF
  sysctl -p /etc/sysctl.d/99-frp-tune.conf >/dev/null 2>&1 || warn "Sysctl apply failed (ignore if not supported)."
  ok "Sysctl tuning applied."
}

# ---- Diagnose common connection failures from logs ------------------
diagnose_logs() {
  local SVC="$1"
  local LOG
  LOG="$(journalctl -u "$SVC" -n 50 --no-pager 2>/dev/null || true)"

  if echo "$LOG" | grep -qiE "authorization failed|auth.*fail|token.*(invalid|mismatch)"; then
    warn "Hint: authentication failed -> auth.token in frps.toml and frpc.toml do not match. Re-check the token you pasted."
  fi
  if echo "$LOG" | grep -qiE "tls: |certificate|handshake"; then
    warn "Hint: TLS handshake issue -> make sure TLS is enabled/disabled identically on BOTH server and client."
  fi
  if echo "$LOG" | grep -qiE "i/o timeout|dial tcp.*timeout|no route to host"; then
    warn "Hint: network/timeout -> server unreachable on this port. Check firewall/security-group rules and that frps is actually running."
  fi
  if echo "$LOG" | grep -qiE "address already in use|bind: address already in use"; then
    warn "Hint: port already in use -> another process is holding the bind port. Pick a different port."
  fi
  if echo "$LOG" | grep -qiE "connection refused"; then
    warn "Hint: connection refused -> frps is not listening on that IP/port yet, or a firewall is dropping it silently before that."
  fi
}

# ===================== Main Menu ===================================
echo -e "${CYAN}"
echo "==================================================="
echo "        FRP Reverse Tunnel - One-Click Setup"
echo "           (Stable v0.57.0 - Low Latency)"
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
  *) fail "Invalid" ;;
esac

# ------------------------------------------------------------------
if [[ "$ROLE" == "status" ]]; then
  for SVC in frps frpc; do
    if systemctl list-unit-files | grep -q "^${SVC}.service"; then
      echo -e "\n${CYAN}=== $SVC ===${NC}"
      systemctl is-active --quiet "$SVC" && ok "RUNNING" || warn "NOT RUNNING"
      systemctl status "$SVC" --no-pager -l | head -10
      echo "Config: /etc/frp/$SVC.toml"
      [[ -f "/etc/frp/$SVC.toml" ]] && ok "Config present" || warn "Config missing"
      echo "Last logs:"
      journalctl -u "$SVC" -n 5 --no-pager
      diagnose_logs "$SVC"
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
  ufw delete allow 1:65535/tcp 2>/dev/null || true
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

# -------------------- Fixed version v0.57.0 -----------------------
FRP_VERSION="0.57.0"
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
read -rp "Enable TLS (encryption) to avoid DPI? [y/N]: " TLS_ANSWER
if [[ "$TLS_ANSWER" =~ ^[Yy]$ ]]; then
  TLS_ENABLE="true"
else
  TLS_ENABLE="false"
fi

read -rp "Use KCP (UDP-based, may bypass some firewalls)? [y/N]: " KCP_ANSWER
if [[ "$KCP_ANSWER" =~ ^[Yy]$ ]]; then
  PROTOCOL="kcp"
else
  PROTOCOL="tcp"
fi

# ------------------------------------------------------------------
if [[ "$ROLE" == "server" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config found. Keeping it."
    BIND_PORT=$(grep -E '^bindPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || echo "7001")
    # Determine actual protocol/TLS in use from the existing file so
    # firewall rules match reality, not just this session's prompt.
    if grep -q '^kcpBindPort' "$CONFIG_PATH"; then IS_KCP=1; else IS_KCP=0; fi
    # Migrate configs written by older versions of this script that used
    # the non-existent "tls_enable" key — frp rejects unknown fields and
    # crash-loops on startup ("json: unknown field \"tls_enable\"").
    if grep -qE '^tls_enable' "$CONFIG_PATH"; then
      warn "Old config uses invalid key 'tls_enable' — migrating to 'transport.tls.force'."
      sed -i -E 's/^tls_enable = (.*)$/transport.tls.force = \1/' "$CONFIG_PATH"
      ok "Migrated TLS key in ${CONFIG_PATH}."
    fi
  else
    BIND_PORT=$(pick_free_port "7001" "Bind port for tunnel control")
    AUTH_TOKEN="$(gen_token)"

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
transport.tcpMux = false
transport.tcpKeepalive = 30
transport.maxPoolCount = 200
transport.heartbeatTimeout = 90

# ---- TLS (correct key for v0.57.0 is transport.tls.force) ----
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
    echo -e "${YELLOW}Bind port:  ${GREEN}${BIND_PORT}${NC}"
    echo -e "${YELLOW}Auth token: ${GREEN}${AUTH_TOKEN}${NC}"
    warn "Copy this exact token — you'll need to paste it when setting up frpc."
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
    ufw allow 1:65535/tcp >/dev/null 2>&1 || true
    ok "Firewall rules applied."
  else
    warn "ufw not installed – open ports manually (including UDP ${BIND_PORT} if using KCP)."
  fi
fi

# ------------------------------------------------------------------
if [[ "$ROLE" == "client" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config kept."
    SERVER_ADDR=$(grep -E '^serverAddr' "$CONFIG_PATH" | sed -E 's/.*"(.*)".*/\1/' || echo "")
    SERVER_PORT=$(grep -E '^serverPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || echo "")
    if grep -qE '^transport\.protocol *= *"kcp"' "$CONFIG_PATH"; then PROTOCOL="kcp"; else PROTOCOL="tcp"; fi
    if grep -qE '^tls_enable' "$CONFIG_PATH"; then
      warn "Old config uses invalid key 'tls_enable' — migrating to 'transport.tls.enable'."
      sed -i -E 's/^tls_enable = (.*)$/transport.tls.enable = \1/' "$CONFIG_PATH"
      ok "Migrated TLS key in ${CONFIG_PATH}."
    fi
  else
    read -rp "Server IP or domain: " SERVER_ADDR
    read -rp "Server bind port [7001]: " SERVER_PORT
    SERVER_PORT="${SERVER_PORT:-7001}"

    AUTH_TOKEN=""
    while [[ -z "$AUTH_TOKEN" ]]; do
      read -rp "Auth token (paste the exact token shown by frps): " AUTH_TOKEN
      [[ -z "$AUTH_TOKEN" ]] && warn "Token cannot be empty — it must match the server exactly."
    done

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

    # Write config and verify
    cat > "$CONFIG_PATH" <<EOF
# ===================== frpc.toml (client) =====================
serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- Transport ----
transport.protocol = "${PROTOCOL}"
transport.tcpMux = false
transport.poolCount = 2
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.dialServerTimeout = 20
transport.dialServerKeepAlive = 30

# ---- TLS (correct key for v0.57.0 is transport.tls.enable) ----
transport.tls.enable = ${TLS_ENABLE}

log.to = "console"
log.level = "info"

# ============= Auto-generated proxies (TCP only) =============
${PROXIES_BLOCK}
EOF

    # Verify file was created
    if [[ ! -f "$CONFIG_PATH" ]]; then
      fail "Failed to write config file at $CONFIG_PATH. Check disk space or permissions."
    fi
    ok "Client config created at $CONFIG_PATH."

    # Test connectivity — match the actual transport protocol so KCP
    # setups don't get a false "unreachable" warning from a TCP-only probe.
    info "Testing reachability to ${SERVER_ADDR}:${SERVER_PORT} (${PROTOCOL})..."
    if [[ "$PROTOCOL" == "kcp" ]]; then
      if command -v nc >/dev/null 2>&1; then
        if nc -uzw3 "${SERVER_ADDR}" "${SERVER_PORT}" 2>/dev/null; then
          ok "UDP port appears reachable (best-effort; UDP checks are not fully reliable)."
        else
          warn "Could not confirm UDP reachability — this is normal for UDP and not necessarily an error. Verify manually if the tunnel fails."
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
systemctl enable "${BIN_NAME}" >/dev/null 2>&1
systemctl restart "${BIN_NAME}"
sleep 3

# ---- Verify service ----
if systemctl is-active --quiet "${BIN_NAME}"; then
  ok "${BIN_NAME} is RUNNING"
  # Even on a successful start, scan recent logs for reconnect-loop
  # symptoms (auth/TLS/timeout) that indicate the tunnel itself is failing.
  diagnose_logs "${BIN_NAME}"
else
  warn "${BIN_NAME} failed to start. Showing logs:"
  journalctl -u "${BIN_NAME}" -n 20 --no-pager
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
