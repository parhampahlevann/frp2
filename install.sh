#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Fixed version: v0.57.0  (known stable release)
#  - Pure TCP tunnel — NO UDP / NO Health Check / NO web dashboard
#  - Optimized for stable latency (minimal jitter)
#  - Works on Ubuntu 18.04 / 20.04 / 22.04 / 24.04+ (any systemd distro)
#  - Supports amd64 / arm64 / armv7
#  - Auto-fixes immutable /etc/resolv.conf & broken DNS
#  - Detects port conflicts BEFORE binding
#  - Verifies the service actually stays up after start
#  - Interactively asks which TCP ports to forward
#  - Menu: install server / install client / status / full uninstall
#  - Creates a self-healing systemd service (auto-restart)
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

# --------------------------- pre-flight -----------------------------
[[ $EUID -eq 0 ]] || fail "Please run this script as root (sudo bash frp_setup.sh)"

# Fix immutable resolv.conf
if [[ -e /etc/resolv.conf ]] && command -v chattr >/dev/null 2>&1; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
fi
dpkg --configure -a >/dev/null 2>&1 || true

# ---- DNS self-check / auto-repair --------------------------------
check_dns() { getent hosts github.com >/dev/null 2>&1; }
fix_dns_if_needed() {
  if check_dns; then return 0; fi
  warn "DNS resolution is broken. Attempting fix..."
  if command -v chattr >/dev/null 2>&1; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
  fi
  if [[ -L /etc/resolv.conf || -e /etc/resolv.conf ]]; then
    cp -L /etc/resolv.conf "/etc/resolv.conf.bak.$(date +%s)" 2>/dev/null || true
    rm -f /etc/resolv.conf
  fi
  cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 1.0.0.1
EOF
  sleep 1
  check_dns && ok "DNS fixed." || warn "DNS still broken. Fix network manually."
}
fix_dns_if_needed

# ---- Port-conflict helpers -----------------------------------------
port_in_use() {
  local PORT="$1"
  ss -tuln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$"
}
describe_port_owner() {
  local PORT="$1"
  ss -tulpn 2>/dev/null | grep -E ":${PORT}\b" || true
}
pick_free_port() {
  local DEFAULT_PORT="$1" LABEL="$2" CHOSEN="$DEFAULT_PORT"
  while true; do
    read -rp "${LABEL} [${CHOSEN}]: " INPUT_PORT
    CHOSEN="${INPUT_PORT:-$CHOSEN}"
    if port_in_use "$CHOSEN"; then
      warn "Port ${CHOSEN} is already in use:"
      describe_port_owner "$CHOSEN"
      echo "Pick a different port (e.g. $((CHOSEN + 1)))."
      CHOSEN=$((CHOSEN + 1))
      continue
    fi
    break
  done
  echo "$CHOSEN"
}

echo -e "${CYAN}"
echo "==================================================="
echo "        FRP Reverse Tunnel - One-Click Setup"
echo "           (Fixed version: v0.57.0)"
echo "==================================================="
echo -e "${NC}"

echo "What do you want to do?"
echo "  1) Install / Update Server  (frps)"
echo "  2) Install / Update Client  (frpc)"
echo "  3) Status"
echo "  4) Uninstall"
read -rp "Choose [1-4]: " ROLE_CHOICE

case "$ROLE_CHOICE" in
  1) ROLE="server"; BIN_NAME="frps" ;;
  2) ROLE="client"; BIN_NAME="frpc" ;;
  3) ROLE="status" ;;
  4) ROLE="uninstall" ;;
  *) fail "Invalid choice" ;;
esac

# ===================================================================
#                              STATUS
# ===================================================================
if [[ "$ROLE" == "status" ]]; then
  FOUND=0
  for SVC in frps frpc; do
    if [[ -f "/usr/local/bin/${SVC}" ]] || systemctl list-unit-files 2>/dev/null | grep -q "^${SVC}.service"; then
      FOUND=1
      echo ""
      echo -e "${CYAN}=====================================================${NC}"
      echo -e "${CYAN} ${SVC}${NC}"
      echo -e "${CYAN}=====================================================${NC}"
      systemctl is-active --quiet "${SVC}" 2>/dev/null && ok "RUNNING" || warn "NOT RUNNING"
      systemctl --no-pager status "${SVC}" 2>/dev/null | sed -n '1,5p' || true
      echo ""
      echo "Config: /etc/frp/${SVC}.toml"
      [[ -f "/etc/frp/${SVC}.toml" ]] && ok "Config present" || warn "Config missing"
      echo ""
      echo "Listening ports:"
      ss -tulpn 2>/dev/null | grep "${SVC}" || echo "  (none)"
      echo ""
      echo "Last 10 log lines:"
      journalctl -u "${SVC}" -n 10 --no-pager 2>/dev/null || echo "  (no logs)"
    fi
  done
  [[ "$FOUND" -eq 0 ]] && warn "No FRP service installed."
  echo ""
  echo "Live logs: journalctl -u frps -f   (or frpc)"
  exit 0
fi

# ===================================================================
#                          UNINSTALL
# ===================================================================
if [[ "$ROLE" == "uninstall" ]]; then
  echo ""
  warn "This will remove frps AND frpc installed by this script."
  read -rp "Type 'yes' to confirm: " CONFIRM
  [[ "$CONFIRM" == "yes" ]] || fail "Cancelled."
  for SVC in frps frpc; do
    if systemctl list-unit-files | grep -q "^${SVC}.service"; then
      systemctl stop "${SVC}" >/dev/null 2>&1 || true
      systemctl disable "${SVC}" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/${SVC}.service"
    fi
  done
  systemctl daemon-reload
  rm -f /usr/local/bin/frps /usr/local/bin/frpc
  rm -rf /etc/frp /var/log/frp
  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow 7001/tcp >/dev/null 2>&1 || true
    ufw delete allow 8080/tcp >/dev/null 2>&1 || true
    ufw delete allow 8443/tcp >/dev/null 2>&1 || true
    ufw delete allow 7005/tcp >/dev/null 2>&1 || true
    ufw delete allow 1:65535/tcp >/dev/null 2>&1 || true
  fi
  echo -e "${GREEN}FRP fully removed.${NC}"
  exit 0
fi

# ------------------------- install deps -----------------------------
info "Installing dependencies (curl, tar, jq)..."
apt-get update -y -qq
if ! apt-get install -y -qq curl tar jq; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
  dpkg --configure -a >/dev/null 2>&1 || true
  apt-get install -f -y -qq >/dev/null 2>&1 || true
  apt-get install -y -qq curl tar jq || fail "Could not install required packages."
fi
ok "Dependencies ready"

UFW_OK=0
command -v ufw >/dev/null 2>&1 && UFW_OK=1

# ---- detect architecture -------------------------------------------
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64)   FRP_ARCH="amd64" ;;
  aarch64)  FRP_ARCH="arm64" ;;
  armv7l)   FRP_ARCH="arm" ;;
  *) fail "Unsupported architecture: $ARCH_RAW" ;;
esac
ok "Architecture: $FRP_ARCH"

# --------------------- FIXED VERSION: v0.57.0 ------------------------
FRP_VERSION="0.57.0"
FRP_TAG="v${FRP_VERSION}"
ok "Using fixed FRP version: ${FRP_TAG}"

FILENAME="frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${FRP_TAG}/${FILENAME}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${DOWNLOAD_URL}..."
curl -fL --retry 3 -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL" || fail "Failed to download ${FILENAME}. Check architecture or network."

info "Extracting..."
tar -xzf "${TMP_DIR}/${FILENAME}" -C "$TMP_DIR"
EXTRACTED_DIR="${TMP_DIR}/frp_${FRP_VERSION}_linux_${FRP_ARCH}"

mkdir -p /etc/frp /var/log/frp

info "Installing binary /usr/local/bin/${BIN_NAME}"
install -m 755 "${EXTRACTED_DIR}/${BIN_NAME}" "/usr/local/bin/${BIN_NAME}"
ok "Binary installed"

CONFIG_PATH="/etc/frp/${BIN_NAME}.toml"

# ===================================================================
#                        SERVER CONFIG GENERATION
# ===================================================================
if [[ "$ROLE" == "server" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config kept."
    BIND_PORT="$(grep -E '^bindPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || echo 7001)"
  else
    echo ""
    BIND_PORT="$(pick_free_port 7001 "Bind port for tunnel control")"
    AUTH_TOKEN="123"
    warn "Auth token set to default: 123 (change for security)"
    cat > "$CONFIG_PATH" <<EOF
# ===================== frps.toml (server) =====================
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
tcpmuxHTTPConnectPort = 7005

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- Optimized for maximum stability (low jitter) ----
transport.tcpMux = false
transport.tcpKeepalive = 30
transport.maxPoolCount = 200
transport.heartbeatTimeout = 90

allowPorts = [ { start = 1, end = 65535 } ]
maxPortsPerClient = 0

log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7
detailedErrorsToClient = true
EOF
    ok "Server config generated."
    echo -e "${YELLOW}Bind port: ${GREEN}${BIND_PORT}${NC}  |  Token: ${GREEN}${AUTH_TOKEN}${NC}"
  fi

  if [[ "$UFW_OK" -eq 1 ]]; then
    ufw allow "${BIND_PORT}"/tcp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 8443/tcp >/dev/null 2>&1 || true
    ufw allow 7005/tcp >/dev/null 2>&1 || true
    ufw allow 1:65535/tcp >/dev/null 2>&1 || true
    ok "Firewall rules applied (TCP range)."
  else
    warn "ufw not installed – open ports manually."
  fi
fi

# ===================================================================
#                        CLIENT CONFIG GENERATION
# ===================================================================
if [[ "$ROLE" == "client" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config kept."
    SERVER_ADDR="$(grep -E '^serverAddr' "$CONFIG_PATH" | sed -E 's/.*"(.*)".*/\1/' || true)"
    SERVER_PORT="$(grep -E '^serverPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || true)"
  else
    read -rp "Server IP or domain: " SERVER_ADDR
    read -rp "Server bind port [7001]: " SERVER_PORT
    SERVER_PORT="${SERVER_PORT:-7001}"
    AUTH_TOKEN="123"
    warn "Auth token default: 123 (must match server)"

    echo ""
    echo "Enter TCP ports to forward (comma-separated, e.g. 80,443,2053):"
    read -rp "Ports: " PORTS_INPUT

    USE_ENCRYPTION="false"
    USE_COMPRESSION="false"

    PROXIES_BLOCK=""
    IFS=',' read -ra PORT_ARR <<< "$PORTS_INPUT"
    for RAW_PORT in "${PORT_ARR[@]}"; do
      PORT="$(echo "$RAW_PORT" | tr -d '[:space:]')"
      [[ -z "$PORT" ]] && continue
      [[ ! "$PORT" =~ ^[0-9]+$ ]] && warn "Skipping invalid port: $PORT" && continue
      PROXIES_BLOCK+="
[[proxies]]
name = \"tcp-${PORT}\"
type = \"tcp\"
localIP = \"127.0.0.1\"
localPort = ${PORT}
remotePort = ${PORT}
transport.useEncryption = ${USE_ENCRYPTION}
transport.useCompression = ${USE_COMPRESSION}
"
    done

    [[ -z "$PROXIES_BLOCK" ]] && warn "No valid ports entered."

    cat > "$CONFIG_PATH" <<EOF
# ===================== frpc.toml (client) =====================
# Health Check is COMPLETELY DISABLED to prevent any jitter or false disconnections.
serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

transport.protocol = "tcp"
transport.tcpMux = false
transport.poolCount = 5
transport.heartbeatInterval = 35
transport.heartbeatTimeout = 90
transport.dialServerTimeout = 20
transport.dialServerKeepAlive = 30

log.to = "console"
log.level = "info"

# =====================================================================
#  Auto-generated proxies (TCP only - NO health checks)
# =====================================================================
${PROXIES_BLOCK}
# =====================================================================
#  Additional proxy types (http, https, stcp, etc.) – uncomment if needed
# =====================================================================
EOF
    ok "Client config generated (Health Check disabled)."
  fi

  # ---- connectivity test ----
  if [[ -n "${SERVER_ADDR:-}" && -n "${SERVER_PORT:-}" ]]; then
    info "Testing reachability to ${SERVER_ADDR}:${SERVER_PORT}..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" 2>/dev/null; then
      ok "Server reachable."
    else
      warn "Server NOT reachable – tunnel will fail. Check firewall / service."
    fi
  fi
fi

# ===================================================================
#                        SYSTEMD SERVICE
# ===================================================================
SERVICE_FILE="/etc/systemd/system/${BIN_NAME}.service"
info "Writing systemd service..."
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
ok "Service written."

systemctl daemon-reload
systemctl enable "${BIN_NAME}" >/dev/null 2>&1
systemctl restart "${BIN_NAME}"
sleep 2

echo ""
if systemctl is-active --quiet "${BIN_NAME}"; then
  ok "${BIN_NAME} is RUNNING"
else
  warn "${BIN_NAME} failed to start. Check logs:"
  journalctl -u "${BIN_NAME}" -n 15 --no-pager
fi

info "Service status:"
systemctl --no-pager status "${BIN_NAME}" | head -n 8 || true

echo ""
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} ${BIN_NAME} installed/updated to ${FRP_TAG}${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo "  Config : ${CONFIG_PATH}"
echo "  Logs   : journalctl -u ${BIN_NAME} -f"
echo "  Restart: systemctl restart ${BIN_NAME}"
echo ""
echo "This script uses FIXED version ${FRP_TAG}. To switch to another version, edit the script."
