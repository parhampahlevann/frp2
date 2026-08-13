#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Always fetches the LATEST release from GitHub automatically
#  - Works on Ubuntu 18.04 / 20.04 / 22.04 / 24.04+ (any systemd distro)
#  - Supports amd64 / arm64 / armv7
#  - Generates a ready-to-use config with ALL proxy types
#    (tcp, udp, http, https, stcp, xtcp, sudp, tcpmux)
#  - Creates a self-healing systemd service (auto-restart)
#
#  USAGE (just run it, it will ask you what to do):
#     curl -fsSL <raw-url-of-this-script> | sudo bash
#  or:
#     sudo bash frp_setup.sh
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

echo -e "${CYAN}"
echo "==================================================="
echo "        FRP Reverse Tunnel - One-Click Setup"
echo "==================================================="
echo -e "${NC}"

echo "What do you want to do?"
echo "  1) Install / Update Server  (frps - runs on the machine with a public IP)"
echo "  2) Install / Update Client  (frpc - runs on the machine behind NAT/firewall)"
echo "  3) Uninstall               (completely remove everything FRP-related from this machine)"
read -rp "Choose [1-3]: " ROLE_CHOICE

case "$ROLE_CHOICE" in
  1) ROLE="server"; BIN_NAME="frps" ;;
  2) ROLE="client"; BIN_NAME="frpc" ;;
  3) ROLE="uninstall" ;;
  *) fail "Invalid choice" ;;
esac

# ===================================================================
#                          UNINSTALL EVERYTHING
# ===================================================================
if [[ "$ROLE" == "uninstall" ]]; then
  echo ""
  warn "This will completely remove frps AND frpc from this machine:"
  echo "    - stop & disable both systemd services"
  echo "    - delete service unit files"
  echo "    - delete binaries (/usr/local/bin/frps, /usr/local/bin/frpc)"
  echo "    - delete configs (/etc/frp)"
  echo "    - delete logs (/var/log/frp)"
  echo "    - remove the firewall rules this script added"
  read -rp "Are you sure? Type 'yes' to confirm: " CONFIRM
  [[ "$CONFIRM" == "yes" ]] || fail "Uninstall cancelled."

  for SVC in frps frpc; do
    if systemctl list-unit-files | grep -q "^${SVC}.service"; then
      info "Stopping and disabling ${SVC}..."
      systemctl stop "${SVC}" >/dev/null 2>&1 || true
      systemctl disable "${SVC}" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/${SVC}.service"
      ok "${SVC} service removed"
    else
      warn "${SVC} service was not installed, skipping"
    fi
  done
  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true

  info "Removing binaries..."
  rm -f /usr/local/bin/frps /usr/local/bin/frpc
  ok "Binaries removed"

  info "Removing config and log directories..."
  rm -rf /etc/frp
  rm -rf /var/log/frp
  ok "Config and logs removed"

  if command -v ufw >/dev/null 2>&1; then
    info "Removing firewall rules added by this script..."
    for RULE in \
      "7000/tcp" "7000/udp" "7500/tcp" "8080/tcp" "8443/tcp" "7005/tcp" \
      "2000:65000/tcp" "2000:65000/udp"
    do
      ufw delete allow "$RULE" >/dev/null 2>&1 || true
    done
    # also remove a possible custom bind port rule (best-effort, safe no-op if not found)
    ok "Firewall rules cleaned up (default set — remove any custom port manually if you changed it)"
  fi

  echo ""
  echo -e "${GREEN}=====================================================${NC}"
  echo -e "${GREEN} FRP has been completely removed from this machine.${NC}"
  echo -e "${GREEN}=====================================================${NC}"
  exit 0
fi

# ------------------------- install deps -----------------------------
info "Installing dependencies (curl, tar, jq)..."
apt-get update -y -qq
apt-get install -y -qq curl tar jq ufw >/dev/null 2>&1 || apt-get install -y -qq curl tar jq
ok "Dependencies ready"

# ------------------------- detect arch -------------------------------
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64)   FRP_ARCH="amd64" ;;
  aarch64)  FRP_ARCH="arm64" ;;
  armv7l)   FRP_ARCH="arm" ;;
  *) fail "Unsupported architecture: $ARCH_RAW" ;;
esac
ok "Detected architecture: $FRP_ARCH"

# --------------------- fetch latest release ---------------------------
info "Fetching the latest FRP release from GitHub..."
LATEST_TAG="$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest | jq -r .tag_name)"
[[ -n "$LATEST_TAG" && "$LATEST_TAG" != "null" ]] || fail "Could not fetch latest release. Check server internet connection."
VERSION="${LATEST_TAG#v}"
ok "Latest version: $LATEST_TAG"

FILENAME="frp_${VERSION}_linux_${FRP_ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/${LATEST_TAG}/${FILENAME}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading $DOWNLOAD_URL"
curl -fL --retry 3 -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"

info "Extracting..."
tar -xzf "${TMP_DIR}/${FILENAME}" -C "$TMP_DIR"
EXTRACTED_DIR="${TMP_DIR}/frp_${VERSION}_linux_${FRP_ARCH}"

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
    warn "Existing config found at $CONFIG_PATH — keeping it untouched."
  else
    read -rp "Bind port for tunnel control [7000]: " BIND_PORT
    BIND_PORT="${BIND_PORT:-7000}"
    AUTH_TOKEN="123"
    warn "Auth token is set to the default value: 123 (change it later in ${CONFIG_PATH} for real security)"
    read -rp "Dashboard admin password [auto-generate]: " DASH_PASS
    [[ -z "$DASH_PASS" ]] && DASH_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"

    cat > "$CONFIG_PATH" <<EOF
# ===================== frps.toml (server) =====================
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
kcpBindPort = ${BIND_PORT}          # enables KCP (UDP) on same port for unstable networks
quicBindPort = ${BIND_PORT}         # enables QUIC on same port (faster / more resilient)

vhostHTTPPort = 8080                # for proxies of type = http
vhostHTTPSPort = 8443               # for proxies of type = https
tcpmuxHTTPConnectPort = 7005        # for proxies of type = tcpmux

webServer.addr = "0.0.0.0"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "${DASH_PASS}"

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- stability / performance tuning (fixes common disconnect bugs) ----
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 30
transport.tcpKeepalive = 7200
transport.maxPoolCount = 50
transport.heartbeatTimeout = 90
transport.qos = 0

allowPorts = [
  { start = 2000, end = 65000 }
]
maxPortsPerClient = 0

log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7
detailedErrorsToClient = true
EOF
    ok "Config generated at $CONFIG_PATH"
    echo -e "${YELLOW}--------------------------------------------------${NC}"
    echo -e "  Auth token:        ${GREEN}${AUTH_TOKEN}${NC}  (use this on the client!)"
    echo -e "  Dashboard user:    admin"
    echo -e "  Dashboard pass:    ${GREEN}${DASH_PASS}${NC}"
    echo -e "  Dashboard URL:     http://YOUR_SERVER_IP:7500"
    echo -e "${YELLOW}--------------------------------------------------${NC}"
  fi

  info "Opening firewall ports (ufw)..."
  ufw allow "${BIND_PORT:-7000}"/tcp  >/dev/null 2>&1 || true
  ufw allow "${BIND_PORT:-7000}"/udp  >/dev/null 2>&1 || true
  ufw allow 7500/tcp  >/dev/null 2>&1 || true
  ufw allow 8080/tcp  >/dev/null 2>&1 || true
  ufw allow 8443/tcp  >/dev/null 2>&1 || true
  ufw allow 7005/tcp  >/dev/null 2>&1 || true
  ufw allow 2000:65000/tcp >/dev/null 2>&1 || true
  ufw allow 2000:65000/udp >/dev/null 2>&1 || true
  ok "Firewall rules applied (if ufw is active) — full 2000-65000 range opened for forwarded ports"
fi

# ===================================================================
#                        CLIENT CONFIG GENERATION
# ===================================================================
if [[ "$ROLE" == "client" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config found at $CONFIG_PATH — keeping it untouched."
  else
    read -rp "Server public IP or domain: " SERVER_ADDR
    read -rp "Server bind port [7000]: " SERVER_PORT
    SERVER_PORT="${SERVER_PORT:-7000}"
    AUTH_TOKEN="123"
    warn "Auth token is set to the default value: 123 (must match the server, change later for real security)"
    read -rp "Transport protocol [tcp/kcp/quic/websocket/wss] (default tcp): " TRANSPORT_PROTO
    TRANSPORT_PROTO="${TRANSPORT_PROTO:-tcp}"

    # ---- ask which ports need to be forwarded (like the original script) ----
    echo ""
    echo "Which ports do you want to forward through the tunnel?"
    echo "Enter them comma-separated, e.g.:  80,443,2053,2087"
    read -rp "Ports: " PORTS_INPUT
    read -rp "Protocol for these ports? [tcp/udp/both] (default tcp): " PORT_PROTO
    PORT_PROTO="${PORT_PROTO:-tcp}"

    # build the [[proxies]] blocks dynamically from user input
    PROXIES_BLOCK=""
    IFS=',' read -ra PORT_ARR <<< "$PORTS_INPUT"
    for RAW_PORT in "${PORT_ARR[@]}"; do
      PORT="$(echo "$RAW_PORT" | tr -d '[:space:]')"
      [[ -z "$PORT" ]] && continue
      if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
        warn "Skipping invalid port: $PORT"
        continue
      fi

      if [[ "$PORT_PROTO" == "tcp" || "$PORT_PROTO" == "both" ]]; then
        PROXIES_BLOCK+="
[[proxies]]
name = \"tcp-${PORT}\"
type = \"tcp\"
localIP = \"127.0.0.1\"
localPort = ${PORT}
remotePort = ${PORT}
transport.useEncryption = true
transport.useCompression = true
healthCheck.type = \"tcp\"
healthCheck.intervalSeconds = 10
healthCheck.timeoutSeconds = 3
healthCheck.maxFailed = 3
"
      fi

      if [[ "$PORT_PROTO" == "udp" || "$PORT_PROTO" == "both" ]]; then
        PROXIES_BLOCK+="
[[proxies]]
name = \"udp-${PORT}\"
type = \"udp\"
localIP = \"127.0.0.1\"
localPort = ${PORT}
remotePort = ${PORT}
"
      fi
    done

    if [[ -z "$PROXIES_BLOCK" ]]; then
      warn "No valid ports entered — you'll need to add [[proxies]] blocks manually later."
    else
      ok "Will forward these ports (${PORT_PROTO}): ${PORTS_INPUT}"
    fi

    cat > "$CONFIG_PATH" <<EOF
# ===================== frpc.toml (client) =====================
serverAddr = "${SERVER_ADDR}"
serverPort = ${SERVER_PORT}

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# tcp | kcp | quic | websocket | wss
# If your network has packet loss, try kcp or quic for a more stable tunnel
transport.protocol = "${TRANSPORT_PROTO}"
transport.tcpMux = true
transport.poolCount = 5
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.dialServerTimeout = 10
transport.dialServerKeepAlive = 7200

log.to = "console"
log.level = "info"

# =====================================================================
#  Auto-generated proxies for the ports you entered (${PORT_PROTO})
# =====================================================================
${PROXIES_BLOCK}
# =====================================================================
#  Extra protocol examples (http, https, stcp, xtcp, sudp, tcpmux)
#  Uncomment and edit if you need them.
# =====================================================================

# [[proxies]]
# name = "web-http"
# type = "http"
# localIP = "127.0.0.1"
# localPort = 80
# customDomains = ["example.yourdomain.com"]
# locations = ["/"]

# [[proxies]]
# name = "web-https"
# type = "https"
# localIP = "127.0.0.1"
# localPort = 443
# customDomains = ["secure.yourdomain.com"]

# [[proxies]]
# name = "secret-tcp"
# type = "stcp"
# secretKey = "CHANGE_ME_SECRET_KEY"
# localIP = "127.0.0.1"
# localPort = 22

# [[proxies]]
# name = "p2p-tcp"
# type = "xtcp"
# secretKey = "CHANGE_ME_SECRET_KEY"
# localIP = "127.0.0.1"
# localPort = 22

# [[proxies]]
# name = "secret-udp"
# type = "sudp"
# secretKey = "CHANGE_ME_SECRET_KEY"
# localIP = "127.0.0.1"
# localPort = 53

# [[proxies]]
# name = "tcpmux-proxy"
# type = "tcpmux"
# multiplexer = "httpconnect"
# localIP = "127.0.0.1"
# localPort = 22
# customDomains = ["mux.yourdomain.com"]
EOF
    ok "Config generated at $CONFIG_PATH"
  fi
fi

# ===================================================================
#                        SYSTEMD SERVICE
# ===================================================================
SERVICE_FILE="/etc/systemd/system/${BIN_NAME}.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
  info "Creating systemd service..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=frp ${ROLE} (${BIN_NAME})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=always
RestartSec=3
StartLimitIntervalSec=0
ExecStart=/usr/local/bin/${BIN_NAME} -c ${CONFIG_PATH}
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  ok "Service created: $SERVICE_FILE"
else
  ok "Service already exists, reusing it"
fi

systemctl daemon-reload
systemctl enable "${BIN_NAME}" >/dev/null 2>&1
systemctl restart "${BIN_NAME}"
sleep 1

echo ""
info "Service status:"
systemctl --no-pager status "${BIN_NAME}" | head -n 8 || true

echo ""
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} ${BIN_NAME} installed/updated to ${LATEST_TAG} successfully${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo "  Config file : ${CONFIG_PATH}"
echo "  Live logs   : journalctl -u ${BIN_NAME} -f"
echo "  Restart     : systemctl restart ${BIN_NAME}"
if [[ "$ROLE" == "server" ]]; then
  echo "  Dashboard   : http://YOUR_SERVER_IP:7500"
fi
echo ""
echo "Run this same script again anytime to auto-update to the latest FRP release."
