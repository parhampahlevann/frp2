#!/usr/bin/env bash
# =====================================================================
#  FRP One-Click Installer / Updater  (frps + frpc, all-in-one)
#  - Pure server<->client tunnel — NO web dashboard / NO panel
#  - Always fetches the LATEST release from GitHub automatically
#  - Works on Ubuntu 18.04 / 20.04 / 22.04 / 24.04+ (any systemd distro)
#  - Supports amd64 / arm64 / armv7
#  - Auto-fixes immutable /etc/resolv.conf (resolvconf dpkg bug)
#  - Auto-fixes broken DNS resolution (falls back to 1.1.1.1 / 8.8.8.8)
#  - Detects port conflicts BEFORE binding (e.g. a provider-managed frps
#    already sitting on the port you picked) instead of looping/crashing
#  - Verifies the service actually stays up after start, not just "started"
#  - Interactively asks which ports to forward (like the original script)
#  - Menu: install server / install client / status / full uninstall
#  - Creates a self-healing systemd service (auto-restart)
#
#  USAGE (just run it, it will ask you what to do):
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

# Known VPS bug: some cloud images ship /etc/resolv.conf as immutable
# (chattr +i), which makes ANY apt-get install/upgrade fail the moment
# it touches the resolvconf package (postinst script aborts, dpkg breaks,
# and every apt command after that fails too). Fix it up-front, before
# touching apt at all, so it never blocks install/update/uninstall.
if [[ -e /etc/resolv.conf ]] && command -v chattr >/dev/null 2>&1; then
  chattr -i /etc/resolv.conf 2>/dev/null || true
fi
dpkg --configure -a >/dev/null 2>&1 || true

# ---- DNS self-check / auto-repair --------------------------------
# Fixes "Temporary failure resolving..." / "Could not resolve host"
# errors on VPS/containers with a broken or empty resolver config.
# Uses getent (pure libc, no extra package needed) so it works even
# before curl/jq are installed.
check_dns() {
  getent hosts github.com >/dev/null 2>&1
}

fix_dns_if_needed() {
  if check_dns; then
    return 0
  fi
  warn "DNS resolution is broken on this machine (can't resolve hostnames). Attempting an automatic fix..."

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
  if check_dns; then
    ok "DNS fixed using public resolvers (1.1.1.1 / 8.8.8.8)."
  else
    warn "DNS is still broken after the automatic fix."
    warn "This usually means the machine has no working internet route or its provider blocks outbound DNS/UDP:53."
    warn "Check: ping 1.1.1.1   and   cat /etc/resolv.conf   — fix networking first, then re-run this script."
  fi
}

fix_dns_if_needed

# ---- Port-conflict helpers -----------------------------------------
# Learned the hard way: some VPS providers run their OWN frps (or other
# service) on common ports like 7001 as part of their network stack,
# started outside systemd (rc.local, a custom script, etc). If we blindly
# bind to that port, our service loops forever with "address already in
# use", and worse, a client can end up handshaking with the WRONG server
# entirely, which shows up as a confusing "unexpected EOF". So: always
# check before we commit a port to the config.
port_in_use() {
  local PORT="$1"
  # column 4 of `ss -tuln` is "Local Address:Port" (not column 5, which is
  # the peer address) — using the wrong column silently never detects
  # real conflicts, which is exactly the bug we hit with the provider's
  # frps already sitting on port 7001.
  ss -tuln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$"
}

describe_port_owner() {
  local PORT="$1"
  ss -tulpn 2>/dev/null | grep -E ":${PORT}\b" || true
}

pick_free_port() {
  # $1 = suggested/default port, $2 = human label for prompts
  local DEFAULT_PORT="$1"
  local LABEL="$2"
  local CHOSEN="$DEFAULT_PORT"

  while true; do
    read -rp "${LABEL} [${CHOSEN}]: " INPUT_PORT
    CHOSEN="${INPUT_PORT:-$CHOSEN}"

    if port_in_use "$CHOSEN"; then
      warn "Port ${CHOSEN} is already in use by another process on this machine:"
      describe_port_owner "$CHOSEN"
      warn "This is often something the VPS provider itself runs (not related to this script)."
      echo "Pick a different port instead (e.g. $((CHOSEN + 1)))."
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
echo "==================================================="
echo -e "${NC}"

echo "What do you want to do?"
echo "  1) Install / Update Server  (frps - runs on the machine with a public IP)"
echo "  2) Install / Update Client  (frpc - runs on the machine behind NAT/firewall)"
echo "  3) Status                  (show whether the tunnel is up and working)"
echo "  4) Uninstall               (completely remove everything FRP-related from this machine)"
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

      if systemctl is-active --quiet "${SVC}" 2>/dev/null; then
        ok "Service state : RUNNING"
      else
        warn "Service state : NOT RUNNING"
      fi
      systemctl --no-pager status "${SVC}" 2>/dev/null | sed -n '1,5p' || true

      echo ""
      echo "Config file: /etc/frp/${SVC}.toml"
      [[ -f "/etc/frp/${SVC}.toml" ]] && ok "Config present" || warn "Config missing"

      echo ""
      echo "Listening ports for ${SVC}:"
      ss -tulpn 2>/dev/null | grep "${SVC}" || echo "  (none found — process may not be running)"

      echo ""
      echo "Last 10 log lines:"
      journalctl -u "${SVC}" -n 10 --no-pager 2>/dev/null || echo "  (no logs yet)"
    fi
  done

  if [[ "$FOUND" -eq 0 ]]; then
    warn "Neither frps nor frpc is installed on this machine."
  fi
  echo ""
  echo "For a live view: journalctl -u frps -f   (or frpc)"
  exit 0
fi

# ===================================================================
#                          UNINSTALL EVERYTHING
# ===================================================================
if [[ "$ROLE" == "uninstall" ]]; then
  echo ""
  warn "This will completely remove frps AND frpc that THIS SCRIPT installed:"
  echo "    - stop & disable the frps.service / frpc.service systemd units"
  echo "    - delete those service unit files"
  echo "    - delete binaries (/usr/local/bin/frps, /usr/local/bin/frpc)"
  echo "    - delete configs (/etc/frp)"
  echo "    - delete logs (/var/log/frp)"
  echo "    - remove the firewall rules this script added"
  warn "It will NOT touch any other frps@/frpc@ instances your VPS provider may run separately."
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
      "7001/tcp" "7001/udp" "8080/tcp" "8443/tcp" "7005/tcp" \
      "2000:65000/tcp" "2000:65000/udp"
    do
      ufw delete allow "$RULE" >/dev/null 2>&1 || true
    done
    # NOTE: the tunnel's bind port now defaults to 443, but we deliberately
    # do NOT auto-delete a 443/tcp rule here — on a server that also runs
    # a real HTTPS site, that rule may not belong to this script and
    # removing it would take the site offline. Remove it manually if you
    # confirmed it was only used for the tunnel: ufw delete allow 443/tcp
    warn "If the tunnel was using port 443, remove that rule manually if nothing else on this server needs it: ufw delete allow 443/tcp"
    ok "Default firewall rules cleaned up (remove any custom port manually if you changed it)"
  fi

  echo ""
  echo -e "${GREEN}=====================================================${NC}"
  echo -e "${GREEN} FRP (installed by this script) has been removed.${NC}"
  echo -e "${GREEN}=====================================================${NC}"
  exit 0
fi

# ------------------------- install deps -----------------------------
info "Installing required dependencies (curl, tar, jq)..."
apt-get update -y -qq
if ! apt-get install -y -qq curl tar jq; then
  warn "First attempt failed, retrying after a dpkg repair..."
  chattr -i /etc/resolv.conf 2>/dev/null || true
  dpkg --configure -a >/dev/null 2>&1 || true
  apt-get install -f -y -qq >/dev/null 2>&1 || true
  apt-get install -y -qq curl tar jq || fail "Could not install required packages (curl/tar/jq). Fix apt manually and re-run."
fi
ok "Required dependencies ready"

# ---- optional firewall rules via ufw, only if it's already installed.
#      We never install ufw ourselves — this script's only job is the
#      tunnel itself (frps <-> frpc), not managing your firewall or
#      pulling in extra packages like resolvconf. ----
UFW_OK=0
if command -v ufw >/dev/null 2>&1; then
  UFW_OK=1
fi

# ---- detect architecture -------------------------------------------
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64)   FRP_ARCH="amd64" ;;
  aarch64)  FRP_ARCH="arm64" ;;
  armv7l)   FRP_ARCH="arm" ;;
  *) fail "Unsupported architecture: $ARCH_RAW" ;;
esac
ok "Detected architecture: $FRP_ARCH"

# --------------------- fetch latest release ---------------------------
fix_dns_if_needed   # safety net: re-check right before we need real network access
info "Fetching the latest FRP release from GitHub..."
LATEST_TAG="$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest | jq -r .tag_name)"
[[ -n "$LATEST_TAG" && "$LATEST_TAG" != "null" ]] || fail "Could not fetch latest release. DNS/network to github.com is still not working on this machine — fix connectivity and re-run."
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
    BIND_PORT="$(grep -E '^bindPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || echo 443)"
  else
    echo ""
    read -rp "Which protocol will the client(s) mainly use? [tcp/wss] (default tcp): " SERVER_PROTO_HINT
    SERVER_PROTO_HINT="${SERVER_PROTO_HINT:-tcp}"
    if [[ "$SERVER_PROTO_HINT" == "wss" || "$SERVER_PROTO_HINT" == "websocket" ]]; then
      DEFAULT_BIND_PORT=443
      echo "Choosing the tunnel port. Default is 443 (blends in with normal HTTPS"
      echo "traffic, which helps when using wss). If your VPS already runs a real"
      echo "web server on 443, this will detect the conflict and let you pick another."
    else
      DEFAULT_BIND_PORT=7001
      echo "Choosing the tunnel port. Default is 7001 for plain tcp. If your VPS"
      echo "provider already runs something on that port, this will detect it and"
      echo "let you pick another."
    fi
    BIND_PORT="$(pick_free_port "$DEFAULT_BIND_PORT" "Bind port for tunnel control")"
    AUTH_TOKEN="123"
    warn "Auth token is set to the default value: 123 (change it later in ${CONFIG_PATH} for real security)"

    cat > "$CONFIG_PATH" <<EOF
# ===================== frps.toml (server) =====================
# Pure tunnel: no web dashboard / no panel — just server<->client traffic passthrough.
bindAddr = "0.0.0.0"
bindPort = ${BIND_PORT}
# NOTE: kcpBindPort / quicBindPort are intentionally left OFF by default.
# Some VPS/container hosts (OpenVZ/Virtuozzo-style nodes especially) block
# or pre-reserve the matching UDP port at the hypervisor level even though
# it shows as free inside the container, which makes frps fail to start
# with "bind: address already in use" for no visible reason. TCP alone
# covers the default transport.protocol = "tcp" client setting. If you
# want KCP/QUIC and your host supports it, uncomment these two lines:
# kcpBindPort = ${BIND_PORT}
# quicBindPort = ${BIND_PORT}

vhostHTTPPort = 8080                # only used if you enable a proxy of type = http
vhostHTTPSPort = 8443               # only used if you enable a proxy of type = https
tcpmuxHTTPConnectPort = 7005        # only used if you enable a proxy of type = tcpmux

auth.method = "token"
auth.token = "${AUTH_TOKEN}"

# ---- stability / performance tuning (fixes common disconnect bugs) ----
# tcpMux multiplexes every proxy's traffic over ONE shared TCP connection
# to the server. With several proxies active at once, heavy traffic on
# one proxy can head-of-line-block the others sharing that connection —
# they all see jittery, up-and-down latency even though nothing is wrong
# with the network path. Disabled so each proxy gets its own independent
# connection instead.
transport.tcpMux = false
# tcpKeepalive is the OS-level TCP keepalive probe interval in seconds.
# The old default (7200s = 2 hours) is the Linux kernel default and is
# useless for catching a tunnel that drops within seconds — the OS would
# not even send a first probe until 2 hours in. 30s means a dead link on
# a flaky/censored route gets detected and the connection recycled fast.
transport.tcpKeepalive = 30
transport.maxPoolCount = 50
transport.heartbeatTimeout = 90
# NOTE: "transport.qos" is intentionally NOT set here — newer frp releases
# reject it with "json: unknown field \"qos\"" and refuse to start.

allowPorts = [
  { start = 1, end = 65535 }
]
maxPortsPerClient = 0

log.to = "/var/log/frp/frps.log"
log.level = "info"
log.maxDays = 7
detailedErrorsToClient = true
EOF
    ok "Config generated at $CONFIG_PATH"
    echo -e "${YELLOW}--------------------------------------------------${NC}"
    echo -e "  Bind port:   ${GREEN}${BIND_PORT}${NC}  (use this on the client!)"
    echo -e "  Auth token:  ${GREEN}${AUTH_TOKEN}${NC}  (use this on the client!)"
    echo -e "${YELLOW}--------------------------------------------------${NC}"
  fi

  if [[ "$UFW_OK" -eq 1 ]]; then
    info "Opening firewall ports (ufw)..."
    ufw allow "${BIND_PORT}"/tcp  >/dev/null 2>&1 || true
    ufw allow "${BIND_PORT}"/udp  >/dev/null 2>&1 || true
    ufw allow 8080/tcp  >/dev/null 2>&1 || true
    ufw allow 8443/tcp  >/dev/null 2>&1 || true
    ufw allow 7005/tcp  >/dev/null 2>&1 || true
    ufw allow 1:65535/tcp >/dev/null 2>&1 || true
    ufw allow 1:65535/udp >/dev/null 2>&1 || true
    ok "Firewall rules applied — full 1-65535 range opened for forwarded ports"
  else
    warn "ufw is not installed on this machine — skipping firewall rules. Open the needed ports manually (iptables / cloud provider security group / etc)."
  fi
fi

# ===================================================================
#                        CLIENT CONFIG GENERATION
# ===================================================================
if [[ "$ROLE" == "client" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    warn "Existing config found at $CONFIG_PATH — keeping it untouched."
    SERVER_ADDR="$(grep -E '^serverAddr' "$CONFIG_PATH" | sed -E 's/.*"(.*)".*/\1/' || true)"
    SERVER_PORT="$(grep -E '^serverPort' "$CONFIG_PATH" | grep -oE '[0-9]+' || true)"
  else
    read -rp "Server public IP or domain: " SERVER_ADDR
    read -rp "Transport protocol [tcp/kcp/quic/websocket/wss] (default tcp): " TRANSPORT_PROTO
    TRANSPORT_PROTO="${TRANSPORT_PROTO:-tcp}"
    if [[ "$TRANSPORT_PROTO" == "wss" || "$TRANSPORT_PROTO" == "websocket" ]]; then
      DEFAULT_SERVER_PORT=443
    else
      DEFAULT_SERVER_PORT=7001
    fi
    read -rp "Server bind port [${DEFAULT_SERVER_PORT}]: " SERVER_PORT
    SERVER_PORT="${SERVER_PORT:-$DEFAULT_SERVER_PORT}"
    AUTH_TOKEN="123"
    warn "Auth token is set to the default value: 123 (must match the server, change later for real security)"

    # ---- ask which ports need to be forwarded (like the original script) ----
    echo ""
    echo "Which ports do you want to forward through the tunnel?"
    echo "Enter them comma-separated, e.g.:  80,443,2053,2087"
    read -rp "Ports: " PORTS_INPUT
    read -rp "Protocol for these ports? [tcp/udp/both] (default tcp): " PORT_PROTO
    PORT_PROTO="${PORT_PROTO:-tcp}"

    # ---- compression / encryption: always off ------------------------
    # useCompression runs every packet through compression before it goes
    # over the tunnel. For traffic that's already high-entropy (games,
    # video, HTTPS, anything already encrypted) this buys nothing but
    # still burns CPU and adds latency to every single packet — this was
    # the main cause of "disconnects after a few seconds / delayed,
    # dropped packets" seen earlier. useEncryption is redundant too since
    # the forwarded traffic (e.g. xray/x-ui) already handles its own
    # encryption. Both hardcoded off — no prompt needed.
    USE_ENCRYPTION="false"
    USE_COMPRESSION="false"

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
transport.useEncryption = ${USE_ENCRYPTION}
transport.useCompression = ${USE_COMPRESSION}
# Loosened from 3s/3fails (30s total) to 5s/5fails (~25-30s of SUSTAINED
# failure, not one slow response) — the tight version was flapping the
# proxy offline on any brief local CPU/latency blip, which looked like
# random disconnects from the outside.
healthCheck.type = \"tcp\"
healthCheck.intervalSeconds = 10
healthCheck.timeoutSeconds = 5
healthCheck.maxFailed = 5
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
# Disabled to match frps — see the comment in frps.toml. With tcpMux off,
# each proxy dials its own connection instead of sharing one, so a busy
# proxy can no longer delay/jitter the others.
transport.tcpMux = false
# poolCount now actually matters (it's a no-op when tcpMux is on) — this
# many connections per proxy are kept pre-dialed and ready, so a new
# visitor doesn't pay a fresh handshake's latency.
transport.poolCount = 5
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
# Same fix as the server side: 7200s (2h) is the kernel default and won't
# catch a dropped tunnel for hours. 30s lets a dead connection get noticed
# and re-dialed quickly instead of sitting silently broken.
transport.dialServerTimeout = 10
transport.dialServerKeepAlive = 30

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

  # ---- Live reachability test: catches wrong IP/port or a closed
  # firewall/security-group BEFORE the service is even started, instead
  # of you having to dig through journalctl later. ----
  if [[ -n "${SERVER_ADDR:-}" && -n "${SERVER_PORT:-}" ]]; then
    info "Testing connectivity to ${SERVER_ADDR}:${SERVER_PORT}..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${SERVER_ADDR}/${SERVER_PORT}" 2>/dev/null; then
      ok "Server is reachable on ${SERVER_ADDR}:${SERVER_PORT}"
    else
      warn "Could NOT reach ${SERVER_ADDR}:${SERVER_PORT} from this machine."
      warn "The tunnel will fail to connect until this is fixed. Check:"
      warn "  1) frps is actually running on the server:  systemctl status frps"
      warn "  2) the port is open in the server's firewall / cloud security group"
      warn "  3) serverAddr/serverPort in ${CONFIG_PATH} are correct"
      warn "  4) the port isn't already used by something ELSE on the server (e.g."
      warn "     a provider-managed frps/network agent) — pick a different port if so"
    fi
  fi
fi

# ===================================================================
#                        SYSTEMD SERVICE
# ===================================================================
SERVICE_FILE="/etc/systemd/system/${BIN_NAME}.service"
# Always (re)write the service file — unlike the config, it holds no secrets
# or user customization, and regenerating it keeps it in sync with fixes.
info "Writing systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=frp ${ROLE} (${BIN_NAME})
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
ok "Service written: $SERVICE_FILE"

systemctl daemon-reload
systemctl enable "${BIN_NAME}" >/dev/null 2>&1
systemctl restart "${BIN_NAME}"
sleep 2

# ---- Post-start verification: don't just say "started", PROVE it's
# actually still running a couple seconds later, and give an immediate,
# specific hint if it's not (this is what would have caught every bug
# we hit today: qos field, port conflicts, orphaned processes). ----
echo ""
if systemctl is-active --quiet "${BIN_NAME}"; then
  ok "${BIN_NAME} is up and RUNNING"
else
  warn "${BIN_NAME} is NOT staying up. Last log lines:"
  journalctl -u "${BIN_NAME}" -n 15 --no-pager || true
  echo ""
  if journalctl -u "${BIN_NAME}" -n 15 --no-pager 2>/dev/null | grep -qi "address already in use"; then
    warn "That port is already used by something else on this machine."
    warn "Re-run this script and pick a different port when asked, or manually"
    warn "check with:  sudo ss -tulpn | grep <port>   to see who owns it."
  elif journalctl -u "${BIN_NAME}" -n 15 --no-pager 2>/dev/null | grep -qi "unknown field"; then
    warn "The config has a field this frp version doesn't recognize."
    warn "Check ${CONFIG_PATH} against the version installed: ${BIN_NAME} -v vs the toml keys."
  fi
fi

info "Service status:"
systemctl --no-pager status "${BIN_NAME}" | head -n 8 || true

echo ""
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} ${BIN_NAME} installed/updated to ${LATEST_TAG}${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo "  Config file : ${CONFIG_PATH}"
echo "  Live logs   : journalctl -u ${BIN_NAME} -f"
echo "  Restart     : systemctl restart ${BIN_NAME}"
echo "  Status      : sudo bash frp_setup.sh   (choose option 3)"
echo ""
echo "Run this same script again anytime to auto-update to the latest FRP release."
