#!/usr/bin/env bash
set -euo pipefail

# =========================
#   DELTA VPN - Installer
#   telegram: @delta_vpn12
# =========================

STATE_DIR="/etc/delta-vpn"
SWAN_DIR="/etc/swanctl"
SWAN_CONF="${SWAN_DIR}/swanctl.conf"
IP_LIST_FILE="${STATE_DIR}/ip_pairs.list"

AUTO_SERVICE="/etc/systemd/system/delta-vpn-auto.service"
AUTO_TIMER="/etc/systemd/system/delta-vpn-auto.timer"
MAN_SERVICE="/etc/systemd/system/delta-vpn-manual.service"
MAN_TIMER="/etc/systemd/system/delta-vpn-manual.timer"

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[1;33m"; BLU="\033[0;34m"; CYA="\033[0;36m"; NC="\033[0m"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}ERROR:${NC} Please run as root: sudo bash install.sh"
    exit 1
  fi
}

pause() { read -r -p "Press Enter to continue..." _; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

get_public_ip() {
  local ip=""
  if cmd_exists curl; then
    ip="$(curl -4 -s --max-time 2 https://api.ipify.org || true)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  echo "${ip:-Unknown}"
}

banner() {
  clear
  echo -e "${CYA}"
  cat <<'EOF'
██████╗ ███████╗██╗  ████████╗ █████╗     ██╗   ██╗██████╗ ███╗   ██╗
██╔══██╗██╔════╝██║  ╚══██╔══╝██╔══██╗    ██║   ██║██╔══██╗████╗  ██║
██║  ██║█████╗  ██║     ██║   ███████║    ██║   ██║██████╔╝██╔██╗ ██║
██║  ██║██╔══╝  ██║     ██║   ██╔══██║    ██║   ██║██╔═══╝ ██║╚██╗██║
██████╔╝███████╗███████╗██║   ██║  ██║    ╚██████╔╝██║     ██║ ╚████║
╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚═╝     ╚═╝  ╚═══╝
EOF
  echo -e "${NC}"
  echo -e "${BLU}telegram:${NC} ${YLW}@delta_vpn12${NC}"
  echo
}

ensure_dirs() {
  mkdir -p "${STATE_DIR}"
  mkdir -p "${SWAN_DIR}"
  chmod 700 "${STATE_DIR}"
}

install_packages() {
  echo -e "${BLU}[*] Installing required packages...${NC}"
  apt-get update -y
  apt-get install -y strongswan strongswan-swanctl iproute2 curl
  systemctl enable strongswan >/dev/null 2>&1 || true
  systemctl start strongswan >/dev/null 2>&1 || true
}

enable_sysctls() {
  echo -e "${BLU}[*] Applying sysctl tweaks...${NC}"
  cat >/etc/sysctl.d/99-delta-vpn.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl --system >/dev/null 2>&1 || true
}

open_firewall() {
  if cmd_exists ufw; then
    echo -e "${BLU}[*] Configuring UFW (best effort)...${NC}"
    ufw allow 500/udp >/dev/null 2>&1 || true
    ufw allow 4500/udp >/dev/null 2>&1 || true
    ufw allow proto esp >/dev/null 2>&1 || true
  fi
}

read_choice() { local p="$1"; local c; read -r -p "${p}" c; echo "$c"; }

ask_role() {
  echo "Select server location:"
  echo "  1) Iran"
  echo "  2) Abroad"
  local c
  while true; do
    c="$(read_choice "Enter choice [1-2]: ")"
    case "$c" in
      1) echo "iran"; return ;;
      2) echo "abroad"; return ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

ask_ipv4() {
  local prompt="$1"
  local ip
  while true; do
    read -r -p "${prompt}" ip
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      IFS='.' read -r a b c d <<<"$ip"
      if ((a<=255 && b<=255 && c<=255 && d<=255)); then
        echo "$ip"; return
      fi
    fi
    echo "Invalid IPv4. Try again."
  done
}

ask_int_range() {
  local prompt="$1" min="$2" max="$3"
  local n
  while true; do
    read -r -p "${prompt}" n
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n>=min && n<=max )); then
      echo "$n"; return
    fi
    echo "Enter a number between ${min} and ${max}."
  done
}

expected_octets_for_role() {
  local role="$1"
  if [[ "$role" == "iran" ]]; then
    echo "1 2"   # local_octet remote_octet
  else
    echo "2 1"
  fi
}

cleanup_lo_ips() {
  ip -4 addr show dev lo | awk '/10\.50\./ {print $2}' | while read -r cidr; do
    ip addr del "$cidr" dev lo >/dev/null 2>&1 || true
  done
}

enforce_lo_ips_for_role() {
  local role="$1" count="$2"
  read -r local_octet _ < <(expected_octets_for_role "$role")

  # Always clean to prevent mixed roles / both .2 issue
  cleanup_lo_ips

  for ((i=0; i<count; i++)); do
    local net=$((50 + i*10))
    local lip="10.50.${net}.${local_octet}"
    ip addr add "${lip}/32" dev lo >/dev/null 2>&1 || true
  done

  # Sanity check
  local expected_first="10.50.50.${local_octet}"
  if ! ip -4 addr show dev lo | grep -qE "\\b${expected_first}/32\\b"; then
    echo -e "${RED}ERROR:${NC} Loopback sanity check failed."
    echo "Expected ${expected_first}/32 on lo but did not find it."
    exit 1
  fi
}

detect_suggested_location() {
  # Heuristic:
  # If default gateway is private (RFC1918), usually cloud/VPC => Abroad
  # If default gateway is public, often Iran/DC public routed => Iran
  local gw
  gw="$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -n1)"
  if [[ -z "${gw}" ]]; then
    echo "unknown"; return
  fi
  if [[ "${gw}" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
    echo "abroad"
  else
    echo "iran"
  fi
}

extract_children_from_conf() {
  # Prints child names like link50 link60...
  awk '/^[[:space:]]*link[0-9]+[[:space:]]*{/ {gsub("{","",$1); print $1}' "${SWAN_CONF}" 2>/dev/null || true
}

load_strongswan_safe() {
  echo -e "${BLU}[*] Loading configuration...${NC}"
  systemctl restart strongswan >/dev/null 2>&1 || true

  for i in {1..8}; do
    [[ -S /run/charon.vici || -S /var/run/charon.vici ]] && break
    sleep 1
  done

  if [[ ! -S /run/charon.vici && ! -S /var/run/charon.vici ]]; then
    echo -e "${RED}ERROR:${NC} charon.vici not found. StrongSwan is not ready."
    echo "Run: sudo systemctl status strongswan --no-pager"
    exit 1
  fi

  if ! timeout 12 swanctl --load-all --debug 1; then
    echo -e "${RED}ERROR:${NC} swanctl --load-all failed (timeout or error)."
    echo "Check logs: sudo journalctl -u strongswan -n 200 --no-pager"
    exit 1
  fi

  # Initiate each child explicitly (prevents IKE-only)
  local child
  for child in $(extract_children_from_conf); do
    swanctl --initiate --child "$child" >/dev/null 2>&1 || true
  done
}

write_config() {
  local role="$1" remote_pub="$2" count="$3" psk="$4"

  read -r local_octet remote_octet < <(expected_octets_for_role "$role")

  # Save state
  cat >"${STATE_DIR}/state.env" <<EOF
ROLE=${role}
REMOTE_PUB=${remote_pub}
COUNT=${count}
LOCAL_OCTET=${local_octet}
REMOTE_OCTET=${remote_octet}
EOF
  chmod 600 "${STATE_DIR}/state.env"

  # Enforce correct local IPs (ANTI-MISTAKE CORE)
  enforce_lo_ips_for_role "$role" "$count"

  # Build ip pairs file (fresh)
  rm -f "${IP_LIST_FILE}" >/dev/null 2>&1 || true
  : > "${IP_LIST_FILE}"
  for ((i=0; i<count; i++)); do
    local net=$((50 + i*10))
    local lip="10.50.${net}.${local_octet}"
    local rip="10.50.${net}.${remote_octet}"
    echo "${lip} ${rip}" >> "${IP_LIST_FILE}"
  done
  chmod 600 "${IP_LIST_FILE}"

  echo -e "${BLU}[*] Writing StrongSwan configuration...${NC}"
  cat > "${SWAN_CONF}" <<EOF
connections {
  delta {
    version = 2
    remote_addrs = ${remote_pub}

    local {
      auth = psk
      id = %any
    }
    remote {
      auth = psk
      id = %any
    }

    dpd_delay = 30s
    dpd_timeout = 120s
    rekey_time = 1h
    proposals = aes256-sha256-modp2048

    children {
EOF

  for ((i=0; i<count; i++)); do
    local net=$((50 + i*10))
    local lip="10.50.${net}.${local_octet}"
    local rip="10.50.${net}.${remote_octet}"
    cat >> "${SWAN_CONF}" <<EOF
      link${net} {
        local_ts = ${lip}/32
        remote_ts = ${rip}/32
        esp_proposals = aes256-sha256-modp2048
        start_action = start
        close_action = restart
        dpd_action = restart
      }
EOF
  done

  cat >> "${SWAN_CONF}" <<'EOF'
    }
  }
}

secrets {
  ike-psk {
    secret = "__PSK__"
  }
}
EOF

  sed -i "s|__PSK__|${psk//\\/\\\\}|g" "${SWAN_CONF}"
  chmod 600 "${SWAN_CONF}"

  load_strongswan_safe

  echo -e "${GRN}[OK] Configuration applied.${NC}"
}

install_or_update() {
  banner
  ensure_dirs
  echo -e "${BLU}Public IPv4:${NC} $(get_public_ip)"
  echo

  install_packages
  enable_sysctls
  open_firewall

  local role remote_pub count psk
  role="$(ask_role)"

  # Role Guard (anti mistake)
  local suggested
  suggested="$(detect_suggested_location)"
  if [[ "${suggested}" != "unknown" && "${role}" != "${suggested}" ]]; then
    echo
    echo -e "${RED}WARNING:${NC} Your selection looks wrong for this server."
    echo -e "Detected environment suggests: ${YLW}${suggested^^}${NC}"
    echo -e "You selected: ${YLW}${role^^}${NC}"
    echo -e "${YLW}If you continue, both servers may end up with the same .1/.2 side and it will NOT work.${NC}"
    echo
    local ok
    ok="$(read_choice "Type YES to continue anyway: ")"
    [[ "$ok" == "YES" ]] || return
  fi

  echo
  remote_pub="$(ask_ipv4 "Enter the OTHER server Public IPv4: ")"
  echo
  count="$(ask_int_range "How many VPN IP pairs do you want? (1-10): " 1 10)"

  # Summary (prevents user confusion)
  read -r local_octet remote_octet < <(expected_octets_for_role "$role")
  echo
  echo -e "${BLU}Summary:${NC}"
  echo "  This server LOCAL IPs will end with .${local_octet}"
  echo "  Remote IPs will end with .${remote_octet}"
  echo "  First pair: 10.50.50.${local_octet} <-> 10.50.50.${remote_octet}"
  echo

  read -r -s -p "Enter PSK (will be saved on server): " psk
  echo

  write_config "$role" "$remote_pub" "$count" "$psk"
  echo
  echo -e "${YLW}Tip:${NC} Use option 4 to verify status."
  pause
}

write_auto_units() {
  cat > "${AUTO_SERVICE}" <<'EOF'
[Unit]
Description=DELTA VPN - Auto health check (every minute)
After=network-online.target strongswan.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/delta-vpn-healthcheck.sh
EOF

  cat > "${AUTO_TIMER}" <<'EOF'
[Unit]
Description=DELTA VPN - Auto health check timer

[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=10
Unit=delta-vpn-auto.service

[Install]
WantedBy=timers.target
EOF

  cat > /usr/local/bin/delta-vpn-healthcheck.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/etc/delta-vpn"
IP_LIST_FILE="${STATE_DIR}/ip_pairs.list"

if [[ ! -f "${IP_LIST_FILE}" ]]; then
  exit 0
fi

ok=1
while read -r lip rip; do
  if ! ip -4 addr show dev lo | grep -qE "\\b${lip}/32\\b"; then
    ip addr add "${lip}/32" dev lo >/dev/null 2>&1 || true
  fi

  if ping -c 1 -W 1 -I "${lip}" "${rip}" >/dev/null 2>&1; then
    :
  else
    ok=0
    break
  fi
done < "${IP_LIST_FILE}"

if [[ "${ok}" -eq 0 ]]; then
  systemctl restart strongswan || true
  swanctl --load-all >/dev/null 2>&1 || true
  # initiate children from config
  for child in $(awk '/^[[:space:]]*link[0-9]+[[:space:]]*{/ {gsub("{","",$1); print $1}' /etc/swanctl/swanctl.conf); do
    swanctl --initiate --child "$child" >/dev/null 2>&1 || true
  done
fi
EOF
  chmod +x /usr/local/bin/delta-vpn-healthcheck.sh
}

write_manual_units() {
  local seconds="$1"
  cat > "${MAN_SERVICE}" <<'EOF'
[Unit]
Description=DELTA VPN - Scheduled restart
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/delta-vpn-restart.sh
EOF

  cat > "${MAN_TIMER}" <<EOF
[Unit]
Description=DELTA VPN - Scheduled restart timer

[Timer]
OnBootSec=60
OnUnitActiveSec=${seconds}
AccuracySec=10
Unit=delta-vpn-manual.service

[Install]
WantedBy=timers.target
EOF

  cat > /usr/local/bin/delta-vpn-restart.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
systemctl restart strongswan || true
swanctl --load-all >/dev/null 2>&1 || true
swanctl --terminate --ike delta >/dev/null 2>&1 || true
for child in $(awk '/^[[:space:]]*link[0-9]+[[:space:]]*{/ {gsub("{","",$1); print $1}' /etc/swanctl/swanctl.conf); do
  swanctl --initiate --child "$child" >/dev/null 2>&1 || true
done
EOF
  chmod +x /usr/local/bin/delta-vpn-restart.sh
}

restart_menu() {
  banner
  echo "Restart / Recovery:"
  echo "  1) Automatic (every 1 minute health-check)"
  echo "  2) Scheduled (restart every N hours)"
  echo "  3) Disable all"
  echo "  0) Back"
  echo

  local c
  c="$(read_choice "Enter choice: ")"
  case "$c" in
    1)
      write_auto_units
      systemctl daemon-reload
      systemctl enable --now delta-vpn-auto.timer >/dev/null 2>&1 || true
      echo -e "${GRN}[OK] Automatic mode enabled.${NC}"
      pause
      ;;
    2)
      local hours seconds
      hours="$(ask_int_range "Enter interval in hours (1-168): " 1 168)"
      seconds=$((hours*3600))
      write_manual_units "$seconds"
      systemctl daemon-reload
      systemctl enable --now delta-vpn-manual.timer >/dev/null 2>&1 || true
      echo -e "${GRN}[OK] Scheduled mode enabled (every ${hours} hour(s)).${NC}"
      pause
      ;;
    3)
      systemctl disable --now delta-vpn-auto.timer >/dev/null 2>&1 || true
      systemctl disable --now delta-vpn-manual.timer >/dev/null 2>&1 || true
      rm -f "${AUTO_SERVICE}" "${AUTO_TIMER}" "${MAN_SERVICE}" "${MAN_TIMER}" \
            /usr/local/bin/delta-vpn-healthcheck.sh /usr/local/bin/delta-vpn-restart.sh
      systemctl daemon-reload
      echo -e "${GRN}[OK] All restart modes disabled.${NC}"
      pause
      ;;
    0) ;;
    *) echo "Invalid choice."; pause ;;
  esac
}

remove_all() {
  banner
  echo -e "${YLW}This will remove DELTA VPN configuration and related services.${NC}"
  local c
  c="$(read_choice "Type YES to continue: ")"
  if [[ "$c" != "YES" ]]; then
    echo "Canceled."
    pause
    return
  fi

  systemctl disable --now delta-vpn-auto.timer >/dev/null 2>&1 || true
  systemctl disable --now delta-vpn-manual.timer >/dev/null 2>&1 || true
  rm -f "${AUTO_SERVICE}" "${AUTO_TIMER}" "${MAN_SERVICE}" "${MAN_TIMER}" \
        /usr/local/bin/delta-vpn-healthcheck.sh /usr/local/bin/delta-vpn-restart.sh
  systemctl daemon-reload || true

  cleanup_lo_ips

  swanctl --terminate --ike delta >/dev/null 2>&1 || true
  rm -f "${SWAN_CONF}"
  rm -rf "${STATE_DIR}"

  systemctl restart strongswan >/dev/null 2>&1 || true

  echo -e "${GRN}[OK] Removed.${NC}"
  pause
}

show_status() {
  banner
  echo -e "${BLU}Public IPv4:${NC} $(get_public_ip)"
  echo
  echo -e "${BLU}StrongSwan service:${NC}"
  systemctl --no-pager --full status strongswan || true
  echo
  echo -e "${BLU}SAs:${NC}"
  swanctl --list-sas || true
  echo
  echo -e "${BLU}Timers:${NC}"
  systemctl --no-pager list-timers | grep -E "delta-vpn-(auto|manual)\.timer" || echo "(none)"
  echo
  pause
}

list_pairs() {
  banner
  if [[ -f "${IP_LIST_FILE}" ]]; then
    echo -e "${BLU}Configured IP pairs:${NC}"
    echo
    awk '{printf "  Local: %-15s  Remote: %-15s\n", $1, $2}' "${IP_LIST_FILE}"
    echo
    echo -e "${BLU}Local loopback IPs:${NC}"
    ip -4 addr show dev lo | awk '/10\.50\./ {print "  " $2}' || true
  else
    echo -e "${YLW}No configuration found.${NC}"
  fi
  echo
  pause
}

main_menu() {
  while true; do
    banner
    echo -e "${BLU}Public IPv4:${NC} $(get_public_ip)"
    echo
    echo "1) Install / Update"
    echo "2) Restart / Recovery"
    echo "3) Remove"
    echo "4) Status"
    echo "5) List"
    echo "0) Exit"
    echo
    local c
    c="$(read_choice "Select an option: ")"
    case "$c" in
      1) install_or_update ;;
      2) restart_menu ;;
      3) remove_all ;;
      4) show_status ;;
      5) list_pairs ;;
      0) exit 0 ;;
      *) echo "Invalid option."; pause ;;
    esac
  done
}

require_root
ensure_dirs
main_menu
