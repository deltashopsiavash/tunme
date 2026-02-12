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

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[1;33m"; BLU="\033[0;34m"; CYA="\033[0;36m"; MAG="\033[0;35m"; WHT="\033[1;37m"; NC="\033[0m"

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

bbanner() {
  clear
  echo -e "${MAG}"
  cat <<'EOF'
👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅
👅        DELTA VPN        👅
👅   telegram: @delta_vpn12 👅
👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅👅
EOF
  echo -e "${NC}"
  echo
}


ensure_dirs() {
  mkdir -p "${STATE_DIR}" "${SWAN_DIR}"
  chmod 700 "${STATE_DIR}"
}

install_packages() {
  echo -e "${BLU}[*] Installing required packages...${NC}"
  apt-get update -y
  apt-get install -y strongswan strongswan-swanctl iproute2 curl
  systemctl enable strongswan >/dev/null 2>&1 || true
  systemctl start strongswan  >/dev/null 2>&1 || true
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

# ---------- input helpers ----------
ask_role() {
  # IMPORTANT: menu text goes to stderr so it does NOT pollute captured output.
  local c
  while true; do
    echo -e "${WHT}Select server location:${NC}" >&2
    echo -e "  ${GRN}1) Iran${NC}" >&2
    echo -e "  ${CYA}2) Abroad${NC}" >&2
    read -r -p "Enter choice [1-2]: " c
    case "$c" in
      1) echo "iran"; return 0 ;;
      2) echo "abroad"; return 0 ;;
      *) echo -e "${RED}Invalid choice.${NC}" >&2; echo >&2 ;;
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
        echo "$ip"; return 0
      fi
    fi
    echo -e "${RED}Invalid IPv4. Try again.${NC}" >&2
  done
}

ask_int_range() {
  local prompt="$1" min="$2" max="$3"
  local n
  while true; do
    read -r -p "${prompt}" n
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n>=min && n<=max )); then
      echo "$n"; return 0
    fi
    echo -e "${RED}Enter a number between ${min} and ${max}.${NC}" >&2
  done
}

# ---------- role logic ----------
expected_octets_for_role() {
  local role="$1"
  if [[ "$role" == "iran" ]]; then
    echo "1 2"   # local remote
  else
    echo "2 1"
  fi
}

detect_suggested_location() {
  # Heuristic:
  # - private gateway (RFC1918) usually cloud/VPC => Abroad
  # - public gateway often routed DC => Iran
  local gw
  gw="$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -n1)"
  if [[ -z "${gw}" ]]; then
    echo "unknown"; return 0
  fi
  if [[ "${gw}" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
    echo "abroad"
  else
    echo "iran"
  fi
}

# ---------- network setup ----------
cleanup_lo_ips() {
  ip -4 addr show dev lo | awk '/10\.50\./ {print $2}' | while read -r cidr; do
    ip addr del "$cidr" dev lo >/dev/null 2>&1 || true
  done
}

enforce_lo_ips_for_role() {
  local role="$1" count="$2"
  read -r local_octet _ < <(expected_octets_for_role "$role")

  # ALWAYS clean to avoid mixed role or "both .2"
  cleanup_lo_ips

  for ((i=0; i<count; i++)); do
    local net=$((50 + i*10))
    local lip="10.50.${net}.${local_octet}"
    ip addr add "${lip}/32" dev lo >/dev/null 2>&1 || true
  done

  # sanity check
  local expected_first="10.50.50.${local_octet}"
  if ! ip -4 addr show dev lo | grep -qE "\\b${expected_first}/32\\b"; then
    echo -e "${RED}ERROR:${NC} Loopback sanity check failed (expected ${expected_first}/32 on lo)."
    exit 1
  fi
}

extract_children_from_conf() {
  awk '/^[[:space:]]*link[0-9]+[[:space:]]*{/ {gsub("{","",$1); print $1}' "${SWAN_CONF}" 2>/dev/null || true
}

load_strongswan_safe() {
  echo -e "${BLU}[*] Loading configuration...${NC}"

  # restart quickly
  systemctl restart strongswan >/dev/null 2>&1 || true

  # wait for VICI socket (max 12s, but usually <1s)
  for _ in {1..12}; do
    [[ -S /run/charon.vici || -S /var/run/charon.vici ]] && break
    sleep 1
  done

  if [[ ! -S /run/charon.vici && ! -S /var/run/charon.vici ]]; then
    echo -e "${RED}ERROR:${NC} charon.vici not found. StrongSwan is not ready."
    echo "Run: sudo systemctl status strongswan --no-pager"
    exit 1
  fi

  # FAST path (no debug output)
  if timeout 12 swanctl --load-all >/dev/null 2>&1; then
    :
  else
    # SLOW path: show debug only on failure
    echo -e "${YLW}[!] Load failed, retrying with debug output...${NC}"
    timeout 20 swanctl --load-all --debug 1 || {
      echo -e "${RED}ERROR:${NC} swanctl --load-all failed."
      echo "Check logs: sudo journalctl -u strongswan -n 200 --no-pager"
      exit 1
    }
  fi

  # initiate children explicitly
  local child
  for child in $(extract_children_from_conf); do
    swanctl --initiate --child "$child" >/dev/null 2>&1 || true
  done
}

# ---------- main config ----------
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

  # Set local loopback IPs correctly (ANTI-MISTAKE)
  enforce_lo_ips_for_role "$role" "$count"

  # Build IP pairs list (fresh)
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

  # Final self-check: make sure first pair is correct orientation
  local expected_local="10.50.50.${local_octet}/32"
  local expected_remote="10.50.50.${remote_octet}/32"
  if ! grep -q "local_ts = ${expected_local}" "${SWAN_CONF}" || ! grep -q "remote_ts = ${expected_remote}" "${SWAN_CONF}"; then
    echo -e "${RED}ERROR:${NC} Config orientation sanity check failed."
    echo "Expected: local_ts=${expected_local} remote_ts=${expected_remote}"
    exit 1
  fi

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

  local role suggested remote_pub count psk local_octet remote_octet

  role="$(ask_role)"
  suggested="$(detect_suggested_location)"

  if [[ "${suggested}" != "unknown" && "${role}" != "${suggested}" ]]; then
    echo
    echo -e "${RED}WARNING:${NC} Your selection looks wrong for this server."
    echo -e "Detected environment suggests: ${YLW}${suggested^^}${NC}"
    echo -e "You selected: ${YLW}${role^^}${NC}"
    echo -e "${YLW}If you continue, both servers may end up with the same .1/.2 side and it will NOT work.${NC}"
    echo
    local ok
    read -r -p "Type YES to continue anyway: " ok
    [[ "$ok" == "YES" ]] || return
  fi

  echo
  remote_pub="$(ask_ipv4 "Enter the OTHER server Public IPv4: ")"
  echo
  count="$(ask_int_range "How many VPN IP pairs do you want? (1-10): " 1 10)"

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

# ---------- restart / recovery ----------
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

IP_LIST_FILE="/etc/delta-vpn/ip_pairs.list"

[[ -f "${IP_LIST_FILE}" ]] || exit 0

ok=1
while read -r lip rip; do
  ip -4 addr show dev lo | grep -qE "\\b${lip}/32\\b" || ip addr add "${lip}/32" dev lo >/dev/null 2>&1 || true
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
  echo -e "${MAG}Restart / Recovery:${NC}"
  echo -e "  ${GRN}1) Automatic${NC} ${WHT}(every 1 minute health-check)${NC}"
  echo -e "  ${CYA}2) Scheduled${NC} ${WHT}(restart every N hours)${NC}"
  echo -e "  ${YLW}3) Disable all${NC}"
  echo -e "  ${RED}0) Back${NC}"
  echo

  local c
  read -r -p "Enter choice: " c
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
      systemctl disable --now delta-vpn-auto.timer   >/dev/null 2>&1 || true
      systemctl disable --now delta-vpn-manual.timer >/dev/null 2>&1 || true
      rm -f "${AUTO_SERVICE}" "${AUTO_TIMER}" "${MAN_SERVICE}" "${MAN_TIMER}" \
            /usr/local/bin/delta-vpn-healthcheck.sh /usr/local/bin/delta-vpn-restart.sh
      systemctl daemon-reload
      echo -e "${GRN}[OK] All restart modes disabled.${NC}"
      pause
      ;;
    0) ;;
    *) echo -e "${RED}Invalid choice.${NC}"; pause ;;
  esac
}

remove_all() {
  banner
  echo -e "${YLW}This will remove DELTA VPN configuration and related services.${NC}"
  local c
  read -r -p "Type YES to continue: " c
  [[ "$c" == "YES" ]] || { echo "Canceled."; pause; return; }

  systemctl disable --now delta-vpn-auto.timer   >/dev/null 2>&1 || true
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

# =========================
# NEW MENUS / FEATURES
# =========================

menu_tunell_kosmos() {
  while true; do
    banner
    echo -e "${MAG}tunell kosmos${NC}"
    echo -e "${WHT}Public IPv4:${NC} ${YLW}$(get_public_ip)${NC}"
    echo
    echo -e "  ${GRN}1) Install / Update${NC}"
    echo -e "  ${CYA}2) Restart / Recovery${NC}"
    echo -e "  ${RED}3) Remove${NC}"
    echo -e "  ${BLU}4) Status${NC}"
    echo -e "  ${YLW}5) List${NC}"
    echo -e "  ${WHT}0) Back${NC}"
    echo
    local c
    read -r -p "Select an option: " c
    case "$c" in
      1) install_or_update ;;
      2) restart_menu ;;
      3) remove_all ;;
      4) show_status ;;
      5) list_pairs ;;
      0) return ;;
      *) echo -e "${RED}Invalid option.${NC}"; pause ;;
    esac
  done
}

enable_rc_local_systemd_if_needed() {
  # Ubuntu 22/24: rc.local not enabled by default. Create rc-local.service if missing.
  if [[ ! -f /etc/systemd/system/rc-local.service ]]; then
    cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  systemctl enable rc-local.service >/dev/null 2>&1 || true
}

kosmos1_install() {
  banner
  echo -e "${MAG}tunell kosmos 1${NC}"
  echo -e "${WHT}This server Public IPv4:${NC} ${YLW}$(get_public_ip)${NC}"
  echo

  local role other_ip local_ip
  role="$(ask_role)"
  local_ip="$(get_public_ip)"
  other_ip="$(ask_ipv4 "Enter the OTHER server Public IPv4: ")"

  if [[ "$local_ip" == "Unknown" ]]; then
    echo -e "${RED}ERROR:${NC} Could not detect local public IP. Please ensure IPv4 connectivity."
    pause
    return
  fi

  echo -e "${BLU}[*] Writing /etc/rc.local ...${NC}"

  if [[ "$role" == "iran" ]]; then
    cat >/etc/rc.local <<EOF
#!/bin/bash
ip tunnel add gre1 mode gre remote ${other_ip} local ${local_ip} ttl 255
ip link set gre1 mtu 1420
ip link set gre1 up
ip addr add 10.10.10.1/30 dev gre1
nohup ping 10.10.10.2 >/dev/null 2>&1 &
exit 0
EOF
  else
    cat >/etc/rc.local <<EOF
#!/bin/bash
ip tunnel add gre1 mode gre remote ${other_ip} local ${local_ip} ttl 255
ip link set gre1 mtu 1420
ip link set gre1 up
ip addr add 10.10.10.2/30 dev gre1
nohup ping 10.10.10.1 >/dev/null 2>&1 &
exit 0
EOF
  fi

  chmod +x /etc/rc.local
  enable_rc_local_systemd_if_needed

  echo -e "${BLU}[*] Applying now...${NC}"
  # clean any old gre1 first (best effort)
  ip link set gre1 down >/dev/null 2>&1 || true
  ip tunnel del gre1 >/dev/null 2>&1 || true

  bash /etc/rc.local >/dev/null 2>&1 || true

  echo
  echo -e "${GRN}[OK] tunell kosmos 1 installed.${NC}"
  echo -e "${YLW}Tip:${NC} Use Inquiry to check gre1 status."
  pause
}

kosmos1_remove() {
  banner
  echo -e "${MAG}tunell kosmos 1${NC}"
  echo

  echo -e "${BLU}[*] Removing gre1 ...${NC}"
  ip link set gre1 down >/dev/null 2>&1 || true
  ip tunnel del gre1 >/dev/null 2>&1 || true

  # remove from rc.local (simple: disable file content if it contains gre1)
  if [[ -f /etc/rc.local ]] && grep -q "ip tunnel add gre1" /etc/rc.local; then
    cat >/etc/rc.local <<'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x /etc/rc.local
  fi

  echo -e "${GRN}[OK] tunell kosmos 1 removed.${NC}"
  pause
}

menu_kosmos1() {
  while true; do
    banner
    echo -e "${MAG}tunell kosmos 1${NC}"
    echo -e "${WHT}Public IPv4:${NC} ${YLW}$(get_public_ip)${NC}"
    echo
    echo -e "  ${GRN}1) Install${NC}"
    echo -e "  ${RED}2) Remove${NC}"
    echo -e "  ${WHT}0) Back${NC}"
    echo
    local c
    read -r -p "Select an option: " c
    case "$c" in
      1) kosmos1_install ;;
      2) kosmos1_remove ;;
      0) return ;;
      *) echo -e "${RED}Invalid option.${NC}"; pause ;;
    esac
  done
}

backhaul_install() {
  banner
  echo -e "${MAG}backhaul${NC}"
  echo
  echo -e "${BLU}[*] Running installer...${NC}"
  bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/wafflenoodle/zenith-stash/refs/heads/main/backhaul.sh)
  echo
  echo -e "${GRN}[OK] backhaul install command finished.${NC}"
  pause
}

backhaul_service_setup() {
  banner
  echo -e "${MAG}backhaul${NC}"
  echo -e "${BLU}[*] Creating systemd service...${NC}"
  cat >/etc/systemd/system/backhaul.service <<'EOF'
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=/root/backhaul/backhaul -c /root/backhaul/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable backhaul.service
  systemctl start backhaul.service

  echo
  echo -e "${GRN}[OK] backhaul.service enabled and started.${NC}"
  pause
}

menu_backhaul() {
  while true; do
    banner
    echo -e "${MAG}backhaul${NC}"
    echo
    echo -e "  ${GRN}1) Install${NC}"
    echo -e "  ${CYA}2) Cron Job (systemd)${NC}"
    echo -e "  ${WHT}0) Back${NC}"
    echo
    local c
    read -r -p "Select an option: " c
    case "$c" in
      1) backhaul_install ;;
      2) backhaul_service_setup ;;
      0) return ;;
      *) echo -e "${RED}Invalid option.${NC}"; pause ;;
    esac
  done
}

rathole_install() {
  banner
  echo -e "${MAG}rathole${NC}"
  echo
  echo -e "${BLU}[*] Running installer...${NC}"
  bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/Musixal/rathole-tunnel/main/rathole_v2.sh)
  echo
  echo -e "${GRN}[OK] rathole install command finished.${NC}"
  pause
}

menu_rathole() {
  while true; do
    banner
    echo -e "${MAG}rathole${NC}"
    echo
    echo -e "  ${GRN}1) Install${NC}"
    echo -e "  ${WHT}0) Back${NC}"
    echo
    local c
    read -r -p "Select an option: " c
    case "$c" in
      1) rathole_install ;;
      0) return ;;
      *) echo -e "${RED}Invalid option.${NC}"; pause ;;
    esac
  done
}

inquiry_all() {
  banner
  echo -e "${MAG}Inquiry${NC}"
  echo -e "${WHT}Public IPv4:${NC} ${YLW}$(get_public_ip)${NC}"
  echo

  echo -e "${CYA}== tunell kosmos (StrongSwan) ==${NC}"
  if cmd_exists swanctl; then
    swanctl --list-sas 2>/dev/null || echo "(no SAs / swanctl error)"
  else
    echo "(swanctl not found)"
  fi
  echo

  echo -e "${CYA}== tunell kosmos 1 (GRE gre1) ==${NC}"
  if ip tunnel show 2>/dev/null | grep -q "^gre1"; then
    ip tunnel show gre1 || true
    ip link show gre1 || true
    ip -4 addr show dev gre1 || true
  else
    echo "(gre1 not present)"
  fi
  echo

  echo -e "${CYA}== backhaul.service ==${NC}"
  if systemctl list-unit-files | grep -q "^backhaul\.service"; then
    systemctl --no-pager --full status backhaul.service || true
  else
    echo "(backhaul.service not installed)"
  fi
  echo

  echo -e "${CYA}== rathole ==${NC}"
  # best-effort checks (script may create its own service name)
  if systemctl list-units --type=service --all | grep -qi rathole; then
    systemctl list-units --type=service --all | grep -i rathole || true
  elif pgrep -af rathole >/dev/null 2>&1; then
    pgrep -af rathole || true
  else
    echo "(no rathole service/process detected)"
  fi

  echo
  pause
}

# =========================
# MAIN MENU (NEW)
# =========================
main_menu() {
  while true; do
    banner
    echo -e "${WHT}Public IPv4:${NC} ${YLW}$(get_public_ip)${NC}"
    echo
    echo -e "  ${MAG}1) tunell kosmos${NC}"
    echo -e "  ${CYA}2) tunell kosmos 1${NC}"
    echo -e "  ${GRN}3) backhaul${NC}"
    echo -e "  ${BLU}4) rathole${NC}"
    echo -e "  ${YLW}5) Inquiry${NC}"
    echo -e "  ${RED}0) Exit${NC}"
    echo
    local c
    read -r -p "Select an option: " c
    case "$c" in
      1) menu_tunell_kosmos ;;
      2) menu_kosmos1 ;;
      3) menu_backhaul ;;
      4) menu_rathole ;;
      5) inquiry_all ;;
      0) exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}"; pause ;;
    esac
  done
}

require_root
ensure_dirs
main_menu
