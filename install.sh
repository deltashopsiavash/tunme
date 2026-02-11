#!/usr/bin/env bash
set -euo pipefail

# Atomic simple IPsec (StrongSwan IKEv2) installer
# Ubuntu 20.04+ | Policy-based /32 <-> /32
# Iran tunnel IP:    10.50.50.1/32
# Foreign tunnel IP: 10.50.50.2/32

IRAN_TUN_IP="10.50.50.1/32"
FOREIGN_TUN_IP="10.50.50.2/32"
CONN_NAME="atomic-s2s"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[-] Run as root: sudo bash install.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_public_ip() {
  if have_cmd curl; then
    curl -fsS https://api.ipify.org || true
  fi
}

prompt() {
  local var="$1" msg="$2" def="${3:-}"
  local val=""
  if [[ -n "$def" ]]; then
    read -rp "${msg} [${def}]: " val
    val="${val:-$def}"
  else
    read -rp "${msg}: " val
  fi
  printf -v "$var" "%s" "$val"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y strongswan strongswan-pki ufw curl
}

enable_ip_forward() {
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

ensure_lo_ip() {
  local ip_cidr="$1"   # e.g. 10.50.50.1/32
  local ip="${ip_cidr%/*}"

  if ip addr show dev lo | grep -q " ${ip}/"; then
    echo "[i] lo already has ${ip_cidr}"
    return 0
  fi

  echo "[+] Adding ${ip_cidr} to lo"
  ip addr add "${ip_cidr}" dev lo
}

open_firewall() {
  # Only what we need for IPsec NAT-T / IKE
  ufw allow 500/udp >/dev/null || true
  ufw allow 4500/udp >/dev/null || true
}

write_ipsec_conf() {
  local left_pub="$1" right_pub="$2" left_subnet="$3" right_subnet="$4"

  cat >/etc/ipsec.conf <<EOF
config setup
    uniqueids=no

conn ${CONN_NAME}
    auto=start
    type=tunnel
    keyexchange=ikev2
    authby=psk

    left=${left_pub}
    leftsubnet=${left_subnet}

    right=${right_pub}
    rightsubnet=${right_subnet}

    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!

    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
EOF
}

write_ipsec_secrets() {
  local left_pub="$1" right_pub="$2" psk="$3"
  umask 077
  cat >/etc/ipsec.secrets <<EOF
${left_pub} ${right_pub} : PSK "${psk}"
EOF
  chmod 600 /etc/ipsec.secrets
}

restart_strongswan() {
  systemctl enable --now strongswan >/dev/null
  systemctl restart strongswan
}

show_status() {
  echo
  echo "=== strongSwan status ==="
  ipsec statusall || true
  echo "========================="
  echo
  echo "Logs: journalctl -u strongswan -f"
}

main() {
  need_root

  echo "== Atomic StrongSwan S2S installer =="
  echo "This script sets up IKEv2 IPsec tunnel between:"
  echo "  Iran:    ${IRAN_TUN_IP}"
  echo "  Foreign: ${FOREIGN_TUN_IP}"
  echo

  local role=""
  while [[ "$role" != "iran" && "$role" != "foreign" ]]; do
    read -rp "Role of THIS server? (iran/foreign): " role
    role="${role,,}"
  done

  local default_pub; default_pub="$(detect_public_ip)"
  local LEFT_PUB RIGHT_PUB PSK

  prompt LEFT_PUB  "THIS server PUBLIC IP" "${default_pub}"
  prompt RIGHT_PUB "REMOTE server PUBLIC IP" ""
  prompt PSK "PSK (shared secret, same on both servers)" ""

  echo "[+] Installing packages..."
  install_packages

  echo "[+] Enabling IP forward..."
  enable_ip_forward

  echo "[+] Opening firewall (UDP 500/4500)..."
  open_firewall

  if [[ "$role" == "iran" ]]; then
    ensure_lo_ip "${IRAN_TUN_IP}"
    echo "[+] Writing /etc/ipsec.conf (iran -> foreign)..."
    write_ipsec_conf "${LEFT_PUB}" "${RIGHT_PUB}" "${IRAN_TUN_IP}" "${FOREIGN_TUN_IP}"
    echo "[+] Writing /etc/ipsec.secrets ..."
    write_ipsec_secrets "${LEFT_PUB}" "${RIGHT_PUB}" "${PSK}"
  else
    ensure_lo_ip "${FOREIGN_TUN_IP}"
    echo "[+] Writing /etc/ipsec.conf (foreign -> iran)..."
    write_ipsec_conf "${LEFT_PUB}" "${RIGHT_PUB}" "${FOREIGN_TUN_IP}" "${IRAN_TUN_IP}"
    echo "[+] Writing /etc/ipsec.secrets ..."
    write_ipsec_secrets "${LEFT_PUB}" "${RIGHT_PUB}" "${PSK}"
  fi

  echo "[+] Restarting strongSwan..."
  restart_strongswan

  show_status

  echo "[+] Done."
  echo "Test:"
  if [[ "$role" == "iran" ]]; then
    echo "  ping -c 3 10.50.50.2"
  else
    echo "  ping -c 3 10.50.50.1"
  fi
}

main "$@"
