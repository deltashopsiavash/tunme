#!/bin/bash

IPSEC_CONF="/etc/ipsec.conf"
IPSEC_SECRETS="/etc/ipsec.secrets"
SYSCTL_CONF="/etc/sysctl.conf"
VTI_SCRIPT="/usr/local/sbin/vti.sh"

read -p "Enter IRAN server IP: " IRAN
read -p "Enter KHAREJ server IP: " KHAREJ

enable_sysctl() {
    grep -q "net.ipv4.ip_forward=1" $SYSCTL_CONF || cat <<EOF >> $SYSCTL_CONF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.vti0.rp_filter=0
EOF
    sysctl -p >/dev/null
}

create_vti_iran() {
cat <<EOF > $VTI_SCRIPT
#!/bin/bash

if ! ip link show vti0 >/dev/null 2>&1; then
    ip link add vti0 type vti local $IRAN remote $KHAREJ key 5
    ip addr add 10.50.50.1/30 dev vti0
    ip link set vti0 mtu 1400
    ip link set vti0 up
fi

ip route replace 10.50.50.2 dev vti0
EOF
chmod +x $VTI_SCRIPT
}

create_vti_kharej() {
cat <<EOF > $VTI_SCRIPT
#!/bin/bash

if ! ip link show vti0 >/dev/null 2>&1; then
    ip link add vti0 type vti local $KHAREJ remote $IRAN key 5
    ip addr add 10.50.50.2/30 dev vti0
    ip link set vti0 mtu 1400
    ip link set vti0 up
fi

ip route replace 10.50.50.1 dev vti0
EOF
chmod +x $VTI_SCRIPT
}

install_iran() {
    enable_sysctl

cat <<EOF > $IPSEC_CONF
config setup
    charondebug="ike 1"

conn vti-tunnel
    auto=start
    type=tunnel
    keyexchange=ikev2
    authby=psk

    left=$IRAN
    leftid=$IRAN
    leftsubnet=10.50.50.1/32

    right=$KHAREJ
    rightid=$KHAREJ
    rightsubnet=10.50.50.2/32

    ike=aes256-sha256-modp2048
    esp=aes256-sha256

    mark=5
    vti-interface=vti0
    vti-routing=no
EOF

cat <<EOF > $IPSEC_SECRETS
$IRAN $KHAREJ : PSK "SuperStrongPassword123!"
EOF

    systemctl restart strongswan-starter
    sleep 2

    create_vti_iran
    bash $VTI_SCRIPT
}

install_kharej() {
    enable_sysctl

cat <<EOF > $IPSEC_CONF
config setup
    charondebug="ike 1"

conn vti-tunnel
    auto=start
    type=tunnel
    keyexchange=ikev2
    authby=psk

    left=$KHAREJ
    leftid=$KHAREJ
    leftsubnet=10.50.50.2/32

    right=$IRAN
    rightid=$IRAN
    rightsubnet=10.50.50.1/32

    ike=aes256-sha256-modp2048
    esp=aes256-sha256

    mark=5
    vti-interface=vti0
    vti-routing=no
EOF

cat <<EOF > $IPSEC_SECRETS
$IRAN $KHAREJ : PSK "SuperStrongPassword123!"
EOF

    systemctl restart strongswan-starter
    sleep 2

    create_vti_kharej
    bash $VTI_SCRIPT
}

restart_services() {
    systemctl restart strongswan-starter
    sleep 2
    [ -f $VTI_SCRIPT ] && bash $VTI_SCRIPT
}

remove_all() {
    rm -f $IPSEC_CONF $IPSEC_SECRETS $VTI_SCRIPT
    ip link del vti0 2>/dev/null
    systemctl restart strongswan-starter
}

add_cron() {
    (crontab -l 2>/dev/null | grep -v "$VTI_SCRIPT"; echo "@reboot bash $VTI_SCRIPT") | crontab -
}

test_tunnel() {
    echo "Testing tunnel connectivity..."
    if ping -c 3 -W 2 10.50.50.2 >/dev/null 2>&1 || ping -c 3 -W 2 10.50.50.1 >/dev/null 2>&1; then
        echo "✅ Tunnel is UP"
    else
        echo "❌ Tunnel is DOWN"
    fi
}

while true; do
echo "---------------------------------"
echo "      VTI Tunnel Manager"
echo "---------------------------------"
echo "1) Install on IRAN server"
echo "2) Install on KHAREJ server"
echo "3) Restart services"
echo "4) Remove all configs"
echo "5) Add CronJob (auto start)"
echo "6) Test tunnel connectivity"
echo "0) Exit"
echo "---------------------------------"
read -p "Select option: " opt

case $opt in
    1) install_iran ;;
    2) install_kharej ;;
    3) restart_services ;;
    4) remove_all ;;
    5) add_cron ;;
    6) test_tunnel ;;
    0) exit ;;
    *) echo "Invalid option" ;;
esac
done
