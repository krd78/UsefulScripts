#!/bin/bash

[ -n "$IFACE_ETH" ] || IFACE_ETH=eth0
# Personnalize these names
IFACE_BR=mybr0
IFACE_TAP=mytap0
# Precised if necessary in args
SCRIPT_OWNER="$USER"

# Help for usage
usage()
{
    cat << EOF
Usage:
    $0 --install --user <$IFACE_TAP interface owner>
    $0 --remove
Options:
    -h or --help        show this help
    -u or --user        create the tun/tap interface with this user rights
    -i or --install     make an environement installing
    -r or --remove      make an environment removing
Default values:
    main interface       $IFACE_ETH
    tun/tap interface   $IFACE_TAP
    bridge interface    $IFACE_BR
EOF
}

fail()
{
    EXIT_MSG="$1"
    EXIT_CODE="$2"

    cat << EOF
[*] +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[*] Fatal error: "$EXIT_MSG" !!!
[*] +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
EOF

    [ -n "$EXIT_CODE" ] || EXIT_CODE=1
    exit $EXIT_CODE
}


is_network_env_installed()
{
    THIS_SCRIPT=$(basename $0)
    IFACE="$1"
    ip link show $IFACE
    ETH_ERR="$?"
    [ "$ETH_ERR" = "0" ] || fail "$IFACE does not exist... Fix the name manually in the script $THIS_SCRIPT."
    ip route | grep $IFACE | grep default
    ROUTE_ERR="$?"
    [ "$ROUTE_ERR" = "0" ] || fail "$IFACE is not your default route... Fix it in the script: ${THIS_SCRIPT}. IFACE_ETH for installing, and IFACE_BR for removing."
}

# Uninstall network environment
remove()
{
    ADDR_GW=$(ip r | grep $IFACE_BR | grep default | cut -d" " -f3)
    ADDR_SUBNET=$(ip r | grep $IFACE_BR | grep -v default | cut -d" " -f1)

    ip route flush dev $IFACE_BR
    ip link set dev $IFACE_TAP down
    ip link set dev $IFACE_BR down
    ifdown $IFACE_ETH
    brctl delbr $IFACE_BR
    tunctl -d $IFACE_TAP
    ifup -v $IFACE_ETH
 
    rm -f /etc/network/interfaces.d/$IFACE_BR || true
    set -x

    if ! ip r | grep default; then
        # Route deletement (to reset it)
        ip route add $ADDR_SUBNET dev $IFACE_ETH
        ip route add default dev $IFACE_ETH via $ADDR_GW
    fi

    set +x
}

# Install network environment
install()
{
    echo "[*] Run as ${SCRIPT_OWNER}..."
    ADDR_GW=$(ip r | grep $IFACE_ETH | grep default | cut -d" " -f3)
    ADDR_SUBNET=$(ip r | grep $IFACE_ETH | grep -v default | cut -d" " -f1)
    ADDR_MAC_ETH=$(ip link | grep -n1 $IFACE_ETH | grep link/ether | awk '{print $3}')

    tunctl -t $IFACE_TAP -u $SCRIPT_OWNER
    if ! grep -Rq "iface $IFACE_BR" /etc/network/interfaces* ; then
        cat << EOF > /etc/network/interfaces.d/$IFACE_BR
auto $IFACE_BR
iface $IFACE_BR inet dhcp
    pre-up tunctl -t $IFACE_TAP -u $SCRIPT_OWNER
    bridge_ports $IFACE_ETH $IFACE_TAP
    bridge_stp off
EOF
    fi

    brctl addbr $IFACE_BR
    ip link set $IFACE_BR address $ADDR_MAC_ETH
    ip link set dev $IFACE_TAP up
    brctl addif $IFACE_BR eth0 $IFACE_TAP
    ifup -v $IFACE_BR # = ip link set dev br0 up; dhclient -v $IFACE_BR

    set -x

    # Route configuration (flushing and creating for bridge)
    if ip r | egrep -q "dev $IFACE_ETH " ; then
        ip route flush dev $IFACE_ETH
    fi
    ip r | egrep -q "^$ADDR_SUBNET dev $IFACE_BR " || ip route add $ADDR_SUBNET dev $IFACE_BR
    ip r | egrep -q "^default via $ADDR_GW dev $IFACE_BR $" || ip route add default dev $IFACE_BR via $ADDR_GW

    set +x

    ip r
    ADDR_IFACE_BR=$(ip a show dev $IFACE_BR | grep "inet " | awk '{print $2}')
    ADDR_IFACE_ETH=$(ip a show dev $IFACE_ETH | grep "inet " | awk '{print $2}')

    #[ "$ADDR_IFACE_BR" != "$ADDR_IFACE_ETH" ] && echo "[*] Error: $IFACE_BR and $IFACE_ETH don't have the same address." && remove
}

# Argument parsing
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
        ;;
        -i|--install)
            is_network_env_installed "$IFACE_ETH"
            EXEC_QUEUE=install
        ;;
        -r|--remove)
            is_network_env_installed "$IFACE_BR"
            EXEC_QUEUE=remove
        ;;
        -u|--user)
            SCRIPT_OWNER="$2"
            shift
        ;;
        *)
            usage
        ;;  
    esac
    shift
done


which brctl > /dev/null || fail "brctl is not present! install it with bridge-utils..."
which tunctl > /dev/null || fail "tunctl is not present! install it with uml-utilities..."
grep -q interfaces.d /etc/network/interfaces || fail "interfaces.d is not sourced by your interfaces file! Add 'source-directory interfaces.d' line in your /etc/network/interfaces file..."

$EXEC_QUEUE
