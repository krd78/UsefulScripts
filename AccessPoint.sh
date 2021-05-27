#!/bin/bash

delete_mon() {
	err="0"
	i=0
	while [ "$err" == "0" ]; do
        	echo "Deleting mon$i"
	        iw dev mon"$i" del
	        err="$?"
	        i=`bc <<< $i+1`
	done
}

mac_choice() {
        echo
	vendor_mac=([0]="00:00:00" [1]="00:0F:4F" [2]="00:23:D3"\
                    [3]="50:6F:9A" [4]="DC:86:D8" [5]="00:C0:4F"  \
                    [6]="00:A0:BF" [7]="58:94:6B" [8]="00:8E:F2"\
                    [9]="00:18:02")							
	vendor_nam=([0]="None" [1]="Cadmus" [2]="AirLink" [3]="Wi-FiAlliance"\
   		    [4]="Apple" [5]="Dell" [6]="Motorola" [7]="Intel"	     \
	            [8]="Netgear" [9]="AlphaNetwork")
	echo
	echo "++  MAC CONFIGURATION  ++"
	echo "+ Manufacturer list:"
	c=0
	for vend in ${vendor_nam[*]}; do
		echo "$c = $vend"
		c=$(expr $c + 1)
	done
	read -p "*Vendor: n°" v
	r=255
	o1=$RANDOM
	o2=$RANDOM
	o3=$RANDOM	
	mac="${vendor_mac[$v]}:"
	let "o1 %= 255"
        [ $o1 -lt 15 ] && o1=$o1+15
	let "o2 %= 255"
        [ $o2 -lt 15 ] && o2=$o2+15
	let "o3 %= 255"
        [ $o3 -lt 15 ] && o3=$o3+15
	m1=$(echo "obase=16;$o1" | bc)
	m2=$(echo "obase=16;$o2" | bc)
	m3=$(echo "obase=16;$o3" | bc)
	MAC="${vendor_mac[$v]}:$m1:$m2:$m3"
	set -x
	ip link set $iface address $MAC
	set +x
}

dhcp_info() {
	echo
	echo "++  DHCP CONFIGURATION  ++"
	d=$(cat /etc/resolv.conf | grep nameserver | \
                awk '{split($0, a, " "); print a[2]}')
        f_hosts=/tmp/hosts.dnsmasq
        #echo "$ip akira" > $f_hosts
	echo
	echo "+ DNS configured: $d"
	read -p "*DNS: " dns
	g=$(ip route | grep default | awk '{print $3}')
	echo
	#echo "+ GATEWAY configure: $g" 
	#read -p "*GW: " gw
	#echo
	echo "+ RANGE:"
	read -p "*1st: " first
	read -p "*Last: " last
	echo
	read -p "+ FORWARD(iface): " fwd
	######	DHCPD	######
#	echo "
#default-lease-time 600;
#max-lease-time 7200;
#option routers $gw;
#option domain-name-servers 8.8.8.8, 4.4.4.4;
#subnet $subnet netmask $netmask {
#option routers $ip;
#option domain-name-servers 8.8.8.8, 4.4.4.4;
#range $first $last;
#}" > $dhcp_file
	######	DNSMASQ	######
	echo
	echo "
interface=$iface
no-resolv
no-hosts
#addn-hosts=$f_hosts
dhcp-range=$first,$last,$netmask,12h
dhcp-authoritative
dhcp-option=1,$netmask
#cache-size=0
#bogus-priv
#alias=$ip,$gw
dhcp-option=6,$dns,8.8.8.8
" > $dhcp_file
}

netrules() {
        echo
	dhcp_file="/etc/dhcp/dhcpd.conf"
	read -p "+ CIDR (8->32): " cidr
	if [ "$apd" == "2" ]; then
		iface="at0"
		ip a add $ip/$cidr dev $iface
		#ip route add $subnet$submask via $ip
		echo "+ Airbase technique used."
	fi
	if [ "$apd" == "1" ]; then
		ip a add $ip/$cidr dev $iface
	fi
	set -x
	iptables -t nat -F
        iptables -t nat -X
	iptables -t nat -A POSTROUTING -o "$fwd" -j MASQUERADE
	iptables -A FORWARD -i $iface -o "$fwd" -j ACCEPT
	iptables -A FORWARD -d $subnet -i "$fwd" -o "$iface" -j ACCEPT
        #iptables -A FORWARD -p udp -i "$fwd" -d "$subnet" -j DROP
	#iptables -t nat -A PREROUTING -s "$subnet" -p udp --dport 53 \
        #         -j DNAT --to $dns
	set +x
	echo
	echo "+ Net rules fixed."
	verif=`cat /proc/sys/net/ipv4/ip_forward`
	if [ "$verif" == "1" ]; then
	        echo "+ Forwarding already enabled."
	else
		echo "- Forwarding disabled..."
	        echo 1 > /proc/sys/net/ipv4/ip_forward
	        echo "+ Forwarding has been enabled."
	fi
#	dhcpd -d -f -cf "$dhcp_file" -pf /var/run/dhcp-server/dhcpd.pid \
#		  -p 65530 $iface &
	#echo "interface=$iface" >> $dhcp_file
        set -x
	dnsmasq -q -d -p 5353 -C $dhcp_file >> /var/log/dnsmasq.log &
        set +x
	sleep 3
	dhcp_id=`pidof dnsmasq`
	echo "+ DHCP server started with PID $dhcp_id."
	echo ""
}

air() {
	airmon-ng start "$iface"
	modprobe tun
        echo "+ Needed: airodump-ng mon0"
        read -p "BSSID : " bssid
        if [ "$q" == "0" ]; then
			read -p "WEP KEY : " wkey
		fi
		if [ "$bssid" == "" ]; then
			airbase-ng -P -C 30 -i $iface -e "$ssid" -w "$wkey" \
				   -c $channel -F "$ssid"_beacons mon0 &
			airb_pid="$!"
		else
          	airbase-ng -P -C 30 -i $iface -e "$ssid" -a $bssid -w "$wkey" \
				    -c $channel -F "$ssid"_beacons mon0 &
			airb_pid="$!"
		fi
        if [ "$q" == "1" ]; then
                read -p "+WPA Pairwise :
                         1 = WPA-WEP40
                         2 = WPA-TKIP
                         3 = WPA-WRAP
                         4 = WPA-CCMP
                         5 = WPA-WEP104
* Choice : " q1
        fi
		if [ "$bssid" == "" ]; then
	            airbase-ng -P -C 30 -i $iface  -e "$ssid" -z $q1 \
                                -c $channel -F "$ssid"_beacons mon0 &
		else
		    airbase-ng -P -C 30 -i $iface  -e "$ssid" -a $bssid \
                                -z $q1 -c $channel -F "$ssid"_beacons mon0 &
		fi
        if [ "$q" == "2" ]; then
                read -p "+ WPA2 pairwise :
                         1 = WPA2-WEP40
                         2 = WPA2-TKIP
                         3 = WPA2-WRAP
                         4 = WPA2-CCMP
                         5 = WPA2-WEP104
* Choice : " q1
    	fi
		if [ "$bssid" == "" ]; then
		    airbase-ng -P -C 30 -i $iface  -e "$ssid" -Z $q1 \
                                  -c $channel -F "$ssid"_beacons mon0 &
		else
         	    airbase-ng -P -C 30 -i $iface  -e "$ssid" -a $bssid -Z $q1\
                                  -c $channel -F "$ssid"_beacons mon0 & 
		fi
	sleep 3
	echo
	airb_pid=`pidof airbase-ng -P`
	echo "+ Airbase-ng started with PID $airb_pid."
	echo
}

host() {
	echo
	echo "++  HOSTAPD CONFIGURATION  ++"
	if [ "$q" == "1" -o "$q" == "2" ]; then
		read -p "
+ WPA Pairwise :        WEP40
                        TKIP
                        WRAP
                        CCMP
                        WEP104
                        TKIP CCMP
*WPA-" q1
		read -sp "+ PSK needed (8-64 chars): " psk
		cat > $hostapd << EOF
interface=$iface
#driver=nl80211
ssid=$ssid
hw_mode=n
channel=$channel
auth_algs=3
wpa=$q
wpa_key_mgmt=WPA-PSK
#wpa_pairwise=$q1
rsn_pairwise=$q1
wpa_passphrase=$psk
ieee80211n=1
wmm_enabled=1
#macaddr_acl=0
EOF
	fi
	if [ "$q" == "0" ]; then
		read -p "WEP key needed (5, 13, or 16 characters): " wep
		echo "wep_default_key=$wep" >> "$hostapd"
	fi
	hostapd -B -d "$hostapd"
	hap_pid=`pidof hostapd`
	echo
	echo "+ Hostapd started with PID $hap_pid"
	echo
}

helper() {
    cat << EOF
$0 <OPTIONS>

OPTIONS:
    -i  or  --interface         Define the interface to use.
    -a  or  --address           IP address of this AP.
    -e  or  --essid             ESSID of this AP.
    -n  or  --netmask           Netmask of the managed network.
    -c  or  --channel           Channel to use for this AP.
    -h  or  --help              This help menu.
EOF
    exit 0
}


dhcp_file="/etc/dhcp/dhcpd.conf"
hostapd="/etc/hostapd/tmp.conf"

killall dnsmasq && killall hostapd
echo ""
if [ -z "$1" ]; then
    ip link
    echo ""
    echo "- "${error}""
    echo ""
    read -p "Interface : " iface
    read -p "IP Adress : " ip
    read -p "ESSID : " ssid
    read -p "Netmask : " netmask
    read -p "Channel : " channel
fi
while [ "$1" != "" ]; do
    case $1 in
	-i|--interface)
	    iface="$2"
	;;
	-a|--address)
	    ip="$2"
	;;
	-e|--essid)
	    ssid="$2"
	;;
	-n|--netmask)
	    netmask="$2"
	;;
	-c|--channel)
	    channel="$2"
	;;
	-h|--help)
	    helper
	;;
    esac
    shift; shift
done
delete_mon
dhcp_info
read -p "+ Technique to use :
1 = Hostapd
2 = Airbase-ng ?
* Choice : " apd
echo ""
read -p "+ Security to use :
0 = WEP
1 = WPA
2 = WPA2
* Choice : " q
if [ "$apd" == "2" ]; then
	iface="at0"
	air
	netrules
fi
if [ "$apd" == "1" ]; then
        mac_choice
	host
	netrules
fi
while true; do
	read -p "
	0 = STOP
	1 = TCPDUMP
	" end
	if [ "$end" == "0" ]; then
		if [ -z "$airb_pid" ]; then
			for pid in $hap_pid; do
				echo "+ Killing $pid and $dhcp_id..."
				ip a del $ip/$cidr dev $iface
				#ifconfig $iface down
				kill -9 $pid $dhcp_id
			done
		fi
		if [ -z "$hap_pid" ]; then
			for pid in $airb_pid; do
				echo "+ Killing $pid and $dhcp_id..."
				kill -9 $pid $dhcp_id
				ip a del $ip/$cidr $dev $iface
				iw dev mon.$iface del
				delete_mon
			done
		fi
		set -x
#		ip route del $subnet$submask via "$ip" dev "$fwd"
#	        ip route del "$gw" via "$fwd_ip" dev "$iface"
		iptables -t nat -F
		iptables -t nat -X
		iptables -F
		iptables -X
		set +x
		exit 0
	fi
	if [ "$end" == "1" ]; then
		tcpdump -ni $iface -vv -w /tmp/"$ssid"_sniff.cap 
	fi
done
