#!/bin/bash
#
# A script for create a test environment

ip netns add host1 ## provisioning server on PE
ip netns add host2 ## host behind the CPE
ip netns add host3 ## host behind the CPE
#ip netns add host3 ## the PE router (the AFTR)



ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ip link add veth4 type veth peer name veth5
#ip link add veth6 type veth peer name veth7

ip link set dev veth1 up
ip link set dev veth3 up
ip link set dev veth5 up

#ip link set dev veth5 mtu 1500
#ip link set dev veth6 up
#ip link set dev veth6 mtu 1500
#ip link set dev veth7 up
#ip link set dev veth7 mtu 1500

#ip link add br-ip6tnl type bridge
#ip link set br-ip6tnl up
#ip link set dev br-ip6tnl mtu 1500
#ip link set veth1 master br-ip6tnl
#ip link set veth5 master br-ip6tnl
#ip link set veth7 master br-ip6tnl

ip link set dev veth0 netns host1
ip link set dev veth2 netns host2
ip link set dev veth4 netns host3

ip netns exec host1 ip link set dev veth0 up
ip netns exec host1 ip addr add 2001:db8::1/64 dev veth0
ip netns exec host1 ip addr add fe80::1/64 dev veth0

ip netns exec host2 ip link set dev veth2 up
ip netns exec host2 ip addr add 192.168.0.2/24 dev veth2
ip netns exec host2 ip route add default via 192.168.0.1

ip netns exec host3 ip link set dev veth4 up
ip netns exec host3 ip addr add 192.168.0.3/24 dev veth4
ip netns exec host3 ip route add default via 192.168.0.1

#ip netns exec host3 ip addr add 172.16.1.100/24 dev veth4
#ip netns exec host3 ip addr add 2001:db8::2/64 dev veth4 nodad
#ip netns exec host3 ip link set dev veth4 up
#ip netns exec host3 \
#		ip link add dev ip6tnl \
#        type ip6tnl \
#        mode ip6ip6 \
#        local  2001:db8::2 \
#        remote 2001:db8::200:ff:fe01:20\
#ip netns exec host3 ip link set dev ip6tnl up
#ip netns exec host3 ip addr add dev ip6tnl 2601:646::1/64
#ip netns exec host3 ip route add default dev ip6tnl
#
ip netns exec host1 sysctl -w net.ipv6.conf.all.forwarding=1

#ip netns exec host1 cat <<'EOS' > /tmp/radvd.conf
#interface veth0 {
#
#    # Send Route Advertisement periodically
#    AdvSendAdvert on;
#
#    # Advertise a prefix used for generate an address with SLAAC
#    prefix 2001:db8::/64 { };
#
#    # Advertise the DNS server with RDNSS (RFC 8106)
#    RDNSS 2001:db8::1 { };
#};
#EOS
#ip netns exec host1 radvd -C /tmp/radvd.conf
#

ip netns exec host1 dnsmasq \
    --enable-ra \
    --dhcp-range=::,constructor:veth0,ra-stateless \
    --dhcp-option=option6:dns-server,[2001:db8::1]  \
    --dhcp-option=option6:ntp-server,[2001:db8::1]  \
    --address=/4over6.info/2001:db8::1 \
    --address=/gw.transix.jp/2001:db8::1 \
    --address=/setup46.transix.jp/2001:db8::1 \
    --txt-record=4over6.info,"v=v6mig-1 url=https://setup46.transix.jp/config t=b" \
    --interface=veth0 #\
#    --no-daemon
