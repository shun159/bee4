#!/bin/bash
#
# A script for create a test environment

# +-------------------------------+
# |     netns       netns         |
# |   +--------+  +---------+     |
# |   |        |  |         |     |
# |   |  host2 |  |  host3  |     |
# |   |        |  |         |     |
# |   +---+----+  +---------+     |
# |  veth2| .2    veth4| .3       |
# |       |            |          |
# |       |            |          | 
# |  veth3|       veth5|          |
# |       +------------+          |
# |       | 192.168.0.0/24        |
# |       |                       |
# |       |                       |
# |       | .1                    |
# |     +--------+                |
# +---- |        | ---------------+
#       |   B4   | 
#       |        | systemd-networkd
#       +--------+
#   veth1   ||
#           ||
#   veth0   || 2001:db8::1/64
#    +------------+
#    |            | DHCP: dnsmasq
#    |   cpe      | WebServer: python webserver
#    |  host1     | netns
#    +------------+
#   veth6   || 2401:db00::1/64
#           ||
#   veth7   ||
#  +---------------+
#  |               |
#  |   ipip6-br0   | linux bridge
#  |               |
#  +---------------+
#  veth9    ||
#           ||
#           ||
#  veth8    || 2401:db00::3/64
#   +-------------+
#   |             |
#   |    AFTR     | netns
#   |             |
#   +-------------+
#



ip netns add aftr
ip netns add host1 ## provisioning server on PE
ip netns add host2 ## host behind the CPE
ip netns add host3 ## host behind the CPE

ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ip link add veth4 type veth peer name veth5
ip link add veth6 type veth peer name veth7
ip link add veth8 type veth peer name veth9

ip link add ipip6-br0 type bridge
ip link set ipip6-br0 up
ip link set dev ipip6-br0 mtu 1500
ip link set veth7 master ipip6-br0
ip link set veth9 master ipip6-br0

ip link set dev veth1 up
ip link set dev veth3 up
ip link set dev veth5 up
ip link set dev veth7 up
ip link set dev veth9 up

ip link set dev veth5 mtu 1500
ip link set dev veth6 mtu 1500
ip link set dev veth7 mtu 1500

ip link set dev veth0 netns host1
ip link set dev veth6 netns host1
ip link set dev veth2 netns host2
ip link set dev veth4 netns host3
ip link set dev veth8 netns aftr

ip netns exec host1 ip link set dev veth0 up
ip netns exec host1 ip addr add 2001:db8::1/64 dev veth0
ip netns exec host1 ip addr add fe80::1/64 dev veth0
ip netns exec host1 ip link set dev veth6 up
ip netns exec host1 ip addr add 2401:db00::1/64 dev veth6

ip netns exec aftr  ip link set dev veth8 up
ip netns exec aftr  ip addr add 2401:db00::3/64 dev veth8
ip netns exec aftr  ip -6 route add 2001:db8::0/64 via 2401:db00::1
scripts/set-ipip6-remote.py 2001:db8::0/64 2401:db00::3 192.0.2.1 aftr &

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

# https://gist.github.com/lambdalisue/ef78bade10890e754c161220f9f2fcec
# https://zenn.dev/zyun/articles/auto-config-transix-aftr-address
#
# Run dnsmasq as daemon with ra-stateless and ra-names options
#   SLAAC enabled, stateless DHCPv6. 
#   Hosts will get only auto-configured address and get additional configuration from DHCPv6. 
#   DNS will try to guess the auto-configured addresses.
ip netns exec host1 dnsmasq \
    --enable-ra \
    --dhcp-range=::,constructor:veth0,ra-stateless,ra-names \
    --dhcp-option=option6:dns-server,[2001:db8::1] \
    --dhcp-option=option6:ntp-server,[2001:db8::1] \
    --address=/4over6.info/2001:db8::1 \
    --address=/gw.transix.jp/2001:db8::1 \
    --address=/setup46.transix.jp/2001:db8::1 \
    --txt-record=4over6.info,"v=v6mig-1 url=https://setup46.transix.jp/config t=b" \
    --interface=veth0

ip netns exec host1 python scripts/config_server.py&
