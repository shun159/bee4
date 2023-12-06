#!/usr/bin/env python

import time
import sys
import os

import ipaddress
import netifaces as ni

b4_tun_iface = 'dslite0'
ip6tnl_dev = 'ipip-std'
ip6tnl_remote = None
ip6tnl_local = sys.argv[2]
ip6tnl_subnet = ipaddress.IPv6Network(sys.argv[1])
aftr_netns = sys.argv[4]
inner_ip4_addr = sys.argv[3]

netns_cmd_str = "ip netns exec %s " % aftr_netns
ipip6_add_cmd_str = "ip link add dev %(dev)s type ip6tnl mode ipip6 local %(local)s remote %(remote)s"
ipip6_del_cmd_str = "ip link del dev %(dev)s"
ipip6_dev_up_cmd = "ip link set dev %(dev)s up"
ipip6_inner_set_cmd = "ip addr add dev %(dev)s %(addr)s"
ipip6_def_route_cmd = "ip route add 0.0.0.0 dev %(dev)s"


def netns_cmd(cmd, **kwargs):
    cmd_str = netns_cmd_str + cmd % kwargs
    os.system(cmd_str)


def enable_ipip6_dev():
    netns_cmd(ipip6_dev_up_cmd, dev=ip6tnl_dev)


def add_route_ipip6_dev():
    netns_cmd(ipip6_def_route_cmd, dev=ip6tnl_dev)


def del_ip6tnl():
    netns_cmd(ipip6_del_cmd_str, dev=ip6tnl_dev)


def set_inner():
    netns_cmd(
        ipip6_inner_set_cmd,
        dev=ip6tnl_dev,
        addr=inner_ip4_addr,
    )


def add_ip6tnl():
    netns_cmd(
        ipip6_add_cmd_str,
        dev=ip6tnl_dev,
        local=ip6tnl_local,
        remote=ip6tnl_remote,
    )


def set_ip6tnl(new_remote):
    global ip6tnl_remote

    if ip6tnl_remote == new_remote:
        return

    ip6tnl_remote = ifaddr['addr']
    del_ip6tnl()
    add_ip6tnl()
    enable_ipip6_dev()
    set_inner()
    add_route_ipip6_dev()


while True:
    try:
        ifaddrs = ni.ifaddresses(b4_tun_iface)[ni.AF_INET6]
        for ifaddr in ifaddrs:
            if ipaddress.ip_address(ifaddr['addr']) in ip6tnl_subnet:
                set_ip6tnl(ifaddr['addr'])
    except:
        pass

    time.sleep(3)
