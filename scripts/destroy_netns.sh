#!/bin/bash
#
# A script for teardown the test environment

ip netns exec host1 kill $(cat /var/run/radvd.pid)
ip netns exec host1 \
    ps aux | \
    grep dnsmasq | \
    grep -E "dnsmasq.*gw\.transix\.jp" | \
    awk '{print $2}' | \
    xargs kill

ip netns del host1
ip link del dev veth1
