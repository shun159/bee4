/* Copyright (C) 2022-present, Eishun Kondoh <dreamdiagnosis@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU GPL as published by
 * the FSF; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_kfuncs.h"
#include "datapath_helpers.h"
#include "datapath_maps.h"
#include "datapath_slow.h"

// Reduces packet size to the minimum, preparing the packet buffer for new data.
// This is typically used before constructing new packet contents.
static __always_inline int
shrink_packet_to_zero(struct xdp_md *ctx)
{
    __u32 data_len = ctx->data_end - ctx->data;
    return bpf_xdp_adjust_tail(ctx, 42 - data_len);
}

// Prepares and sends an ARP request or reply based on provided parameters.
// Constructs the ARP packet by setting the Ethernet and ARP headers.
static __always_inline int
send_arp(struct packet *pkt, struct port_conf *port, __u8 target_mac[6], __u32 target_ip,
         __u16 op_code)
{
    __u32 offset = 0;
    __u8 ar_sha[6];
    __u32 ar_spa = port->in4addr;
    memcpy(ar_sha, port->macaddr, sizeof(ar_sha));

    if (shrink_packet_to_zero(pkt->ctx))
        return -1;

    if (set_ethernet(pkt->ptr, &offset, target_mac, port->macaddr, ETH_P_ARP))
        return -1;

    if (op_code == ARPOP_REQUEST) {
        __u8 ar_tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (write_arp_to_ctx(pkt->ctx, pkt->ptr, &offset, op_code, ar_sha, ar_spa, ar_tha,
                             target_ip))
            return -1;
    }

    return 0;
}

// Broadcasts an ARP request to all nodes in the local network to resolve an IP
// address. This is used to find the MAC address corresponding to a given IP
// address.
static __always_inline int
broadcast_arp_request(struct packet *pkt)
{
    struct port_conf *port = get_port_conf(1);
    if (!port) {
        bpf_printk("failed to get port config for sending broadcast arp req");
        return -1;
    }

    __u8 daddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    __u32 ar_tpa = pkt->inner_in4->daddr;

    if (send_arp(pkt, port, daddr, ar_tpa, ARPOP_REQUEST))
        return -1;

    pkt->egress_ifindex = EGRESS_BR_FLOOD;

    return 0;
}

// Processes an incoming ARP request and sends an ARP reply if the target IP
// address matches the local port's configured IP address.
static __always_inline int
process_bridge_arp_request(struct packet *pkt, __u8 ar_sha[6], __u32 ar_spa, __u32 ar_tpa)
{
    if (ar_tpa != pkt->ingress_port->in4addr) {
        pkt->egress_ifindex = EGRESS_BR_FLOOD;
        return 0;
    }
    pkt->egress_ifindex = EGRESS_SLOW_PATH;

    return 0;
}

// Main function for ARP processing that routes to specific functions for
// handling ARP requests and replies based on the operation code.
static __always_inline int
process_bridge_arp(struct packet *pkt)
{
    struct arphdr arphdr;
    int ret;

    __u8 ar_sha[6], ar_tha[6];
    __u16 ar_op;
    __u32 ar_spa, ar_tpa;

    if (parse_arp(pkt->ptr, pkt->offset, &arphdr, ar_sha, &ar_spa, ar_tha, &ar_tpa))
        ret = -1;

    if (bpf_ntohs(arphdr.ar_pro) != ETH_P_IP)
        return -1;

    ar_op = bpf_ntohs(arphdr.ar_op);
    switch (ar_op) {
    case ARPOP_REPLY:
        ret = put_arp_entry(ar_sha, ar_spa, pkt->ctx->ingress_ifindex);
        pkt->egress_ifindex = EGRESS_SLOW_PATH;
        break;
    case ARPOP_REQUEST:
        ret = process_bridge_arp_request(pkt, ar_sha, ar_spa, ar_tpa);
        break;
    default:
        bpf_printk("arp: unsupported op: %d received", ar_op);
        ret = -1;
    }

    return ret;
}

static __always_inline int
process_bridge_in4(struct packet *pkt)
{
    struct iphdr iph;
    struct port_conf *port;
    struct lpm_nh_in4 *nh_in4;

    if (parse_ipv4(pkt->ptr, pkt->offset, &iph))
        return -1;

    port = get_port_conf(1);
    if (!port) {
        bpf_printk("failed to get port config for process IPv4 packet");
        return -1;
    }

    if (port->in4addr == iph.daddr) {
        // TODO: Add handler for a packet that destine to slowpath.
        pkt->egress_ifindex = EGRESS_SLOW_PATH;
        return 0;
    }

    // lookup a route for packet that through this router from a local interface
    nh_in4 = get_route_in4(iph.daddr);
    if (!nh_in4)
        // TODO: Add handler for a packet that destine to internet.
        return -1;
    // TODO: Add handler for local packet

    return 0;
}

// Determines the next hop based on IPv4 routing and sets the packet's Ethernet
// header for the next hop. If no entry is found in the ARP table, initiates ARP
// resolution.
static __always_inline int
uplink_set_in4_neigh(struct packet *pkt)
{
    struct lpm_nh_in4 *nh;
    struct arp_entry *neigh;
    struct port_conf *port;
    struct ethhdr *ethhdr;

    __u32 offset = 0;
    __u32 neigh_key;
    __u32 egress_ifindex;
    __u32 daddr = pkt->inner_in4->daddr;

    nh = get_route_in4(daddr);
    if (!nh) {
        bpf_printk("uplink_set_in4_neigh: route_table lookup failed for ip %u\n", daddr);
        return -1;
    }

    if (nh->nh_type == NH_LOCAL)
        neigh_key = daddr;
    else if (nh->nh_type == NH_REMOTE)
        neigh_key = nh->addr;
    else
        return -1;

    neigh = bpf_map_lookup_elem(&arp_table, &neigh_key);
    if (!neigh)
        return broadcast_arp_request(pkt);

    egress_ifindex = neigh->port_no;
    port = bpf_map_lookup_elem(&port_config, &egress_ifindex);
    if (!port) {
        bpf_printk(
            "uplink_set_in4_neigh: port_config lookup failed for egress_ifindex %u\n",
            egress_ifindex);
        return -1;
    }

    if (set_ethernet(pkt->ptr, &offset, neigh->macaddr, port->macaddr, ETH_P_IP))
        return -1;

    pkt->egress_ifindex = neigh->port_no;

    return 0;
}

// Removes the IPv6 encapsulation from a packet, revealing the inner IPv4
// packet. Used when the uplink receives an encapsulated IPv4 packet within an
// IPv6 packet.
static __always_inline int
uplink_in6_decap(struct packet *pkt)
{
    struct iphdr iph;

    // Trim outer in6 and ether header.
    bpf_xdp_adjust_head(pkt->ctx, *pkt->offset);
    // Reset offset to point inner header.
    *pkt->offset = 0;
    if (parse_ipv4(pkt->ptr, pkt->offset, &iph))
        return -1;

    pkt->inner_in4 = &iph;

    return 0;
}

static __always_inline int
process_bridge_l3(struct packet *pkt)
{
    int ret;

    switch (pkt->l3_proto) {
    case ETH_P_ARP:
        ret = process_bridge_arp(pkt);
        break;
    case ETH_P_IP:
        ret = process_bridge_in4(pkt);
        break;
    case ETH_P_IPV6:
        return 0;
    default:
        // unsupported protocol
        return -1;
    }

    return ret;
}

static __always_inline int
process_uplink_l3(struct packet *pkt)
{
    struct ipv6hdr ip6hdr;

    if (pkt->l3_proto != ETH_P_IPV6)
        return -1;
    if (parse_ipv6(pkt->ptr, pkt->offset, &ip6hdr, &pkt->l4_proto, &pkt->is_frag))
        return -1;

    pkt->in6 = &ip6hdr;
    pkt->should_be_encaped = pkt->l4_proto == IPPROTO_IPIP;

    if (pkt->should_be_encaped) {
        if (uplink_in6_decap(pkt))
            return -1;
        if (push_ethernet(pkt->ptr, pkt->ctx, ETH_P_IP))
            return -1;
    }

    if (pkt->should_be_encaped)
        uplink_set_in4_neigh(pkt);

    return 0;
}

static __always_inline int
process_l2(struct packet *pkt)
{
    struct ethhdr ethhdr;

    if (parse_ethernet(pkt->ptr, pkt->offset, &ethhdr))
        return -1;

    pkt->eth = &ethhdr;
    pkt->l3_proto = bpf_ntohs(ethhdr.h_proto);
    if (put_fdb_entry(ethhdr.h_source, pkt->ingress_ifindex))
        return -1;

    pkt->is_mac_bmcast = IS_MAC_BMCAST(ethhdr.h_dest);
    pkt->is_mac_self = MAC_CMP(ethhdr.h_dest, pkt->ingress_port->macaddr);

    return 0;
}

static __always_inline int
process_forward(struct packet *pkt)
{
    int ret;

    if (pkt->egress_ifindex == EGRESS_BR_FLOOD) {
        __u64 f = BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS;
        bpf_redirect_map(&tx_port, 0, f);
        ret = XDP_REDIRECT;
    } else if (pkt->egress_ifindex == EGRESS_SLOW_PATH) {
        ret = XDP_PASS;
    } else if (pkt->ctx->ingress_ifindex == pkt->egress_ifindex) {
        ret = XDP_TX;
    } else if (pkt->egress_ifindex > 0) {
        bpf_redirect_map(&tx_port, pkt->egress_ifindex, BPF_F_EXCLUDE_INGRESS);
        ret = XDP_REDIRECT;
    } else {
        // shouldn't be happen
        ret = XDP_DROP;
    }

    return ret;
}

static __always_inline int
process_bridge_local_l2(struct packet *pkt)
{
    struct fdb_entry *e;

    e = get_fdb_entry(pkt->eth->h_dest);
    if (!e) {
        pkt->egress_ifindex = EGRESS_BR_FLOOD;
        return 0;
    }
    pkt->egress_ifindex = e->port_no;
    return 0;
}

static __always_inline int
process_uplink_packet(struct packet *pkt)
{
    struct fdb_entry *fdb;

    if (process_l2(pkt))
        return -1;
    if (process_uplink_l3(pkt))
        return -1;

    return 0;
}

static __always_inline int
process_bridge_packet(struct packet *pkt)
{
    if (process_l2(pkt))
        return -1;

    if (!(pkt->is_mac_bmcast || pkt->is_mac_self))
        // TODO: handle bridging packet
        return process_bridge_local_l2(pkt);

    if (process_bridge_l3(pkt))
        return -1;

    return 0;
}

// BPF programs

// XDP program entry point for packets arriving on the bridge interface.
// It processes packets at layer 2, layer 3, and determines their forwarding.
SEC("xdp")
int
xdp_bridge_in(struct xdp_md *ctx)
{
    struct packet pkt = {0};
    struct bpf_dynptr ptr;
    struct port_conf *port;

    __u64 offset = 0;
    int ret;

    pkt.ctx = ctx;
    pkt.offset = &offset;
    pkt.ptr = &ptr;

    port = get_port_conf(1);
    if (!port)
        return XDP_DROP;

    pkt.ingress_ifindex = ctx->ingress_ifindex;
    pkt.ingress_port = port;

    if (bpf_dynptr_from_xdp(ctx, 0, pkt.ptr))
        return XDP_DROP;
    if (process_bridge_packet(&pkt))
        return XDP_DROP;

    ret = process_forward(&pkt);
    return ret;
}

// XDP program entry point for packets arriving on the uplink interface.
// It processes packets at layer 2, layer 3, and determines their forwarding.
SEC("xdp")
int
xdp_uplink_in(struct xdp_md *ctx)
{
    struct packet pkt = {0};
    struct bpf_dynptr ptr;
    struct port_conf *port;

    __u64 offset = 0;
    int ret;

    pkt.ctx = ctx;
    pkt.offset = &offset;
    pkt.ptr = &ptr;

    port = get_port_conf(2);
    if (!port)
        return XDP_DROP;

    pkt.ingress_ifindex = ctx->ingress_ifindex;
    pkt.ingress_port = port;

    if (bpf_dynptr_from_xdp(ctx, 0, pkt.ptr))
        return XDP_DROP;
    if (process_uplink_packet(&pkt))
        return XDP_DROP;

    ret = process_forward(&pkt);
    return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
