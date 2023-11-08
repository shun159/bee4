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

// Retrieves port configuration data from eBPF maps using a given port key.
// Returns NULL if the port configuration is not found.
static __always_inline struct port_conf *get_port_conf(__u32 port_key)
{
	__u32 *pkt_ifidx = bpf_map_lookup_elem(&l3_port_map, &port_key);
	if (!pkt_ifidx) {
		bpf_printk("get_port_conf: l3_port_map lookup failed for port_key %u\n", port_key);
		return NULL;
	}

	struct port_conf *port = bpf_map_lookup_elem(&port_config, pkt_ifidx);
	if (!port) {
		bpf_printk("get_port_conf: port_config lookup failed for ifidx %u\n", *pkt_ifidx);
	}

	return port;
}

// Reduces packet size to the minimum, preparing the packet buffer for new data.
// This is typically used before constructing new packet contents.
static __always_inline int shrink_packet_to_zero(struct xdp_md *ctx)
{
	__u32 data_len = ctx->data_end - ctx->data;
	return bpf_xdp_adjust_tail(ctx, 42 - data_len);
}

// Prepares and sends an ARP request or reply based on provided parameters.
// Constructs the ARP packet by setting the Ethernet and ARP headers.
static __always_inline int send_arp(struct packet *pkt, struct port_conf *port, __u8 target_mac[6],
				    __u32 target_ip, __u16 op_code)
{
	__u32 offset = 0;
	__u8 ar_sha[6];
	__u32 ar_spa = port->in4addr;
	memcpy(ar_sha, port->macaddr, sizeof(ar_sha));

	if (shrink_packet_to_zero(pkt->ctx))
		return -1;

	if (write_ethernet_to_ctx(pkt->ptr, &offset, target_mac, port->macaddr, ETH_P_ARP))
		return -1;

	if (op_code == ARPOP_REQUEST) {
		__u8 ar_tha[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		if (write_arp_to_ctx(pkt->ctx, pkt->ptr, &offset, op_code, ar_sha, ar_spa, ar_tha,
				     target_ip))
			return -1;
	} else if (op_code == ARPOP_REPLY) {
		if (write_arp_to_ctx(pkt->ctx, pkt->ptr, &offset, op_code, ar_sha, port->in4addr,
				     target_mac, target_ip))
			return -1;
	}

	return 0;
}

// Broadcasts an ARP request to all nodes in the local network to resolve an IP address.
// This is used to find the MAC address corresponding to a given IP address.
static __always_inline int broadcast_arp_request(struct packet *pkt)
{
	struct port_conf *port = get_port_conf(1);
	if (!port) {
		bpf_printk("failed to get port config for sending broadcast arp req");
		return -1;
	}

	__u8 daddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	__u32 ar_tpa = pkt->inner_in4->daddr;

	if (send_arp(pkt, port, daddr, ar_tpa, ARPOP_REQUEST))
		return -1;

	pkt->egress_port = EGRESS_BR_FLOOD;

	return 0;
}

// Processes an incoming ARP request and sends an ARP reply if the target IP address
// matches the local port's configured IP address.
static __always_inline int process_arp_request(struct packet *pkt, __u8 ar_sha[6], __u32 ar_spa,
					       __u32 ar_tpa)
{
	struct port_conf *port = get_port_conf(1);
	if (!port) {
		bpf_printk("failed to get port config for sending unicast arp req");
		return -1;
	}

	if (ar_tpa != port->in4addr)
		return -1;

	if (shrink_packet_to_zero(pkt->ctx))
		return -1;

	if (send_arp(pkt, port, ar_sha, ar_spa, ARPOP_REPLY))
		return -1;

	pkt->egress_port = pkt->ctx->ingress_ifindex;

	return 0;
}

// Processes an ARP reply by updating the ARP table with the sender's MAC and IP address.
// This information is used for future packet forwarding decisions.
static __always_inline int process_arp_reply(struct packet *pkt, __u8 ar_sha[6], __u32 ar_spa)
{
	struct arp_entry neigh;
	neigh.last_updated = bpf_ktime_get_ns();
	memcpy(&neigh.port_no, &pkt->ctx->ingress_ifindex, sizeof(__u32));
	memcpy(&neigh.macaddr, ar_sha, sizeof(neigh.macaddr));

	if (bpf_map_update_elem(&arp_table, &ar_spa, &neigh, BPF_ANY)) {
		bpf_printk("process_arp_reply: arp_table update failed for ip %u\n", ar_spa);
		return -1;
	}

	return 0;
}

// Main function for ARP processing that routes to specific functions for handling
// ARP requests and replies based on the operation code.
static __always_inline int process_arp(struct packet *pkt)
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
		ret = process_arp_reply(pkt, ar_sha, ar_spa);
		break;
	case ARPOP_REQUEST:
		ret = process_arp_request(pkt, ar_sha, ar_spa, ar_tpa);
		break;
	default:
		bpf_printk("arp: unsupported op: %d received", ar_op);
		ret = -1;
	}

	return ret;
}

// Determines the next hop based on IPv4 routing and sets the packet's Ethernet header
// for the next hop. If no entry is found in the ARP table, initiates ARP resolution.
static __always_inline int uplink_set_in4_neigh(struct packet *pkt)
{
	struct route_key_in4 k;
	struct lpm_nh_in4 *nh;
	struct arp_entry *neigh;
	struct port_conf *port;
	struct ethhdr *ethhdr;

	__u32 offset = 0;
	__u32 neigh_key;
	__u32 egress_port;
	__u32 daddr = pkt->inner_in4->daddr;

	k.prefix_len = 32;
	k.addr = daddr;

	nh = (struct lpm_nh_in4 *)bpf_map_lookup_elem(&route_table, &k);
	if (!nh) {
		bpf_printk("uplink_set_in4_neigh: route_table lookup failed for ip %u\n", daddr);
		return -1;
	}

	switch (nh->nh_type) {
	case NH_LOCAL:
		neigh_key = daddr;
		break;
	case NH_REMOTE:
		neigh_key = nh->addr;
		break;
	default:
		return -1;
	};

	neigh = bpf_map_lookup_elem(&arp_table, &neigh_key);
	if (!neigh)
		return broadcast_arp_request(pkt);

	egress_port = neigh->port_no;
	port = bpf_map_lookup_elem(&port_config, &egress_port);
	if (!port) {
		bpf_printk("uplink_set_in4_neigh: port_config lookup failed for egress_port %u\n",
			   egress_port);
		return -1;
	}

	if (write_ethernet_to_ctx(pkt->ptr, &offset, neigh->macaddr, port->macaddr, ETH_P_IP))
		return -1;

	pkt->egress_port = neigh->port_no;

	return 0;
}

// Removes the IPv6 encapsulation from a packet, revealing the inner IPv4 packet.
// Used when the uplink receives an encapsulated IPv4 packet within an IPv6 packet.
static __always_inline int uplink_ipv6_decap(struct packet *pkt)
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

static __always_inline int process_bridge_l3(struct packet *pkt)
{
	int ret;

	switch (pkt->l3_proto) {
	case ETH_P_ARP:
		ret = process_arp(pkt);
		break;
	case ETH_P_IP:
		return 0;
	case ETH_P_IPV6:
		return 0;
	default:
		// unsupported protocol
		return -1;
	}

	return ret;
}

static __always_inline int process_uplink_l3(struct packet *pkt)
{
	struct ipv6hdr ip6hdr;

	if (pkt->l3_proto != ETH_P_IPV6)
		return -1;
	if (parse_ipv6(pkt->ptr, pkt->offset, &ip6hdr, &pkt->l4_proto, &pkt->is_frag))
		return -1;

	pkt->in6 = &ip6hdr;
	pkt->should_be_encaped = pkt->l4_proto == IPPROTO_IPIP;

	if (pkt->should_be_encaped) {
		if (uplink_ipv6_decap(pkt))
			return -1;
		if (push_ethernet(pkt->ptr, pkt->ctx, ETH_P_IP))
			return -1;
	}

	if (pkt->should_be_encaped)
		uplink_set_in4_neigh(pkt);

	return 0;
}

static __always_inline int process_l2(struct packet *pkt)
{
	struct ethhdr ethhdr;

	if (parse_ethernet(pkt->ptr, pkt->offset, &ethhdr))
		return -1;

	pkt->eth = &ethhdr;
	pkt->l3_proto = bpf_ntohs(ethhdr.h_proto);

	return 0;
}

static __always_inline int process_uplink_packet(struct packet *pkt)
{
	if (process_l2(pkt))
		return -1;
	if (process_uplink_l3(pkt))
		return -1;

	return 0;
}

static __always_inline int process_forward(struct packet *pkt)
{
	int ret;

	if (pkt->egress_port == EGRESS_BR_FLOOD) {
		__u64 f = BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS;
		bpf_redirect_map(&tx_port, 0, f);
		ret = XDP_REDIRECT;
	} else if (pkt->egress_port == EGRESS_SLOW_PATH) {
		ret = XDP_PASS;
	} else if (pkt->ctx->ingress_ifindex == pkt->egress_port) {
		ret = XDP_TX;
	} else if (pkt->egress_port > 0) {
		bpf_redirect_map(&tx_port, pkt->egress_port, 0);
		ret = XDP_REDIRECT;
	} else {
		// shouldn't be happen
		ret = XDP_DROP;
	}

	return ret;
}

static __always_inline int process_bridge_packet(struct packet *pkt)
{
	if (process_l2(pkt))
		return -1;
	if (process_bridge_l3(pkt))
		return -1;

	return 0;
}

// BPF programs

// XDP program entry point for packets arriving on the bridge interface.
// It processes packets at layer 2, layer 3, and determines their forwarding.
SEC("xdp")
int xdp_bridge_in(struct xdp_md *ctx)
{
	struct packet pkt = { 0 };
	struct bpf_dynptr ptr;
	__u64 offset = 0;
	int ret;

	pkt.ctx = ctx;
	pkt.offset = &offset;
	pkt.ptr = &ptr;

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
int xdp_uplink_in(struct xdp_md *ctx)
{
	struct packet pkt = { 0 };
	struct bpf_dynptr ptr;
	__u64 offset = 0;
	int ret;

	pkt.ctx = ctx;
	pkt.offset = &offset;
	pkt.ptr = &ptr;

	if (bpf_dynptr_from_xdp(ctx, 0, pkt.ptr))
		return XDP_DROP;
	if (process_uplink_packet(&pkt))
		return XDP_DROP;

	ret = process_forward(&pkt);
	return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
