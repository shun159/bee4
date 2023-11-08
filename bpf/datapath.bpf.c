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

static __always_inline int send_arp_to_local(struct packet *pkt)
{
	struct ethhdr *eth;
	struct arphdr *arp;
	struct port_conf *port;

	__u8 ar_sha[6];
	__u32 ar_spa, ar_tpa;
	__u32 *pkt_ifidx;
	__u32 offset = 0;
	__u32 port_key = 1;

	pkt_ifidx = (__u32 *)bpf_map_lookup_elem(&l3_port_map, &port_key);
	if (!pkt_ifidx) {
		bpf_printk("pkt_ifidx not found");
		return -1;
	}

	port = (struct port_conf *)bpf_map_lookup_elem(&port_config, &*pkt_ifidx);
	if (!port) {
		bpf_printk("port not found");
		return -1;
	}

	// shrink the packet length to zero before perform packet translation.
	__u32 data_len = pkt->ctx->data_end - pkt->ctx->data;
	bpf_xdp_adjust_tail(pkt->ctx, 42 - data_len);

	__u8 daddr[6];
	daddr[0] = 0xff;
	daddr[1] = 0xff;
	daddr[2] = 0xff;
	daddr[3] = 0xff;
	daddr[4] = 0xff;
	daddr[5] = 0xff;
	if (write_ethernet_to_ctx(pkt->ptr, &offset, daddr, port->macaddr, ETH_P_ARP))
		return -1;

	ar_spa = port->in4addr;
	ar_tpa = pkt->inner_in4->daddr;
	memcpy(ar_sha, port->macaddr, sizeof(ar_sha));
	__u8 ar_tha[6] = { 0 };
	if (write_arp_to_ctx(pkt->ctx, pkt->ptr, &offset, ARPOP_REQUEST, ar_sha, ar_spa, ar_tha,
			     ar_tpa))
		return -1;

	pkt->egress_port = EGRESS_BR_FLOOD;

	return 0;
}

static __always_inline int process_arp_reply(struct packet *pkt, struct arphdr *arp, __u8 ar_sha[6],
					     __u32 ar_spa)
{
	struct arp_entry neigh;

	if (bpf_ntohs(arp->ar_pro) != ETH_P_IP)
		return -1;

	neigh.last_updated = bpf_ktime_get_ns();
	memcpy(&neigh.port_no, &pkt->ctx->ingress_ifindex, sizeof(__u32));
	memcpy(&neigh.macaddr, ar_sha, sizeof(neigh.macaddr));

	if (bpf_map_update_elem(&arp_table, &ar_spa, &neigh, BPF_ANY))
		return -1;

	return 0;
}

static __always_inline int process_arp(struct packet *pkt)
{
	struct arphdr arphdr;
	int ret;

	__u8 ar_sha[6], ar_tha[6];
	__u32 ar_spa, ar_tpa;

	if (parse_arp(pkt->ptr, pkt->offset, &arphdr, ar_sha, &ar_spa, ar_tha, &ar_tpa))
		ret = -1;

	bpf_printk("ar_op: %d", bpf_ntohs(arphdr.ar_op));
	bpf_printk("ar_spa: %d", ar_spa);
	bpf_printk("ar_sha: %x:%x:%x:%x:%x:%x", ar_sha[0], ar_sha[1], ar_sha[2], ar_sha[3],
		   ar_sha[4], ar_sha[5]);

	switch (bpf_ntohs(arphdr.ar_op)) {
	case ARPOP_REPLY:
		ret = process_arp_reply(pkt, &arphdr, ar_sha, ar_spa);
	case ARPOP_REQUEST:
		return 0;
	default:
		return -1;
	}

	return ret;
}

static __always_inline int uplink_set_in4_neigh(struct packet *pkt)
{
	struct route_key_in4 k;
	struct lpm_nh_in4 *nh;
	struct arp_entry *neigh;
	struct ethhdr *ethhdr;

	__u8 buf[sizeof(struct ethhdr)];
	__u32 neigh_key;
	__u32 daddr = pkt->inner_in4->daddr;

	k.prefix_len = 32;
	k.addr = daddr;

	nh = (struct lpm_nh_in4 *)bpf_map_lookup_elem(&route_table, &k);
	if (!nh) {
		bpf_printk("route missing");
		return -1;
	}
	bpf_printk("route found: %d", nh->nh_type);

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
	if (!neigh) {
		send_arp_to_local(pkt);
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	ethhdr = bpf_dynptr_slice_rdwr(pkt->ptr, 0, buf, sizeof(buf));
	if (!ethhdr)
		return -1;
	memcpy(ethhdr->h_dest, neigh->macaddr, sizeof(ethhdr->h_dest));

	return 0;
}

static __always_inline int uplink_ipv6_decap(struct packet *pkt)
{
	struct iphdr iph;

	// Trim outer in6 and ether header.
	bpf_xdp_adjust_head(pkt->ctx, *pkt->offset);
	// Reset offset to point inner header.
	*pkt->offset = 0;
	if (parse_ipv4(pkt->ptr, pkt->offset, &iph)) {
		bpf_printk("failed to parse ipheader");
		return -1;
	}

	pkt->inner_in4 = &iph;

	return 0;
}

static __always_inline int uplink_push_ethhdr(struct packet *pkt)
{
	struct ethhdr *ethhdr;
	__u8 buf[sizeof(struct ethhdr)];

	// make head for ethernet header
	bpf_xdp_adjust_head(pkt->ctx, 0 - (int)sizeof(struct ethhdr));

	memset(buf, 0, sizeof(buf));
	ethhdr = bpf_dynptr_slice_rdwr(pkt->ptr, 0, buf, sizeof(buf));
	if (!ethhdr)
		return -1;
	ethhdr->h_proto = bpf_htons(ETH_P_IP);

	return 0;
}

static __always_inline int process_bridge_l3(struct packet *pkt)
{
	int ret;

	bpf_printk("l3_proto: %x", pkt->l3_proto);

	switch (pkt->l3_proto) {
	case ETH_P_ARP:
		ret = process_arp(pkt);
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
		if (uplink_push_ethhdr(pkt))
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

static __always_inline int uplink_br_forward(struct packet *pkt)
{
	int ret;

	if (pkt->egress_port == EGRESS_BR_FLOOD) {
		__u64 f = BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS;
		bpf_redirect_map(&tx_port, 0, f);
		ret = XDP_REDIRECT;
	} else if (pkt->egress_port == EGRESS_SLOW_PATH) {
		ret = XDP_PASS;
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

	return XDP_PASS;
}

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
	if (process_uplink_packet(&pkt)) {
		bpf_printk("failed to process packet");
		return XDP_DROP;
	}

	ret = uplink_br_forward(&pkt);
	return ret;
}

char __license[] SEC("license") = "Dual MIT/GPL";
