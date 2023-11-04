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

	__u32 ar_spa, ar_tpa;
	__u8 buf[sizeof(struct ethhdr)];
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

	memset(buf, 0, sizeof(buf));
	eth = bpf_dynptr_slice_rdwr(pkt->ptr, offset, buf, sizeof(buf));
	if (!eth) {
		bpf_printk("failed to create slice");
		return -1;
	}
	offset += sizeof(struct ethhdr);

	memcpy(eth->h_source, port->macaddr, sizeof(eth->h_source));
	eth->h_dest[0] = 0xff;
	eth->h_dest[1] = 0xff;
	eth->h_dest[2] = 0xff;
	eth->h_dest[3] = 0xff;
	eth->h_dest[4] = 0xff;
	eth->h_dest[5] = 0xff;
	eth->h_proto = bpf_ntohs(ETH_P_ARP);

	arp = bpf_dynptr_slice_rdwr(pkt->ptr, offset, buf, sizeof(buf));
	if (!arp) {
		bpf_printk("failed to create slice");
		return -1;
	}

	arp->ar_hrd = bpf_ntohs(ARPHRD_ETHER);
	arp->ar_pro = bpf_ntohs(ETH_P_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = bpf_ntohs(ARPOP_REQUEST);

	if (bpf_xdp_get_buff_len(pkt->ctx) < 64)
		bpf_xdp_adjust_tail(pkt->ctx, 40);

	offset += sizeof(struct arphdr);
	bpf_xdp_store_bytes(pkt->ctx, offset, port->macaddr, sizeof(port->macaddr));
	offset += sizeof(port->macaddr);

	ar_spa = port->in4addr;
	bpf_xdp_store_bytes(pkt->ctx, offset, &ar_spa, sizeof(__u32));
	offset += sizeof(__u32);

	__u8 z[6] = { 0 };
	bpf_xdp_store_bytes(pkt->ctx, offset, z, sizeof(port->macaddr));
	offset += sizeof(port->macaddr);

	ar_tpa = pkt->inner_in4->daddr;
	bpf_xdp_store_bytes(pkt->ctx, offset, &ar_tpa, sizeof(__u32));
	offset += sizeof(__u32);

	return 0;
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
		bpf_printk("send arp");
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

static __always_inline int uplink_forward(struct packet *pkt)
{
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

static __always_inline int process_ip6(struct packet *pkt)
{
	struct ipv6hdr ip6hdr;

	if (pkt->l3_proto != ETH_P_IPV6)
		return -1;

	if (parse_ipv6(pkt->ptr, pkt->offset, &ip6hdr, &pkt->l4_proto, &pkt->is_frag))
		return -1;

	pkt->in6 = &ip6hdr;
	pkt->should_be_encaped = pkt->l4_proto == IPPROTO_IPIP;

	if (uplink_forward(pkt))
		return -1;

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
	__u8 l4_proto;
	bool is_frag;

	if (process_l2(pkt))
		return -1;

	if (process_ip6(pkt))
		return -1;

	return 0;
}

// BPF programs

SEC("xdp")
int xdp_uplink_in(struct xdp_md *ctx)
{
	struct packet pkt = { 0 };
	struct bpf_dynptr ptr;
	struct ethhdr ethhdr;
	__u64 offset = 0;

	pkt.ctx = ctx;
	pkt.offset = &offset;
	pkt.ptr = &ptr;

	if (bpf_dynptr_from_xdp(ctx, 0, pkt.ptr)) {
		bpf_printk("failed to init ptr");
		return XDP_DROP;
	}

	if (process_uplink_packet(&pkt)) {
		bpf_printk("failed to process packet");
		return XDP_DROP;
	}

	return XDP_TX;
}

char __license[] SEC("license") = "Dual MIT/GPL";
