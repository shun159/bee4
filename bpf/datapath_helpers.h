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

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bpf_kfuncs.h"

#ifndef __DP_HELPERS__
#define __DP_HELPERS__

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(buf, ch, n) __builtin_memset((buf), (ch), (n))
#endif

#ifndef memcmp
#define memcmp(buf1, buf2, n) __builtin_memcmp((buf1), (buf2), (n))
#endif

#define MAC_CMP(dst, src)                                                                \
    ((((__u16 *)dst)[0] == ((__u16 *)src)[0]) &&                                         \
     (((__u16 *)dst)[1] == ((__u16 *)src)[1]) &&                                         \
     (((__u16 *)dst)[2] == ((__u16 *)src)[2]))

#define IS_MAC_ZERO(dst)                                                                 \
    ((((__u16 *)dst)[0] == 0) && (((__u16 *)dst)[1] == 0) && (((__u16 *)dst)[2] == 0))

#define IS_MAC_BCAST(dst)                                                                \
    ((((__u16 *)dst)[0] == 0xffff) && (((__u16 *)dst)[1] == 0xffff) &&                   \
     (((__u16 *)dst)[2] == 0xffff))

#define IS_MAC_BMCAST(dst) (((__u8 *)dst)[0] & 0x1)

#define IS_IP4_BCAST(dst) (((__u32)dst) == 0xffffffff)

#define IS_IP6_MCAST_ALL_NODES(dst)              \
    ((bpf_ntohs(((__u16 *)dst)[0]) == 0xff02) && \
     (bpf_ntohs(((__u16 *)dst)[7]) == 0x0001))

#define IS_IP6_MCAST_ALL_ROUTER(dst)             \
    ((bpf_ntohs(((__u16 *)dst)[0]) == 0xff02) && \
     (bpf_ntohs(((__u16 *)dst)[7]) == 0x0002))

#define IS_IP6_MCAST(dst)           \
    (IS_IP6_MCAST_ALL_NODES(dst) || \
     IS_IP6_MCAST_ALL_ROUTER(dst))

#define IP_OFFSET_MASK (0x1FFF)
#define IP_MF (0x2000)

#define ARPHRD_ETHER 1

/* ARP protocol opcodes. */
#define ARPOP_REQUEST 1   /* ARP request			*/
#define ARPOP_REPLY 2     /* ARP reply			*/
#define ARPOP_RREQUEST 3  /* RARP request			*/
#define ARPOP_RREPLY 4    /* RARP reply			*/
#define ARPOP_InREQUEST 8 /* InARP request		*/
#define ARPOP_InREPLY 9   /* InARP reply			*/
#define ARPOP_NAK 10      /* (ATM)ARP NAK			*/

#define ETH_P_IP 0x0800   /* Internet Protocol packet */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook       */
#define ETH_P_ARP 0x0806  /* Address Resolution Protocol */

/*
 *	IPV6 extension headers
 */
#define IPPROTO_HOPOPTS 0   /* IPv6 hop-by-hop options	*/
#define IPPROTO_ROUTING 43  /* IPv6 routing header		*/
#define IPPROTO_FRAGMENT 44 /* IPv6 fragmentation header	*/
#define IPPROTO_ICMPV6 58   /* ICMPv6			*/
#define IPPROTO_NONE 59     /* IPv6 no next header		*/
#define IPPROTO_DSTOPTS 60  /* IPv6 destination options	*/
#define IPPROTO_MH 135      /* IPv6 mobility header		*/

enum egress_type {
    // pass the packet to the normal network stack.
    EGRESS_SLOW_PATH = 0xffffff00,
    // flood the packet to the all port of `br_member` devmap.
    EGRESS_BR_FLOOD = 0xfffffffd,
};

typedef struct {
    __u16 src, dst;
} flow_ports_t;

struct packet {
    // contexts
    struct xdp_md *ctx;
    struct bpf_dynptr *ptr;
    __u64 *offset;

    // metadata fields
    __u16 l3_proto;
    __u8 l4_proto;
    __u32 ingress_ifindex;
    __u32 egress_ifindex;

    struct port_conf *ingress_port;
    struct port_conf *egress_port;

    bool is_frag;
    bool should_be_encaped;
    bool is_mac_bmcast;
    bool is_mac_self;

    // packet fields
    struct ethhdr *eth;
    struct ipv6hdr *in6;
    struct iphdr *inner_in4;
};

static __always_inline int
parse_ethernet(struct bpf_dynptr *ptr, __u64 *offset, struct ethhdr *ethhdr)
{
    if (bpf_dynptr_read(ethhdr, sizeof(*ethhdr), ptr, *offset, 0))
        return -1;
    *offset += sizeof(struct ethhdr);

    return 0;
}

static __always_inline int
set_ethernet(struct bpf_dynptr *ptr, __u32 *offset, __u8 daddr[6], __u8 saddr[6],
             __u16 proto)
{
    struct ethhdr *eth;
    __u8 buf[sizeof(*eth)];

    memset(buf, 0, sizeof(buf));
    eth = bpf_dynptr_slice_rdwr(ptr, *offset, buf, sizeof(buf));
    if (!eth)
        return -1;

    memcpy(eth->h_dest, daddr, 6);
    memcpy(eth->h_source, saddr, 6);
    eth->h_proto = bpf_ntohs(proto);

    *offset += sizeof(struct ethhdr);

    return 0;
}

static __always_inline int
push_ethernet(struct bpf_dynptr *ptr, struct xdp_md *ctx, __u16 proto)
{
    struct ethhdr *ethhdr;
    __u8 buf[sizeof(struct ethhdr)];

    // make head for ethernet header
    bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct ethhdr));

    memset(buf, 0, sizeof(buf));
    ethhdr = bpf_dynptr_slice_rdwr(ptr, 0, buf, sizeof(buf));
    if (!ethhdr)
        return -1;
    ethhdr->h_proto = bpf_htons(proto);

    return 0;
}

static __always_inline int
parse_arp(struct bpf_dynptr *ptr, __u64 *offset, struct arphdr *arphdr, __u8 ar_sha[],
          __u32 *ar_spa, __u8 ar_tha[], __u32 *ar_tpa)
{
    if (bpf_dynptr_read(arphdr, sizeof(*arphdr), ptr, *offset, 0))
        return -1;
    *offset += sizeof(struct arphdr);

    if (!(arphdr->ar_hrd == bpf_ntohs(ARPHRD_ETHER)) &&
        (arphdr->ar_pro == bpf_ntohs(ETH_P_IP)))
        return -1;

    if (bpf_dynptr_read(ar_sha, 6, ptr, *offset, 0))
        return -1;
    *offset += 6;

    if (bpf_dynptr_read(ar_spa, 4, ptr, *offset, 0))
        return -1;
    *offset += 4;

    if (bpf_dynptr_read(ar_tha, 6, ptr, *offset, 0))
        return -1;
    *offset += 6;

    if (bpf_dynptr_read(ar_tpa, 4, ptr, *offset, 0))
        return -1;
    *offset += 4;

    return 0;
}

static __always_inline int
write_arp_to_ctx(struct xdp_md *ctx, struct bpf_dynptr *ptr, __u32 *offset, __u8 op,
                 __u8 ar_sha[6], __u32 ar_spa, __u8 ar_tha[6], __u32 ar_tpa)
{
    struct arphdr *arp;
    __u8 buf[sizeof(struct arphdr) + 20];

    memset(buf, 0, sizeof(buf));
    arp = bpf_dynptr_slice_rdwr(ptr, *offset, buf, sizeof(buf));
    if (!arp)
        return -1;

    arp->ar_hrd = bpf_ntohs(ARPHRD_ETHER);
    arp->ar_pro = bpf_ntohs(ETH_P_IP);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = bpf_ntohs(op);
    *offset += sizeof(struct arphdr);

    bpf_xdp_store_bytes(ctx, *offset, ar_sha, 6);
    *offset += 6;

    bpf_xdp_store_bytes(ctx, *offset, &ar_spa, sizeof(__u32));
    *offset += 4;

    bpf_xdp_store_bytes(ctx, *offset, ar_tha, 6);
    *offset += 6;

    bpf_xdp_store_bytes(ctx, *offset, &ar_tpa, sizeof(__u32));

    return 0;
}

static __always_inline bool
ipv4_is_fragmemt(const struct iphdr *ip)
{
    __u16 frag_off = ip->frag_off & bpf_htons(IP_OFFSET_MASK);
    return (ip->frag_off & bpf_htons(IP_MF)) != 0 || frag_off > 0;
}

static __always_inline int
parse_ipv4(struct bpf_dynptr *dynptr, __u64 *offset, struct iphdr *iphdr)
{
    if (bpf_dynptr_read(iphdr, sizeof(*iphdr), dynptr, *offset, 0))
        return -1;

    if (iphdr->ihl < 5)
        return -1;

    *offset += sizeof(*iphdr);
    /* skip ipv4 options */
    *offset += (iphdr->ihl - 5) * 4;

    return 0;
}

/* Parse the L4 ports from a packet, assuming a layout like TCP or UDP. */
static __always_inline bool
parse_icmp_l4_ports(struct bpf_dynptr *dynptr, __u64 *offset, flow_ports_t *ports)
{
    if (bpf_dynptr_read(ports, sizeof(*ports), dynptr, *offset, 0))
        return false;

    *offset += sizeof(*ports);

    /* Ports in the L4 headers are reversed, since we are parsing an ICMP
     * payload which is going towards the eyeball.
     */
    __u16 dst = ports->src;
    ports->src = ports->dst;
    ports->dst = dst;
    return true;
}

static __always_inline __u16
checksum_fold(__u32 csum)
{
    /* The highest reasonable value for an IPv4 header
     * checksum requires two folds, so we just do that always.
     */
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline void
ipv4_checksum(struct iphdr *iph)
{
    iph->check = 0;

    /* An IP header without options is 20 bytes. Two of those
     * are the checksum, which we always set to zero. Hence,
     * the maximum accumulated value is 18 / 2 * 0xffff = 0x8fff7,
     * which fits in 32 bit.
     */
    _Static_assert(sizeof(struct iphdr) == 20, "iphdr must be 20 bytes");
    __u32 acc = 0;
    __u16 *ipw = (__u16 *)iph;

    for (size_t i = 0; i < sizeof(struct iphdr) / 2; i++)
        acc += ipw[i];

    iph->check = checksum_fold(acc);
}

static __always_inline bool
skip_ipv6_extension_headers(struct bpf_dynptr *dynptr, __u64 *offset,
                            const struct ipv6hdr *ipv6, uint8_t *upper_proto,
                            bool *is_fragment)
{
    /* We understand five extension headers.
     * https://tools.ietf.org/html/rfc8200#section-4.1 states that all
     * headers should occur once, except Destination Options, which may
     * occur twice. Hence we give up after 6 headers.
     */
    struct {
        uint8_t next;
        uint8_t len;
    } exthdr = {
        .next = ipv6->nexthdr,
    };
    *is_fragment = false;

    for (int i = 0; i < 6; i++) {
        switch (exthdr.next) {
        case IPPROTO_FRAGMENT:
            *is_fragment = true;
            /* NB: We don't check that hdrlen == 0 as per spec. */
            /* fallthrough; */

        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH:
            if (bpf_dynptr_read(&exthdr, sizeof(exthdr), dynptr, *offset, 0))
                return false;

            /* hdrlen is in 8-octet units, and excludes the first 8 octets. */
            *offset += (exthdr.len + 1) * 8;

            /* Decode next header */
            break;

        default:
            /* The next header is not one of the known extension
             * headers, treat it as the upper layer header.
             *
             * This handles IPPROTO_NONE.
             *
             * Encapsulating Security Payload (50) and Authentication
             * Header (51) also end up here (and will trigger an
             * unknown proto error later). They have a custom header
             * format and seem too esoteric to care about.
             */
            *upper_proto = exthdr.next;
            return true;
        }
    }

    /* We never found an upper layer header. */
    return false;
}

static __always_inline int
parse_ipv6(struct bpf_dynptr *dynptr, __u64 *offset, struct ipv6hdr *ipv6, uint8_t *proto,
           bool *is_fragment)
{
    if (bpf_dynptr_read(ipv6, sizeof(*ipv6), dynptr, *offset, 0))
        return -1;

    *offset += sizeof(*ipv6);

    if (!skip_ipv6_extension_headers(dynptr, offset, ipv6, proto, is_fragment))
        return -1;

    return 0;
}

static __always_inline int
parse_icmpv6(struct bpf_dynptr *dynptr, __u64 *offset, struct icmp6hdr *icmp6)
{
    if (bpf_dynptr_read(icmp6, sizeof(*icmp6), dynptr, *offset, 0))
        return -1;
    *offset += sizeof(*icmp6);

    return 0;
}

#endif
