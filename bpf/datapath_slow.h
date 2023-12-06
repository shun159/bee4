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

#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_kfuncs.h"
#include "datapath_helpers.h"
#include "datapath_maps.h"

struct callback_ctx {
    struct __sk_buff *ctx;
};

static __always_inline int
tc_pkt1_process_broadcast(struct bpf_map *map, __u32 *ifidx, struct port_conf *port,
                          struct callback_ctx *ctx)
{
    if (port->isroutable)
        return 0;
    if (ctx->ctx->ingress_ifindex == *ifidx)
        return 0;
    bpf_clone_redirect(ctx->ctx, *ifidx, BPF_F_INGRESS);
    return 0;
}

static __always_inline int
tc_pkt1_process_out(struct __sk_buff *ctx)
{
    struct bpf_dynptr ptr;
    struct ethhdr eth;
    struct callback_ctx data;
    struct fdb_entry *fdb;
    __u64 offset = 0;

    data.ctx = ctx;

    if (bpf_dynptr_from_skb(ctx, 0, &ptr))
        return TC_ACT_SHOT;

    if (parse_ethernet(&ptr, &offset, &eth))
        return TC_ACT_SHOT;

    if (IS_MAC_BMCAST(eth.h_dest)) {
        bpf_for_each_map_elem(&port_config, tc_pkt1_process_broadcast, &data, 0);
        return TC_ACT_OK;
    }

    fdb = get_fdb_entry(eth.h_dest);
    if (!fdb) {
        bpf_for_each_map_elem(&port_config, tc_pkt1_process_broadcast, &data, 0);
        return TC_ACT_OK;
    }

    return bpf_redirect(fdb->port_no, 0);
}

SEC("tc")
int
tc_pkt1_in(struct __sk_buff *ctx)
{
    // TODO: this TC hook need to be deleted
    return TC_ACT_OK;
}

SEC("tc")
int
tc_pkt1_out(struct __sk_buff *ctx)
{
    return tc_pkt1_process_out(ctx);
}

SEC("tc")
int
tc_br_member_in(struct __sk_buff *ctx)
{
    __u32 *pkt_ifidx;

    pkt_ifidx = get_l3_port_idx(1);
    if (!pkt_ifidx)
        return TC_ACT_SHOT;

    return bpf_redirect(*pkt_ifidx, BPF_F_INGRESS);
}

SEC("tc")
int
tc_br_member_out(struct __sk_buff *ctx)
{
    bpf_printk("tc_br_member_out");
    return TC_ACT_OK;
}

SEC("tc")
int
tc_dslite_in(struct __sk_buff *ctx)
{
    bpf_printk("tc_dslite_in");
    return TC_ACT_OK;
}

SEC("tc") int tc_dslite_out(struct __sk_buff *ctx)
{
    __u32 *phy_ifidx;
    phy_ifidx = get_dslite_phy_idx(0);
    if (!phy_ifidx) {
        bpf_printk("tc_dslite_out: phy_ifidx not found");
        return TC_ACT_SHOT;
    }

    int ret = bpf_redirect(*phy_ifidx, 0);
    return ret;
}

SEC("tc")
int
tc_uplink_in(struct __sk_buff *ctx)
{
    __u32 *ifidx = get_l3_port_idx(2);
    if (!ifidx)
        return TC_ACT_SHOT;

    int ret = bpf_redirect(*ifidx, BPF_F_INGRESS);
    return ret;
}

SEC("tc")
int
tc_uplink_out(struct __sk_buff *ctx)
{
    bpf_printk("tc_uplink_out");
    return TC_ACT_OK;
}
