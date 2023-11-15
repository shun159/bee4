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

#include "datapath_helpers.h"

#ifndef __DP_MAP_HELPERS__
#define __DP_MAP_HELPERS__

enum l3if_type {
    L3IF_UNDEF,
    L3IF_LOCAL,
    L3IF_UPLINK,
};

enum nh_type {
    NH_UNDEF,
    NH_LOCAL,
    NH_REMOTE,
    NH_UPLINK,
};

struct nd_key {
    __u32 addr[4];
};

struct arp_entry {
    __u8 macaddr[6];
    __u32 port_no;
	__u64 last_updated;
}__attribute__((packed));

struct fdb_key {
    __u8 macaddr[6];
};

struct fdb_entry {
    __u32 port_no;
    __u64 last_updated;
}__attribute__((packed));

struct port_conf {
    __u8 macaddr[6];
    __u8 isroutable;
    __u32 in4addr;
}__attribute__((packed));

struct route_key_in4 {
    __u32 prefix_len;
    __u32 addr;
};

struct lpm_nh_in4 {
    __u8  nh_type;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
} tx_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct port_conf);
	__uint(max_entries, 256);
} port_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct arp_entry);
	__uint(max_entries, 256);
} arp_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nd_key);
	__type(value, struct arp_entry);
	__uint(max_entries, 256);
} nd_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fdb_key);
    __type(value, struct fdb_entry);
    __uint(max_entries, 1024);
} fdb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct route_key_in4);
    __type(value, struct lpm_nh_in4);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} l3_port_map SEC(".maps");

// BPF map wrapper

static __always_inline __u32 *
get_l3_port_idx(__u32 port_key)
{
    __u32 *ifidx = (__u32 *)bpf_map_lookup_elem(&l3_port_map, &port_key);
    if (!ifidx)
        return NULL;

    return ifidx;
}

// Retrieves port configuration data from eBPF maps using a given port key.
// Returns NULL if the port configuration is not found.
static __always_inline struct port_conf *
get_port_conf(__u32 port_key)
{
    __u32 *pkt_ifidx = get_l3_port_idx(port_key);
    if (!pkt_ifidx) {
        bpf_printk("l3_port_map lookup failed for port_key %u\n", port_key);
        return NULL;
    }

    struct port_conf *port = bpf_map_lookup_elem(&port_config, pkt_ifidx);
    if (!port) {
        bpf_printk("port_config lookup failed for ifidx %u\n", *pkt_ifidx);
    }

    return port;
}

static __always_inline struct lpm_nh_in4 *
get_route_in4(__u32 daddr)
{
    struct lpm_nh_in4 *nh;
    struct route_key_in4 k;

    k.prefix_len = 32;
    k.addr = daddr;

    nh = (struct lpm_nh_in4 *)bpf_map_lookup_elem(&route_table, &k);
    if (!nh) {
        bpf_printk("route_table lookup failed for ip %u\n", daddr);
        return NULL;
    }

    return nh;
}

static __always_inline int
put_arp_entry(__u8 *ar_sha, __u32 ar_spa, __u32 port_no)
{
    struct arp_entry e;

    e.last_updated = bpf_ktime_get_ns();
    e.port_no = port_no;
    memcpy(&e.macaddr, ar_sha, sizeof(e.macaddr));

    if (bpf_map_update_elem(&arp_table, &ar_spa, &e, BPF_ANY))
        return -1;

    return 0;
}

static __always_inline int
put_fdb_entry(__u8 *macaddr, __u32 port_no)
{
    struct fdb_entry e;

    e.last_updated = bpf_ktime_get_ns();
    e.port_no = port_no;
    
    if (bpf_map_update_elem(&fdb, &macaddr, &e, BPF_ANY))
        return -1;

    return 0;
}

static __always_inline struct fdb_entry *
get_fdb_entry(__u8 *mac_addr)
{
    struct fdb_entry *ret;

    ret = (struct fdb_entry *)bpf_map_lookup_elem(&fdb, &mac_addr);
    return ret;
}

#endif
