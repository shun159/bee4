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
