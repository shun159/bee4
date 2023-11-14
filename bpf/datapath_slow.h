
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

SEC("tc")
int tc_pkt1_in(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

SEC("tc")
int tc_pkt1_out(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

SEC("tc")
int tc_uplink_in(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

SEC("tc")
int tc_uplink_out(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}
