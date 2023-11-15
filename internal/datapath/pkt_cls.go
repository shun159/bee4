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

package datapath

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/shun159/hoge/internal/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func setGenericQdisc(ifname string) (netlink.Qdisc, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	q := genericQdisc(iface.Index)
	if err := netlink.QdiscReplace(q); err != nil {
		return nil, err
	}

	return q, nil
}

func delQdisc(q netlink.Qdisc) error {
	if err := netlink.QdiscDel(q); err != nil {
		return err
	}
	return nil
}

func setTcPkt1In(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcPkt1In()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_INGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func setTcPkt1Out(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcPkt1Out()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_EGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func setTcBrMemberIn(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcBrMemberIn()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_INGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func setTcBrMemberOut(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcBrMemberOut()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_EGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func setTcUplinkIn(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcUplinkIn()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_INGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func setTcUplinkOut(ifname string) (*netlink.BpfFilter, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	prog, err := bpf.GetTcUplinkOut()
	if err != nil {
		return nil, err
	}

	f := bpfFilter(iface.Index, prog, netlink.HANDLE_MIN_EGRESS)
	if err := netlink.FilterReplace(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

func delTcFilter(f *netlink.BpfFilter) error {
	if err := netlink.FilterDel(f); err != nil {
		return err
	}
	return nil
}

// internal functions

func genericQdisc(ifidx int) *netlink.GenericQdisc {
	attr := netlink.QdiscAttrs{
		LinkIndex: ifidx,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	q := new(netlink.GenericQdisc)
	q.QdiscAttrs = attr
	q.QdiscType = "clsact"

	return q
}

func bpfFilter(ifidx int, prog *ebpf.Program, parent int) netlink.BpfFilter {
	attr := netlink.FilterAttrs{
		LinkIndex: ifidx,
		Parent:    uint32(parent),
		Handle:    1,
		Protocol:  unix.ETH_P_ALL,
	}

	f := new(netlink.BpfFilter)
	f.FilterAttrs = attr
	f.Fd = prog.FD()
	f.Name = prog.String()
	f.DirectAction = true

	return *f
}
