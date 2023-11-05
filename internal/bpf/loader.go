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

package bpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang datapath ../../bpf/datapath.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

var objs *datapathObjects
var maps *datapathMaps
var prog *datapathPrograms

func LoadBPF() error {
	objs = &datapathObjects{}
	if err := loadDatapathObjects(objs, nil); err != nil {
		return err
	}

	maps = &objs.datapathMaps
	prog = &objs.datapathPrograms

	return nil
}

func GetRouteTable() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, err
	}
	return m.RouteTable, nil
}

func GetPortConfigMap() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, err
	}
	return m.PortConfig, nil
}

func GetL3PortMap() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, err
	}
	return m.L3PortMap, nil
}

func GetTxPortMap() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, err
	}
	return m.TxPort, nil
}

func AddRoute(prefLen, pref uint32, nhType int, nhAddr uint32) error {
	lpmKey := datapathRouteKeyIn4{prefLen, pref}
	lpmVal := datapathLpmNhIn4{NhType: uint8(nhType), Addr: nhAddr}

	m, err := GetRouteTable()
	if err != nil {
		return err
	}
	return m.Put(lpmKey, lpmVal)
}

func AddPort(ifindex int, in4addr uint32, macaddr [6]uint8, routable bool) error {
	key := uint32(ifindex)
	val := datapathPortConf{}

	var isroutable uint8 = 0
	if routable {
		isroutable = 1
	}

	val.In4addr = in4addr
	val.Macaddr = macaddr
	val.Isroutable = isroutable

	m, err := GetPortConfigMap()
	if err != nil {
		return err
	}
	return m.Put(key, val)
}

func AddL3Port(ifindex, l3if_type int) error {
	key := uint32(l3if_type)
	val := uint32(ifindex)

	m, err := GetL3PortMap()
	if err != nil {
		return err
	}
	return m.Put(key, val)
}

func AddTxBrPort(ifindex int) error {
	ifidx := uint32(ifindex)

	m, err := GetTxPortMap()
	if err != nil {
		return err
	}
	return m.Put(&ifidx, &ifidx)
}

func AttachXdpUplinkInFn(ifname string) (link.Link, error) {
	prog, err := getProgram()
	if err != nil {
		return nil, err
	}
	return attachXdp(ifname, prog.XdpUplinkIn)
}

func AttachXdpBridgeInFn(ifname string) (link.Link, error) {
	prog, err := getProgram()
	if err != nil {
		return nil, err
	}
	return attachXdp(ifname, prog.XdpBridgeIn)
}

// private functions

func getMap() (*datapathMaps, error) {
	if maps == nil {
		return nil, fmt.Errorf("BPF maps is not loaded yet")
	}
	return maps, nil
}

func getProgram() (*datapathPrograms, error) {
	if prog == nil {
		return nil, errors.New("program is not initialized")
	}
	return prog, nil
}

func attachXdp(ifname string, prog *ebpf.Program) (link.Link, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("attach xdp: failed to get iface for %s: %w", ifname, err)
	}

	l, err := link.AttachXDP(xdpOptions(prog, iface, link.XDPGenericMode))
	if err != nil {
		return nil, fmt.Errorf("attach xdp: failed to attach xdp for iface: %s: %w", ifname, err)
	}

	return l, nil
}

func xdpOptions(prog *ebpf.Program,
	iface *net.Interface,
	mode link.XDPAttachFlags) link.XDPOptions {
	return link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	}
}
