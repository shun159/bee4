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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/shun159/hoge/internal/bpf"
	"golang.org/x/sys/unix"
)

type dpIface struct {
	devname string
	ifindex int
	family  int
	hwaddr  [6]uint8
	ipaddr  string
}

type Datapath struct {
	routes          []RoutingEntry
	brIface         *dpIface
	dsIface         *dpIface
	brMember        []*dpIface
	tuntap          *Tun
	uplink_xdp_link *link.Link
}

func Open(filename string) (*Datapath, error) {
	c, err := parseConfigJSON(filename)
	if err != nil {
		return nil, err
	}

	dp := &Datapath{}
	if err := dp.loadConfig(c); err != nil {
		return nil, err
	}

	return dp, nil
}

func (dp *Datapath) Start() error {
	uplink_xdp_link, err := bpf.AttachXdpUplinkInFn(dp.dsIface.devname)
	if err != nil {
		return fmt.Errorf("failed to attach uplink_xdp: %s", err)
	}

	dp.uplink_xdp_link = &uplink_xdp_link
	return nil
}

func (dp *Datapath) Close() error {
	dp.tuntap.Close()
	return nil
}

// private functions

func (dp *Datapath) loadConfig(c *DatapathConfig) error {
	if err := dp.setupRoutes(c); err != nil {
		return err
	}

	if err := dp.setupDsLiteIf(c); err != nil {
		return err
	}

	if err := dp.setupBrMembers(c); err != nil {
		return err
	}

	if err := dp.setupIrb(c); err != nil {
		return err
	}

	return nil
}

func (dp *Datapath) setupRoutes(c *DatapathConfig) error {
	dp.routes = c.Routes

	for _, r := range c.Routes {
		if err := AddIn4Route(r.Dst, r.NextHop, 2); err != nil {
			return fmt.Errorf("failed to add route: %s", err)
		}
	}

	return nil
}

func (dp *Datapath) setupDsLiteIf(c *DatapathConfig) error {
	dsl := c.Dslite

	iface, err := net.InterfaceByName(dsl.DevName)
	if err != nil {
		return fmt.Errorf("failed to find interface: %s: %s", dsl.DevName, err)
	}

	macaddr := [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		macaddr[idx] = uint8(b)
	}

	dp.dsIface = new(dpIface)
	dp.dsIface.devname = dsl.DevName
	dp.dsIface.family = unix.AF_INET6
	dp.dsIface.hwaddr = macaddr
	dp.dsIface.ipaddr = "::0/0"

	if err := bpf.AddL3Port(iface.Index, 2); err != nil {
		return err
	}

	if err := enableIPv6(dsl.DevName, true); err != nil {
		return err
	}

	return nil
}

func (dp *Datapath) setupIrb(c *DatapathConfig) error {
	irb := c.Irb
	tun, err := CreateTun(irb.DevName)
	if err != nil {
		return err
	}

	// Wait for creation completed
	time.Sleep(time.Second * 5)
	enableIPv6(irb.DevName, false)

	iface, err := net.InterfaceByName(irb.DevName)
	if err != nil {
		return err
	}

	macaddr := [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		macaddr[idx] = uint8(b)
	}

	if err := bpf.AddL3Port(iface.Index, 1); err != nil {
		return err
	}

	if err := tun.SetAddress(irb.In4Addr); err != nil {
		return fmt.Errorf("failed to set address on %s: %s", irb.DevName, err)
	}

	if err := tun.Up(); err != nil {
		return fmt.Errorf("failed to set up on %s: %s", irb.DevName, err)
	}

	if err := AddIn4Route(irb.In4Addr, "0.0.0.0", 1); err != nil {
		return fmt.Errorf("failed to add route: %s", err)
	}

	p, _, err := net.ParseCIDR(irb.In4Addr)
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %s", err)
	}

	pbytes := [4]byte{}
	for idx, b := range p.To4() {
		pbytes[idx] = b
	}

	pref := binary.LittleEndian.Uint32(pbytes[:])
	if err := bpf.AddPort(tun.ifindex, pref, macaddr, true); err != nil {
		return fmt.Errorf("failed to config bridging interface: %s: %s", irb.DevName, err)
	}

	dp.brIface = new(dpIface)
	dp.tuntap = tun
	dp.brIface.devname = irb.DevName
	dp.brIface.family = unix.AF_INET
	dp.brIface.hwaddr = macaddr
	dp.brIface.ipaddr = c.Irb.In4Addr

	return nil
}

func (dp *Datapath) setupBrMembers(c *DatapathConfig) error {
	brmember := c.BrMember
	dp.brMember = make([]*dpIface, 0)

	for _, name := range brmember {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("failed to find interface: %s: %s", name, err)
		}

		macaddr := [6]uint8{}
		for idx, b := range iface.HardwareAddr {
			macaddr[idx] = uint8(b)
		}

		if err := bpf.AddPort(iface.Index, 0, macaddr, false); err != nil {
			return fmt.Errorf("failed to config bridging interface: %s: %s", name, err)
		}

		if err := bpf.AddTxBrPort(iface.Index); err != nil {
			return fmt.Errorf("failed to add %s as tx_port: %s", name, err)
		}

		briface := &dpIface{}
		briface.devname = name
		briface.ifindex = iface.Index
		briface.hwaddr = macaddr
		briface.ipaddr = "0.0.0.0/0"

		dp.brMember = append(dp.brMember, briface)
	}

	return nil
}

func enableIPv6(name string, f bool) error {
	ipv6(name, f)
	ipv6Forwarding(name, f)
	ipv6SLAAC(name, f)

	return nil
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func ipv6SLAAC(name string, ctrl bool) error {
	k := boolToByte(ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/autoconf", []byte{k}, 0)
}

// IPv6Forwarding enables/disables ipv6 forwarding for the interface.
func ipv6Forwarding(name string, ctrl bool) error {
	k := boolToByte(ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/forwarding", []byte{k}, 0)
}

// IPv6 enables/disable ipv6 for the interface.
func ipv6(name string, ctrl bool) error {
	k := boolToByte(!ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte{k}, 0)
}

func boolToByte(x bool) byte {
	if x {
		return 1
	}
	return 0
}
