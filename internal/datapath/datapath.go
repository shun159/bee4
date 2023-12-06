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
	"github.com/shun159/hoge/internal/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const dsliteIface = "dslite0"

type dpIface struct {
	devname   string
	ifindex   int
	family    int
	hwaddr    [6]uint8
	ipaddr    string
	tcQdisc   netlink.Qdisc
	tcFilters []*datapathBpfFilter
}

type Datapath struct {
	routes           []RoutingEntry
	brIface          *dpIface
	dsIfacePhy       *dpIface
	dsIfaceIrb       *dpIface
	brMember         []*dpIface
	brTuntap         *Tun
	dsTuntap         *Tun
	uplink_xdp_link  *link.Link
	bridge_xdp_links []*link.Link
	dhcpConfigFile   string
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
	if err := dp.attachXdpFn(); err != nil {
		return err
	}

	if err := dp.attachTcFn(); err != nil {
		return err
	}

	go dhcp.Serve(dp.dhcpConfigFile)

	return nil
}

func (dp *Datapath) Close() error {
	for _, iface := range dp.brMember {
		if err := delQdisc(iface.tcQdisc); err != nil {
			return err
		}
	}

	if err := delQdisc(dp.dsIfacePhy.tcQdisc); err != nil {
		return err
	}

	if err := delQdisc(dp.brIface.tcQdisc); err != nil {
		return err
	}

	if err := dp.brTuntap.Close(); err != nil {
		return fmt.Errorf("failed to close bridge irb interface: %s", err)
	}

	if err := dp.dsTuntap.Close(); err != nil {
		return fmt.Errorf("failed to close dslite irb interface: %s", err)
	}

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

	if err := dp.setupDsLiteTapIf(c); err != nil {
		return err
	}

	if err := dp.setupBrMembers(c); err != nil {
		return err
	}

	if err := dp.setupIrb(c); err != nil {
		return err
	}

	dp.dhcpConfigFile = c.DhcpConfig

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

	dp.dsIfacePhy = new(dpIface)
	dp.dsIfacePhy.devname = dsl.DevName
	dp.dsIfacePhy.family = unix.AF_BRIDGE
	dp.dsIfacePhy.hwaddr = macaddr
	dp.dsIfacePhy.ipaddr = "::0/0"

	if err := bpf.AddPort(iface.Index, 0, macaddr, false); err != nil {
		return fmt.Errorf("failed to config bridging interface: %s: %s", dsl.DevName, err)
	}

	if err := bpf.AddDslitePhyIdx(iface.Index); err != nil {
		return fmt.Errorf("failed to register dslite phy ifidx: %s", err)
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

	iface, err := net.InterfaceByName(irb.DevName)
	if err != nil {
		return err
	}

	macaddr := [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		macaddr[idx] = uint8(b)
	}

	if err := bpf.AddL3Port(iface.Index, 1); err != nil {
		return fmt.Errorf("failed to put interface for irb:%s %s", irb.DevName, err)
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
	dp.brTuntap = tun
	dp.brIface.devname = irb.DevName
	dp.brIface.family = unix.AF_INET
	dp.brIface.hwaddr = macaddr
	dp.brIface.ipaddr = c.Irb.In4Addr

	return nil
}

func (dp *Datapath) setupDsLiteTapIf(c *DatapathConfig) error {
	tun, err := CreateTun(dsliteIface)
	if err != nil {
		return fmt.Errorf("failed to create dslite0: %s", err)
	}

	// wait for create completed
	time.Sleep(time.Second * 5)

	iface, err := net.InterfaceByName(dsliteIface)
	if err != nil {
		return fmt.Errorf("failed to fetch interface: %s", err)
	}

	macaddr := [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		macaddr[idx] = uint8(b)
	}

	if err := bpf.AddPort(iface.Index, 0, macaddr, true); err != nil {
		return fmt.Errorf("failed to config dslite interface: %s: %s", dsliteIface, err)
	}

	if err := bpf.AddL3Port(iface.Index, 2); err != nil {
		return fmt.Errorf("failed to put interface for %s %s", dsliteIface, err)
	}

	if err := tun.Up(); err != nil {
		return fmt.Errorf("failed to set up on %s: %s", dsliteIface, err)
	}

	if err := enableIPv6(dsliteIface, true); err != nil {
		return err
	}

	dp.dsIfaceIrb = new(dpIface)
	dp.dsTuntap = tun
	dp.dsIfaceIrb.devname = dsliteIface
	dp.dsIfaceIrb.family = unix.AF_INET6
	dp.dsIfaceIrb.hwaddr = macaddr
	dp.dsIfaceIrb.ipaddr = c.Irb.In4Addr

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
		briface.family = unix.AF_BRIDGE
		briface.ifindex = iface.Index
		briface.hwaddr = macaddr
		briface.ipaddr = "0.0.0.0/0"

		dp.brMember = append(dp.brMember, briface)
	}

	return nil
}

func (dp *Datapath) attachXdpFn() error {
	uplink_xdp_link, err := bpf.AttachXdpUplinkInFn(dp.dsIfacePhy.devname)
	if err != nil {
		return fmt.Errorf("failed to attach uplink_xdp: %s", err)
	}
	dp.uplink_xdp_link = &uplink_xdp_link

	for _, iface := range dp.brMember {
		l, err := bpf.AttachXdpBridgeInFn(iface.devname)
		if err != nil {
			return fmt.Errorf("failed to attach bridge_xdp: %s", err)
		}
		dp.bridge_xdp_links = append(dp.bridge_xdp_links, &l)
	}

	return nil
}

func (dp *Datapath) attachTcFn() error {
	if err := dp.attachTcUplinkFn(); err != nil {
		return fmt.Errorf("failed to attach uplink tc filter: %s", err)
	}

	if err := dp.attachTcDsliteFn(); err != nil {
		return fmt.Errorf("failed to attach dslite tc filter: %s", err)
	}

	if err := dp.attachTcPkt1Fn(); err != nil {
		return fmt.Errorf("failed to attach pkt1 tc filter: %s", err)
	}

	if err := dp.attachTcBrMemberFn(); err != nil {
		return fmt.Errorf("failed to attach bridge member tc filter: %s", err)
	}

	return nil
}

func (dp *Datapath) attachTcUplinkFn() error {
	dp.dsIfacePhy.tcFilters = make([]*datapathBpfFilter, 0)

	qdisc, err := setGenericQdisc(dp.dsIfacePhy.devname)
	if err != nil {
		return fmt.Errorf("failed to attach qdisc: %s", err)
	}
	dp.dsIfacePhy.tcQdisc = qdisc

	tcFilter1, err := setTcUplinkIn(dp.dsIfacePhy.devname)
	if err != nil {
		return fmt.Errorf("failed to attach ingress tc: %s", err)
	}
	dp.dsIfacePhy.tcFilters = append(dp.dsIfacePhy.tcFilters, tcFilter1)

	tcFilter2, err := setTcUplinkOut(dp.dsIfacePhy.devname)
	if err != nil {
		return fmt.Errorf("failed to attach egress tc: %s", err)
	}
	dp.dsIfacePhy.tcFilters = append(dp.dsIfacePhy.tcFilters, tcFilter2)

	return nil
}

func (dp *Datapath) attachTcDsliteFn() error {
	dp.dsIfaceIrb.tcFilters = make([]*datapathBpfFilter, 0)

	qdisc, err := setGenericQdisc(dp.dsIfaceIrb.devname)
	if err != nil {
		return fmt.Errorf("failed to attach qdisc: %s", err)
	}
	dp.dsIfaceIrb.tcQdisc = qdisc

	tcFilter1, err := setTcDsliteIn(dp.dsIfaceIrb.devname)
	if err != nil {
		return fmt.Errorf("failed to attach ingress tc: %s", err)
	}
	dp.dsIfaceIrb.tcFilters = append(dp.dsIfaceIrb.tcFilters, tcFilter1)

	tcFilter2, err := setTcDsliteOut(dp.dsIfaceIrb.devname)
	if err != nil {
		return fmt.Errorf("failed to attach egress tc: %s", err)
	}
	dp.dsIfaceIrb.tcFilters = append(dp.dsIfaceIrb.tcFilters, tcFilter2)

	return nil
}

func (dp *Datapath) attachTcPkt1Fn() error {
	dp.brIface.tcFilters = make([]*datapathBpfFilter, 0)

	qdisc, err := setGenericQdisc(dp.brIface.devname)
	if err != nil {
		return fmt.Errorf("failed to attach qdisc: %s", err)
	}
	dp.brIface.tcQdisc = qdisc

	tcFilter1, err := setTcPkt1In(dp.brIface.devname)
	if err != nil {
		return fmt.Errorf("failed to attach ingress tc: %s", err)
	}
	dp.brIface.tcFilters = append(dp.brIface.tcFilters, tcFilter1)

	tcFilter2, err := setTcPkt1Out(dp.brIface.devname)
	if err != nil {
		return fmt.Errorf("failed to attach egress tc: %s", err)
	}
	dp.brIface.tcFilters = append(dp.brIface.tcFilters, tcFilter2)

	return nil
}

func (dp *Datapath) attachTcBrMemberFn() error {
	for _, iface := range dp.brMember {
		iface.tcFilters = make([]*datapathBpfFilter, 0)

		qdisc, err := setGenericQdisc(iface.devname)
		if err != nil {
			return fmt.Errorf("failed to attach qdisc: %s", err)
		}
		iface.tcQdisc = qdisc

		tcFilter1, err := setTcBrMemberIn(iface.devname)
		if err != nil {
			return fmt.Errorf("failed to attach ingress tc: %s", err)
		}
		iface.tcFilters = append(iface.tcFilters, tcFilter1)

		tcFilter2, err := setTcBrMemberOut(iface.devname)
		if err != nil {
			return fmt.Errorf("failed to attach egress tc: %s", err)
		}
		iface.tcFilters = append(iface.tcFilters, tcFilter2)
	}

	return nil
}

func enableIPv6(name string, f bool) error {
	ipv6(name, f)
	ipv6Forwarding(name, f)
	ipv6SLAAC(name, f)
	ipv6AcceptRA(name, f)
	ipv6AddrGenMode(name, 1)

	return nil
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func ipv6AcceptRA(name string, ctrl bool) error {
	k := boolToByte(ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/accept_ra", []byte{k}, 0o644)
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func ipv6SLAAC(name string, ctrl bool) error {
	k := boolToByte(ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/autoconf", []byte{k}, 0o644)
}

// IPv6Forwarding enables/disables ipv6 forwarding for the interface.
func ipv6Forwarding(name string, ctrl bool) error {
	k := boolToByte(ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/forwarding", []byte{k}, 0o644)
}

func ipv6AddrGenMode(name string, mode int) error {
	m := byte(mode)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/addr_gen_mode", []byte{m}, 0o644)
}

// IPv6 enables/disable ipv6 for the interface.
func ipv6(name string, ctrl bool) error {
	k := boolToByte(!ctrl)
	return os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte{k}, 0o644)
}

func boolToByte(x bool) byte {
	if x {
		return 1
	}
	return 0
}
