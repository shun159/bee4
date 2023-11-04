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
	"fmt"
	"net"

	"github.com/mistsys/tuntap"
)

type Tun struct {
	iface   *tuntap.Interface
	ifindex int
	macaddr [6]uint8
}

func CreateTun(name string) (*Tun, error) {
	tunif, err := tuntap.Open(name, tuntap.DevTap)
	if err != nil {
		return nil, fmt.Errorf("failed to create tun interface: %w", err)
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find tun interface: %w", err)
	}

	macaddr := [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		macaddr[idx] = uint8(b)
	}

	tun := &Tun{}
	tun.iface = tunif
	tun.ifindex = iface.Index
	tun.macaddr = macaddr

	return tun, nil
}

func (tun *Tun) SetAddress(s string) error {
	ipaddr, netaddr, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}
	return tun.iface.AddAddress(ipaddr, netaddr)
}

func (tun *Tun) Up() error {
	return tun.iface.Up()
}

func (tun *Tun) Close() error {
	return tun.iface.Close()
}
