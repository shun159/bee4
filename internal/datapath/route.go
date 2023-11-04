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
	"net/netip"

	"github.com/shun159/hoge/internal/bpf"
)

type In4RouteKey struct {
	PrefixLen uint32
	Addr      uint32
}

type In4RouteNh struct {
	NhType uint8
	_      [3]byte
	Addr   uint32
}

func AddIn4Route(prefix, nexthop string, routeType int) error {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("failed to parse prefix: %w", err)
	}

	n, err := netip.ParseAddr(nexthop)
	if err != nil {
		return fmt.Errorf("failed to parse nexthop: %w", err)
	}

	pAddr := [4]byte{}
	for idx, b := range p.Addr().As4() {
		pAddr[idx] = b
	}

	pref := binary.LittleEndian.Uint32(pAddr[:])
	prefLen := uint32(p.Bits())

	nAddr := [4]byte{}
	for idx, b := range n.As4() {
		nAddr[idx] = b
	}
	nhAddr := binary.LittleEndian.Uint32(nAddr[:])

	if err := bpf.AddRoute(prefLen, pref, routeType, nhAddr); err != nil {
		return fmt.Errorf("failed to add route entry(%s, %s):%w", prefix, nexthop, err)
	}

	return nil
}
