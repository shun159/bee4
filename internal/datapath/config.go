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
	"encoding/json"
	"fmt"
	"os"
)

type RoutingEntry struct {
	Dst     string `json:"dst"`
	NextHop string `json:"nexthop"`
}

type RbIface struct {
	DevName string `json:"dev_name"`
	In4Addr string `json:"in4addr"`
}

type DsIface struct {
	DevName string `json:"dev_name"`
}

type DatapathConfig struct {
	Routes   []RoutingEntry `json:"routes"`
	Irb      RbIface        `json:"rb"`
	Dslite   DsIface        `json:"ds"`
	BrMember []string       `json:"br_ifaces"`
}

// private functions

func parseConfigJSON(filename string) (*DatapathConfig, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config json file: %w", err)
	}

	var c DatapathConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("failed to decode config JSON file: %w", err)
	}

	return &c, nil
}
