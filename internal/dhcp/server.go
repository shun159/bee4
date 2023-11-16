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

package dhcp

import (
	"log"
	"time"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/server"

	"github.com/coredhcp/coredhcp/plugins"
	pl_dns "github.com/coredhcp/coredhcp/plugins/dns"
	pl_file "github.com/coredhcp/coredhcp/plugins/file"
	pl_leasetime "github.com/coredhcp/coredhcp/plugins/leasetime"
	pl_mtu "github.com/coredhcp/coredhcp/plugins/mtu"
	pl_nbp "github.com/coredhcp/coredhcp/plugins/nbp"
	pl_netmask "github.com/coredhcp/coredhcp/plugins/netmask"
	pl_prefix "github.com/coredhcp/coredhcp/plugins/prefix"
	pl_range "github.com/coredhcp/coredhcp/plugins/range"
	pl_router "github.com/coredhcp/coredhcp/plugins/router"
	pl_searchdomains "github.com/coredhcp/coredhcp/plugins/searchdomains"
	pl_serverid "github.com/coredhcp/coredhcp/plugins/serverid"
	pl_sleep "github.com/coredhcp/coredhcp/plugins/sleep"
	pl_staticroute "github.com/coredhcp/coredhcp/plugins/staticroute"
)

var desiredPlugins = []*plugins.Plugin{
	&pl_dns.Plugin,
	&pl_file.Plugin,
	&pl_leasetime.Plugin,
	&pl_mtu.Plugin,
	&pl_nbp.Plugin,
	&pl_netmask.Plugin,
	&pl_prefix.Plugin,
	&pl_range.Plugin,
	&pl_router.Plugin,
	&pl_searchdomains.Plugin,
	&pl_serverid.Plugin,
	&pl_sleep.Plugin,
	&pl_staticroute.Plugin,
}

func Serve(filepath string) error {
	config, err := config.Load(filepath)
	if err != nil {
		return err
	}

	for _, plugin := range desiredPlugins {
		if err := plugins.RegisterPlugin(plugin); err != nil {
			log.Fatalf("Failed to register plugin '%s': %v", plugin.Name, err)
		}
	}

	srv, err := server.Start(config)
	if err != nil {
		return err
	}

	if err := srv.Wait(); err != nil {
		return err
	}

	time.Sleep(time.Second)

	return nil
}
