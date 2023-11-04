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

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/shun159/hoge/internal/bpf"
	"github.com/shun159/hoge/internal/datapath"
)

func handleSignal() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to bump memlock:%+v", err)
	}

	if err := bpf.LoadBPF(); err != nil {
		log.Fatal(err)
	}

	s := flag.String("f", "", "config file path")
	flag.Parse()

	dp, err := datapath.Open(*s)
	if err != nil {
		log.Fatalf("failed to open datapath: %s", err)
	}
	defer dp.Close()

	dp.Start()

	handleSignal()
}
