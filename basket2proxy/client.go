// client.go - Tor Pluggable Transport client implementation.
// Copyright (C) 2016  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"net"
	"net/url"

	"git.schwanenlied.me/yawning/basket2.git/basket2proxy/internal/log"

	"git.torproject.org/pluggable-transports/goptlib.git"
)

func clientAcceptLoop(ln net.Listener, proxyURL *url.URL) {

}

func clientInit() []net.Listener {
	ci, err := pt.ClientSetup(nil)
	if err != nil {
		log.Errorf("Failed to initialize as client: %v", err)
		return nil
	}

	// Assume for now that the proxy URL is well formed.
	if ci.ProxyURL != nil {
		pt.ProxyDone()
	}

	// Iterate over the requested transports and spawn SOCKS listeners.
	var listeners []net.Listener
	for _, name := range ci.MethodNames {
		if name != transportName {
			pt.CmethodError(name, "no such transport is supported")
			continue
		}

		ln, err := pt.ListenSocks("tcp", socksAddr)
		if err != nil {
			pt.CmethodError(name, err.Error())
			continue
		}
		go clientAcceptLoop(ln, ci.ProxyURL)
		pt.Cmethod(name, ln.Version(), ln.Addr())
		listeners = append(listeners, ln)
	}
	pt.CmethodsDone()

	return listeners
}
