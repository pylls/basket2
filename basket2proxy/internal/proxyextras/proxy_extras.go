// proxy_extras.go - Proxy extensions.
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

package proxyextras

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"

	"golang.org/x/net/proxy"
)

var initOnce sync.Once

func IsURLValid(url *url.URL) bool {
	initBackends()

	switch url.Scheme {
	case "http", "socks4a", "socks5":
	default:
		return false
	}

	if _, err := resolveAddrStr(url.Host); err != nil {
		return false
	}

	return true
}

func resolveAddrStr(addrStr string) (*net.TCPAddr, error) {
	ipStr, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, err
	}

	if ipStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a host part", addrStr))
	}
	if portStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a port part", addrStr))
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, net.InvalidAddrError(fmt.Sprintf("not an IP string: %q", ipStr))
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, net.InvalidAddrError(fmt.Sprintf("not a Port string: %q", portStr))
	}

	return &net.TCPAddr{IP: ip, Port: int(port), Zone: ""}, nil
}

func initBackends() {
	initOnce.Do(func() {
		proxy.RegisterDialerType("http", newHTTP)
		proxy.RegisterDialerType("socks4a", newSOCKS4)
	})
}
