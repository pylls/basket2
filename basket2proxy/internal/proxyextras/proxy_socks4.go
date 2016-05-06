// proxy_socks4.go - SOCKS4 proxy client.
// Copyright (C) 2014, 2016  Yawning Angel.
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
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"

	"golang.org/x/net/proxy"
)

// socks4Proxy is a SOCKS4 proxy.
type socks4Proxy struct {
	hostPort string
	username string
	forward  proxy.Dialer
}

const (
	socks4Version        = 0x04
	socks4CommandConnect = 0x01
	socks4Null           = 0x00
	socks4ReplyVersion   = 0x00

	socks4Granted                = 0x5a
	socks4Rejected               = 0x5b
	socks4RejectedIdentdFailed   = 0x5c
	socks4RejectedIdentdMismatch = 0x5d
)

func newSOCKS4(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(socks4Proxy)
	s.hostPort = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.username = uri.User.Username()
	}
	return s, nil
}

func (s *socks4Proxy) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("invalid network type")
	}

	// Deal with the destination address/string.
	ipStr, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("failed to parse destination IP")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("destination address is not IPv4")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	// Connect to the proxy.
	c, err := s.forward.Dial("tcp", s.hostPort)
	if err != nil {
		return nil, err
	}

	// Make/write the request:
	//  +----+----+----+----+----+----+----+----+----+----+....+----+
	//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	//  +----+----+----+----+----+----+----+----+----+----+....+----+

	req := make([]byte, 0, 9+len(s.username))
	req = append(req, socks4Version)
	req = append(req, socks4CommandConnect)
	req = append(req, byte(port>>8), byte(port))
	req = append(req, ip4...)
	if s.username != "" {
		req = append(req, s.username...)
	}
	req = append(req, socks4Null)
	_, err = c.Write(req)
	if err != nil {
		c.Close()
		return nil, err
	}

	// Read the response:
	// +----+----+----+----+----+----+----+----+
	// | VN | CD | DSTPORT |      DSTIP        |
	// +----+----+----+----+----+----+----+----+

	var resp [8]byte
	_, err = io.ReadFull(c, resp[:])
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp[0] != socks4ReplyVersion {
		c.Close()
		return nil, errors.New("proxy returned invalid SOCKS4 version")
	}
	if resp[1] != socks4Granted {
		c.Close()
		return nil, fmt.Errorf("proxy error: %s", socks4ErrorToString(resp[1]))
	}

	return c, nil
}

func socks4ErrorToString(code byte) string {
	switch code {
	case socks4Rejected:
		return "request rejected or failed"
	case socks4RejectedIdentdFailed:
		return "request rejected becasue SOCKS server cannot connect to identd on the client"
	case socks4RejectedIdentdMismatch:
		return "request rejected because the client program and identd report different user-ids"
	default:
		return fmt.Sprintf("unknown failure code %x", code)
	}
}

func init() {
	// Despite the scheme name, this really is SOCKS4.
	proxy.RegisterDialerType("socks4a", newSOCKS4)
}
