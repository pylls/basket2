// proxy_http.go - HTTP CONNECT proxy client.
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
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// httpProxy is a HTTP connect proxy.
type httpProxy struct {
	hostPort string
	haveAuth bool
	username string
	password string
	forward  proxy.Dialer
}

func newHTTP(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(httpProxy)
	s.hostPort = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.haveAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}

	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the http client connection.
	c, err := s.forward.Dial("tcp", s.hostPort)
	if err != nil {
		return nil, err
	}
	conn := new(httpConn)
	conn.httpConn = httputil.NewClientConn(c, nil)
	conn.remoteAddr, err = net.ResolveTCPAddr(network, addr)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}

	// HACK HACK HACK HACK.  http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	req.Close = false
	if s.haveAuth {
		req.SetBasicAuth(s.username, s.password)
	}
	req.Header.Set("User-Agent", "")

	resp, err := conn.httpConn.Do(req)
	if err != nil && err != httputil.ErrPersistEOF {
		conn.httpConn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.httpConn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	conn.hijackedConn, conn.staleReader = conn.httpConn.Hijack()
	return conn, nil
}

type httpConn struct {
	remoteAddr   *net.TCPAddr
	httpConn     *httputil.ClientConn
	hijackedConn net.Conn
	staleReader  *bufio.Reader
}

func (c *httpConn) Read(b []byte) (int, error) {
	if c.staleReader != nil {
		if c.staleReader.Buffered() > 0 {
			return c.staleReader.Read(b)
		}
		c.staleReader = nil
	}
	return c.hijackedConn.Read(b)
}

func (c *httpConn) Write(b []byte) (int, error) {
	return c.hijackedConn.Write(b)
}

func (c *httpConn) Close() error {
	return c.hijackedConn.Close()
}

func (c *httpConn) LocalAddr() net.Addr {
	return c.hijackedConn.LocalAddr()
}

func (c *httpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *httpConn) SetDeadline(t time.Time) error {
	return c.hijackedConn.SetDeadline(t)
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	return c.hijackedConn.SetReadDeadline(t)
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return c.hijackedConn.SetWriteDeadline(t)
}
