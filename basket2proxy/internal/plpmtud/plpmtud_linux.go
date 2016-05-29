// pmtud_linux.go - Linux PLPMTUD.
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

// +build linux

package plpmtud

import (
	"net"
	"syscall"
)

func enableImpl(conn net.Conn) error {
	tConn, ok := (conn).(*net.TCPConn)
	if !ok {
		return syscall.EBADFD
	}

	// The net.TCPConn.File() documentation has warnings about changes made
	// to one copy of the socket potentially not being propagated to the
	// other, but at least on my system, it appears to do the right thing.
	//
	// The alternative would be to use reflection to extract the fd from the
	// guts of the runtime internals like thus:
	//
	// int(reflect.ValueOf(tConn).Elem().FieldByName("fd").Elem().FieldByName("sysfd").Int())
	//
	// See: https://github.com/golang/go/issues/9661

	// The `dup()` call is somewhat wasteful, but this is less fragile than
	// abusing reflection.
	fConn, err := tConn.File()
	if err != nil {
		return err
	}
	defer fConn.Close()

	// ip(7) only references SOCK_DGRAM and SOCK_RAW, but this also applies
	// to SOCK_STREAM.  It's utterly horrid prior to Linux 4.1.x, but may
	// be better than nothing when needed.
	fd := int(fConn.Fd())
	return syscall.SetsockoptByte(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
}

func init() {
	enableFn = enableImpl
}
