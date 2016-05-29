// plpmtud.go - Packetization Layer Path MTU Discovery.
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

// Package plpmtud allows force enabling Packetization Layer Path MTU
// Discovery for a given connection, if supported by the operating system.
package plpmtud

import (
	"net"
	"syscall"
)

var enableFn func(conn net.Conn) error

// Enable attempts to force enable RFC 4821 Packetization Layer Path MTU
// Discovery on a given connection.
func Enable(conn net.Conn) error {
	if enableFn == nil {
		return syscall.ENOTSUP
	}
	return enableFn(conn)
}
