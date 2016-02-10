// const.go - Various constants.
// Copyright (C) 2015-2016  Yawning Angel.
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

package framing

// The various commands for each message carried via the framing layer.  Each
// command is 7 bits, with the most significant bit, signifying the direction.
const (
	CmdData = iota
	CmdHandshake

	CmdServer     = 0x80
	CmdServerMask = 0x7f
)

const (
	// MaxIPv4TcpSize is the typical Ethernet IPv4 TCP MSS.
	MaxIPv4TcpSize = 1500 - (20 + 20)

	// MaxIPv6TcpSize is the typical Ethernet IPv6 TCP MSS.
	MaxIPv6TcpSize = 1500 - (40 + 20)
)
