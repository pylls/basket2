// tcpinfo.go - Low level TCP/IP information query.
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

// Package tcpinfo queries the per-connection low level TCP/IP metrics for
// useful information like congestion control values. It is currently only
// supported on Linux.
//
// See: https://trac.torproject.org/projects/tor/ticket/12890#comment:9
package tcpinfo

import (
	"os"
	"syscall"
)

var writeCapacityFn func(*os.File) (int, error)

// EstimatedWriteCapacity queries the kernel for the estimated data that can
// be enqueued for a write, that will be dispatched immediately without
// blocking.
func EstimatedWriteCapacity(f *os.File) (int, error) {
	if f == nil {
		return 0, syscall.EBADFD
	}
	if writeCapacityFn == nil {
		return 0, syscall.ENOTSUP
	}

	return writeCapacityFn(f)
}
