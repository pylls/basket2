// padding_impl.go - Padding implementation common routines.
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

package basket2

import (
	"bytes"

	"github.com/pylls/basket2/framing"
)

type paddingImpl interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	OnClose()
}

func paddingImplGenericRead(conn *commonConn, recvBuf *bytes.Buffer, b []byte) (n int, err error) {
	// This buffering strategy will return short reads, since a new record
	// is only consumed off the network once the entirety of the previous
	// record has been returned.  A goroutine that consumes off the network
	// instead would minimize this, but this is simple and prevents rampant
	// runaway buffer growth.

	// Refill the receive buffer as needed...
	for recvBuf.Len() == 0 && err == nil {
		// ... by reading the next record off the network...
		var cmd byte
		var msg []byte
		cmd, msg, err = conn.RecvRawRecord()
		if err != nil {
			break
		}
		if cmd != framing.CmdData {
			return 0, ErrInvalidCmd
		}

		// ... and stashing it in the buffer.
		if len(msg) > 0 {
			recvBuf.Write(msg)
		}
	}

	// Service the Read using buffered payload.
	if recvBuf.Len() > 0 && err == nil {
		n, _ = recvBuf.Read(b)
	}
	return
}
