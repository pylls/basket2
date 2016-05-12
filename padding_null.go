// padding_null.go - Null padding implementation.
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

	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
)

const (
	// PaddingNull is the "NULL" padding algorithm.  No packet length or
	// timing obfuscation will be done beyond the standard handshake
	// obfuscation.  This method SHOULD NOT currently be used, and is only
	// provided for testing, and in anticipation of Tor getting it's own
	// circuit level padding implementation.
	PaddingNull PaddingMethod = 0
)

type nullPadding struct {
	conn *commonConn

	recvBuf bytes.Buffer
}

func (c *nullPadding) Write(p []byte) (int, error) {
	// Break the write up into records, and send them out on the wire.  The
	// kernel is better at breaking writes into appropriate sized packets than
	// any userland app will be (at least with TCP), so use the maximum record
	// size permitted by the framing layer as padding isn't a concern.
	for off, left := 0, len(p); left > 0; {
		wrSize := tentp.MaxPlaintextRecordSize
		if left < wrSize {
			wrSize = left
		}

		if err := c.conn.SendRawRecord(framing.CmdData, p[off:off+wrSize], 0); err != nil {
			return 0, err
		}

		off += wrSize
		left -= wrSize
	}

	return len(p), nil
}

func (c *nullPadding) Read(p []byte) (n int, err error) {
	return paddingImplGenericRead(c.conn, &c.recvBuf, p)
}

func (c *nullPadding) OnClose() {
	c.recvBuf.Reset()
}

func newNullPadding(conn *commonConn) paddingImpl {
	c := new(nullPadding)
	c.conn = conn

	// The net package default beahvior is to disable Nagle's algorithm,
	// but it's more efficient to enable it, since the kernel will handle
	// framing better than we can, especially for this use case.
	conn.setNagle(true)

	return c
}
