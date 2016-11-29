// padding_ape.go - Null padding implementation.
// Copyright (C) 2016 Tobias Pulls.
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
	"time"

	"github.com/pylls/basket2/framing"
	"github.com/pylls/basket2/framing/tentp"
)

const (
	// PaddingApe is the Adaptive Padding Early (APE) padding method,
	// designed to be an early implementation of an adaptive padding
	// based defense against website fingerprinting (WF) attacks,
	// related to the WTF-PAD defense by Juarez et al..
	// APE tries to make simple, but probably náive, changes
	// to the complex WTF-PAD design to be an improvement (in terms of overhead)
	// over Tamaraw while still offering significantly better protection
	// than the obfs4 censorship resistance methods against WF attacks.
	// Once WTF-PAD has a practical approach to, e.g. histogram generation,
	// APE should be abandoned.
	PaddingApe PaddingMethod = 0xa0
)

type apePadding struct {
	conn *commonConn

	recvBuf bytes.Buffer
	padlen  int
}

// an adaptive padding (AP) state machine (see Figure 2 in "Toward an
// Efficient Website Fingerprinting Defense") for data events.
// Channels:
// data - triggers on a data to send / received (depending on use-case)
// die - connection is being torn down
func (p *apePadding) ap(data, die chan bool,
	hb, hg func() (<-chan time.Time, bool)) {
	type apState int // the different AP states
	const (
		stateWait  apState = iota // idle starting state, waiting for data
		stateBurst                // burst mode, waiting for burst to finish
		stateGap                  // gap mode, sending dummy data
	)

	var state apState          // our state
	var timer <-chan time.Time // current running timer
	var inf bool               // infinity bin flag

	for { // event driven loop until we should die
		select {
		case <-data: // data sent/received
			if state == stateWait || state == stateGap {
				state = stateBurst // enter burst mode
			}
			if timer, inf = hb(); inf { // sample burst histogram, back to waiting?
				state = stateWait
			}

		case <-timer: // timer expired
			switch state {
			case stateBurst: // transition to gap mode
				state = stateGap
				timer = time.After(0) // HACK: triggers stateGap below
			case stateGap: // send dummy, sample gap histogram
				if err := p.sendDummy(); err != nil {
					// TODO: should this be logged somewhere?
					return // all errors to write are fatal, blocking future writes
				}
				if timer, inf = hg(); inf { // sample gap histogram, back to burst?
					state = stateBurst
				}
			}

		case <-die: // connection being closed
			return
		}
	}
}

func (p *apePadding) sendDummy() error {
	return p.conn.SendRawRecord(framing.CmdData, nil, p.padlen)
}

func (p *apePadding) Write(b []byte) (int, error) {
	// Break the write up into records, and send them out on the wire.  The
	// kernel is better at breaking writes into appropriate sized packets than
	// any userland app will be (at least with TCP), so use the maximum record
	// size permitted by the framing layer as padding isn't a concern.
	for off, left := 0, len(b); left > 0; {
		wrSize := tentp.MaxPlaintextRecordSize
		if left < wrSize {
			wrSize = left
		}

		if err := p.conn.SendRawRecord(framing.CmdData, b[off:off+wrSize], 0); err != nil {
			return 0, err
		}

		off += wrSize
		left -= wrSize
	}

	return len(b), nil
}

func (p *apePadding) Read(b []byte) (n int, err error) {
	return paddingImplGenericRead(p.conn, &p.recvBuf, b)
}

func (p *apePadding) OnClose() {
	p.recvBuf.Reset()
}

func newApePadding(conn *commonConn) paddingImpl {
	p := new(apePadding)
	p.conn = conn

	// The net package default beahvior is to disable Nagle's algorithm,
	// but it's more efficient to enable it, since the kernel will handle
	// framing better than we can, especially for this use case.
	conn.setNagle(true)

	return p
}
