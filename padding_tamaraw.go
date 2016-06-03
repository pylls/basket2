// padding_tamaraw.go - Tamaraw padding implementation.
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
	"io"
	"net"
	"os"
	"sync"
	"time"

	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
	"git.schwanenlied.me/yawning/basket2.git/internal/tcpinfo"
)

const (
	// PaddingTamaraw is an implementation of a variant of the Tamaraw
	// website fingerprinting defense as specified in "A Systematic
	// Approach to Developing and Evaluating Website Fingerprinting
	// Defenses", with some ideas taken from CS-BuFLO  This method
	// should be avoided for "obfuscation" purposes as it is about
	// as subtle as going over to the DPI box and smashing it with
	// a brick, and guzzles bandwith like no tomorrow.
	//
	// Parameters are taken from Wang, T., "Website Fingerprinting:
	// Attacks and Defenses", and are tuned assuming the client is
	// primarily interested in things like web browsing, and that the
	// link MTU is 1500 bytes.
	PaddingTamaraw PaddingMethod = 0xf0
)

type tamarawPadding struct {
	sync.WaitGroup

	conn  *commonConn
	fConn *os.File

	sendChan chan []byte

	lPpad int
	lSeg  int
	rho   int

	recvBuf bytes.Buffer
}

func (p *tamarawPadding) writeWorker() {
	defer p.Done()

	for {
		// Blocking channel read, since the write worker is idling (waiting
		// on next burst).
		b, ok := <-p.sendChan
		if !ok {
			// The send channel is closed, connection must be being torn down.
			break
		}
		if err := p.workerOnBurst(b); err != nil {
			// All errors are fatal, and no further writes are possible.
			break
		}
	}
}

func (p *tamarawPadding) workerOnBurst(b []byte) error {
	// CS-BuFLO uses 2 seconds, basket1 uses 250 ms...  Not sure what the
	// best thing to do here is.  Shorter is better for efficiency, but
	// I suspect this doesn't matter too much.
	const minIdleTime = 50 * time.Millisecond

	// Unblocked due to data entering the send channel, indicating the start
	// of a burst.
	nSegs := 0
	nPaddingSegs := 0
	canIdleAt := time.Now().Add(minIdleTime)

	sleepRho := func() {
		// Instead of scheduling packets at absolute intervals, draw from
		// the CS-BuFLO design and sample a random value [0, 2*rho), to
		// avoid leaking load information.
		//
		// CS-BuFLO uses an adaptive value for `rho`, which may be a good
		// idea...
		rho := time.Duration(p.conn.mRNG.Intn(2*p.rho)) * time.Microsecond
		time.Sleep(rho)
	}

	for {
		// Check channel capacity, if supported.
		//
		// Tamaraw will happily choke itself by clogging up the link with
		// padding, CS-BuFLO will start to back off when the send socket
		// buffer is full.  Follow in the footsteps of the original basket
		// code and use TCP_INFO (or similar).
		if p.fConn != nil {
			linkCapacity, err := tcpinfo.EstimatedWriteCapacity(p.fConn)
			if err == nil {
				const hdrOverhead = 20 + 20 // Assuming IPv4 is prolly ok.
				const tentOverhead = tentp.FramingOverhead + tentp.PayloadOverhead
				if linkCapacity < hdrOverhead+tentOverhead+p.lPpad {
					// Either insufficient buffer space, or the link is
					// snd_cwnd bound.  Writes now will just block/get
					// queued, so there's no point.
					sleepRho()
					continue
				}
			}
		}

		// Send the data (or pure padding), and update accounting.
		padLen := p.lPpad - len(b)
		if err := p.conn.SendRawRecord(framing.CmdData, b, padLen); err != nil {
			return err
		}
		if b == nil {
			nPaddingSegs++
		}
		nSegs++

		// Delay after the send.
		sleepRho()

		// Obtain further data from the channel.
		b = nil
		ok := false
		select {
		case b, ok = <-p.sendChan:
			canIdleAt = time.Now().Add(minIdleTime)
		case <-time.After(0):
			// Channel empty.
			if nPaddingSegs > 0 && (nSegs%p.lSeg == 0) && time.Now().After(canIdleAt) {
				// We have sent at least 1 segment of padding, are exactly at
				// a multiple of Lseg, and the channel has not provided us
				// with data to send for minIdleTime ms.  Consider the burst
				// finished.
				return nil
			}
			ok = true
		}
		if !ok {
			// Channel is closed, return, and allow the caller to clean up.
			// XXX: Should I attempt to pad out the final burst?
			return io.EOF
		}
	}
}

func (p *tamarawPadding) Write(b []byte) (n int, err error) {
	// The OnClose() hook will close the sendChan, which is a problem
	// if we are in the packetization loop.  Catch this case and
	// gracefully deal with it.
	defer func() {
		if r := recover(); r != nil {
			err = io.ErrShortWrite
		}
	}()

	// Break up the write into lPpad sized chunks.
	for toSend := len(b); toSend > 0; {
		wrLen := p.lPpad
		if wrLen > toSend {
			// Short is ok, the worker will pad it out.
			wrLen = toSend
		}
		frame := make([]byte, wrLen)
		copy(frame, b[n:n+wrLen])

		p.sendChan <- frame

		n += wrLen
		toSend -= wrLen
	}
	return
}

func (p *tamarawPadding) Read(b []byte) (int, error) {
	return paddingImplGenericRead(p.conn, &p.recvBuf, b)
}

func (p *tamarawPadding) OnClose() {
	p.recvBuf.Reset()

	// Close the send channel and wait for the worker to finish.
	if p.fConn != nil {
		p.fConn.Close()
	}
	close(p.sendChan)
	p.Wait()

}

func newTamarawPadding(conn *commonConn, isClient bool) paddingImpl {
	p := new(tamarawPadding)
	p.conn = conn
	p.sendChan = make(chan []byte, 64)
	if tConn, ok := (conn.rawConn).(*net.TCPConn); ok {
		if fConn, err := tConn.File(); err == nil {
			p.fConn = fConn
		}
	}
	p.conn.enforceRecordSize = true

	// The thesis that evaluates this suggests:
	//
	//  Client: rho: 20 ms, l ppad: 800 bytes, Lseg: 500 segments
	//  Server: rho: 5 ms, l ppad: 1500 bytes, Lseg: 500 segments
	//
	// The l ppad numbers were chosed for a non-tor data set, which is
	// a poor value for basket2 given that Tor for the most part uses
	// fixed length cells.
	//
	// Lseg = 100 gives a maximum attacker accuracy of 0.59, while 500
	// reduces that to ~0.35.

	if isClient {
		// Tune for "short infrequent bursts".
		//
		// The CS-BuFLO's early termination feature suggests that the tail
		// end of the padding doesn't gain much, so lowering Lseg may be
		// acceptable.
		p.rho = 20 * 1000 // ms -> usec
		p.lPpad = 543     // Tuned for a single Tor cell in a TLS record.
		p.lSeg = 100
	} else {
		// Tune for "bulk data transfer".
		p.rho = 5 * 1000               // ms -> usec
		p.lPpad = p.conn.maxRecordSize // Could lower it by 2 for PPPoE links.
		p.lSeg = 100

		// Random read side delivery jitter.
		p.conn.enableReadDelay = true

		// Clamp acceptable packets to the client side lPpad value.
		p.conn.maxRecordSize = 543
	}

	p.Add(1)
	go p.writeWorker()

	return p
}
