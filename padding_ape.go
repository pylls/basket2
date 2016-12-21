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
	"io"
	mrand "math/rand"
	"sync"
	"time"

	rng "github.com/leesper/go_rng"
	"github.com/pylls/basket2/framing"
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
	conn    *commonConn
	recvBuf bytes.Buffer

	padlen int

	onSendChan chan bool
	onRecvChan chan bool

	apWG      sync.WaitGroup
	apDieChan chan bool

	writeChan chan []byte
	writeWG   sync.WaitGroup
}

// an adaptive padding (AP) state machine (see Figure 2 in "Toward an
// Efficient Website Fingerprinting Defense") for data events.
// channel data triggers on a data sent / received (depending on use-case)
func (p *apePadding) ap(data chan bool,
	hb, hg func() (<-chan time.Time, bool)) {
	type apState int // the different AP states
	const (
		stateWait  apState = iota // idle starting state, waiting for data
		stateBurst                // burst mode, waiting for burst to finish
		stateGap                  // gap mode, sending dummy data
	)

	defer p.apWG.Done() // report done when done

	var state apState          // our state
	var timer <-chan time.Time // current running timer
	var inf bool               // infinity bin flag

	for { // event driven loop until we should die
		select {
		case <-p.apDieChan: // connection being closed
			return

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
				p.writeChan <- nil
				if timer, inf = hg(); inf { // sample gap histogram, back to burst?
					state = stateBurst
				}
			case stateGap: // send dummy, sample gap histogram
				p.writeChan <- nil
				if timer, inf = hg(); inf { // sample gap histogram, back to burst?
					state = stateBurst
				}
			}
		}
	}
}

func (p *apePadding) writeWorker() {
	defer p.writeWG.Done()

	for {
		b, ok := <-p.writeChan
		if !ok { // channel closed
			break
		}
		if err := p.conn.SendRawRecord(framing.CmdData,
			b, p.padlen-len(b)); err != nil { // errors are fatal
			break
		}
	}
}

func (p *apePadding) Write(b []byte) (n int, err error) {
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
		wrLen := p.padlen
		if wrLen > toSend {
			// Short is ok, the worker will pad it out.
			wrLen = toSend
		}
		frame := make([]byte, wrLen)
		copy(frame, b[n:n+wrLen])

		p.writeChan <- frame
		p.onSendChan <- true

		n += wrLen
		toSend -= wrLen
	}
	return
}

func (p *apePadding) Read(b []byte) (n int, err error) {
	// This buffering strategy will return short reads, since a new record
	// is only consumed off the network once the entirety of the previous
	// record has been returned.  A goroutine that consumes off the network
	// instead would minimize this, but this is simple and prevents rampant
	// runaway buffer growth.

	// Refill the receive buffer as needed...
	for p.recvBuf.Len() == 0 && err == nil {
		// ... by reading the next record off the network...
		var cmd byte
		var msg []byte
		cmd, msg, err = p.conn.RecvRawRecord()
		if err != nil {
			break
		}
		p.onRecvChan <- true
		if cmd != framing.CmdData {
			return 0, ErrInvalidCmd
		}

		// ... and stashing it in the buffer.
		if len(msg) > 0 {
			p.recvBuf.Write(msg)
		}
	}

	// Service the Read using buffered payload.
	if p.recvBuf.Len() > 0 && err == nil {
		n, _ = p.recvBuf.Read(b)
	}
	return
}

func (p *apePadding) OnClose() {
	// tell APs to die and wait
	p.apDieChan <- true
	p.apDieChan <- true
	p.apWG.Wait()

	// wait for writeChan to finish
	close(p.writeChan)
	p.writeWG.Wait()
	p.recvBuf.Reset()
}

func newApePadding(conn *commonConn) paddingImpl {
	p := new(apePadding)
	p.padlen = 543 // Tuned for a single Tor cell in a TLS record.
	p.conn = conn
	p.conn.enforceRecordSize = true // TODO: think about Nagle's
	p.conn.enableReadDelay = true

	p.writeChan = make(chan []byte, 128)
	p.onSendChan = make(chan bool, 128)
	p.onRecvChan = make(chan bool, 128)
	p.apDieChan = make(chan bool, 2)

	p.apWG.Add(2) // we have two APs launched below

	// Below we set the distributions, and this is where APE shows that it's a
	// primitive version of WTF-PAD: optimal distributions is _the_ problem with
	// deploying WTF-PAD, so in search for a "good enough" solution APE creates
	// randomised (biased) distributions like Obfs4 and ScrambleSuit per
	// connection.
	if conn.isClient {
		// assumptions for clients (HTTP traffic):
		// - a client is expected to send primarily HTTP requests
		// - a faked response to receiving data is basically the time it takes to
		//   move the data through the stack to the application and back,
		//   which is a relatively fast (compared to network)

		// the time to process data application-side: rarely more than a ms
		// when we send data, send few packets due to being a client, so high
		// probability to "exit" in our AP
		hb := makeDist(2.5, 0.8, 0.65, 1000.0, conn.mRNG)
		hg := makeDist(0.25, 0.5, 0.45, 1000.0, conn.mRNG)
		go p.ap(p.onSendChan, hb, hg)
		go p.ap(p.onRecvChan, hb, hg)
	} else {
		// assumptions for servers:
		// - a server is expected to send more data than it receives
		// - a fake response to receiving data is basically the roundtrip for three
		//   hops in the Tor network (middle -> exit -> destination), and we know
		//   that most nodes in the network (by bandwidth) are located in Europe
		//   and the US. This is in the order of 10s or 100s of ms
		// - when adding another burst after another (when sending data), the
		//   IAT is in the order of 0.1 to 1 ms

		// when we send data as a reply, this can be significantly sized, so a
		// smaller chance to exit
		hg := makeDist(0.25, 0.8, 0.3, 100.0, conn.mRNG)
		go p.ap(p.onSendChan, makeDist(0.25, 0.5, 0.5, 20*1000.0, conn.mRNG), hg)
		go p.ap(p.onRecvChan, makeDist(0.05, 0.4, 0.5, 1000.0, conn.mRNG), hg)
	}

	p.writeWG.Add(1)
	go p.writeWorker()

	return p
}

func makeDist(mean, stddev, exitProbability, order float64,
	r *mrand.Rand) func() (<-chan time.Time, bool) {

	// we reduce mean by up to 50%, increasing padding: we do not want to increase
	// the mean since this shifts the distribution towards being easier to
	// distinguish (see WTFD-PAD paper)
	for {
		f := r.Float64()
		if f < 0.5 {
			mean *= (1.0 - f)
			break
		}
	}

	// randomize stddev, exitProbability and order (because why not?)
	vary := func(d, value float64) float64 {
		for {
			f := r.Float64()
			if f < d {
				return value * (1.0 + f)
			}
			if f > 1-d {
				return value * f
			}
		}
	}
	stddev = vary(0.25, stddev)
	exitProbability = vary(0.1, exitProbability)
	order = vary(0.5, order)

	// create our lognormal distribution that returns a timer or a flag indicating
	// that the adaptive padding should change state (ininity bin in WTF-PAD)
	ln := rng.NewLognormalGenerator(r.Int63())
	return func() (<-chan time.Time, bool) {
		if exitProbability > r.Float64() { // time to exit?
			return nil, true
		}

		// sample from our lognormal distribution
		return time.After(time.Duration(ln.Lognormal(mean, stddev)*order) * time.Microsecond), false
	}
}
