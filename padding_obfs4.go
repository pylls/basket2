// padding_obfs4.go - Obfs4 padding implementation.
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
	"time"

	"git.schwanenlied.me/yawning/basket2.git/crypto/rand"
	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
	"git.schwanenlied.me/yawning/basket2.git/internal/discretedist"
)

const (
	// PaddingObfs4Burst is the obfs4 style padding algorithm, approximately
	// equivalent to the obfs4 `iat-mode=0` configuration.  No timing
	// obfuscation is done, and only a minimal amount of padding is
	// injected. on a per-burst basis.
	PaddingObfs4Burst PaddingMethod = 1

	// PaddingObfs4BurstIAT is the obfs4 style padding algorithm,
	// approximately equivalent to the obfs4 `iat-mode=1` configuration.
	// Randomized delay is inserted after each "burst" except if the padding
	// code thinks we are in the middle of a large burst.
	PaddingObfs4BurstIAT PaddingMethod = 2

	// Obfs4SeedLength is the length of the randomness to provide to the obfs4
	// padding algoriths to parameterize the distributions.
	Obfs4SeedLength = 32
)

type obfs4Padding struct {
	conn *commonConn

	burstDist *discretedist.DiscreteDist
	shortDist *discretedist.DiscreteDist
	delayDist *discretedist.DiscreteDist

	method PaddingMethod

	recvBuf bytes.Buffer
}

func (p *obfs4Padding) shortWrite(b []byte) (n int, err error) {
	// Special case len(p) being "short".
	//
	// This is kind of annoying to obfuscate, since sending 2 segments isn't
	// that different from sending 1 segment, and I assume the forces of evil
	// know how to count.
	//
	// So, attempt to be somewhat clever by disabling Nagle and sending short
	// records sized to something from the distribution.
	p.conn.setNagle(false)
	defer p.conn.setNagle(true)

	for remaining := len(b); remaining > 0; {
		// Sample from the "short" distribution, which omits values less than
		// the tentp framing+payload overhead.
		targetLen := p.shortDist.Sample(p.conn.mRNG)
		wrLen := targetLen - (tentp.FramingOverhead + tentp.PayloadOverhead)
		padLen := 0
		if remaining < wrLen {
			padLen = wrLen - remaining
			wrLen = remaining
		}

		if err := p.conn.SendRawRecord(framing.CmdData, b[n:n+wrLen], padLen); err != nil {
			return 0, err
		}
		n += wrLen
		remaining -= wrLen

		// Always inject a delay here, since discrete packets are wanted.
		delay := time.Duration(p.delayDist.Sample(p.conn.mRNG)) * time.Microsecond
		time.Sleep(delay)
	}

	return
}

func (p *obfs4Padding) largeWrite(b []byte) (n int, err error) {
	// Because the generic io.Copy() code is used, this gets called with up to
	// 32 kib of data.
	//
	// There's an interesting problem in that it *always* will get called with
	// 32 kib of data when doing bulk trasfers.
	//
	// If I could get Linux-ish TCP_INFO on all platforms, the obvious
	// solution would be to packetize things in userland and write based on
	// the available buffer size, but alas the *BSDs do not expose sufficient
	// information.
	//
	// TCP_CORK/TCP_NOPUSH would also be an option, but is not portable.
	//
	// The obfs4 version of this code buffered and sent everything all at
	// once, and I'm not sure if that's great because bulk transfers proably
	// stood out more (vs packetizing and writing to a connection with Nagel
	// enabled).

	remaining := len(b)
	isLargeWrite := remaining >= p.conn.copyBufferSize

	tailPadLen := p.burstDist.Sample(p.conn.mRNG)
	// tailPadLen += c.conn.maxRecordSize * c.conn.mRNG.Intn(3)

	// Write out each frame (with payload).
	for remaining > 0 {
		wrLen := p.conn.maxRecordSize
		padLen := 0
		if remaining <= wrLen {
			// Append the padding to the last frame.
			if tailPadLen < tentp.FramingOverhead+tentp.PayloadOverhead+wrLen {
				// Need to also pad out to a "full" record.
				tailPadLen += wrLen - remaining
			} else {
				// The tail of the burst counts towards part of the
				// padding.
				tailPadLen -= tentp.FramingOverhead + tentp.PayloadOverhead + remaining
			}

			padLen = tailPadLen
			wrLen = remaining
		}

		if err := p.conn.SendRawRecord(framing.CmdData, b[n:n+wrLen], padLen); err != nil {
			return 0, err
		}
		n += wrLen
		remaining -= wrLen
	}

	// Add a delay sampled from the IAT distribution if we do not suspect that
	// further data will be coming shortly.
	if p.method == PaddingObfs4BurstIAT && !isLargeWrite {
		delay := time.Duration(p.delayDist.Sample(p.conn.mRNG)) * time.Microsecond
		time.Sleep(delay)
	}
	return
}

func (p *obfs4Padding) Write(b []byte) (n int, err error) {
	if len(b) > p.conn.maxRecordSize {
		n, err = p.shortWrite(b)
	} else {
		n, err = p.largeWrite(b)
	}
	return
}

func (p *obfs4Padding) Read(b []byte) (int, error) {
	return paddingImplGenericRead(p.conn, &p.recvBuf, b)
}

func (p *obfs4Padding) OnClose() {
	p.recvBuf.Reset()
}

func newObfs4Padding(conn *commonConn, m PaddingMethod, seed []byte) (paddingImpl, error) {
	p := new(obfs4Padding)
	p.conn = conn
	p.method = m

	if len(seed) != Obfs4SeedLength {
		return nil, ErrInvalidPadding
	}

	// Initialize the deterministic random number generator and create the
	// discrete distributions.
	//
	// XXX: Cache the distributions? (Should these be biased?)
	r := rand.NewDRBG(seed)
	p.burstDist = discretedist.NewUniform(r, 1, p.conn.maxRecordSize, 100, false)
	p.shortDist = discretedist.NewUniform(r, tentp.FramingOverhead+tentp.PayloadOverhead, p.conn.maxRecordSize, 100, false)

	// IAT delay dist between 0 to 25 ms.
	// Note: This is always needed due to the short write obfsucation strategy.
	p.delayDist = discretedist.NewUniform(r, 0, 5*1000, 100, false)
	if !p.conn.isClient {
		// Add random [0, 2 * tau) read delay to mask timings on data
		// fed to the upstream as well.
		p.conn.enableReadDelay = true
	}

	// There's a fundemental mismatch between what our idea of a packet should
	// be and what should be sent over the wire due to unavailable/inaccurate
	// PMTU information, and variable length TCP headers (SACK options).
	//
	// So fuck it, enable Nagle's algorithm and hope that it helps to mask the
	// disconnect.
	conn.setNagle(true)

	return p, nil
}
