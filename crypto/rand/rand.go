// rand.go - Random number generator.
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

// Package rand exposes a math/rand.Rand instance that is backed by the
// system entropy source, with SipHash-2-4 based whitening.
package rand

import (
	csrand "crypto/rand"
	"encoding/binary"
	"hash"
	"io"
	"math/rand"
	"sync"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"github.com/dchest/siphash"
)

var (
	usingImprovedSyscallEntropy = false

	// Reader is a conveninece alias for crypto/rand.Reader.
	Reader = csrand.Reader
)

type sipSource struct {
	sync.Mutex
	h   hash.Hash
	off int
}

func (s *sipSource) Int63() int64 {
	// Obtain additional entropy from the system source.
	var entropy [siphash.BlockSize]byte
	if _, err := io.ReadFull(Reader, entropy[:]); err != nil {
		panic("sipSource: failed to read entropy")
	}
	defer crypto.Memwipe(entropy[:])

	s.Lock()
	defer s.Unlock()

	// Add the new entropy to the hash state.
	s.h.Write(entropy[:])

	// Extract the whitened output and massage it into [0,2^63].
	sum := s.h.Sum(nil) // Only the 128 bit interface has non-destructive Sum.
	ret := binary.BigEndian.Uint64(sum[s.off:])
	ret &= (1 << 63) - 1

	// Toggle the read offset for the next fetch.
	s.off = s.off ^ (1 << 3) // 0 -> 8 -> 0 -> 8...

	return int64(ret)
}

func (s *sipSource) Seed(seed int64) {
	// This call is totally nonsensical since the system entropy pool is
	// hit up for every single call.
	return
}

func newSource() (rand.Source, error) {
	var seed [16]byte

	// Random key the SipHash-2-4 instance.
	if _, err := io.ReadFull(Reader, seed[:]); err != nil {
		return nil, err
	}
	defer crypto.Memwipe(seed[:])

	s := new(sipSource)
	s.h = siphash.New128(seed[:]) // 128 bit output!
	return s, nil
}

// New creates a new "cryptograpically secure" math/rand.Rand.
func New() (*rand.Rand, error) {
	s, err := newSource()
	if err != nil {
		return nil, err
	}
	return rand.New(s), nil
}
