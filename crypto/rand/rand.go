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

// Package rand provides various utitilies related to generating
// cryptographically secure random numbers and byte vectors.
package rand

import (
	"encoding/binary"
	"hash"
	"io"
	"math/rand"
	"sync"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"github.com/dchest/siphash"
	"golang.org/x/crypto/sha3"
)

var shakeDRBGTweak = []byte("basket2-shake-drbg-tweak")

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
	// The seed value is totally ignored because the system entropy source is
	// hit up on each call.  But, since the output is whitened via a
	// random keyed SipHash-2-4 instance, re-randomize the key.
	var key [16]byte

	// Obtain a SipHash-2-4 key from the system entropy source.
	if _, err := io.ReadFull(Reader, key[:]); err != nil {
		panic("sipSource: failed to generate a key: " + err.Error())
	}
	defer crypto.Memwipe(key[:])

	s.Lock()
	defer s.Unlock()

	s.h = siphash.New128(key[:]) // 128 bit output!
	s.off = 0                    // Doesn't really matter, but why not.

	return
}

func newSource() rand.Source {
	s := new(sipSource)
	s.Seed(0)
	return s
}

// New creates a new "cryptograpically secure" math/rand.Rand.
func New() *rand.Rand {
	return rand.New(newSource())
}

type shakeDRBG struct {
	sync.Mutex
	h sha3.ShakeHash
}

func (s *shakeDRBG) Int63() int64 {
	s.Lock()
	defer s.Unlock()

	var v [8]byte
	s.h.Read(v[:])
	ret := binary.BigEndian.Uint64(v[:])
	ret &= (1 << 63) - 1

	return int64(ret)
}

func (s *shakeDRBG) Seed(seed int64) {
	panic("shakeDRBG: Attempted to Seed() the DRBG instance")
}

// NewDRBG creates a new Deterministic Random Bit Generator initialized with
// the provided seed and backed by SHAKE-128 that exposes a math/rand.Rand
// interface.  As the output is entirely deterministic, this should NOT
// be used to generate cryptographic keying material.
func NewDRBG(seed []byte) *rand.Rand {
	if len(seed) == 0 {
		panic("shakeDRBG: invalid seed provided")
	}

	s := new(shakeDRBG)
	s.h = sha3.NewShake128()
	s.h.Write(shakeDRBGTweak)
	s.h.Write(seed)

	return rand.New(s)
}
