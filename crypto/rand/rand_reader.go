// rand_reader.go - `crypto/rand.Reader` replacement
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

package rand

import (
	csrand "crypto/rand"
	"io"

	"github.com/pylls/basket2/crypto"

	"golang.org/x/crypto/sha3"
)

//
// At least as of Go 1.6.1,  Go's crypto/rand does some horrific bullshit that
// defeats the point of getrandom(2), namedly, it cowardly refuses to use the
// syscall based entropy source if it would have blocked on the first call.
//
// This is absolutely retarded.  The correct thing to do for something named
// "crypto/rand" is to fucking BLOCK if the entropy pool isn't there and not
// to pull poor quality entropy by falling back to doing blocking reads on
// "/dev/urandom".
//
// This was brought up in https://github.com/golang/go/issues/11833
// and dismissed, I think they're wrong, I'm fixing it on common systems
// that I care about.
//

var (
	// Reader is a replacement for crypto/rand.Reader.
	Reader = csrand.Reader

	usingImprovedSyscallEntropy = false
	getentropyTweak             = []byte("basket2-getentropy-tweak")
)

type nonShitRandReader struct {
	getentropyFn func([]byte) error
}

func (r *nonShitRandReader) Read(b []byte) (int, error) {
	blen := len(b)
	if blen == 0 {
		return 0, nil
	} else if blen <= 256 {
		// For short reads, use getentropy directly.
		if err := r.getentropyFn(b); err != nil {
			return 0, err
		}
		return blen, nil
	} else {
		// For large requests used a tweaked SHAKE256 instance initialized
		// with 256 bytes of entropy.
		h := sha3.NewShake256()
		defer h.Reset()
		h.Write(getentropyTweak[:])

		var seed [256]byte
		defer crypto.Memwipe(seed[:])
		if err := r.getentropyFn(seed[:]); err != nil {
			return 0, err
		}
		h.Write(seed[:])

		return io.ReadFull(h, b)
	}
}
