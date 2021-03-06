// utils.go - Misc crypto utilities.
// Copyright (C) 2015  Yawning Angel.
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

package crypto

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// Memwipe santizes the buffer buf.
func Memwipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// MemIsZero returns true if all bytes in the buffer buf are 0.
func MemIsZero(buf []byte) bool {
	var b byte
	for _, v := range buf {
		b |= v
	}
	return b == 0
}

// NewTweakedShake256 creats a new SHAKE256 instance, and writes the provided
// tweak followed by 256 bits of entropy from the provided source.
func NewTweakedShake256(rand io.Reader, tweak []byte) (sha3.ShakeHash, error) {
	var seed [32]byte
	defer Memwipe(seed[:])

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}

	h := sha3.NewShake256()
	h.Write(tweak)
	h.Write(seed[:])

	return h, nil
}
