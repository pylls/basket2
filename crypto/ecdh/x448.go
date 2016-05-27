// x448.go - X448 routines.
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

package ecdh

import (
	"io"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"git.schwanenlied.me/yawning/x448.git"
)

// X448Size is the X448 private/public key and shared secret size in bytes.
const X448Size = 56

type x448PublicKey struct {
	pubBytes [X448Size]byte
}

func (k *x448PublicKey) Size() int {
	return X448Size
}

func (k *x448PublicKey) ToBytes() []byte {
	return k.pubBytes[:]
}

func (k *x448PublicKey) ToUniformBytes() []byte {
	// Not supported.
	return nil
}

func publicFromBytesX448(b []byte) (PublicKey, error) {
	if len(b) != X448Size {
		return nil, ErrInvalidKeySize
	}

	pk := new(x448PublicKey)
	copy(pk.pubBytes[:], b)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		return nil, ErrInvalidPoint
	}
	return pk, nil
}

type x448PrivateKey struct {
	publicKey *x448PublicKey
	privBytes [X448Size]byte
}

func (k *x448PrivateKey) PublicKey() PublicKey {
	return k.publicKey
}

func (k *x448PrivateKey) ScalarMult(publicKey PublicKey) ([]byte, bool) {
	xpk := (publicKey).(*x448PublicKey)

	var sharedSecret [X448Size]byte
	ok := x448.ScalarMult(&sharedSecret, &k.privBytes, &xpk.pubBytes)
	return sharedSecret[:], ok == 0
}

func (k *x448PrivateKey) Size() int {
	return X448Size
}

func (k *x448PrivateKey) ToBytes() []byte {
	return k.privBytes[:]
}

func (k *x448PrivateKey) Reset() {
	crypto.Memwipe(k.privBytes[:])
}

func privateFromBytesX448(b []byte) (PrivateKey, error) {
	if len(b) != X448Size {
		return nil, ErrInvalidKeySize
	}

	sk := new(x448PrivateKey)
	sk.publicKey = new(x448PublicKey)
	pk := sk.publicKey
	copy(sk.privBytes[:], b)
	x448.ScalarBaseMult(&pk.pubBytes, &sk.privBytes)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		sk.Reset()
		return nil, ErrInvalidPoint
	}
	return sk, nil
}

func newX448(rand io.Reader, uniform bool) (PrivateKey, error) {
	if uniform {
		return nil, ErrNotSupported
	}

	sk := new(x448PrivateKey)
	sk.publicKey = new(x448PublicKey)
	pk := sk.publicKey

	r, err := crypto.NewTweakedShake256(rand, ecdhRandTweak)
	if err != nil {
		return nil, err
	}
	defer r.Reset()

	if _, err := io.ReadFull(r, sk.privBytes[:]); err != nil {
		return nil, err
	}
	x448.ScalarBaseMult(&pk.pubBytes, &sk.privBytes)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		return nil, ErrInvalidPoint
	}
	return sk, nil
}
