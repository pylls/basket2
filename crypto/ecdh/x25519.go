// x25519.go - X25519 routines.
// Copyright (C) 2015-2016  Yawning Angel.
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
	"git.schwanenlied.me/yawning/basket2.git/ext/x25519/elligator2"

	"golang.org/x/crypto/curve25519"
)

// X25519Size is the X25519 private/public key and shared secret size in bytes.
const X25519Size = 32

type x25519PublicKey struct {
	pubBytes     [X25519Size]byte
	uniformBytes *[X25519Size]byte
}

func (k *x25519PublicKey) Size() int {
	return X25519Size
}

func (k *x25519PublicKey) ToBytes() []byte {
	return k.pubBytes[:]
}

func (k *x25519PublicKey) ToUniformBytes() []byte {
	if k.uniformBytes == nil {
		return nil
	}
	return k.uniformBytes[:]
}

func publicFromBytesX25519(b []byte) (PublicKey, error) {
	if len(b) != X25519Size {
		return nil, ErrInvalidKeySize
	}

	pk := new(x25519PublicKey)
	copy(pk.pubBytes[:], b)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		return nil, ErrInvalidPoint
	}
	return pk, nil
}

func publicFromUniformBytesX25519(b []byte) (PublicKey, error) {
	if len(b) != X25519Size {
		return nil, ErrInvalidKeySize
	}

	pk := new(x25519PublicKey)
	pk.uniformBytes = new([X25519Size]byte)
	copy(pk.uniformBytes[:], b)
	elligator2.RepresentativeToPublicKey(&pk.pubBytes, pk.uniformBytes)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		return nil, ErrInvalidPoint
	}
	return pk, nil
}

type x25519PrivateKey struct {
	publicKey *x25519PublicKey
	privBytes [X25519Size]byte
}

func (k *x25519PrivateKey) PublicKey() PublicKey {
	return k.publicKey
}

func (k *x25519PrivateKey) ScalarMult(publicKey PublicKey) ([]byte, bool) {
	xpk := (publicKey).(*x25519PublicKey)

	var sharedSecret [X25519Size]byte
	ok := !crypto.MemIsZero(xpk.pubBytes[:])
	curve25519.ScalarMult(&sharedSecret, &k.privBytes, &xpk.pubBytes)
	ok = ok && !crypto.MemIsZero(sharedSecret[:])
	return sharedSecret[:], ok
}

func (k *x25519PrivateKey) Size() int {
	return X25519Size
}

func (k *x25519PrivateKey) ToBytes() []byte {
	return k.privBytes[:]
}

func (k *x25519PrivateKey) Reset() {
	crypto.Memwipe(k.privBytes[:])
}

func privateFromBytesX25519(b []byte) (PrivateKey, error) {
	if len(b) != X25519Size {
		return nil, ErrInvalidKeySize
	}

	sk := new(x25519PrivateKey)
	sk.publicKey = new(x25519PublicKey)
	pk := sk.publicKey
	copy(sk.privBytes[:], b)
	curve25519.ScalarBaseMult(&pk.pubBytes, &sk.privBytes)
	if crypto.MemIsZero(pk.pubBytes[:]) {
		sk.Reset()
		return nil, ErrInvalidPoint
	}
	return sk, nil
}

func newX25519(rand io.Reader, uniform bool) (PrivateKey, error) {
	sk := new(x25519PrivateKey)
	sk.publicKey = new(x25519PublicKey)
	pk := sk.publicKey

	if uniform {
		repr := new([X25519Size]byte)
		if err := elligator2.GenerateKey(rand, &pk.pubBytes, repr, &sk.privBytes); err != nil {
			return nil, err
		}
		pk.uniformBytes = repr
	} else {
		r, err := crypto.NewTweakedShake256(rand, ecdhRandTweak)
		if err != nil {
			return nil, err
		}
		defer r.Reset()

		if _, err := io.ReadFull(r, sk.privBytes[:]); err != nil {
			return nil, err
		}
		curve25519.ScalarBaseMult(&pk.pubBytes, &sk.privBytes)
		if crypto.MemIsZero(pk.pubBytes[:]) {
			return nil, ErrInvalidPoint
		}
	}
	return sk, nil
}
