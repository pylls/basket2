// identity.go - Identity key routines. 
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

// Package identity provides convinient wrapper types around an Ed25519/X25519
// based keypair.  Both EdDSA and X25519 are supported with the same keypair.
package identity

import (
	"io"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

const (
	SharedSecretSize = 32
	PublicKeySize = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SignatureSize = ed25519.SignatureSize

	maxKeygenAttempts = 8
)

type PrivateKey struct {
	PublicKey
	DSAPrivateKey *[PrivateKeySize]byte
	KEXPrivateKey [32]byte
}

// ScalarMult derives a shared secret given a peer's public key suitable as
// an input to a key derivation function, and returns true on success.  The
// return value MUST be validated to thwart invalid point attacks.
func (k *PrivateKey) ScalarMult(secret *[SharedSecretSize]byte, publicKey *[PublicKeySize]byte) bool {
	ok := !crypto.MemIsZero(publicKey[:])
	curve25519.ScalarMult(secret, &k.KEXPrivateKey, publicKey)
	ok = ok && !crypto.MemIsZero(secret[:])
	return ok
}

// Reset sanitizes private values from the PrivateKey such that they no longer
// appear in memory.
func (k *PrivateKey) Reset() {
	if k.DSAPrivateKey != nil {
		crypto.Memwipe(k.DSAPrivateKey[:])
		k.DSAPrivateKey = nil
	}
	crypto.Memwipe(k.KEXPrivateKey[:])
}

// NewPrivateKey generates an Ed25519/X25519 keypair using the random source
// rand (use crypto/rand.Reader).
func NewPrivateKey(rand io.Reader) (*PrivateKey, error) {
	var err error
	k := new(PrivateKey)

	for iters := 0; iters < maxKeygenAttempts; iters++ {
		// Generate the Ed25519 keypair.
		k.DSAPublicKey, k.DSAPrivateKey, err = ed25519.GenerateKey(rand)
		if err != nil {
			return nil, err
		}

		// Generate the X25519 keypair.
		extra25519.PrivateKeyToCurve25519(&k.KEXPrivateKey, k.DSAPrivateKey)
		extra25519.PublicKeyToCurve25519(&k.KEXPublicKey, k.DSAPublicKey)
		if !crypto.MemIsZero(k.KEXPublicKey[:]) {
			return k, nil
		}
	}

	// This should essentially never happen, even with a relatively low
	// retry count.
	panic("crypto/identity: failed to generate keypair, broken rng?")
}

type PublicKey struct {
	DSAPublicKey *[PublicKeySize]byte
	KEXPublicKey [PublicKeySize]byte
}


