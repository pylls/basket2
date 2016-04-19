// identity.go - Identity key routines.
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

// Package identity provides convinient wrapper types around an Ed25519/X25519
// based keypair.  Both EdDSA and X25519 are supported with the same keypair.
package identity

import (
	"errors"
	"io"
	"runtime"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

const (
	// SharedSecretSize is the side of a ECDH shared secret in bytes.
	SharedSecretSize = 32

	// PublicKeySize is the side of a PublicKey in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a PrivateKey in bytes.
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a Signature in bytes.
	SignatureSize = ed25519.SignatureSize

	maxKeygenAttempts = 8
)

var (
	// ErrInvalidKeySize is the error returned when deserialization failes due
	// to an invalid length buffer.
	ErrInvalidKeySize = errors.New("identity: invalid key size")

	// ErrInvalidKey is the error returned when deserialization fails due to
	// one of the keys consisting of invalid points.
	ErrInvalidKey = errors.New("identity: deserialized key is invalid")

	identityRandTweak = []byte("basket2-identity-tweak")
)

// PrivateKey is a EdDSA private key and it's X25519 counterpart.
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

func (k *PrivateKey) toCurve25519() error {
	extra25519.PrivateKeyToCurve25519(&k.KEXPrivateKey, k.DSAPrivateKey)
	extra25519.PublicKeyToCurve25519(&k.KEXPublicKey, k.DSAPublicKey)
	if !crypto.MemIsZero(k.KEXPublicKey[:]) {
		return nil
	}
	return ErrInvalidKey
}

// NewPrivateKey generates an Ed25519/X25519 keypair using the random source
// rand (use crypto/rand.Reader).
func NewPrivateKey(rand io.Reader) (*PrivateKey, error) {
	var err error
	k := new(PrivateKey)
	h, err := crypto.NewTweakedShake256(rand, identityRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()

	runtime.SetFinalizer(k, finalizePrivateKey) // Not always run on exit.
	for iters := 0; iters < maxKeygenAttempts; iters++ {
		// Generate the Ed25519 keypair.
		k.DSAPublicKey, k.DSAPrivateKey, err = ed25519.GenerateKey(h)
		if err != nil {
			return nil, err
		}

		// Generate the X25519 keypair.
		if err = k.toCurve25519(); err == nil {
			return k, nil
		}
	}

	// This should essentially never happen, even with a relatively low
	// retry count.
	panic("crypto/identity: failed to generate keypair, broken rng?")
}

// PrivateKeyFromBytes deserializes a private key.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	k := new(PrivateKey)
	k.DSAPrivateKey = new([PrivateKeySize]byte)
	copy(k.DSAPrivateKey[:], b)
	k.PublicKey.DSAPublicKey = new([PublicKeySize]byte)
	copy(k.PublicKey.DSAPublicKey[:], k.DSAPrivateKey[32:])
	if err := k.toCurve25519(); err != nil {
		k.Reset()
		return nil, err
	}
	return k, nil
}

func finalizePrivateKey(k *PrivateKey) {
	k.Reset()
}

// PublicKey is a EdDSA public key and it's X25519 counterpart.
type PublicKey struct {
	DSAPublicKey *[PublicKeySize]byte
	KEXPublicKey [PublicKeySize]byte
}
