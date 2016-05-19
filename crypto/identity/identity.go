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

// Package identity provides convinient wrapper types around an X25519
// keypair.
package identity

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"runtime"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"golang.org/x/crypto/curve25519"
)

const (
	// SharedSecretSize is the side of a ECDH shared secret in bytes.
	SharedSecretSize = 32

	// PublicKeySize is the side of a PublicKey in bytes.
	PublicKeySize = 32

	// PrivateKeySize is the size of a PrivateKey in bytes.
	PrivateKeySize = 32

	maxKeygenAttempts = 8

	publicKeyPEMType  = "X25519 PUBLIC KEY"
	privateKeyPEMType = "X25519 PRIVATE KEY"
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

// PrivateKey is a X25519 private key.
type PrivateKey struct {
	PublicKey
	PrivateKey [32]byte
}

func (k *PrivateKey) genPublic() error {
	curve25519.ScalarBaseMult(&k.PublicKey.PublicKey, &k.PrivateKey)
	if !crypto.MemIsZero(k.PublicKey.PublicKey[:]) {
		return nil
	}
	return ErrInvalidKey
}

// ScalarMult derives a shared secret given a peer's public key, suitable
// for use as an input to a key derivation function, and returns true on
// success.  The return value MUST be validated to thwart invalid point
// attacks.
func (k *PrivateKey) ScalarMult(secret *[SharedSecretSize]byte, publicKey *[PublicKeySize]byte) bool {
	ok := !crypto.MemIsZero(publicKey[:])
	curve25519.ScalarMult(secret, &k.PrivateKey, publicKey)
	ok = ok && !crypto.MemIsZero(secret[:])
	return ok
}

// Reset sanitizes private values from the PrivateKey such that they no longer
// appear in memory.
func (k *PrivateKey) Reset() {
	crypto.Memwipe(k.PrivateKey[:])
}

// ToPEM serializes a private key to PEM format.
func (k *PrivateKey) ToPEM() []byte {
	block := &pem.Block{
		Type:  privateKeyPEMType,
		Bytes: k.PrivateKey[:],
	}
	return pem.EncodeToMemory(block)
}

// NewPrivateKey generates a X25519 keypair using the random source rand (use
// crypto/rand.Reader).
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
		// Generate the X25519 keypair.
		if _, err := io.ReadFull(rand, k.PrivateKey[:]); err != nil {
			return nil, err
		}
		if err := k.genPublic(); err == nil {
			return k, nil
		}
	}

	// This should essentially never happen, even with a relatively low
	// retry count.
	panic("crypto/identity: failed to generate keypair, broken rng?")
}

// PrivateKeyFromPEM deserializes a PEM encoded private key.
func PrivateKeyFromPEM(b []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, ErrInvalidKey
	}
	if block.Type != privateKeyPEMType {
		return nil, ErrInvalidKey
	}
	defer crypto.Memwipe(block.Bytes)
	// XXX: Just ignore trailing bullshit?
	return PrivateKeyFromBytes(block.Bytes)
}

// PrivateKeyFromBytes deserializes a private key.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	k := new(PrivateKey)
	runtime.SetFinalizer(k, finalizePrivateKey) // Not always run on exit.
	copy(k.PrivateKey[:], b)
	if err := k.genPublic(); err != nil {
		k.Reset()
		return nil, err
	}
	return k, nil
}

func finalizePrivateKey(k *PrivateKey) {
	k.Reset()
}

// PublicKey is a X25519 public key.
type PublicKey struct {
	PublicKey [PublicKeySize]byte
}

// ScalarMult derives a shared secret given a private key, suitable
// for use as an input to a key derivation function, and returns true on
// success.  The return value MUST be validated to thwart invalid point
// attacks.
func (k *PublicKey) ScalarMult(secret *[SharedSecretSize]byte, privateKey *[PrivateKeySize]byte) bool {
	ok := !crypto.MemIsZero(k.PublicKey[:])
	curve25519.ScalarMult(secret, privateKey, &k.PublicKey)
	ok = ok && !crypto.MemIsZero(secret[:])
	return ok
}

// ToPEM serializes a public key to PEM format.
func (k *PublicKey) ToPEM() []byte {
	block := &pem.Block{
		Type:  publicKeyPEMType,
		Bytes: k.PublicKey[:],
	}
	return pem.EncodeToMemory(block)
}

// PublicKeyFromPEM deserializes a PEM encoded public key.
func PublicKeyFromPEM(b []byte) (*PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, ErrInvalidKey
	}
	if block.Type != publicKeyPEMType {
		return nil, ErrInvalidKey
	}
	// XXX: Just ignore trailing bullshit?
	return PublicKeyFromBytes(block.Bytes)
}

// ToString serializes a public key to a string.
func (k *PublicKey) ToString() string {
	return base64.RawStdEncoding.EncodeToString(k.PublicKey[:])
}

// ToBytes returns the raw internal byte array as a slice.
func (k *PublicKey) ToBytes() []byte {
	return k.PublicKey[:]
}

// PublicKeyFromString deserializes a string encoded public key.
func PublicKeyFromString(s string) (*PublicKey, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return PublicKeyFromBytes(b)
}

// PublicKeyFromBytes deserializes a public key.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	k := new(PublicKey)
	copy(k.PublicKey[:], b)
	if crypto.MemIsZero(k.PublicKey[:]) {
		return nil, ErrInvalidKey
	}

	return k, nil
}
