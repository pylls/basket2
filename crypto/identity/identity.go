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
	gocrypto "crypto"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"runtime"

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/crypto/rand"
	"git.schwanenlied.me/yawning/basket2.git/ext/x25519"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
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

	publicKeyPEMType  = "ED25519 PUBLIC KEY"
	privateKeyPEMType = "ED25519 PRIVATE KEY"
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
	DSAPrivateKey ed25519.PrivateKey
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

// Sign signs a message and returns a signature.
func (k *PrivateKey) Sign(message []byte) []byte {
	sig, err := k.DSAPrivateKey.Sign(rand.Reader, message, gocrypto.Hash(0))
	if err != nil {
		panic("identity: failed to sign: " + err.Error())
	}
	return sig
}

// Reset sanitizes private values from the PrivateKey such that they no longer
// appear in memory.
func (k *PrivateKey) Reset() {
	crypto.Memwipe(k.DSAPrivateKey)
	crypto.Memwipe(k.KEXPrivateKey[:])
}

// ToPEM serializes a private key to PEM format.
func (k *PrivateKey) ToPEM() []byte {
	block := &pem.Block{
		Type:  privateKeyPEMType,
		Bytes: k.DSAPrivateKey,
	}
	return pem.EncodeToMemory(block)
}

func (k *PrivateKey) toCurve25519() error {
	x25519.PrivateKeyToCurve25519(&k.KEXPrivateKey, k.DSAPrivateKey)
	return k.PublicKey.toCurve25519()
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
	k.DSAPrivateKey = make([]byte, ed25519.PrivateKeySize)
	k.PublicKey.DSAPublicKey = make([]byte, ed25519.PublicKeySize)
	copy(k.DSAPrivateKey, b)
	copy(k.PublicKey.DSAPublicKey, k.DSAPrivateKey[32:])
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
	DSAPublicKey ed25519.PublicKey
	KEXPublicKey [PublicKeySize]byte
}

// Verify returns true iff sig is a valid signature of message.
func (k *PublicKey) Verify(message []byte, sig []byte) bool {
	return ed25519.Verify(k.DSAPublicKey, message, sig)
}

func (k *PublicKey) toCurve25519() error {
	x25519.PublicKeyToCurve25519(&k.KEXPublicKey, k.DSAPublicKey)
	if !crypto.MemIsZero(k.KEXPublicKey[:]) {
		return nil
	}
	return ErrInvalidKey
}

// ToPEM serializes a public key to PEM format.
func (k *PublicKey) ToPEM() []byte {
	block := &pem.Block{
		Type:  publicKeyPEMType,
		Bytes: k.DSAPublicKey,
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
	return base64.RawStdEncoding.EncodeToString(k.DSAPublicKey)
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
	k.DSAPublicKey = make([]byte, ed25519.PublicKeySize)
	copy(k.DSAPublicKey, b)
	if err := k.toCurve25519(); err != nil {
		return nil, err
	}

	return k, nil
}
