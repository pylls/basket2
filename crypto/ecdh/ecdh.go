// ecdh.go - RFC 7748 ECDH implementations.
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

// Package ecdh provides support for ECDH with the IETF CFRG Curves as
// specified in RFC 7748.
package ecdh

import (
	"errors"
	"io"
)

const (
	// X25519 is curve25519 from RFC 7748.
	X25519 Curve = iota

	// X448 is curve448 from RFC 7748.
	X448
)

var (
	// ErrInvalidCurve is the error returned when the curve is unknown/invalid.
	ErrInvalidCurve = errors.New("ecdh: invalid curve")

	// ErrInvalidPoint is the error returned when when the point is of small
	// order, where the order divides the cofactor of the curve.
	ErrInvalidPoint = errors.New("ecdh: invalid point")

	// ErrInvalidKeySize is the error returned when deserialization fails due
	// to an invalid length buffer.
	ErrInvalidKeySize = errors.New("ecdh: invalid key size")

	// ErrNotSupported is the error returned when a operation is not supported.
	ErrNotSupported = errors.New("ecdh: not supported")

	ecdhRandTweak = []byte("basket2-ecdh-tweak")
)

// Curve is a curve identifier.
type Curve byte

// PublicKey is an ECDH public key.
type PublicKey interface {
	// Curve returns the Curve that this public key is for.
	Curve() Curve

	// Size returns the size of the encoded public key in bytes.
	Size() int

	// ToBytes returns a byte slice pointing to the internal byte encoded
	// public key.
	ToBytes() []byte

	// ToUniformBytes returns the Elligator2 uniform representative of the
	// public key, if one is available or nil if one is not.
	ToUniformBytes() []byte
}

// PublicKeyFromUniformBytes returns the PublicKey corresponding to the given
// curve and  Elligator2 uniform representative.
func PublicKeyFromUniformBytes(curve Curve, b []byte) (PublicKey, error) {
	switch curve {
	case X25519:
		return publicFromUniformBytesX25519(b)
	}
	return nil, ErrInvalidCurve
}

// PublicKeyFromBytes returns the PublicKey corresponding to the given curve
// and byte slice.
func PublicKeyFromBytes(curve Curve, b []byte) (PublicKey, error) {
	switch curve {
	case X25519:
		return publicFromBytesX25519(b)
	case X448:
		return publicFromBytesX448(b)
	}
	return nil, ErrInvalidCurve
}

// PrivateKey is an ECDH private key.
type PrivateKey interface {
	// PublicKey returns the PublicKey corresponding to the PrivateKey.
	PublicKey() PublicKey

	// ScalarMult returns a shared secret given a peer's public key, suitable
	// for use as an input to a key derivation function, and returns true on
	// success.  The return value MUST be validated to thward invalid point
	// attacks.
	ScalarMult(PublicKey) ([]byte, bool)

	// Curve returns the Curve that this private key is for.
	Curve() Curve

	// Size returns the size of the encoded private key in bytes.
	Size() int

	// ToBytes returns a byte slice pointing to the interal byte encoded
	// private key.
	ToBytes() []byte

	// Reset sanitizes private values from the PrivateKey such that they no
	// longer appear in memory.
	Reset()
}

// PrivateKeyFromBytes returns the PrivateKey corresponding to the given curve
// and byte slice.
func PrivateKeyFromBytes(curve Curve, b []byte) (PrivateKey, error) {
	switch curve {
	case X25519:
		return privateFromBytesX25519(b)
	case X448:
		return privateFromBytesX448(b)
	}
	return nil, ErrInvalidCurve
}

// New generates a new PrivateKey in the provided curve using the random source
// rand.  If uniform is true, an Elligator2 representative will also be
// generated if supported.
func New(rand io.Reader, curve Curve, uniform bool) (PrivateKey, error) {
	switch curve {
	case X25519:
		return newX25519(rand, uniform)
	case X448:
		return newX448(rand, uniform)
	}
	return nil, ErrInvalidCurve
}
