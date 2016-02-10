// secretbox.go - crypto_secretbox_xchacha20poly1305
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

// Package secretbox provides secret-key authenticated encryption based
// around a crypto_secretbox_xchacha20poly1305 construct.
package secretbox

import (
	"errors"

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/chacha20.git"
	"golang.org/x/crypto/poly1305"
)

const (
	// KeySize is the secretbox key size in bytes.
	KeySize = chacha20.KeySize

	// NonceSize is the secretbox nonce size in bytes.
	NonceSize = chacha20.XNonceSize

	// OverheadSize is the secretbox overhead size in bytes.
	OverheadSize = poly1305.TagSize
)

// ErrInvalidTag is the error returned when the tag is invalid.
var ErrInvalidTag = errors.New("tag is invalid")

// Seal encrypts and authenticates the message msg using a secret key and a
// nonce, and returns the resulting ciphertext.  Note that it is the caller's
// responsiblity to ensure the uniqueness of nonces.  Nonces are long enough
// that randomly generated nonces have a negligible risk of collision.
func Seal(msg []byte, nonce *[NonceSize]byte, key *[KeySize]byte) []byte {
	s, err := chacha20.NewCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}

	var authKey [32]byte
	var authTag [poly1305.TagSize]byte
	defer crypto.Memwipe(authKey[:])
	s.KeyStream(authKey[:])

	box := make([]byte, OverheadSize+len(msg))
	s.XORKeyStream(box[OverheadSize:], msg)
	poly1305.Sum(&authTag, box[OverheadSize:], &authKey)
	copy(box[:OverheadSize], authTag[:])
	return box
}

// Open authentictates and decrypts the ciphertext box using a secret key and a
// nonce, and returns the resulting plaintext.
func Open(box []byte, nonce *[NonceSize]byte, key *[KeySize]byte) ([]byte, error) {
	if len(box) < OverheadSize {
		return nil, ErrInvalidTag
	}

	s, err := chacha20.NewCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}

	var authKey [32]byte
	var authTag [poly1305.TagSize]byte
	defer crypto.Memwipe(authKey[:])
	s.KeyStream(authKey[:])

	copy(authTag[:], box[:OverheadSize])
	if poly1305.Verify(&authTag, box[OverheadSize:], &authKey) {
		msg := make([]byte, len(box)-OverheadSize)
		s.XORKeyStream(msg, box[OverheadSize:])
		return msg, nil
	}
	return nil, ErrInvalidTag
}
