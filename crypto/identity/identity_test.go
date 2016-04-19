// identity_test.go - Identity key routines.
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

package identity

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestIdentity(t *testing.T) {
	k0, err := NewPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate identity key: %v", err)
	}

	k1, err := PrivateKeyFromBytes(k0.DSAPrivateKey[:])
	if err != nil {
		t.Fatalf("failed to deseralize identity key: %v", err)
	}

	if !bytes.Equal(k0.DSAPrivateKey[:], k1.DSAPrivateKey[:]) {
		t.Fatalf("DSA private key mismatch")
	}
	if !bytes.Equal(k0.KEXPrivateKey[:], k1.KEXPrivateKey[:]) {
		t.Fatalf("KEX private key mismatch")
	}

	pk0, pk1 := &k0.PublicKey, &k1.PublicKey
	if !bytes.Equal(pk0.DSAPublicKey[:], pk1.DSAPublicKey[:]) {
		t.Fatalf("DSA public key mismatch")
	}
	if !bytes.Equal(pk0.KEXPublicKey[:], pk1.KEXPublicKey[:]) {
		t.Fatalf("KEX public key mismatch")
	}

	pk2, err := PublicKeyFromBytes(pk0.DSAPublicKey[:])
	if err != nil {
		t.Fatalf("failed to deserialize identity public key: %v", err)
	}
	if !bytes.Equal(pk0.DSAPublicKey[:], pk2.DSAPublicKey[:]) {
		t.Fatalf("DSA public key2 mismatch")
	}
	if !bytes.Equal(pk0.KEXPublicKey[:], pk2.KEXPublicKey[:]) {
		t.Fatalf("KEX public key2 mismatch")
	}
}
