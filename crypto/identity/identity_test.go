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
	"errors"
	"testing"
)

func comparePublic(a, b *PublicKey) error {
	if !bytes.Equal(a.DSAPublicKey[:], b.DSAPublicKey[:]) {
		return errors.New("DSA public key mismatch")
	}
	if !bytes.Equal(a.KEXPublicKey[:], b.KEXPublicKey[:]) {
		return errors.New("KEX public key mismatch")
	}
	return nil
}

func comparePrivate(a, b *PrivateKey) error {
	if err := comparePublic(&a.PublicKey, &b.PublicKey); err != nil {
		return err
	}
	if !bytes.Equal(a.DSAPrivateKey[:], b.DSAPrivateKey[:]) {
		return errors.New("DSA private key mismatch")
	}
	if !bytes.Equal(a.KEXPrivateKey[:], b.KEXPrivateKey[:]) {
		return errors.New("KEX private key mismatch")
	}

	return nil
}

func TestIdentity(t *testing.T) {
	k0, err := NewPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate identity key: %v", err)
	}

	k1, err := PrivateKeyFromBytes(k0.DSAPrivateKey[:])
	if err != nil {
		t.Fatalf("failed to deseralize identity key: %v", err)
	}
	if err = comparePrivate(k0, k1); err != nil {
		t.Fatalf("byte serialized SK: %v", err)
	}

	pemEncodedSk := k1.ToPEM()
	k3, err := PrivateKeyFromPEM(pemEncodedSk)
	if err != nil {
		t.Fatalf("failed to deserialize PEM identity key: %v", err)
	}
	if err = comparePrivate(k0, k3); err != nil {
		t.Fatalf("PEM serialized SK: %v", err)
	}

	pk2, err := PublicKeyFromBytes(k0.DSAPublicKey[:])
	if err != nil {
		t.Fatalf("failed to deserialize identity public key: %v", err)
	}
	if err = comparePublic(&k0.PublicKey, pk2); err != nil {
		t.Fatalf("byte serialized PK: %v", err)
	}

	pemEncodedPk := pk2.ToPEM()
	pk3, err := PublicKeyFromPEM(pemEncodedPk)
	if err != nil {
		t.Fatalf("failed to deserialize PEM public key: %v", err)
	}
	if err = comparePublic(&k0.PublicKey, pk3); err != nil {
		t.Fatalf("PEM serialized PK: %v", err)
	}
}
