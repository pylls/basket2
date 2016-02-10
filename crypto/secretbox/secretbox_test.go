// secretbox_test.go - crypto_secretbox_xchacha20poly1305
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

package secretbox

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func TestSecretBox(t *testing.T) {
	key := [KeySize]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	nonce := [NonceSize]byte{
		0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
		0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
		0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
	}

	msg := []byte("At start, no has lyte. An Ceiling Cat sayz, i can haz lite? An lite wuz. An Ceiling Cat sawed teh lite, to seez stuffs, An splitted teh lite from dark but taht wuz ok cuz kittehs can see in teh dark An not tripz over nethin. An Ceiling Cat sayed light Day An dark no Day. It were FURST!!!1")

	// Seal()/Open()
	box := Seal(msg, &nonce, &key)
	opened, err := Open(box, &nonce, &key)
	if err != nil {
		t.Fatal(err)
	}

	// Test that Seal -> Open is indepotent.
	if !bytes.Equal(opened, msg) {
		t.Errorf("opened != msg (%x != %x)", opened, msg)
	}

	// Test that a invalid tag will be rejected.
	fuktbox := make([]byte, len(box))
	copy(fuktbox, box)
	fuktbox[0] = ^fuktbox[0]
	_, err = Open(fuktbox, &nonce, &key)
	if err == nil {
		t.Errorf("invalid tag was accepted")
	}

	// Test that a invalid ciphertext will be rejected.
	copy(fuktbox, box)
	fuktbox[OverheadSize] = ^fuktbox[OverheadSize]
	_, err = Open(fuktbox, &nonce, &key)
	if err == nil {
		t.Errorf("invalid ciphertext was accepted")
	}
}

func doBenchN(b *testing.B, n int) {
	var key [KeySize]byte
	var nonce [NonceSize]byte
	msg := make([]byte, n)

	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		box := Seal(msg, &nonce, &key)
		_, err := Open(box, &nonce, &key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecretbox_16(b *testing.B) {
	doBenchN(b, 16)
}

func BenchmarkSecretbox_1k(b *testing.B) {
	doBenchN(b, 1024)
}

func BenchmarkSecretbox_4k(b *testing.B) {
	doBenchN(b, 4096)
}

func BenchmarkSecretbox_64k(b *testing.B) {
	doBenchN(b, 65536)
}

// As a comparison.
func BenchmarkNaCl_64k(b *testing.B) {
	var key [KeySize]byte
	var nonce [NonceSize]byte
	msg := make([]byte, 65536)

	b.SetBytes(int64(65536))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		box := secretbox.Seal(nil, msg, &nonce, &key)
		_, ok := secretbox.Open(nil, box, &nonce, &key)
		if !ok {
			b.Fatal("secretbox.Open failed")
		}
	}
}
