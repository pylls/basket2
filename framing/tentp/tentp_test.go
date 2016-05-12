// tentp_test.go - Trivial Encrypted Network Transport Protocol tests
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

package tentp

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"
	"time"
)

func TestTentpSmoke(t *testing.T) {
	// Yes, I'm time seeding a non-CSPRNG, so I can randomize the pad lengths
	// I test.  Deal with it.
	mrand.Seed(time.Now().UnixNano())

	var key [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	enc, err := NewEncoder(key[:])
	if err != nil {
		t.Fatalf("failed to initialize encoder: %v", err)
	}
	dec, err := NewDecoder(key[:])
	if err != nil {
		t.Fatalf("failed to initialize decoder: %v", err)
	}

	// This used to be 10, but since I increased the framesize...
	padIters := 2

	for i := 0; i <= MaxPlaintextRecordSize; i++ {
		var sndCmd [1]byte
		if _, err := io.ReadFull(rand.Reader, sndCmd[:]); err != nil {
			t.Fatalf("failed to generate command: %v", err)
		}

		// For each size, randomize the padding.
	padLoop:
		for j := 0; j < padIters; j++ {
			padLen := 0
			if i != MaxPlaintextRecordSize && j != 0 {
				// Production code should use a CSPRNG, naturally...
				padLen = mrand.Intn(MaxPlaintextRecordSize - i)
			}

			buf := make([]byte, i)
			if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
				t.Fatalf("failed to generate payload: %v", err)
			}

			encoded, err := enc.EncodeRecord(sndCmd[0], buf, padLen)
			if err != nil {
				t.Fatalf("[%d]: failed to encode: %v", i, err)
			}

			rxCmd, want, err := dec.DecodeRecordHdr(encoded[:FramingOverhead])
			if err != nil {
				t.Fatalf("[%d]: failed to decode hdr: %v", i, err)
			}
			if want != len(encoded)-FramingOverhead {
				t.Fatalf("[%d]: unexpected want length: %v", i, want)
			}
			if rxCmd != sndCmd[0] {
				t.Fatalf("[%d]: snd/recv cmd mismatch", i)
			}
			rxMsg, err := dec.DecodeRecordBody(encoded[FramingOverhead:])
			if err != nil {
				t.Fatalf("[%d]: failed to decode body: %v", i, err)
			}
			if !bytes.Equal(rxMsg, buf) {
				t.Fatalf("[%d]: payload mismatch", i)
			}
			if i == MaxPlaintextRecordSize {
				// No point in altering the padding here.
				break padLoop
			}
		}
	}
}

func doBenchN(b *testing.B, n int, encode bool) {
	var key [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}
	enc, err := NewEncoder(key[:])
	if err != nil {
		b.Fatalf("failed to initialize encoder: %v", err)
	}
	dec, err := NewDecoder(key[:])
	if err != nil {
		b.Fatalf("failed to initialize decoder: %v", err)
	}
	s := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		b.Fatalf("failed to generate payload: %v", err)
	}

	b.SetBytes(int64(n))
	b.ResetTimer()
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		if encode {
			b.StartTimer()
		}

		encoded, err := enc.EncodeRecord(0xa5, s, 0)
		if err != nil {
			b.Fatalf("failed to encode: %v", err)
		}

		if encode {
			b.StopTimer()
		} else {
			b.StartTimer()
		}

		rxCmd, want, err := dec.DecodeRecordHdr(encoded[:FramingOverhead])
		if err != nil {
			b.Fatalf("failed to decode: %v", err)
		}

		// These checks get timed, but they're cheap, so whatever.
		if want != len(encoded)-FramingOverhead {
			b.Fatalf("unexpected want length: %v", want)
		}
		if rxCmd != 0xa5 {
			b.Fatalf("snd/recv cmd mismatch")
		}

		rxMsg, err := dec.DecodeRecordBody(encoded[FramingOverhead:])
		if err != nil {
			b.Fatalf("failed to decode body: %v", err)
		}

		if !encode {
			b.StopTimer()
		}

		if !bytes.Equal(rxMsg, s) {
			b.Fatalf("payload mismatch")
		}
	}
}

func BenchmarkTentp_Encode_64(b *testing.B) {
	doBenchN(b, 64, true)
}

func BenchmarkTentp_Decode_64(b *testing.B) {
	doBenchN(b, 64, false)
}

func BenchmarkTentp_Encode_512(b *testing.B) {
	doBenchN(b, 512, true)
}

func BenchmarkTentp_Decode_512(b *testing.B) {
	doBenchN(b, 512, false)
}

func BenchmarkTentp_Encode_1500(b *testing.B) {
	doBenchN(b, 1500, true)
}

func BenchmarkTentp_Decode_1500(b *testing.B) {
	doBenchN(b, 1500, false)
}

func BenchmarkTentp_Encode_16383(b *testing.B) {
	doBenchN(b, 16383, true)
}

func BenchmarkTentp_Decode_16383(b *testing.B) {
	doBenchN(b, 16383, false)
}
