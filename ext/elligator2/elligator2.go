// Copyright (c) 2012-2013 The Go Authors. All rights reserved.
// Copyright (c) 2014 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following disclaimer
//     in the documentation and/or other materials provided with the
//     distribution.
//   * Neither the name of Google Inc. nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package elligator2 implements the Elligator 2 forward/reverse mapping for
// Curve25519.  This implementation does NOT interoperate with the original
// codebase as the original codebase is wrong.
//
// See http://elligator.cr.yp.to/elligator-20130828.pdf.
package elligator2

import (
	"errors"
	"io"

	"github.com/agl/ed25519/edwards25519"
	"golang.org/x/crypto/sha3"
)

const maxKeygenAttempts = 128

// ErrKeygenFailed is the error returned when a suitable base keypair was not
// generated after the maximum number of retries.
var ErrKeygenFailed = errors.New("elligator2: failed to generate key pair")

// sqrtMinusA is sqrt(-486662)
var sqrtMinusA = edwards25519.FieldElement{
	12222970, 8312128, 11511410, -9067497, 15300785, 241793, -25456130, -14121551, 12187136, -3972024,
}

// sqrtMinusHalf is sqrt(-1/2)
var sqrtMinusHalf = edwards25519.FieldElement{
	-17256545, 3971863, 28865457, -1750208, 27359696, -16640980, 12573105, 1002827, -163343, 11073975,
}

// halfQMinus1Bytes is (2^255-20)/2 expressed in little endian form.
var halfQMinus1Bytes = [32]byte{
	0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
}

// feBytesLess returns one if a <= b and zero otherwise.
func feBytesLE(a, b *[32]byte) int32 {
	equalSoFar := int32(-1)
	greater := int32(0)

	for i := uint(31); i < 32; i-- {
		x := int32(a[i])
		y := int32(b[i])

		greater = (^equalSoFar & greater) | (equalSoFar & ((x - y) >> 31))
		equalSoFar = equalSoFar & (((x ^ y) - 1) >> 31)
	}

	return int32(^equalSoFar & 1 & greater)
}

// GenerateKey generates a Curve25519 key pair along with a uniform
// representative for the public key, using the random source random
// (Hint: crypto/rand.Reader).
func GenerateKey(random io.Reader, publicKey, representative, privateKey *[32]byte) error {
	// Note: This can be optimized by only doing the scalar basepoint multiply
	// once, and manipulating the private key/public key if there is no
	// representative for a ~40% performance gain.
	//
	// However:
	//  * This should not be a critical path operation, since it's ideally
	//    only done once per connection.
	//  * edwards25519 doesn't expose geAdd() so adding the optimization is
	//    somewhat annoying.

	// Initialize a SHAKE128 instance with tweak + 32 bytes of entropy.
	// This avoids hitting up the system entropy pool repeatedly for private
	// keys and attempts to mitigate CSPRNG output with low entropy.
	h := sha3.NewShake128()
	if _, err := io.ReadFull(random, privateKey[:]); err != nil {
		return err
	}
	h.Write([]byte("elligator2-tweak")) // Domain separation.
	h.Write(privateKey[:])
	defer h.Reset()

	for i := 0; i < maxKeygenAttempts; i++ {
		// Squeeze out a candidate private key from the SHAKE construct.
		if _, err := io.ReadFull(h, privateKey[:]); err != nil {
			return err
		}

		// Attempt to generate a private key and uniform representative.
		if ok := scalarBaseMult(publicKey, representative, privateKey); ok {
			// Randomize the 2 high bits of the representative.  This uses the
			// system entropy source since `h` should only be used for private
			// values that never appear on the wire.
			var bits [1]byte
			if _, err := io.ReadFull(random, bits[:]); err != nil {
				return err
			}

			// Whiten the bits, such that the direct output of the system
			// entropy source never appears on the wire.
			low, hi := (bits[0]&0x0f)<<4, bits[0]&0xf0
			representative[31] |= (low ^ hi) & 0xc0

			return nil
		}
	}

	// Something has gone catastrophically wrong, and there was a total
	// failure to generate a suitable base keypair.  The probability of
	// this happening is 1/2^maxKeygentAttempts.
	return ErrKeygenFailed
}

// scalarBaseMult computes a curve25519 public key from a private key and also
// a uniform representative for that public key. Note that this function will
// fail and return false for about half of private keys.
//
// It is the caller's responsibility to randomize the 2 high bits of the
// representative before sending it out on the network.
//
// See http://elligator.cr.yp.to/elligator-20130828.pdf.
func scalarBaseMult(publicKey, representative, privateKey *[32]byte) bool {
	var maskedPrivateKey [32]byte
	copy(maskedPrivateKey[:], privateKey[:])

	maskedPrivateKey[0] &= 248
	maskedPrivateKey[31] &= 127
	maskedPrivateKey[31] |= 64

	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &maskedPrivateKey)

	var inv1 edwards25519.FieldElement
	edwards25519.FeSub(&inv1, &A.Z, &A.Y)
	edwards25519.FeMul(&inv1, &inv1, &A.X)
	edwards25519.FeInvert(&inv1, &inv1)

	var t0, u edwards25519.FieldElement
	edwards25519.FeMul(&u, &inv1, &A.X)
	edwards25519.FeAdd(&t0, &A.Y, &A.Z)
	edwards25519.FeMul(&u, &u, &t0)

	var v edwards25519.FieldElement
	edwards25519.FeMul(&v, &t0, &inv1)
	edwards25519.FeMul(&v, &v, &A.Z)
	edwards25519.FeMul(&v, &v, &sqrtMinusA)

	var b edwards25519.FieldElement
	edwards25519.FeAdd(&b, &u, &edwards25519.A)

	var c, b3, b8 edwards25519.FieldElement
	edwards25519.FeSquare(&b3, &b)   // 2
	edwards25519.FeMul(&b3, &b3, &b) // 3
	edwards25519.FeSquare(&c, &b3)   // 6
	edwards25519.FeMul(&c, &c, &b)   // 7
	edwards25519.FeMul(&b8, &c, &b)  // 8
	edwards25519.FeMul(&c, &c, &u)
	q58(&c, &c)

	var chi edwards25519.FieldElement
	edwards25519.FeSquare(&chi, &c)
	edwards25519.FeSquare(&chi, &chi)

	edwards25519.FeSquare(&t0, &u)
	edwards25519.FeMul(&chi, &chi, &t0)

	edwards25519.FeSquare(&t0, &b)   // 2
	edwards25519.FeMul(&t0, &t0, &b) // 3
	edwards25519.FeSquare(&t0, &t0)  // 6
	edwards25519.FeMul(&t0, &t0, &b) // 7
	edwards25519.FeSquare(&t0, &t0)  // 14
	edwards25519.FeMul(&chi, &chi, &t0)
	edwards25519.FeNeg(&chi, &chi)

	var chiBytes [32]byte
	edwards25519.FeToBytes(&chiBytes, &chi)
	// chi[1] is either 0 or 0xff
	if chiBytes[1] == 0xff {
		return false
	}

	// Calculate r1 = sqrt(-u/(2*(u+A)))
	var r1 edwards25519.FieldElement
	edwards25519.FeMul(&r1, &c, &u)
	edwards25519.FeMul(&r1, &r1, &b3)
	edwards25519.FeMul(&r1, &r1, &sqrtMinusHalf)

	var maybeSqrtM1 edwards25519.FieldElement
	edwards25519.FeSquare(&t0, &r1)
	edwards25519.FeMul(&t0, &t0, &b)
	edwards25519.FeAdd(&t0, &t0, &t0)
	edwards25519.FeAdd(&t0, &t0, &u)

	edwards25519.FeOne(&maybeSqrtM1)
	edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
	edwards25519.FeMul(&r1, &r1, &maybeSqrtM1)

	// Calculate r = sqrt(-(u+A)/(2u))
	var r edwards25519.FieldElement
	edwards25519.FeSquare(&t0, &c)   // 2
	edwards25519.FeMul(&t0, &t0, &c) // 3
	edwards25519.FeSquare(&t0, &t0)  // 6
	edwards25519.FeMul(&r, &t0, &c)  // 7

	edwards25519.FeSquare(&t0, &u)   // 2
	edwards25519.FeMul(&t0, &t0, &u) // 3
	edwards25519.FeMul(&r, &r, &t0)

	edwards25519.FeSquare(&t0, &b8)   // 16
	edwards25519.FeMul(&t0, &t0, &b8) // 24
	edwards25519.FeMul(&t0, &t0, &b)  // 25
	edwards25519.FeMul(&r, &r, &t0)
	edwards25519.FeMul(&r, &r, &sqrtMinusHalf)

	edwards25519.FeSquare(&t0, &r)
	edwards25519.FeMul(&t0, &t0, &u)
	edwards25519.FeAdd(&t0, &t0, &t0)
	edwards25519.FeAdd(&t0, &t0, &b)
	edwards25519.FeOne(&maybeSqrtM1)
	edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0))
	edwards25519.FeMul(&r, &r, &maybeSqrtM1)

	var vBytes [32]byte
	edwards25519.FeToBytes(&vBytes, &v)
	vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes)
	edwards25519.FeCMove(&r, &r1, vInSquareRootImage)

	// 5.5: Here |b| means b if b in {0, 1, ..., (q - 1)/2}, otherwise -b.
	var rBytes [32]byte
	edwards25519.FeToBytes(&rBytes, &r)
	negateB := 1 & (^feBytesLE(&rBytes, &halfQMinus1Bytes))
	edwards25519.FeNeg(&r1, &r)
	edwards25519.FeCMove(&r, &r1, negateB)

	edwards25519.FeToBytes(publicKey, &u)
	edwards25519.FeToBytes(representative, &r)
	return true
}

// q58 calculates out = z^((p-5)/8).
func q58(out, z *edwards25519.FieldElement) {
	var t1, t2, t3 edwards25519.FieldElement
	var i int

	edwards25519.FeSquare(&t1, z)     // 2^1
	edwards25519.FeMul(&t1, &t1, z)   // 2^1 + 2^0
	edwards25519.FeSquare(&t1, &t1)   // 2^2 + 2^1
	edwards25519.FeSquare(&t2, &t1)   // 2^3 + 2^2
	edwards25519.FeSquare(&t2, &t2)   // 2^4 + 2^3
	edwards25519.FeMul(&t2, &t2, &t1) // 4,3,2,1
	edwards25519.FeMul(&t1, &t2, z)   // 4..0
	edwards25519.FeSquare(&t2, &t1)   // 5..1
	for i = 1; i < 5; i++ {           // 9,8,7,6,5
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0
	edwards25519.FeSquare(&t2, &t1)   // 10..1
	for i = 1; i < 10; i++ {          // 19..10
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t2, &t2, &t1) // 19..0
	edwards25519.FeSquare(&t3, &t2)   // 20..1
	for i = 1; i < 20; i++ {          // 39..20
		edwards25519.FeSquare(&t3, &t3)
	}
	edwards25519.FeMul(&t2, &t3, &t2) // 39..0
	edwards25519.FeSquare(&t2, &t2)   // 40..1
	for i = 1; i < 10; i++ {          // 49..10
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 49..0
	edwards25519.FeSquare(&t2, &t1)   // 50..1
	for i = 1; i < 50; i++ {          // 99..50
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t2, &t2, &t1) // 99..0
	edwards25519.FeSquare(&t3, &t2)   // 100..1
	for i = 1; i < 100; i++ {         // 199..100
		edwards25519.FeSquare(&t3, &t3)
	}
	edwards25519.FeMul(&t2, &t3, &t2) // 199..0
	edwards25519.FeSquare(&t2, &t2)   // 200..1
	for i = 1; i < 50; i++ {          // 249..50
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 249..0
	edwards25519.FeSquare(&t1, &t1)   // 250..1
	edwards25519.FeSquare(&t1, &t1)   // 251..2
	edwards25519.FeMul(out, &t1, z)   // 251..2,0
}

// chi calculates out = z^((p-1)/2). The result is either 1, 0, or -1 depending
// on whether z is a non-zero square, zero, or a non-square.
func chi(out, z *edwards25519.FieldElement) {
	var t0, t1, t2, t3 edwards25519.FieldElement
	var i int

	edwards25519.FeSquare(&t0, z)     // 2^1
	edwards25519.FeMul(&t1, &t0, z)   // 2^1 + 2^0
	edwards25519.FeSquare(&t0, &t1)   // 2^2 + 2^1
	edwards25519.FeSquare(&t2, &t0)   // 2^3 + 2^2
	edwards25519.FeSquare(&t2, &t2)   // 4,3
	edwards25519.FeMul(&t2, &t2, &t0) // 4,3,2,1
	edwards25519.FeMul(&t1, &t2, z)   // 4..0
	edwards25519.FeSquare(&t2, &t1)   // 5..1
	for i = 1; i < 5; i++ {           // 9,8,7,6,5
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0
	edwards25519.FeSquare(&t2, &t1)   // 10..1
	for i = 1; i < 10; i++ {          // 19..10
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t2, &t2, &t1) // 19..0
	edwards25519.FeSquare(&t3, &t2)   // 20..1
	for i = 1; i < 20; i++ {          // 39..20
		edwards25519.FeSquare(&t3, &t3)
	}
	edwards25519.FeMul(&t2, &t3, &t2) // 39..0
	edwards25519.FeSquare(&t2, &t2)   // 40..1
	for i = 1; i < 10; i++ {          // 49..10
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 49..0
	edwards25519.FeSquare(&t2, &t1)   // 50..1
	for i = 1; i < 50; i++ {          // 99..50
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t2, &t2, &t1) // 99..0
	edwards25519.FeSquare(&t3, &t2)   // 100..1
	for i = 1; i < 100; i++ {         // 199..100
		edwards25519.FeSquare(&t3, &t3)
	}
	edwards25519.FeMul(&t2, &t3, &t2) // 199..0
	edwards25519.FeSquare(&t2, &t2)   // 200..1
	for i = 1; i < 50; i++ {          // 249..50
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1) // 249..0
	edwards25519.FeSquare(&t1, &t1)   // 250..1
	for i = 1; i < 4; i++ {           // 253..4
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(out, &t1, &t0) // 253..4,2,1
}

// RepresentativeToPublicKey converts a uniform representative value for a
// curve25519 public key, as produced by GenerateKey, to a curve25519 public
// key.
func RepresentativeToPublicKey(publicKey, representative *[32]byte) {
	// Mask out the 2 high bits, of the representative.
	var maskedRepresentative [32]byte
	copy(maskedRepresentative[:], representative[:])
	maskedRepresentative[31] &= 0x3f

	var rr2, v, e edwards25519.FieldElement
	edwards25519.FeFromBytes(&rr2, &maskedRepresentative)

	edwards25519.FeSquare2(&rr2, &rr2)
	rr2[0]++
	edwards25519.FeInvert(&rr2, &rr2)
	edwards25519.FeMul(&v, &edwards25519.A, &rr2)
	edwards25519.FeNeg(&v, &v)

	var v2, v3 edwards25519.FieldElement
	edwards25519.FeSquare(&v2, &v)
	edwards25519.FeMul(&v3, &v, &v2)
	edwards25519.FeAdd(&e, &v3, &v)
	edwards25519.FeMul(&v2, &v2, &edwards25519.A)
	edwards25519.FeAdd(&e, &v2, &e)
	chi(&e, &e)
	var eBytes [32]byte
	edwards25519.FeToBytes(&eBytes, &e)
	// eBytes[1] is either 0 (for e = 1) or 0xff (for e = -1)
	eIsMinus1 := int32(eBytes[1]) & 1
	var negV edwards25519.FieldElement
	edwards25519.FeNeg(&negV, &v)
	edwards25519.FeCMove(&v, &negV, eIsMinus1)

	edwards25519.FeZero(&v2)
	edwards25519.FeCMove(&v2, &edwards25519.A, eIsMinus1)
	edwards25519.FeSub(&v, &v, &v2)

	edwards25519.FeToBytes(publicKey, &v)
}
