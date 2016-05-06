// handshake.go - ECDHE + NewHope key exchange.
// Copyright (C) 2016 Yawning Angel.
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

// Package handshake implements the basket2 obfuscated/authenticated key
// exchange currently based on ECDHE + NewHope.
package handshake

import (
	"errors"
	"fmt"
	"io"

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
	"git.schwanenlied.me/yawning/newhope.git"

	"golang.org/x/crypto/sha3"
)

// KEXMethod is a supported/known handshake key exchange primitive set
// approximately analagous to a TLS ciphersuite.
type KEXMethod byte

const (
	// HandshakeVersion is the current handshake version.
	HandshakeVersion = 1

	// KEXInvalid is a invalid/undefined KEX method.
	KEXInvalid KEXMethod = 0xff

	// MessageSize is the length that all handshake messages get padded to,
	// without including user extData or padding (2146 bytes).
	MessageSize = x448RespSize + obfsServerOverhead

	// MinHandshakeSize is the minimum total handshake length.
	MinHandshakeSize = 4096

	// MaxHandshakeSize is the maximum total handshake length.
	MaxHandshakeSize = 8192

	minReqSize = 1 + 1
)

var (
	// ErrInvalidKEXMethod is the error returned when the handshake KEX method
	// is invalid/unsupported.
	ErrInvalidKEXMethod = errors.New("handshake: invalid KEX method")

	// ErrInvalidPayload is the error returned when the handshake message
	// is malformed.
	ErrInvalidPayload = errors.New("handshake: invalid payload")

	handshakeKdfTweak = []byte("basket2-handshake-v1-kdf-tweak")
	newhopeRandTweak  = []byte("basket2-newhope-tweak")

	supportedMethods map[KEXMethod]bool
)

// ToHexString returns the hexdecimal string representation of a KEX method.
func (m KEXMethod) ToHexString() string {
	return fmt.Sprintf("%02x", m)
}

// SessionKeys is the handshake output.  It is safe to assume contributatory
// behavior from both parties in the KDF output and the handshake transcript
// digest, as points of small order are explicitly rejected.
type SessionKeys struct {
	// KDF is the key derivation function initialized with handshake output.
	KDF io.Reader

	// TranscriptDigest is the 32 byte handshake transcript digest, the tweaked
	// SHA3-256 hash of every single bit sent on the network for the handshake.
	// Both the client and server will have matching values, unless active
	// attackers are doing evil.
	TranscriptDigest []byte
}

// Reset clears a SessionKeys instance such that no sensitive values appear in
// memory.
func (k *SessionKeys) Reset() {
	if k.KDF != nil {
		kdf := k.KDF.(sha3.ShakeHash)
		kdf.Reset()
		k.KDF = nil
	}
	crypto.Memwipe(k.TranscriptDigest)
}

func newSessionKeys(transcriptDigest, oSecret, xSecret, nhSecret []byte) *SessionKeys {
	k := new(SessionKeys)

	// Alice: SHAKE256(tweak | EXP(a,B) | EXP(x,Y) | NewHopeA(sk, BobPK) | transcriptDigest)
	// Bob: SHAKE256(tweak | EXP(b,A) EXP(y,X) | NewHopeB(AlicePK) | transcriptDigest)
	kdf := sha3.NewShake256()
	kdf.Write(handshakeKdfTweak)
	kdf.Write(oSecret)
	kdf.Write(xSecret)
	kdf.Write(nhSecret)
	kdf.Write(transcriptDigest)

	k.KDF = kdf
	k.TranscriptDigest = transcriptDigest

	return k
}

// ClientHandshake is the client handshake state.
type ClientHandshake struct {
	rand io.Reader

	obfs *clientObfsCtx

	kexMethod KEXMethod

	nhPublicKey  *newhope.PublicKeyAlice
	nhPrivateKey *newhope.PrivateKeyAlice
}

// Handshake completes the client side of the handshake, and returns the
// dervied session keys, and whatever extended data the server sent as part
// of it's handshake response.  Callers are responsible for setting timeouts as
// appropriate.  Upon return, Reset will be called automatically.
//
// Note: Both the client and server's extData is encrypted and authenticated,
// however there is no Perfect Forward Secrecy due to the use of
// ephemeral/static ECDH.  Suitable care must be taken in what is sent as
// extData.  The session keys derived from the handshake DO have PFS.
func (c *ClientHandshake) Handshake(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, []byte, error) {
	defer c.Reset()

	switch c.kexMethod {
	case X25519NewHope:
		return c.handshakeX25519(rw, extData, padLen)
	case X448NewHope:
		return c.handshakeX448(rw, extData, padLen)
	default:
		return nil, nil, ErrInvalidKEXMethod
	}
}

// Reset clears a ClientHandshake instance such that senstive material no longer
// appears in memory.
func (c *ClientHandshake) Reset() {
	if c.obfs != nil {
		c.obfs.reset()
		c.obfs = nil
	}
	c.nhPublicKey = nil
	if c.nhPrivateKey != nil {
		c.nhPrivateKey.Reset()
		c.nhPrivateKey = nil
	}
}

// NewClientHandshake creates a new ClientHandshake instance suitable for
// a single handshake with a provided peer identified by a public key.
//
// Note: Due to the rejection sampling in Elligator 2 keypair generation, this
// should be done offline.  The timing variation only leaks information about
// the obfuscation method, and does not compromise secrecy or integrity.
func NewClientHandshake(rand io.Reader, kexMethod KEXMethod, serverPublicKey *identity.PublicKey) (*ClientHandshake, error) {
	var err error
	c := new(ClientHandshake)
	c.rand = rand
	c.kexMethod = kexMethod

	// Generate the NewHope keypair.
	h, err := crypto.NewTweakedShake256(rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	if c.nhPrivateKey, c.nhPublicKey, err = newhope.GenerateKeyPair(h); err != nil {
		return nil, err
	}

	switch c.kexMethod {
	case X25519NewHope:
	case X448NewHope:
	default:
		return nil, ErrInvalidKEXMethod
	}

	// Generate the obfuscation state (which generates a X25519 keypair and
	// Elligator 2 representative).
	if c.obfs, err = newClientObfs(rand, serverPublicKey); err != nil {
		c.Reset()
		return nil, err
	}

	return c, nil
}

// ServerHandshake is the server handshake state.
type ServerHandshake struct {
	rand              io.Reader
	allowedKEXMethods []KEXMethod

	obfs *serverObfsCtx

	kexMethod KEXMethod
	reqBlob   []byte
}

// RecvHandshakeReq receives and validates the client's handshake request and
// returns the client's extData if any.  Callers are responsible for setting
// timeouts as appropriate.
func (s *ServerHandshake) RecvHandshakeReq(r io.Reader) ([]byte, error) {
	reqBlob, err := s.obfs.recvHandshakeReq(r)
	if err != nil {
		return nil, err
	}

	// Parse the request, and extract the required keying material.
	if len(reqBlob) < minReqSize {
		return nil, ErrInvalidPayload
	}
	if reqBlob[0] != HandshakeVersion {
		return nil, ErrInvalidPayload
	}
	s.kexMethod = KEXMethod(reqBlob[1])
	s.reqBlob = reqBlob
	if !s.isAllowedKEXMethod(s.kexMethod) {
		return nil, ErrInvalidKEXMethod
	}

	switch s.kexMethod {
	case X25519NewHope:
		return s.parseReqX25519()
	case X448NewHope:
		return s.parseReqX448()
	default:
		return nil, ErrInvalidKEXMethod
	}
}

// SendHandshakeResp sends the handshake response, any extData if neccecary,
// and derives the session keys.  Like with ClientHandshake.Handshake, the
// extData is encrypted/authenticated without PFS.  Callers are responsible
// for setting timeouts as appropriate.  Upon return, Reset will be called
// automatically.
func (s *ServerHandshake) SendHandshakeResp(w io.Writer, extData []byte, padLen int) (*SessionKeys, error) {
	defer s.Reset()

	switch s.kexMethod {
	case X25519NewHope:
		return s.sendRespX25519(w, extData, padLen)
	case X448NewHope:
		return s.sendRespX448(w, extData, padLen)
	default:
		return nil, ErrInvalidKEXMethod
	}
}

// Reset clears a ServerHandshake instance such that sensitive material no
// longer appears in memory.
func (s *ServerHandshake) Reset() {
	if s.obfs != nil {
		s.obfs.reset()
		s.obfs = nil
	}
}

func (s *ServerHandshake) isAllowedKEXMethod(kexMethod KEXMethod) bool {
	for _, v := range s.allowedKEXMethods {
		if v == kexMethod {
			return true
		}
	}
	return false
}

// NewServerHandshake creates a new ServerHandshake instance suitable for a
// single handshake to the provided peer identified by a private key.
func NewServerHandshake(rand io.Reader, kexMethods []KEXMethod, replay ReplayFilter, serverPrivateKey *identity.PrivateKey) (*ServerHandshake, error) {
	var err error
	s := new(ServerHandshake)
	s.rand = rand
	s.allowedKEXMethods = kexMethods

	// Generate the obfuscation state.  The actual handshake response keypair
	// generation is handled when the handshake actually occurs.
	if s.obfs, err = newServerObfs(replay, serverPrivateKey); err != nil {
		s.Reset()
		return nil, err
	}

	return s, nil
}

// IsSupportedMethod returns true iff the KEX method is supported.
func IsSupportedMethod(m KEXMethod) bool {
	return supportedMethods[m]
}

func init() {
	supportedMethods = make(map[KEXMethod]bool)
	supportedMethods[X25519NewHope] = true
	supportedMethods[X448NewHope] = true
}
