// handshake.go - X25519/New Hope key exchange.
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
// exchange currently based on X25519/New Hope.
package handshake

import (
	"errors"
	"io"

	"git.schwanenlied.me/yawning/a2filter.git"
	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
	"git.schwanenlied.me/yawning/newhope.git"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// Method is a supported/known handshake primitive set approximately analagous
// to a TLS ciphersuite.
type Method int

const (
	// X25519NewHope is the current X25519/New Hope based handshake method.
	X25519NewHope Method = iota

	handshakeVersion = 0

	clientReqSize  = 1 + 1 + newhope.SendASize
	serverRespSize = 1 + 1 + 32 + newhope.SendBSize

	respXOffset  = 2
	respNHOffset = 2 + 32

	reqNHOffset = 2

	// Client handshake is shorter than the server handshake after obfuscation
	// due to the client sending a mark, and the server's New Hope "public key"
	// being larger.
	clientPadNormSize = newhope.SendBSize - (32 + newhope.SendASize)

	maxKeygenAttempts = 8
	replayDefaultSize = 22      // 4 MiB (2^22 bytes)
	replayDefaultRate = 0.00001 // 1/100k (False postive rate)
)

var (
	// ErrInvalidMethod is the error returned when the handshake method is
	// invalid/unsupported.
	ErrInvalidMethod = errors.New("handshake: invalid method")

	// ErrInvalidPayload is the error returned when the handshake message
	// is malformed.
	ErrInvalidPayload = errors.New("handshake: invalid payload")

	handshakeKdfTweak = []byte("basket2-handshake-v0-kdf-tweak")
	newhopeRandTweak  = []byte("basket2-newhope-tweak")
	x25519RandTewak   = []byte("basket2-x25519-tweak")
)

// SessionKeys is the handshake output.
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

func newSessionKeys(transcriptDigest, xSecret, nhSecret []byte) *SessionKeys {
	k := new(SessionKeys)

	// Alice: SHAKE256(tweak | EXP(x,Y) | NewHopeA(sk, BobPK) | transcriptDigest)
	// Bob: SHAKE256(tweak | EXP(y,X) | NewHopeB(AlicePK) | transcriptDigest)
	kdf := sha3.NewShake256()
	kdf.Write(handshakeKdfTweak)
	kdf.Write(xSecret)
	kdf.Write(nhSecret)
	kdf.Write(transcriptDigest)

	k.KDF = kdf
	k.TranscriptDigest = transcriptDigest

	return k
}

// ClientHandshake is the client handshake state.
type ClientHandshake struct {
	obfs *clientObfsCtx

	method Method

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

	// The method is for futue-proofing.  Till alternate methods exist,
	// an assert equivalent is ok and simplifies the rest of the code.
	if c.method != X25519NewHope {
		panic("handshake: unsupported method")
	}

	// Craft the handshake request blob.
	reqBlob := make([]byte, 0, clientReqSize+len(extData))
	reqBlob = append(reqBlob, handshakeVersion)
	reqBlob = append(reqBlob, byte(c.method))
	reqBlob = append(reqBlob, c.nhPublicKey.Send[:]...)
	reqBlob = append(reqBlob, extData...)

	// Normalize the pre-padding client request length with the pre-padding
	// server response length.
	padLen += clientPadNormSize

	// Obfuscate and transmit the blob, receive and deobfuscate the response.
	respBlob, err := c.obfs.handshake(rw, reqBlob, padLen)
	if err != nil {
		return nil, nil, err
	}

	// Parse the response, complete the handshake.
	if len(respBlob) < serverRespSize {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[0] != handshakeVersion {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[1] != byte(X25519NewHope) {
		return nil, nil, ErrInvalidMethod
	}

	// X25519 key exchange with the server's ephemeral key.
	var xPublicKey, xSharedSecret [32]byte
	defer crypto.Memwipe(xSharedSecret[:])
	copy(xPublicKey[:], respBlob[respXOffset:])
	curve25519.ScalarMult(&xSharedSecret, &c.obfs.privKey, &xPublicKey)
	if crypto.MemIsZero(xSharedSecret[:]) {
		return nil, nil, ErrInvalidPoint
	}

	// New Hope key exchange with the server's public key.
	var nhPublicKey newhope.PublicKeyBob
	copy(nhPublicKey.Send[:], respBlob[respNHOffset:])
	nhSharedSecret, err := newhope.KeyExchangeAlice(&nhPublicKey, c.nhPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)

	k := newSessionKeys(c.obfs.transcriptDigest[:], xSharedSecret[:], nhSharedSecret)

	return k, respBlob[serverRespSize:], nil
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
func NewClientHandshake(rand io.Reader, serverPublicKey *identity.PublicKey) (*ClientHandshake, error) {
	var err error
	c := new(ClientHandshake)
	c.method = X25519NewHope // Make this a param later.

	// Generate the New Hope keypair.
	h, err := crypto.NewTweakedShake256(rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	if c.nhPrivateKey, c.nhPublicKey, err = newhope.GenerateKeyPair(h); err != nil {
		return nil, err
	}

	switch c.method {
	case X25519NewHope:
		// The obfuscation key can safely be used as the ephemeral session key,
		// so there is no separate keygen neccecary.
	default:
		return nil, ErrInvalidMethod
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
	obfs *serverObfsCtx

	method Method

	nhPublicKey *newhope.PublicKeyAlice
}

// RecvHandshakeReq receives and validates the client's handshake request and
// returns the client's extData if any.  Callers are responsible for setting
// timeouts as appropriate.
func (s *ServerHandshake) RecvHandshakeReq(rw io.ReadWriter) ([]byte, error) {
	reqBlob, err := s.obfs.recvHandshakeReq(rw)
	if err != nil {
		return nil, err
	}

	// Parse the request, and extract the required keying material.
	if len(reqBlob) < clientReqSize {
		return nil, ErrInvalidPayload
	}
	if reqBlob[0] != handshakeVersion {
		return nil, ErrInvalidPayload
	}
	if reqBlob[1] != byte(X25519NewHope) {
		return nil, ErrInvalidMethod
	}
	s.method = Method(reqBlob[1])

	s.nhPublicKey = new(newhope.PublicKeyAlice)
	copy(s.nhPublicKey.Send[:], reqBlob[reqNHOffset:])

	return reqBlob[clientReqSize:], nil
}

// SendHandshakeResp sends the handshake response, any extData if neccecary,
// and derives the session keys.  Like with ClientHandshake.Handshake, the
// extData is encrypted/authenticated without PFS.  Callers are responsible
// for setting timeouts as appropriate.  Upon return, Reset will be called
// automatically.
func (s *ServerHandshake) SendHandshakeResp(rand io.Reader, rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, error) {
	defer s.Reset()

	// Blah blah blah, only one method exists, blah.
	if s.method != X25519NewHope {
		panic("handshake: unsupported method")
	}

	// Craft the static portions of the response body, which will be appended
	// to as the handshake proceeds.
	respBlob := make([]byte, 0, serverRespSize+len(extData))
	respBlob = append(respBlob, handshakeVersion)
	respBlob = append(respBlob, byte(s.method))

	// Generate a new X25519 keypair.
	var xPublicKey, xPrivateKey, xSharedSecret [32]byte
	defer crypto.Memwipe(xPrivateKey[:])
	defer crypto.Memwipe(xSharedSecret[:])
	if err := newX25519KeyPair(rand, &xPublicKey, &xPrivateKey); err != nil {
		return nil, err
	}
	respBlob = append(respBlob, xPublicKey[:]...)

	// X25519 key exchange with both ephemeral keys.
	curve25519.ScalarMult(&xSharedSecret, &xPrivateKey, &s.obfs.clientPublicKey)
	if crypto.MemIsZero(xSharedSecret[:]) {
		return nil, ErrInvalidPoint
	}

	// New Hope key exchange with the client's public key.
	h, err := crypto.NewTweakedShake256(rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	nhPublicKey, nhSharedSecret, err := newhope.KeyExchangeBob(h, s.nhPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)
	respBlob = append(respBlob, nhPublicKey.Send[:]...)

	// Append the extData and dispatch the response.
	respBlob = append(respBlob, extData...)
	if err := s.obfs.sendHandshakeResp(rw, respBlob, padLen); err != nil {
		return nil, err
	}

	// Derive the session keys.
	k := newSessionKeys(s.obfs.transcriptDigest[:], xSharedSecret[:], nhSharedSecret)

	return k, nil
}

// Reset clears a ServerHandshake instance such that sensitive material no
// longer appears in memory.
func (s *ServerHandshake) Reset() {
	if s.obfs != nil {
		s.obfs.reset()
		s.obfs = nil
	}
}

// NewServerHandshake creates a new ServerHandshake instance suitable for a
// single handshake to the provided peer identified by a private key.
func NewServerHandshake(replay *a2filter.A2Filter, serverPrivateKey *identity.PrivateKey) (*ServerHandshake, error) {
	var err error
	s := new(ServerHandshake)

	// Generate the obfuscation state.  The actual handshake response keypair
	// generation is handled when the handshake actually occurs.
	if s.obfs, err = newServerObfs(replay, serverPrivateKey); err != nil {
		s.Reset()
		return nil, err
	}

	return s, nil
}

func newX25519KeyPair(rand io.Reader, publicKey, privateKey *[32]byte) error {
	rh, err := crypto.NewTweakedShake256(rand, x25519RandTewak)
	if err != nil {
		return err
	}
	defer rh.Reset()
	for i := 0; i < maxKeygenAttempts; i++ {
		if _, err := io.ReadFull(rh, privateKey[:]); err != nil {
			return err
		}

		curve25519.ScalarBaseMult(publicKey, privateKey)
		if !crypto.MemIsZero(publicKey[:]) {
			return nil
		}
	}

	return ErrInvalidPoint
}

// NewReplay creates a new replay filter suitable for most server endpoints.
func NewReplay() (*a2filter.A2Filter, error) {
	return a2filter.New(replayDefaultSize, replayDefaultRate)
}
