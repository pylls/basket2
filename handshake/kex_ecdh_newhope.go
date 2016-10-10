// kex_ecdh_newhope.go - ECDH/NewHope key exchange.
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

package handshake

import (
	"io"

	"github.com/pylls/basket2/crypto"
	"github.com/pylls/basket2/crypto/ecdh"
	"git.schwanenlied.me/yawning/newhope.git"
)

const (
	// X25519NewHope is the X25519/NewHope based handshake method.
	X25519NewHope KEXMethod = 0

	// X448NewHope is the X448/NewHope based handshake method.
	X448NewHope KEXMethod = 1

	x25519NHReqSize         = 1 + 1 + newhope.SendASize
	x25519NHRespSize        = 1 + 1 + ecdh.X25519Size + newhope.SendBSize
	x25519NHReqPadNormSize  = (x448NHReqSize - x25519NHReqSize) + x448NHPadNormSize
	x25519NHRespPadNormSize = x448NHRespSize - x25519NHRespSize

	x448NHReqSize     = 1 + 1 + ecdh.X448Size + newhope.SendASize
	x448NHRespSize    = 1 + 1 + ecdh.X448Size + newhope.SendBSize
	x448NHPadNormSize = newhope.SendBSize - ((obfsClientOverhead - obfsServerOverhead) + newhope.SendASize)
)

var (
	newhopeRandTweak = []byte("basket2-newhope-tweak")
)

type clientKexEcdhNewHope struct {
	hs *ClientHandshake

	curve      ecdh.Curve
	privateKey ecdh.PrivateKey

	nhPublicKey  *newhope.PublicKeyAlice
	nhPrivateKey *newhope.PrivateKeyAlice
}

func (c *clientKexEcdhNewHope) handshake(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, []byte, error) {
	var reqSize, respSize, padNormSize int
	switch c.curve {
	case ecdh.X25519:
		reqSize, respSize, padNormSize = x25519NHReqSize, x25519NHRespSize, x25519NHReqPadNormSize
	case ecdh.X448:
		reqSize, respSize, padNormSize = x448NHReqSize, x448NHRespSize, x448NHPadNormSize
	default:
		panic("kex: unknown curve")
	}

	// Craft the handshake request blob.
	reqBlob := make([]byte, 0, reqSize+len(extData))
	reqBlob = append(reqBlob, HandshakeVersion)
	reqBlob = append(reqBlob, byte(c.hs.kexMethod))
	if c.curve != ecdh.X25519 {
		reqBlob = append(reqBlob, c.privateKey.PublicKey().ToBytes()...)
	}
	reqBlob = append(reqBlob, c.nhPublicKey.Send[:]...)
	reqBlob = append(reqBlob, extData...)

	// Normalize the pre-padding request length with the pre-padding
	// response length.
	padLen += padNormSize

	// Obfuscate and transmit the blob, receive and deobfuscate the response.
	respBlob, err := c.hs.obfs.handshake(rw, reqBlob, padLen)
	if err != nil {
		return nil, nil, err
	}

	// Parse the response, complete the handshake.
	if len(respBlob) < respSize {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[0] != HandshakeVersion {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[1] != byte(c.hs.kexMethod) {
		return nil, nil, ErrInvalidKEXMethod
	}

	// ECDH key exchange with the server's ephemeral key.
	pkTail := 2 + c.privateKey.PublicKey().Size()
	xPublicKey, err := ecdh.PublicKeyFromBytes(c.curve, respBlob[2:pkTail])
	if err != nil {
		return nil, nil, err
	}
	xSharedSecret, err := c.privateKey.ScalarMult(xPublicKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

	// NewHope key exchange with the server's public key.
	var nhPublicKey newhope.PublicKeyBob
	copy(nhPublicKey.Send[:], respBlob[pkTail:])
	nhSharedSecret, err := newhope.KeyExchangeAlice(&nhPublicKey, c.nhPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)

	// Derive the session keys.
	secrets := make([]([]byte), 0, 3)
	secrets = append(secrets, c.hs.obfs.sharedSecret)
	secrets = append(secrets, xSharedSecret)
	secrets = append(secrets, nhSharedSecret)
	k := newSessionKeys(secrets, c.hs.obfs.transcriptDigest[:])

	return k, respBlob[respSize:], nil
}

func (c *clientKexEcdhNewHope) Reset() {
	if c.nhPrivateKey != nil {
		c.nhPrivateKey.Reset()
		c.nhPrivateKey = nil
	}
	if c.privateKey != nil {
		if c.curve != ecdh.X25519 {
			// The X25519 case is skipped since it's an alias into the
			// obfuscation state.
			c.privateKey.Reset()
		}
		c.privateKey = nil
	}
}

func newClientKexEcdhNewHope(hs *ClientHandshake) (*clientKexEcdhNewHope, error) {
	c := new(clientKexEcdhNewHope)
	c.hs = hs

	// Generate the NewHope keypair.
	h, err := crypto.NewTweakedShake256(hs.rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	if c.nhPrivateKey, c.nhPublicKey, err = newhope.GenerateKeyPair(h); err != nil {
		return nil, err
	}

	// Generate the ECDH keypair.
	switch hs.kexMethod {
	case X25519NewHope:
		// Reuse the key pair from the obfsucation context.  This loses approx
		// 0.5 bits of security, but saves a scalar basepoint multiply.
		c.privateKey = hs.obfs.privKey
		c.curve = ecdh.X25519
	case X448NewHope:
		if c.privateKey, err = ecdh.New(hs.rand, ecdh.X448, false); err != nil {
			return nil, err
		}
		c.curve = ecdh.X448
	default:
		return nil, ecdh.ErrInvalidCurve
	}

	return c, nil
}

type serverKexEcdhNewHope struct {
	hs *ServerHandshake

	respSize    int
	padNormSize int

	curve           ecdh.Curve
	clientPublicKey ecdh.PublicKey

	clientNHPublicKey newhope.PublicKeyAlice
}

func (s *serverKexEcdhNewHope) handshake(w io.Writer, extData []byte, padLen int) (*SessionKeys, error) {
	// Craft the static portions of the response body, which will be appended
	// to as the handshake proceeds.
	respBlob := make([]byte, 0, s.respSize+len(extData))
	respBlob = append(respBlob, HandshakeVersion)
	respBlob = append(respBlob, byte(s.hs.kexMethod))

	// Generate a new ECDH keypair.
	xPrivateKey, err := ecdh.New(s.hs.rand, s.curve, false)
	if err != nil {
		return nil, err
	}
	defer xPrivateKey.Reset()
	respBlob = append(respBlob, xPrivateKey.PublicKey().ToBytes()...)

	// ECDH key exchange with both ephemeral keys.
	xSharedSecret, err := xPrivateKey.ScalarMult(s.clientPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

	// NewHope key exchange with the client's public key.
	h, err := crypto.NewTweakedShake256(s.hs.rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	nhPublicKey, nhSharedSecret, err := newhope.KeyExchangeBob(h, &s.clientNHPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)
	respBlob = append(respBlob, nhPublicKey.Send[:]...)

	// Append the extData and dispatch the response.
	padLen += s.padNormSize
	respBlob = append(respBlob, extData...)
	if err := s.hs.obfs.sendHandshakeResp(w, respBlob, padLen); err != nil {
		return nil, err
	}

	// Derive the session keys.
	secrets := make([]([]byte), 0, 3)
	secrets = append(secrets, s.hs.obfs.sharedSecret)
	secrets = append(secrets, xSharedSecret)
	secrets = append(secrets, nhSharedSecret)
	k := newSessionKeys(secrets, s.hs.obfs.transcriptDigest[:])

	return k, nil
}

func newServerKexEcdhNewHope(hs *ServerHandshake, reqBlob []byte) (*serverKexEcdhNewHope, []byte, error) {
	s := new(serverKexEcdhNewHope)
	s.hs = hs

	var reqLen, pkTail int
	switch hs.kexMethod {
	case X25519NewHope:
		s.curve = ecdh.X25519
		s.respSize = x25519NHRespSize
		s.padNormSize = x25519NHRespPadNormSize
		reqLen = x25519NHReqSize
	case X448NewHope:
		pkTail = 2 + ecdh.X448Size
		s.curve = ecdh.X448
		s.respSize = x448NHRespSize
		reqLen = x448NHReqSize
	default:
		return nil, nil, ecdh.ErrInvalidCurve
	}

	if len(reqBlob) < reqLen {
		return nil, nil, ErrInvalidPayload
	}

	// Stash the ECDH public key.
	if s.curve == ecdh.X25519 {
		s.clientPublicKey = hs.obfs.clientPublicKey
	} else {
		var err error
		s.clientPublicKey, err = ecdh.PublicKeyFromBytes(s.curve, reqBlob[2:pkTail])
		if err != nil {
			return nil, nil, err
		}
	}

	// Stash the NewHope public key.
	copy(s.clientNHPublicKey.Send[:], reqBlob[reqLen-newhope.SendASize:])

	return s, reqBlob[reqLen:], nil
}
