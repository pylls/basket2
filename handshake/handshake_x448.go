// handshake_x448.go - X448/NewHope key exchange.
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

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/newhope.git"
	"git.schwanenlied.me/yawning/x448.git"
)

const (
	// X448NewHope is the X448/NewHope based handshake method.
	X448NewHope Method = 1

	x448ReqSize  = 1 + 1 + 56 + newhope.SendASize
	x448RespSize = 1 + 1 + 56 + newhope.SendBSize

	x448XOffset  = 2
	x448NHOffset = 2 + 56

	x448PadNormSize = newhope.SendBSize - (64 + newhope.SendASize)
)

var (
	x448RandTweak = []byte("basket2-x448-tweak")
)

func (c *ClientHandshake) handshakeX448(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, []byte, error) {
	if c.method != X448NewHope {
		panic("handshake: expected X448")
	}

	// Generate the ephemeral X448 keypair.
	var xPublicKey, xPrivateKey [56]byte
	defer crypto.Memwipe(xPrivateKey[:])
	if err := newX448KeyPair(c.rand, &xPublicKey, &xPrivateKey); err != nil {
		return nil, nil, err
	}

	// Craft the handshake request blob.
	reqBlob := make([]byte, 0, x448ReqSize+len(extData))
	reqBlob = append(reqBlob, HandshakeVersion)
	reqBlob = append(reqBlob, byte(c.method))
	reqBlob = append(reqBlob, xPublicKey[:]...)
	reqBlob = append(reqBlob, c.nhPublicKey.Send[:]...)
	reqBlob = append(reqBlob, extData...)

	// Normalize the pre-padding request length with the pre-padding
	// response length.
	padLen += x448PadNormSize

	// Obfuscate and transmit the blob, receive and deobfuscate the response.
	respBlob, err := c.obfs.handshake(rw, reqBlob, padLen)
	if err != nil {
		return nil, nil, err
	}

	// Parse the response, complete the handshake.
	if len(respBlob) < x448RespSize {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[0] != HandshakeVersion {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[1] != byte(X448NewHope) {
		return nil, nil, ErrInvalidMethod
	}

	// X448 key exchange with the server's ephemeral key.
	var xSharedSecret [56]byte
	defer crypto.Memwipe(xSharedSecret[:])
	copy(xPublicKey[:], respBlob[x448XOffset:])
	if x448.ScalarMult(&xSharedSecret, &xPrivateKey, &xPublicKey) != 0 {
		return nil, nil, ErrInvalidPoint
	}

	// NewHope key exchange with the server's public key.
	var nhPublicKey newhope.PublicKeyBob
	copy(nhPublicKey.Send[:], respBlob[x448NHOffset:])
	nhSharedSecret, err := newhope.KeyExchangeAlice(&nhPublicKey, c.nhPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)

	k := newSessionKeys(c.obfs.transcriptDigest[:], xSharedSecret[:], nhSharedSecret)

	return k, respBlob[x448RespSize:], nil
}

func (s *ServerHandshake) parseReqX448() ([]byte, error) {
	if s.method != X448NewHope {
		panic("handshake: expected X448")
	}

	if len(s.reqBlob) < x448ReqSize {
		return nil, ErrInvalidPayload
	}

	return s.reqBlob[x448ReqSize:], nil
}

func (s *ServerHandshake) sendRespX448(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, error) {
	if s.method != X448NewHope {
		panic("handshake: expected X448")
	}

	// Craft the static portions of the response body, which will be appended
	// to as the handshake proceeds.
	respBlob := make([]byte, 0, x448RespSize+len(extData))
	respBlob = append(respBlob, HandshakeVersion)
	respBlob = append(respBlob, byte(s.method))

	// Generate a new X448 keypair.
	var xPublicKey, xPrivateKey, xSharedSecret [56]byte
	defer crypto.Memwipe(xPrivateKey[:])
	defer crypto.Memwipe(xSharedSecret[:])
	if err := newX448KeyPair(s.rand, &xPublicKey, &xPrivateKey); err != nil {
		return nil, err
	}
	respBlob = append(respBlob, xPublicKey[:]...)
	copy(xPublicKey[:], s.reqBlob[x448XOffset:])

	// X448 key exchange with both ephemeral keys.
	if x448.ScalarMult(&xSharedSecret, &xPrivateKey, &xPublicKey) != 0 {
		return nil, ErrInvalidPoint
	}

	// NewHope key exchange with the client's public key.
	var nhPublicKeyAlice newhope.PublicKeyAlice
	copy(nhPublicKeyAlice.Send[:], s.reqBlob[x448NHOffset:])
	h, err := crypto.NewTweakedShake256(s.rand, newhopeRandTweak)
	if err != nil {
		return nil, err
	}
	defer h.Reset()
	nhPublicKey, nhSharedSecret, err := newhope.KeyExchangeBob(h, &nhPublicKeyAlice)
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

func newX448KeyPair(rand io.Reader, publicKey, privateKey *[56]byte) error {
	rh, err := crypto.NewTweakedShake256(rand, x448RandTweak)
	if err != nil {
		return err
	}
	defer rh.Reset()

	if _, err := io.ReadFull(rh, privateKey[:]); err != nil {
		return err
	}
	if x448.ScalarBaseMult(publicKey, privateKey) != 0 {
		return ErrInvalidPoint
	}

	return nil
}