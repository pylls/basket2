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
	"git.schwanenlied.me/yawning/basket2.git/crypto/ecdh"
	"git.schwanenlied.me/yawning/newhope.git"
)

const (
	// X448NewHope is the X448/NewHope based handshake method.
	X448NewHope KEXMethod = 1

	x448ReqSize  = 1 + 1 + ecdh.X448Size + newhope.SendASize
	x448RespSize = 1 + 1 + ecdh.X448Size + newhope.SendBSize

	x448XOffset  = 2
	x448NHOffset = 2 + ecdh.X448Size

	x448PadNormSize = newhope.SendBSize - ((obfsClientOverhead - obfsServerOverhead) + newhope.SendASize)
)

func (c *ClientHandshake) handshakeX448(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, []byte, error) {
	if c.kexMethod != X448NewHope {
		panic("handshake: expected X448")
	}

	// Generate the ephemeral X448 keypair.
	xPrivateKey, err := ecdh.New(c.rand, ecdh.X448, false)
	if err != nil {
		return nil, nil, err
	}
	defer xPrivateKey.Reset()

	// Craft the handshake request blob.
	reqBlob := make([]byte, 0, x448ReqSize+len(extData))
	reqBlob = append(reqBlob, HandshakeVersion)
	reqBlob = append(reqBlob, byte(c.kexMethod))
	reqBlob = append(reqBlob, xPrivateKey.PublicKey().ToBytes()...)
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
		return nil, nil, ErrInvalidKEXMethod
	}

	// X448 key exchange with the server's ephemeral key.
	xPublicKey, err := ecdh.PublicKeyFromBytes(ecdh.X448, respBlob[x448XOffset:x448XOffset+ecdh.X448Size])
	if err != nil {
		return nil, nil, err
	}
	xSharedSecret, err := xPrivateKey.ScalarMult(xPublicKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

	// NewHope key exchange with the server's public key.
	var nhPublicKey newhope.PublicKeyBob
	copy(nhPublicKey.Send[:], respBlob[x448NHOffset:])
	nhSharedSecret, err := newhope.KeyExchangeAlice(&nhPublicKey, c.nhPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(nhSharedSecret)

	// Derive the session keys.
	secrets := make([]([]byte), 0, 3)
	secrets = append(secrets, c.obfs.sharedSecret)
	secrets = append(secrets, xSharedSecret)
	secrets = append(secrets, nhSharedSecret)
	k := newSessionKeys(secrets, c.obfs.transcriptDigest[:])

	return k, respBlob[x448RespSize:], nil
}

func (s *ServerHandshake) parseReqX448() ([]byte, error) {
	if s.kexMethod != X448NewHope {
		panic("handshake: expected X448")
	}

	if len(s.reqBlob) < x448ReqSize {
		return nil, ErrInvalidPayload
	}

	return s.reqBlob[x448ReqSize:], nil
}

func (s *ServerHandshake) sendRespX448(w io.Writer, extData []byte, padLen int) (*SessionKeys, error) {
	if s.kexMethod != X448NewHope {
		panic("handshake: expected X448")
	}

	// Craft the static portions of the response body, which will be appended
	// to as the handshake proceeds.
	respBlob := make([]byte, 0, x448RespSize+len(extData))
	respBlob = append(respBlob, HandshakeVersion)
	respBlob = append(respBlob, byte(s.kexMethod))

	// Generate a new X448 keypair.
	xPrivateKey, err := ecdh.New(s.rand, ecdh.X448, false)
	if err != nil {
		return nil, err
	}
	defer xPrivateKey.Reset()
	respBlob = append(respBlob, xPrivateKey.PublicKey().ToBytes()...)

	// X448 key exchange with both ephemeral keys.
	xPublicKey, err := ecdh.PublicKeyFromBytes(ecdh.X448, s.reqBlob[x448XOffset:x448XOffset+ecdh.X448Size])
	if err != nil {
		return nil, err
	}
	xSharedSecret, err := xPrivateKey.ScalarMult(xPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

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
	if err := s.obfs.sendHandshakeResp(w, respBlob, padLen); err != nil {
		return nil, err
	}

	// Derive the session keys.
	secrets := make([]([]byte), 0, 3)
	secrets = append(secrets, s.obfs.sharedSecret)
	secrets = append(secrets, xSharedSecret)
	secrets = append(secrets, nhSharedSecret)
	k := newSessionKeys(secrets, s.obfs.transcriptDigest[:])

	return k, nil
}
