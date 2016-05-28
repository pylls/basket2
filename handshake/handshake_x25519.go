// handshake_x25519.go - X25519/NewHope key exchange.
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
	// X25519NewHope is the X25519/NewHope based handshake method.
	X25519NewHope KEXMethod = 0

	x25519ReqSize  = 1 + 1 + newhope.SendASize
	x25519RespSize = 1 + 1 + ecdh.X25519Size + newhope.SendBSize

	x25519RespXOffset  = 2
	x25519RespNHOffset = 2 + ecdh.X25519Size
	x25519ReqNHOffset  = 2

	// Pad to X448 handshake size...
	x25519ReqPadNormSize  = (x448ReqSize - x25519ReqSize) + x448PadNormSize
	x25519RespPadNormSize = x448RespSize - x25519RespSize
)

func (c *ClientHandshake) handshakeX25519(rw io.ReadWriter, extData []byte, padLen int) (*SessionKeys, []byte, error) {
	if c.kexMethod != X25519NewHope {
		panic("handshake: expected X25519")
	}

	// Craft the handshake request blob.
	reqBlob := make([]byte, 0, x25519ReqSize+len(extData))
	reqBlob = append(reqBlob, HandshakeVersion)
	reqBlob = append(reqBlob, byte(c.kexMethod))
	reqBlob = append(reqBlob, c.nhPublicKey.Send[:]...)
	reqBlob = append(reqBlob, extData...)

	// Normalize the pre-padding request length with the X448 pre-padding
	// response length.
	padLen += x25519ReqPadNormSize

	// Obfuscate and transmit the blob, receive and deobfuscate the response.
	respBlob, err := c.obfs.handshake(rw, reqBlob, padLen)
	if err != nil {
		return nil, nil, err
	}

	// Parse the response, complete the handshake.
	if len(respBlob) < x25519RespSize {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[0] != HandshakeVersion {
		return nil, nil, ErrInvalidPayload
	}
	if respBlob[1] != byte(X25519NewHope) {
		return nil, nil, ErrInvalidKEXMethod
	}

	// X25519 key exchange with the server's ephemeral key.
	xPublicKey, err := ecdh.PublicKeyFromBytes(ecdh.X25519, respBlob[x25519RespXOffset:x25519RespXOffset+ecdh.X25519Size])
	if err != nil {
		return nil, nil, err
	}
	xSharedSecret, err := c.obfs.privKey.ScalarMult(xPublicKey)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

	// NewHope key exchange with the server's public key.
	var nhPublicKey newhope.PublicKeyBob
	copy(nhPublicKey.Send[:], respBlob[x25519RespNHOffset:])
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

	return k, respBlob[x25519RespSize:], nil
}

func (s *ServerHandshake) parseReqX25519() ([]byte, error) {
	if s.kexMethod != X25519NewHope {
		panic("handshake: expected X25519")
	}

	if len(s.reqBlob) < x25519ReqSize {
		return nil, ErrInvalidPayload
	}

	return s.reqBlob[x25519ReqSize:], nil
}

func (s *ServerHandshake) sendRespX25519(w io.Writer, extData []byte, padLen int) (*SessionKeys, error) {
	if s.kexMethod != X25519NewHope {
		panic("handshake: expected X25519")
	}

	// Craft the static portions of the response body, which will be appended
	// to as the handshake proceeds.
	respBlob := make([]byte, 0, x25519RespSize+len(extData))
	respBlob = append(respBlob, HandshakeVersion)
	respBlob = append(respBlob, byte(s.kexMethod))

	// Generate a new X25519 keypair.
	xPrivateKey, err := ecdh.New(s.rand, ecdh.X25519, false)
	if err != nil {
		return nil, err
	}
	defer xPrivateKey.Reset()
	respBlob = append(respBlob, xPrivateKey.PublicKey().ToBytes()...)

	// X25519 key exchange with both ephemeral keys.
	xSharedSecret, err := xPrivateKey.ScalarMult(s.obfs.clientPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.Memwipe(xSharedSecret)

	// NewHope key exchange with the client's public key.
	var nhPublicKeyAlice newhope.PublicKeyAlice
	copy(nhPublicKeyAlice.Send[:], s.reqBlob[x25519ReqNHOffset:])
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

	// Append the extData.
	respBlob = append(respBlob, extData...)

	// Normalize the pre-padding response length with the X448 pre-padding
	// response length.
	padLen += x25519RespPadNormSize
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
