// client.go - Transport client implementation.
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

package basket2

import (
	"net"

	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
	"git.schwanenlied.me/yawning/basket2.git/crypto/rand"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
	"git.schwanenlied.me/yawning/basket2.git/handshake"
)

// ClientConfig is the client configuration parameters to use when
// constructing a ClientConn.
type ClientConfig struct {
	KEXMethod       handshake.KEXMethod
	PaddingMethods  []PaddingMethod
	ServerPublicKey *identity.PublicKey
}

// ClientConn is a client connection instance, that implements the net.Conn
// interface.
type ClientConn struct {
	commonConn

	config         *ClientConfig
	handshakeState *handshake.ClientHandshake
}

// Handshake associates a ClientConn with an established net.Conn, and executes
// the authenticated/encrypted/obfuscated key exchange, and optionally
// authenticates the client with the server.
func (c *ClientConn) Handshake(conn net.Conn) (err error) {
	// Pass or fail, obliterate the handshake state.
	defer c.handshakeState.Reset()
	defer func() {
		if err != nil {
			c.setState(stateError)
		}
	}()

	if err = c.setState(stateHandshaking); err != nil {
		return
	}
	c.conn = conn

	// Build the request extData to negotiate padding algorithms.
	reqExtData := make([]byte, 0, 1+1+len(c.config.PaddingMethods))
	reqExtData = append(reqExtData, ProtocolVersion)
	reqExtData = append(reqExtData, byte(len(c.config.PaddingMethods)))
	for _, v := range c.config.PaddingMethods {
		reqExtData = append(reqExtData, byte(v))
	}

	// XXX: Determine the request padding length.
	padLen := 0

	var keys *handshake.SessionKeys
	var respExtData []byte
	if keys, respExtData, err = c.handshakeState.Handshake(c.conn, reqExtData, padLen); err != nil {
		return
	}
	defer keys.Reset()

	// XXX: Parse the response extData to see which padding algorithm to use,
	// and if authentication is possible/required.
	_ = respExtData
	shouldAuth := false
	paddingMethod := PaddingNull

	// Validate that the negotiated padding method is contained in our request.
	if !paddingOk(paddingMethod, c.config.PaddingMethods) {
		return ErrInvalidPadding
	}

	// Initialize the frame encoder/decoder with the session key material.
	if c.txEncoder, err = tentp.NewEncoderFromKDF(keys.KDF); err != nil {
		return
	}
	if c.rxDecoder, err = tentp.NewDecoderFromKDF(keys.KDF); err != nil {
		return
	}

	// Bring the chosen padding algorithm online.
	if err = c.setPadding(paddingMethod); err != nil { // XXX: Padding params
		return
	}

	// Authenticate if needed.
	if shouldAuth {
		if err = c.setState(stateAuthenticate); err != nil {
			return
		}

		// XXX: Sign TranscriptDigest, and send the authentication request.
		// keys.TranscriptDigest  <- sign this shit.

		// XXX: Figure out how to invoke the padding algorithm for auth. :/

		// Receive the authentication response.
	}

	// The connection is now fully established.
	if err = c.setState(stateEstablished); err != nil {
		return
	}

	return nil
}

// NewClientConn initializes a ClientConn.  This step should be done offline,
// as timing variation due to the Elligator 2 rejection sampling may leak
// information regarding the obfuscation method.
func NewClientConn(config *ClientConfig) (*ClientConn, error) {
	var err error

	if len(config.PaddingMethods) == 0 {
		panic("basket2: no requested padding methods")
	}
	if len(config.PaddingMethods) > 255 {
		panic("basket2: too many padding methods")
	}
	if config.ServerPublicKey == nil {
		panic("basket2: no server public key")
	}

	c := new(ClientConn)
	c.config = config
	c.isClient = true
	if c.mRNG, err = rand.New(); err != nil {
		return nil, err
	}
	if c.handshakeState, err = handshake.NewClientHandshake(rand.Reader, config.KEXMethod, config.ServerPublicKey); err != nil {
		return nil, err
	}

	return c, nil
}

var _ net.Conn = (*ClientConn)(nil)
