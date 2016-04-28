// server.go - Transport server implementation.
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
	"git.schwanenlied.me/yawning/basket2.git/handshake"
)

// ServerConfig is the server configuration parameters to use when
// constructing a ServerConn.
type ServerConfig struct {
	ServerPrivateKey *identity.PrivateKey

	KEXMethods     []handshake.KEXMethod
	PaddingMethods []PaddingMethod
	AuthPolicy     AuthPolicy

	ReplayFilter handshake.ReplayFilter

	// PaddingParamFn is the function called at handshake time to obtain the
	// per-connection padding parameters used to instantiate the server side
	// padding algorithm (that will also be propagated back to the client).
	PaddingParamFn func(PaddingMethod) ([]byte, error)
}

// ServerConn is a server side client connection instance, that implements the
// net.Conn interface.
type ServerConn struct {
	commonConn

	config         *ServerConfig
	handshakeState *handshake.ServerHandshake
}

// Handshake associates a ServerConn with an established net.Conn, and executes
// the authenticated/encrypted/obfuscated key exchange, and optionally
// authenticates the client.
func (c *ServerConn) Handshake(conn net.Conn) (err error) {
	// Pass or fail, obliterate the handshake state.
	defer c.handshakeState.Reset()
	defer func() {
		if err != nil {
			c.setState(stateError)
		}
	}()

	// Initalize the underlying conn structure, and transition to the
	// handshaking state.
	if err = c.initConn(conn); err != nil {
		return
	}

	// Receive the client's handshake request.
	var reqExtData []byte
	if reqExtData, err = c.handshakeState.RecvHandshakeReq(c.conn); err != nil {
		return
	}

	// Parse the request extData to see which padding algorithm(s) the
	// peer wants us to select from.
	if len(reqExtData) < minReqExtDataSize {
		return ErrInvalidExtData
	}
	if reqExtData[0] != ProtocolVersion {
		return ErrInvalidExtData
	}
	if int(reqExtData[1]) != len(reqExtData)-2 {
		return ErrInvalidExtData
	}
	paddingMethod := paddingInvalid
	for _, v := range reqExtData[2:] {
		if paddingOk(PaddingMethod(v), c.config.PaddingMethods) {
			paddingMethod = PaddingMethod(v)
			break
		}
	}
	if paddingMethod == paddingInvalid {
		return ErrInvalidPadding
	}
	var paddingParams []byte
	if paddingParams, err = c.config.PaddingParamFn(paddingMethod); err != nil {
		return
	}

	// Build the response extData.
	respExtData := make([]byte, 0, minRespExtDataSize+len(paddingParams))
	respExtData = append(respExtData, ProtocolVersion)
	respExtData = append(respExtData, byte(c.config.AuthPolicy))
	respExtData = append(respExtData, byte(paddingMethod))
	respExtData = append(respExtData, paddingParams...)

	// Determine the response padding length by adding padding required to
	// bring the response size up to the minimum target length, and then
	// adding a random amount of padding.
	padLen := minHandshakeSize - (handshake.MessageSize + len(respExtData))
	if padLen < 0 { // Should never happen.
		panic("basket2: handshake response exceeds payload capacity")
	}
	padLen += c.mRNG.Intn(maxHandshakeSize - minHandshakeSize)

	// Send the handshake response and derive the session keys.
	var keys *handshake.SessionKeys
	if keys, err = c.handshakeState.SendHandshakeResp(c.conn, respExtData, padLen); err != nil {
		return
	}
	defer keys.Reset()

	// Initialize the frame decoder/encoder with the session key material.
	if err = c.initFraming(keys.KDF); err != nil {
		return
	}

	// Bring the chosen padding algorithm online.
	if err = c.setPadding(paddingMethod, paddingParams); err != nil {
		return
	}

	// Authenticate the client if needed.
	if c.config.AuthPolicy == AuthMust {
		if err = c.authenticate(keys.TranscriptDigest); err != nil {
			return
		}
	}

	// The connection is now fully established.
	if err = c.setState(stateEstablished); err != nil {
		return
	}

	return nil
}

func (c *ServerConn) authenticate(transcriptDigest []byte) error {
	if err := c.setState(stateAuthenticate); err != nil {
		return err
	}

	// Receive the peer's authenticate frame.

	// Verify that the peer has signed keys.TranscriptDigest.

	// Send an authetication response.

	return ErrNotSupported
}

// NewServerConn initializes a ServerConn.  Unlike NewClientConn this step may
// and should be done right before Handshake is ready to be called.
func NewServerConn(config *ServerConfig) (*ServerConn, error) {
	var err error

	if len(config.KEXMethods) == 0 {
		panic("basket2: no KEXMethods")
	}
	if len(config.PaddingMethods) == 0 {
		panic("basket2: no PaddingMethods")
	}
	if config.ReplayFilter == nil {
		panic("basket2: no replay filter")
	}
	if config.ServerPrivateKey == nil {
		panic("basket2: no server private key")
	}
	if config.PaddingParamFn == nil {
		config.PaddingParamFn = defaultPaddingParams
	}

	c := new(ServerConn)
	c.config = config
	c.isClient = false
	if c.handshakeState, err = handshake.NewServerHandshake(rand.Reader, config.KEXMethods, config.ReplayFilter, config.ServerPrivateKey); err != nil {
		return nil, err
	}

	return c, nil
}

var _ net.Conn = (*ServerConn)(nil)
