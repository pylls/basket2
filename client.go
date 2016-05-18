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
	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/handshake"
)

// ClientConfig is the client configuration parameters to use when
// constructing a ClientConn.
type ClientConfig struct {
	KEXMethod       handshake.KEXMethod
	PaddingMethods  []PaddingMethod
	ServerPublicKey *identity.PublicKey

	// AuthFn is the function called at handshake time to authenticate with
	// the remote peer.  It is expected to return the authentication request
	// message, the amount of padding to add, or an error if it is not
	// possible to authenticate.
	AuthFn func(conn *ClientConn, transcriptDigest []byte) (reqMsg []byte, padLen int, err error)
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

	// Initalize the underlying conn structure, and transition to the
	// handshaking state.
	if err = c.initConn(conn); err != nil {
		return
	}

	// Build the request extData to negotiate padding algorithms.
	reqExtData := make([]byte, 0, 1+1+len(c.config.PaddingMethods))
	reqExtData = append(reqExtData, ProtocolVersion)
	reqExtData = append(reqExtData, byte(len(c.config.PaddingMethods)))
	for _, v := range c.config.PaddingMethods {
		reqExtData = append(reqExtData, byte(v))
	}

	// Determine the request padding length by adding padding required to
	// bring the request size up to the minimum target length, and then
	// adding a random amount of padding.
	//
	// All requests on the wire will be of length [min, max).
	padLen := handshake.MinHandshakeSize - (handshake.MessageSize + len(reqExtData))
	if padLen < 0 { // Should never happen.
		panic("basket2: handshake request exceeds payload capacity")
	}
	padLen += c.mRNG.Intn(handshake.MaxHandshakeSize - handshake.MinHandshakeSize)

	// Send the request, receive the response, and derive the session keys.
	var keys *handshake.SessionKeys
	var respExtData []byte
	if keys, respExtData, err = c.handshakeState.Handshake(c.rawConn, reqExtData, padLen); err != nil {
		return
	}
	defer keys.Reset()

	// Parse the response extData to see which padding algorithm to use,
	// and if authentication is possible/required.
	if len(respExtData) < minRespExtDataSize {
		return ErrInvalidExtData
	}
	if respExtData[0] != ProtocolVersion {
		return ErrInvalidExtData
	}
	authPolicy := AuthPolicy(respExtData[1])
	paddingMethod := PaddingMethod(respExtData[2])
	paddingParams := respExtData[minRespExtDataSize:]

	// Validate that the negotiated padding method is contained in our request.
	if !paddingOk(paddingMethod, c.config.PaddingMethods) {
		return ErrInvalidPadding
	}

	// Initialize the frame encoder/decoder with the session key material.
	if err = c.initFraming(keys.KDF); err != nil {
		return
	}

	// Bring the chosen padding algorithm online.
	if err = c.setPadding(paddingMethod, paddingParams); err != nil {
		return
	}

	// Authenticate if needed.
	if authPolicy == AuthMust {
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

func (c *ClientConn) authenticate(transcriptDigest []byte) error {
	if err := c.setState(stateAuthenticate); err != nil {
		return err
	}

	// Caller didn't provide an authentication callback.
	if c.config.AuthFn == nil {
		return ErrInvalidAuth
	}

	// Caller does something with transcriptDigest and returns the auth
	// packet payload and pad length.
	reqMsg, padLen, err := c.config.AuthFn(c, transcriptDigest)
	if err != nil {
		return err
	}

	// Send the Authenticate packet.
	if err = c.SendRawRecord(framing.CmdAuthenticate, reqMsg, padLen); err != nil {
		return err
	}

	// Receive the authentication response.
	respCmd, respMsg, err := c.RecvRawRecord()
	if err != nil {
		return err
	}
	if respCmd != framing.CmdAuthenticate || len(respMsg) != 0 {
		// On success, expect an Authenticate packet with no payload.
		return ErrInvalidAuth
	}

	// Authentication successful.
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
	if c.handshakeState, err = handshake.NewClientHandshake(rand.Reader, config.KEXMethod, config.ServerPublicKey); err != nil {
		return nil, err
	}

	return c, nil
}

var _ net.Conn = (*ClientConn)(nil)
