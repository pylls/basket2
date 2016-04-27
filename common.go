// common.go - Transport common implementation.
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

// Package basket2 implements the basket2 authenticated/encrypted/obfuscated
// network transport protocol.
//
// Note that the package will block during init() if the system entropy pool
// is not properly initialized on systems where there is support for
// determining this information.  This is a feature, and "working around" this
// "bug" will likely totally destroy security.
package basket2

import (
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
)

const (
	// ProtocolVersion is the transport protocol version.
	ProtocolVersion = 0

	minHandshakeSize               = 4096
	maxHandshakeSize               = 8192
	minReqExtDataLen               = 1 + 1 + 1 // Version, nrPaddingAlgs, > 1 padding alg.
	paddingInvalid   PaddingMethod = 0xff
)

var (
	// ErrInvalidState is the error returned on an invalid state or transition.
	ErrInvalidState = errors.New("basket2: invalid state")

	// ErrInvalidCmd is the error returned on decoding a framing packet with
	// an invalid command.
	ErrInvalidCmd = errors.New("basket2: invalid command")

	// ErrInvalidPadding is the error returned when the client requests no
	// compatible padding methods, or the server specifies a incompatible
	// padding method.
	ErrInvalidPadding = errors.New("basket2: invalid padding")

	// ErrInvalidExtData is the error returned when the req/resp handshake
	// extData is invalid.
	ErrInvalidExtData = errors.New("basket2: invalid ext data")

	// ErrNotSupported is the error returned on an unsupported call.
	ErrNotSupported = errors.New("basket2: operation not supported")
)

// PaddingMethod is a given padding algorithm identifier.
type PaddingMethod byte

type paddingImpl interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	OnClose()
}

type connState int

const (
	stateInit connState = iota
	stateHandshaking
	stateAuthenticate
	stateEstablished
	stateError
)

type commonConn struct {
	sync.Mutex

	mRNG  *mrand.Rand
	state connState

	conn     net.Conn
	isClient bool

	txEncoder *tentp.Encoder
	rxDecoder *tentp.Decoder
	impl      paddingImpl
}

// Conn returns the raw underlying net.Conn associated with the basket2
// connection.
func (c *commonConn) Conn() net.Conn {
	return c.conn
}

// Write writes len(p) bytes to the stream, and returns the number of bytes
// written, or an error.  All errors must be considered fatal.
func (c *commonConn) Write(p []byte) (n int, err error) {
	defer func() {
		if err != nil {
			c.setState(stateError)
		}
	}()

	if !c.stateAllowsIO() {
		return 0, ErrInvalidState
	}
	return c.impl.Write(p)
}

// Read reads up to len(p) bytes from the stream, and returns the number of
// bytes read, or an error.  All errors must be considered fatal.
func (c *commonConn) Read(p []byte) (n int, err error) {
	defer func() {
		if err != nil {
			c.setState(stateError)
		}
	}()

	if !c.stateAllowsIO() {
		return 0, ErrInvalidState
	}
	return c.impl.Read(p)
}

// Close closes the connection and purges cryptographic keying material from
// memory.
func (c *commonConn) Close() error {
	err := c.conn.Close()
	c.setState(stateError)

	return err
}

// LocalAddr returns the local address of the connection.
func (c *commonConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (c *commonConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline returns ErrNotSupported.
func (c *commonConn) SetDeadline(t time.Time) error {
	return ErrNotSupported
}

// SetReadDeadline returns ErrNotSupported.
func (c *commonConn) SetReadDeadline(t time.Time) error {
	return ErrNotSupported
}

// SetWriteDeadline returns ErrNotSupported.
func (c *commonConn) SetWriteDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *commonConn) setState(newState connState) error {
	c.Lock()
	defer c.Unlock()

	switch newState {
	case stateInit:
		panic("basket2: state transition to Init should NEVER happen")
	case stateHandshaking:
		if c.state != stateInit {
			return ErrInvalidState
		}
	case stateAuthenticate:
		if c.state != stateHandshaking {
			return ErrInvalidState
		}
	case stateEstablished:
		if c.state != stateHandshaking && c.state != stateAuthenticate {
			return ErrInvalidState
		}
	case stateError:
		// Transition to stateError is always allowed, and will obliterate
		// cryptographic material.
		if c.txEncoder != nil {
			c.txEncoder.Reset()
			c.txEncoder = nil
		}
		if c.rxDecoder != nil {
			c.rxDecoder.Reset()
			c.rxDecoder = nil
		}

		// If the padding implementation is present, call the termination
		// handler.
		if c.impl != nil {
			c.impl.OnClose()
			c.impl = nil
		}
	default:
		panic(fmt.Sprintf("basket2: state transition to unknown state: %v", newState))
	}
	c.state = newState
	return nil
}

func (c *commonConn) stateAllowsIO() bool {
	c.Lock()
	defer c.Unlock()

	return c.state == stateAuthenticate || c.state == stateEstablished
}

// SendRawRecord sends a raw record to the peer with the specified command,
// payload and padding length.  This call should NOT be interleaved/mixed
// with the net.Conn Read/Write interface.
func (c *commonConn) SendRawRecord(cmd byte, msg []byte, padLen int) (err error) {
	defer func() {
		if err != nil {
			c.setState(stateError)
		}
	}()

	// Validate the state.
	if !c.stateAllowsIO() {
		return ErrInvalidState
	}
	if !c.isClient {
		cmd |= framing.CmdServer
	}

	// Encode the TENTP record.
	var rec []byte
	rec, err = c.txEncoder.EncodeRecord(cmd, msg, padLen)
	if err != nil {
		return
	}

	// Transmit the record.
	var n int
	n, err = c.conn.Write(rec)
	if err != nil {
		return
	}
	if n != len(rec) {
		return io.ErrShortWrite
	}

	return
}

func (c *commonConn) setPadding(method PaddingMethod) error {
	switch method {
	case PaddingNull:
		c.impl = newNullPadding(c)
	default:
		return ErrInvalidPadding
	}
	return nil
}

// RecvRawRecord receives a raw record from the peer.  This call should NOT be
// interleaved/mixed with the net.Conn Read/Write interface.
func (c *commonConn) RecvRawRecord() (cmd byte, msg []byte, err error) {
	defer func() {
		if err != nil {
			cmd = 0
			msg = nil
			c.setState(stateError)
		}
	}()

	// Validate the state.
	if !c.stateAllowsIO() {
		return 0, nil, ErrInvalidState
	}

	// Receive/Decode the TENTP header.
	var recHdr [tentp.FramingOverhead]byte
	if _, err = io.ReadFull(c.conn, recHdr[:]); err != nil {
		return
	}
	var want int
	cmd, want, err = c.rxDecoder.DecodeRecordHdr(recHdr[:])
	if err != nil {
		return
	}

	// Validate the command direction bit.
	cmdCtoS := cmd&framing.CmdServer == 0
	if c.isClient == cmdCtoS {
		return 0, nil, ErrInvalidCmd
	}
	cmd &= framing.CmdServerMask

	if want == 0 {
		// Record with no payload, return early.
		return
	}

	// Receive/Decode the TENTP record body.
	recBody := make([]byte, want)
	if _, err = io.ReadFull(c.conn, recBody); err != nil {
		return
	}
	if msg, err = c.rxDecoder.DecodeRecordBody(recBody); err != nil {
		return
	}

	return
}

func paddingOk(needle PaddingMethod, haystack []PaddingMethod) bool {
	for _, v := range haystack {
		if needle == v {
			return true
		}
	}
	return false
}

func init() {
	// This check is here for a reason.  If you comment it out, you will
	// receive absolutely NO SUPPORT, and bug reports that do not contain
	// patches will be IGNORED.
	if !isRecentEnoughGo() {
		panic("basket2: built with a Go version that is too old")
	}
}
