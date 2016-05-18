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

	"git.schwanenlied.me/yawning/basket2.git/crypto/rand"
	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"
)

const (
	// ProtocolVersion is the transport protocol version.
	ProtocolVersion = 0

	// PaddingInvalid is a invalid/undefined padding method.
	PaddingInvalid PaddingMethod = 0xff

	minReqExtDataSize  = 1 + 1 + 1 // Version, nrPaddingAlgs, > 1 padding alg.
	minRespExtDataSize = 1 + 1 + 1 // Version, authPolicy, padding alg.

	tauReadDelay          = 5000 // Microseconds.
	defaultCopyBufferSize = 32 * 1024
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

	// ErrMsgSize is the error returned on a message size violation.
	ErrMsgSize = errors.New("basket2: oversized message")

	// ErrInvalidExtData is the error returned when the req/resp handshake
	// extData is invalid.
	ErrInvalidExtData = errors.New("basket2: invalid ext data")

	// ErrInvalidAuth is the error returned when the authentication credentials
	// or signature was invalid, or the client authentication otherwise failed.
	ErrInvalidAuth = errors.New("basket2: invalid auth")

	// ErrNotSupported is the error returned on an unsupported call.
	ErrNotSupported = errors.New("basket2: operation not supported")

	supportedPaddingMethods = []PaddingMethod{
		PaddingTamaraw,
		PaddingObfs4BurstIAT,
		PaddingObfs4Burst,
		PaddingNull,
	}
)

// PaddingMethod is a given padding algorithm identifier.
type PaddingMethod byte

// AuthPolicy is the server authentication policy.
type AuthPolicy byte

const (
	// AuthNone indicates that the client must not authenticate.
	AuthNone AuthPolicy = iota

	// AuthMust indicates that the client must authenticate.
	AuthMust
)

type connState int

const (
	stateInit connState = iota
	stateHandshaking
	stateAuthenticate
	stateEstablished
	stateError
)

// ToHexString returns the hexdecimal string representation of a padding method.
func (m PaddingMethod) ToHexString() string {
	return fmt.Sprintf("%02x", m)
}

// ToString returms the descriptive string representaiton of a padding method.
func (m PaddingMethod) ToString() string {
	switch m {
	case PaddingNull:
		return "Null"
	case PaddingObfs4Burst:
		return "Obfs4Burst"
	case PaddingObfs4BurstIAT:
		return "Obfs4BurstIAT"
	case PaddingTamaraw:
		return "Tamaraw"
	default:
		return "[Unknown algorithm]"
	}
}

// PaddingMethodFromString returns the PaddingMethod corresponding to a given
// string.
func PaddingMethodFromString(s string) PaddingMethod {
	switch s {
	case "Null":
		return PaddingNull
	case "Obfs4Burst":
		return PaddingObfs4Burst
	case "Obfs4BurstIAT":
		return PaddingObfs4BurstIAT
	case "Tamaraw":
		return PaddingTamaraw
	default:
		return PaddingInvalid
	}
}

// ConnStats contains the per-connection metrics useful for examining the
// overhead/performance of the various padding algorithms.
type ConnStats struct {
	RxBytes         uint64
	RxOverheadBytes uint64
	RxPayloadBytes  uint64
	RxPaddingBytes  uint64

	TxBytes         uint64
	TxOverheadBytes uint64
	TxPayloadBytes  uint64
	TxPaddingBytes  uint64
}

// ToString returns the descriptive string representation of the connection
// statistics.
func (s *ConnStats) ToString() string {
	rxGoodput := float64(s.RxPayloadBytes) / float64(s.RxBytes)
	txGoodput := float64(s.TxPayloadBytes) / float64(s.TxBytes)
	return fmt.Sprintf("Receive: Total: %v Overhead: %v Payload: %v Padding: %v Goodput: %v Trasmit: Total: %v Overhead: %v Payload: %v Padding: %v Goodput: %v", s.RxBytes, s.RxOverheadBytes, s.RxPayloadBytes, s.RxPaddingBytes, rxGoodput, s.TxBytes, s.TxOverheadBytes, s.TxPayloadBytes, s.TxPaddingBytes, txGoodput)
}

type commonConn struct {
	sync.Mutex

	mRNG  *mrand.Rand
	state connState
	stats ConnStats

	rawConn net.Conn

	txEncoder *tentp.Encoder
	rxDecoder *tentp.Decoder
	impl      paddingImpl

	paddingMethod PaddingMethod

	maxRecordSize     int
	copyBufferSize    int
	enforceRecordSize bool
	enableReadDelay   bool

	isClient bool
}

// Stats returns the connection's ConnStats structure.
func (c *commonConn) Stats() *ConnStats {
	return &c.stats
}

// SetCopyBufferSize sets the hint used to detect large bulk transfers
// when the connection is the destination side of io.Copy()/io.CopyBuffer().
// By default something sensible for io.Copy() will be used.
func (c *commonConn) SetCopyBufferSize(sz int) {
	if sz <= 0 {
		panic("basket2: SetCopyBufferSize called with invalid value")
	}
	c.copyBufferSize = sz
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

	n, err = c.impl.Read(p)
	if c.enableReadDelay && n > 0 {
		// If data payload was received and read delay is enabled,
		// delay for a random interval [0, 2 * tau) usec.
		//
		// This is primarily intended for the server side of the Tor
		// Pluggable transport code in an attempt to mitigate delay based
		// flow tagging attacks for upstream traffic into the Tor network.
		delay := time.Duration(c.mRNG.Intn(tauReadDelay*2)) * time.Microsecond
		time.Sleep(delay)
	}
	return n, err
}

// Close closes the connection and purges cryptographic keying material from
// memory.
func (c *commonConn) Close() error {
	err := c.rawConn.Close()
	c.setState(stateError)

	return err
}

// LocalAddr returns the local address of the connection.
func (c *commonConn) LocalAddr() net.Addr {
	return c.rawConn.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (c *commonConn) RemoteAddr() net.Addr {
	return c.rawConn.RemoteAddr()
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

func (c *commonConn) initConn(conn net.Conn) error {
	var err error
	if err = c.setState(stateHandshaking); err != nil {
		return err
	}

	c.paddingMethod = PaddingInvalid
	c.mRNG = rand.New()
	if c.copyBufferSize == 0 {
		c.copyBufferSize = defaultCopyBufferSize
	}

	// Derive the "max" record size based off the remote address,
	// under the assumption that 1500 byte MTU ethernet is in use.
	//
	// This value is intended as a hint for the padding algorithms
	// when determining how to size records, and may not actually
	// resemble what goes out on the wire depending on what the kernel
	// does and the state of the TCP/IP stack.
	if taddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if taddr.IP.To16() != nil {
			// Connected to an IPv6 peer.
			c.maxRecordSize = tentp.MaxIdealIPv6Size
		} else {
			// Commected to an IPv4 peer.
			c.maxRecordSize = tentp.MaxIdealIPv4Size
		}
	} else {
		// No idea what kind of connection this is, use the IPv4 max frame
		// size.
		c.maxRecordSize = tentp.MaxIdealIPv4Size
	}
	c.rawConn = conn

	return nil
}

func (c *commonConn) initFraming(kdf io.Reader) error {
	var err error

	if c.isClient {
		if c.txEncoder, err = tentp.NewEncoderFromKDF(kdf); err != nil {
			return err
		}
		if c.rxDecoder, err = tentp.NewDecoderFromKDF(kdf); err != nil {
			return err
		}
	} else {
		if c.rxDecoder, err = tentp.NewDecoderFromKDF(kdf); err != nil {
			return err
		}
		if c.txEncoder, err = tentp.NewEncoderFromKDF(kdf); err != nil {
			return err
		}
	}
	return nil
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

func (c *commonConn) setPadding(method PaddingMethod, params []byte) error {
	switch method {
	case PaddingNull:
		c.impl = newNullPadding(c)
	case PaddingObfs4Burst, PaddingObfs4BurstIAT:
		var err error
		c.impl, err = newObfs4Padding(c, method, params)
		if err != nil {
			return err
		}
	case PaddingTamaraw:
		c.impl = newTamarawPadding(c, c.isClient)
	default:
		return ErrInvalidPadding
	}
	c.paddingMethod = method
	return nil
}

func (c *commonConn) setNagle(enable bool) {
	if tconn, ok := c.rawConn.(*net.TCPConn); ok {
		tconn.SetNoDelay(!enable)
	}
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
	n, err = c.rawConn.Write(rec)
	if err != nil {
		return
	}
	if n != len(rec) {
		return io.ErrShortWrite
	}

	c.stats.TxBytes += uint64(len(rec))
	c.stats.TxPayloadBytes += uint64(len(msg))
	c.stats.TxOverheadBytes += uint64(len(rec) - (len(msg) + padLen))
	c.stats.TxPaddingBytes += uint64(padLen)

	return
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
	if _, err = io.ReadFull(c.rawConn, recHdr[:]); err != nil {
		return
	}
	var want int
	cmd, want, err = c.rxDecoder.DecodeRecordHdr(recHdr[:])
	if err != nil {
		return
	}
	c.stats.RxBytes += tentp.FramingOverhead
	c.stats.RxOverheadBytes += tentp.FramingOverhead

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
	if c.enforceRecordSize && want > c.maxRecordSize+tentp.PayloadOverhead {
		return 0, nil, ErrMsgSize
	}

	// Receive/Decode the TENTP record body.
	recBody := make([]byte, want)
	if _, err = io.ReadFull(c.rawConn, recBody); err != nil {
		return
	}
	if msg, err = c.rxDecoder.DecodeRecordBody(recBody); err != nil {
		return
	}

	c.stats.RxBytes += uint64(want)
	c.stats.RxOverheadBytes += tentp.PayloadOverhead
	c.stats.RxPayloadBytes += uint64(len(msg))
	c.stats.RxPaddingBytes += uint64(want - (tentp.PayloadOverhead + len(msg)))

	return
}

// PaddingMethod returns the padding method negotiated with the peer.  This
// will only be set to something useful after a Handshake() call completes
// successfully.
func (c *commonConn) PaddingMethod() PaddingMethod {
	return c.paddingMethod
}

func paddingOk(needle PaddingMethod, haystack []PaddingMethod) bool {
	for _, v := range haystack {
		if needle == v {
			return true
		}
	}
	return false
}

// DefaultPaddingParams returns "sensible" parameters for each supported
// padding method that requires parameterization.
func DefaultPaddingParams(method PaddingMethod) ([]byte, error) {
	switch method {
	case PaddingNull:
		return nil, nil
	case PaddingObfs4Burst, PaddingObfs4BurstIAT:
		// This should be parameterized from persistent state, but allow
		// random parametrization.
		seed := make([]byte, Obfs4SeedLength)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, err
		}
		return seed, nil
	}
	return nil, ErrInvalidPadding
}

// SupportedPaddingMethods returns the list of supported padding methods in
// order of preference.
func SupportedPaddingMethods() []PaddingMethod {
	var ret []PaddingMethod
	ret = append(ret, supportedPaddingMethods...)
	return ret
}

func init() {
	// This check is here for a reason.  If you comment it out, you will
	// receive absolutely NO SUPPORT, and bug reports that do not contain
	// patches will be IGNORED.
	if !isRecentEnoughGo() {
		panic("basket2: built with a Go version that is too old")
	}
}
