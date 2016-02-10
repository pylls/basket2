// tentp.go - Trivial Encrypted Network Transport Protocol
// Copyright (C) 2015-2016  Yawning Angel.
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

// Package tentp implements the framing layer portion of the Trivial
// Encrypted Network Transport Protocol, a lightweight XChaCha20 + Poly1305
// based authentication/encryption protocol for streams with reliable-in-order
// delivery semantics.
//
// All security properties are lost if multiple sessions re-use the
// Encoder/Decoder keys, so don't do that.
//
// This implementation is somewhat different from the draft that Nick M. and I
// worked on a while ago but the basic ideas and concepts are the same.
package tentp

import (
	"encoding/binary"
	"errors"
	"io"

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/chacha20.git"
	"golang.org/x/crypto/poly1305"
)

const (
	// KeySize is the size of a Encoder/Decoder key in bytes (56 bytes).
	KeySize = chacha20.KeySize + chacha20.XNonceSize

	// MaxPlaintextRecordSize is the maximum length of a message payload that
	// can be sent per record.  (The length of payload + padding is also
	// limited to this maximum value).
	MaxPlaintextRecordSize = 16383

	// MaxPaddingSize is the maximum length of padding that can be sent per
	// record.  (The length of payload + padding is also limited to this
	// maximum value).
	MaxPaddingSize = 16383

	// FramingOverhead is the amount of constant overhead incurred regardless
	// of payload/padding length (24 bytes).
	FramingOverhead = poly1305.TagSize + recordHeaderSize

	// PayloadOverhead is the amount of *additional* overhead incurred when
	// sending any payload/padding (16 bytes).
	PayloadOverhead = poly1305.TagSize

	// MaxIdealIPv4Size is the "ideal" maximum payload + padding for a single
	// record for an IPv4 connection over Ethernet (1420 bytes).
	MaxIdealIPv4Size = framing.MaxIPv4TcpSize - (FramingOverhead + PayloadOverhead)

	// MaxIdealIPv6Size is the "ideal" maximum payload + padding for a single
	// record for an IPv6 connection over Ethernet (1400 bytes).
	MaxIdealIPv6Size = framing.MaxIPv6TcpSize - (FramingOverhead + PayloadOverhead)

	tentpVersion     = 0x01
	recordHeaderSize = 8
	hdrOffset        = poly1305.TagSize
	hdrNsendOffset   = hdrOffset - 8
)

var (
	// ErrInvalidKeySize is the error returned when the key size is invalid.
	ErrInvalidKeySize = errors.New("tentp: invalid key size")

	// ErrMsgSize is the error returned when the message/pad size is invalid.
	ErrMsgSize = errors.New("tentp: invalid msg/pad size")

	// ErrSendSeqNr is the error returned when NSEND is exhausted.
	ErrSendSeqNr = errors.New("tentp: out of send sequence space")

	// ErrHdrSize is the error returned when the header size is invalid.
	ErrHdrSize = errors.New("tentp: invalid hdr size")

	// ErrDecoderState is the error returned when the decoder calls are made
	// in the wrong order (caller bug).
	ErrDecoderState = errors.New("tentp: decoder in invalid state")

	// ErrInvalidTag is the error returned when the MAC verification fails.
	ErrInvalidTag = errors.New("tentp: invalid tag")

	// ErrProtocol is the error returned when the protocol invariants are
	// violated by the peer. (Invalid version, invalid reserved fields).
	ErrProtocol = errors.New("tentp: protocol invariant violation")

	// ErrRecvSeqNr is the error returned when NRECV is exhausted.
	ErrRecvSeqNr = errors.New("tentp: out of recv sequence space")

	// ErrWasReset is the error returned when the Encoder/Decoder are called
	// after the internal state has been obliterated.
	ErrWasReset = errors.New("tentp: attempted encode/decode after Reset")
)

// recordKeys is the keying material derived from the Encoder/Decoder stream
// cipher before the paylaod/padding is processed.  It is exactly 2 XChaCha20
// blocks, and thus the payload/padding processing can take the fast path in
// the underlying cipher implementation.
type recordKeys struct {
	hdrAuthKey    [32]byte
	hdrKeyStream  [recordHeaderSize]byte
	dataAuthKey   [32]byte
	nextRecordKey [KeySize]byte
}

func (k *recordKeys) derive(c *chacha20.Cipher) {
	c.KeyStream(k.hdrAuthKey[:])
	c.KeyStream(k.hdrKeyStream[:])
	c.KeyStream(k.dataAuthKey[:])
	c.KeyStream(k.nextRecordKey[:])
}

func (k *recordKeys) xorHdrStream(dst, src []byte) {
	if len(dst) < recordHeaderSize || len(src) < recordHeaderSize {
		panic("invalid src/dst buffers when xoring key stream")
	}
	for i, v := range k.hdrKeyStream {
		dst[i] = src[i] ^ v
	}
}

func (k *recordKeys) reset() {
	crypto.Memwipe(k.hdrAuthKey[:])
	crypto.Memwipe(k.hdrKeyStream[:])
	crypto.Memwipe(k.dataAuthKey[:])
	crypto.Memwipe(k.nextRecordKey[:])
}

/* This is what the record header looks like, though it's assembled manually.
type recordHeader struct {
	version       byte   // 0x01 for this version.
	cmd           byte
	payloadLength uint16
	paddingLength uint16
	reserved      uint16 // Always 0x00 0x00.
}
*/

// Encoder is a TENTP frame encoder instance.
type Encoder struct {
	cipher *chacha20.Cipher
	keys   recordKeys
	nSend  uint64
	err    error
}

// Reset clears sensitive data from the Encoder's internal state and
// irreversably invalidates the instance.
func (e *Encoder) Reset() {
	e.cipher.Reset()
	e.keys.reset()
	if e.err == nil {
		// Preserve the previous error...
		e.err = ErrWasReset
	}
}

// EncodeRecord encodes a message with command cmd, message msg, and padLen
// bytes of padding, and returns the encrypted/authenticated ciphertext.
func (e *Encoder) EncodeRecord(cmd byte, msg []byte, padLen int) ([]byte, error) {
	if e.err != nil {
		// Certain errors render the encoder permanently unusable.
		return nil, e.err
	}
	if len(msg) > MaxPlaintextRecordSize || padLen > MaxPaddingSize || padLen < 0 {
		return nil, ErrMsgSize
	}
	if len(msg)+padLen > MaxPlaintextRecordSize {
		// Can't overflow, previous check will fail.
		return nil, ErrMsgSize
	}

	// Calculate the encoded length, and preallocate the buffer.
	encodedLen := FramingOverhead
	if len(msg)+padLen > 0 {
		encodedLen += PayloadOverhead + len(msg) + padLen
	}
	buf := make([]byte, encodedLen)

	// Generate all the per-record keys.
	e.keys.derive(e.cipher)
	defer e.keys.reset()

	// Build the encrypted record, starting from the payload, and working
	// backwards.  This lets us temporarily emplace NSEND in the encoded
	// buffer where the tag will live, and saves a malloc since the
	// golang.org poly1305 doesn't have init/update/final semantics.
	var tmpTag [poly1305.TagSize]byte // The API is dumb in other ways...

	// Encrypt/auth the data.
	if len(msg)+padLen > 0 {
		const (
			msgOffset      = FramingOverhead + PayloadOverhead
			msgNsendOffset = msgOffset - 8
		)

		binary.BigEndian.PutUint64(buf[msgNsendOffset:], e.nSend)
		e.cipher.XORKeyStream(buf[msgOffset:], msg)
		if padLen > 0 {
			e.cipher.KeyStream(buf[msgOffset+len(msg):])
		}
		poly1305.Sum(&tmpTag, buf[msgNsendOffset:], &e.keys.dataAuthKey)
		copy(buf[FramingOverhead:], tmpTag[:])
	}

	// Build/encrypt/auth the header.
	const (
		hdrVerOffset        = hdrOffset
		hdrCmdOffset        = hdrVerOffset + 1
		hdrPayloadLenOffset = hdrCmdOffset + 1
		hdrPaddingLenOffset = hdrPayloadLenOffset + 2
	)
	binary.BigEndian.PutUint64(buf[hdrNsendOffset:], e.nSend)
	buf[hdrVerOffset] = tentpVersion
	buf[hdrCmdOffset] = cmd
	binary.BigEndian.PutUint16(buf[hdrPayloadLenOffset:], uint16(len(msg)))
	binary.BigEndian.PutUint16(buf[hdrPaddingLenOffset:], uint16(padLen))

	e.keys.xorHdrStream(buf[hdrOffset:], buf[hdrOffset:])
	poly1305.Sum(&tmpTag, buf[hdrNsendOffset:FramingOverhead], &e.keys.hdrAuthKey)
	copy(buf[:FramingOverhead], tmpTag[:])

	// Advance the state forward.
	if err := e.cipher.ReKey(e.keys.nextRecordKey[:chacha20.KeySize], e.keys.nextRecordKey[chacha20.KeySize:]); err != nil {
		// Failure to rekey the stream cipher in preparation of the next
		// record is catastrophic.
		e.err = err
		return nil, e.err
	}
	e.nSend++ // Increment the send counter.
	if e.nSend == 0 {
		// Out of nSends, this is the 2^64th packet.  The next send should
		// fail.
		e.err = ErrSendSeqNr
	}
	return buf, nil
}

// NewEncoder creates a new Encoder instance with the specificed key.
func NewEncoder(key []byte) (*Encoder, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	var err error
	e := new(Encoder)
	e.cipher, err = chacha20.NewCipher(key[:chacha20.KeySize], key[chacha20.KeySize:])
	if err != nil {
		return nil, err
	}
	return e, nil
}

// NewEncoderFromKDF creates a new Encoder instance with material read from a
// KDF.  This is intended to be used with the golang.org/x/crypto SHAKE
// implementation.
func NewEncoderFromKDF(kdf io.Reader) (*Encoder, error) {
	var key [KeySize]byte
	defer crypto.Memwipe(key[:])
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return nil, err
	}
	return NewEncoder(key[:])
}

type decoderState int

const (
	decoderStateHdr decoderState = iota
	decoderStateMsg
)

// Decoder is a TENTP frame decoder instance.
type Decoder struct {
	cipher *chacha20.Cipher
	keys   recordKeys
	nRecv  uint64
	err    error

	state          decoderState
	wantPayloadLen int
	wantPaddingLen int
}

// Reset clears sensitive data from the Decoder's internal state and
// irreversably invalidates the instance.
func (d *Decoder) Reset() {
	d.cipher.Reset()
	d.keys.reset()
	if d.err == nil {
		// Preserve the previous error...
		d.err = ErrWasReset
	}
}

func (d *Decoder) advanceState() error {
	if err := d.cipher.ReKey(d.keys.nextRecordKey[:chacha20.KeySize], d.keys.nextRecordKey[chacha20.KeySize:]); err != nil {
		d.err = err
		return d.err
	}
	d.keys.reset()
	d.nRecv++ // Increment the recv counter.
	if d.nRecv == 0 {
		// Out of nRecvs, this is the 2^64th packet.  The next send should
		// fail.
		d.err = ErrRecvSeqNr
	}
	d.wantPayloadLen = 0
	d.wantPaddingLen = 0
	d.state = decoderStateHdr
	return nil
}

// DecodeRecordHdr decodes a given FramingOverhead length byte slice, and
// returns the command, and expected payload/padding ciphertext length
// (including overhead) that must be passed to DecodeRecordBody.  If want
// is 0, the call to DecodeRecordBody may be omitted.
func (d *Decoder) DecodeRecordHdr(encHdr []byte) (cmd byte, want int, err error) {
	if d.err != nil {
		// Certain errors render the decoder permanently unusable.
		return 0, 0, d.err
	}

	// Actually, all errors render the decoder permanently unsuable since
	// it's either an attack or a bug.
	defer func() {
		if err != nil {
			d.err = err
		}
	}()

	if len(encHdr) != FramingOverhead {
		return 0, 0, ErrHdrSize
	}
	if d.state != decoderStateHdr {
		return 0, 0, ErrDecoderState
	}

	// Generate all the per-record keys.
	d.keys.derive(d.cipher)
	defer func() {
		if err != nil {
			d.keys.reset()
		}
	}()

	// Authenticate/decrypt the header.
	var recvdTag [poly1305.TagSize]byte
	copy(recvdTag[:], encHdr[:])
	binary.BigEndian.PutUint64(encHdr[hdrNsendOffset:], d.nRecv)
	if !poly1305.Verify(&recvdTag, encHdr[hdrNsendOffset:], &d.keys.hdrAuthKey) {
		return 0, 0, ErrInvalidTag
	}
	var hdr [recordHeaderSize]byte
	d.keys.xorHdrStream(hdr[:], encHdr[hdrOffset:])

	// Deserialize/validate the header.
	const (
		hdrVerOffset        = 0
		hdrCmdOffset        = hdrVerOffset + 1
		hdrPayloadLenOffset = hdrCmdOffset + 1
		hdrPaddingLenOffset = hdrPayloadLenOffset + 2
		hdrReservedOffset   = hdrPaddingLenOffset + 2
	)
	if hdr[hdrVerOffset] != tentpVersion {
		return 0, 0, ErrProtocol
	}
	cmd = hdr[hdrCmdOffset]
	d.wantPayloadLen = int(binary.BigEndian.Uint16(hdr[hdrPayloadLenOffset:]))
	d.wantPaddingLen = int(binary.BigEndian.Uint16(hdr[hdrPaddingLenOffset:]))
	if d.wantPayloadLen+d.wantPaddingLen > MaxPlaintextRecordSize {
		return 0, 0, ErrMsgSize
	}
	if binary.BigEndian.Uint16(hdr[hdrReservedOffset:]) != 0 {
		return 0, 0, ErrProtocol
	}

	// Figure out if we should expect the next header, or payload/padding,
	// and advance the internal state as appropriate.
	want = d.wantPayloadLen + d.wantPaddingLen
	if want == 0 {
		if err = d.advanceState(); err != nil {
			return 0, 0, err
		}
	} else {
		d.state = decoderStateMsg
		want += PayloadOverhead
	}

	return
}

// DecodeRecordBody decodes a encrypted/authenticated record payload + padding
// message and returns the payload plaintext.  It is possible, and perfectly
// valid for buf to be nil.
func (d *Decoder) DecodeRecordBody(encMsg []byte) (buf []byte, err error) {
	defer func() {
		if err != nil {
			d.keys.reset()
		}
	}()
	if d.err != nil {
		return nil, d.err
	}
	if d.state == decoderStateHdr {
		// DecodeRecordHdr returned want = 0, but they called DecodeRecordBody
		// anyway.  Fastpath out and just return, there was no payload.
		return nil, nil
	} else if d.state != decoderStateMsg {
		return nil, ErrDecoderState
	}

	if len(encMsg) != PayloadOverhead+d.wantPayloadLen+d.wantPaddingLen {
		d.err = ErrMsgSize
		return nil, ErrMsgSize
	}

	// Authenticate the payload + padding.
	const (
		msgOffset      = PayloadOverhead
		msgNsendOffset = msgOffset - 8
	)
	var recvdTag [poly1305.TagSize]byte
	copy(recvdTag[:], encMsg[:])
	binary.BigEndian.PutUint64(encMsg[msgNsendOffset:], d.nRecv)
	if !poly1305.Verify(&recvdTag, encMsg[msgNsendOffset:], &d.keys.dataAuthKey) {
		d.err = ErrInvalidTag
		return nil, d.err
	}

	// Decrypt the payload + padding.
	decodedLen := len(encMsg) - PayloadOverhead
	buf = make([]byte, decodedLen)
	d.cipher.XORKeyStream(buf, encMsg[msgOffset:])
	if d.wantPaddingLen > 0 {
		// Ensure that all the padding bytes are 0.  Technically unneeded, but
		// this check makes it harder (but not impossible) to use the padding
		// as a subliminal channel.
		paddingOffset := decodedLen - d.wantPaddingLen
		if !crypto.MemIsZero(buf[paddingOffset:]) {
			d.err = ErrProtocol
			return nil, d.err
		}
	}
	buf = buf[:d.wantPayloadLen] // Truncate off the padding.
	if len(buf) == 0 {
		buf = nil
	}

	// Ready to receive the next header.
	if err := d.advanceState(); err != nil {
		return nil, err
	}

	return buf, nil
}

// NewDecoder creates a new Decoder instance with the specificed key.
func NewDecoder(key []byte) (*Decoder, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	var err error
	d := new(Decoder)
	d.cipher, err = chacha20.NewCipher(key[:chacha20.KeySize], key[chacha20.KeySize:])
	if err != nil {
		return nil, err
	}
	d.state = decoderStateHdr
	return d, nil
}

// NewDecoderFromKDF creates a new Dcoder instance with material read from a
// KDF.  This is intended to be used with the golang.org/x/crypto SHAKE
// implementation.
func NewDecoderFromKDF(kdf io.Reader) (*Decoder, error) {
	var key [KeySize]byte
	defer crypto.Memwipe(key[:])
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return nil, err
	}
	return NewDecoder(key[:])
}
