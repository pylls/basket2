// obfuscation.go - Handshake message obfsucator.
// Copyright (C) 2015-2016 Yawning Angel.
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
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
	"git.schwanenlied.me/yawning/basket2.git/ext/elligator2"
	"git.schwanenlied.me/yawning/basket2.git/framing"
	"git.schwanenlied.me/yawning/basket2.git/framing/tentp"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	obfsClientOverhead = 32 + 32 + tentp.FramingOverhead + tentp.PayloadOverhead
	obfsServerOverhead = tentp.FramingOverhead + tentp.PayloadOverhead
)

var (
	obfsMarkTweak = []byte("basket2-obfs-mark-tweak")
	obfsKdfTweak  = []byte("basket2-obfs-kdf-tweak")

	ErrInvalidPoint = errors.New("obfs: invalid point")
	ErrInvalidCmd   = errors.New("obfs: invalid command")
	ErrInvalidMark  = errors.New("obfs: client send invalid mark")
	ErrNoPayload    = errors.New("obfs: no handshake paylaod")
)

// clientObfsCtx is the client handshake obfuscator state.
type clientObfsCtx struct {
	serverPublicKey *identity.PublicKey

	privKey      [32]byte
	repr         [32]byte
	sharedSecret [32]byte
}

// handshake obfuscates and transmits the request message msg, and returns the
// decrypted peer response.  It is the caller's responsibility to pre-configure
// connection timeouts as appropriate.
func (o *clientObfsCtx) handshake(rw io.ReadWriter, msg []byte, padLen int) ([]byte, error) {
	// Stash the number of hours since the epoch (fixed for the duration of
	// this handshake).
	var epochHour [8]byte
	eh := getEpochHour()
	binary.BigEndian.PutUint64(epochHour[:], eh)

	// Craft the request blob:
	//  uint8_t representative[32]
	//  uint8_t mark[32] (SHA3-256(markTweak | serverPk | repr | epochHour)
	//  uint8_t cipherText[] (TENTP(reqKey, cmd, msg, padLen))
	//
	// Note: The cipherText is structured such that the decoder can determine
	// the length.
	reqBlob := make([]byte, 0, obfsClientOverhead+len(msg)+padLen)
	reqBlob = append(reqBlob, o.repr[:]...)
	markHash := sha3.New256()
	markHash.Write(obfsMarkTweak[:])
	markHash.Write(o.serverPublicKey.KEXPublicKey[:])
	markHash.Write(o.repr[:])
	markHash.Write(epochHour[:])
	reqBlob = markHash.Sum(reqBlob)

	// Derive the reqKey/respKey used for the handshake.
	keyHash := sha3.NewShake256()
	defer keyHash.Reset()
	keyHash.Write(obfsKdfTweak)
	keyHash.Write(o.sharedSecret[:])
	keyHash.Write(reqBlob[32:64]) // Include the mark in the KDF input.

	// Initialize the frame encoder and decoder used for the duration of
	// the handshake process, and frame the handshake record.
	enc, err := tentp.NewEncoderFromKDF(keyHash)
	if err != nil {
		return nil, err
	}
	defer enc.Reset()
	dec, err := tentp.NewDecoderFromKDF(keyHash)
	if err != nil {
		return nil, err
	}
	defer dec.Reset()
	frame, err := enc.EncodeRecord(framing.CmdHandshake, msg, padLen)
	if err != nil {
		return nil, err
	}
	reqBlob = append(reqBlob, frame...)

	// Send the request blob.
	if _, err := rw.Write(reqBlob[:]); err != nil {
		return nil, err
	}

	// Receive/Decode the peer's response TENTP header.
	var respHdr [tentp.FramingOverhead]byte
	if _, err := io.ReadFull(rw, respHdr[:]); err != nil {
		return nil, err
	}
	respCmd, want, err := dec.DecodeRecordHdr(respHdr[:])
	if err != nil {
		return nil, err
	}
	if respCmd != framing.CmdServer|framing.CmdHandshake {
		return nil, ErrInvalidCmd
	}
	if want == 0 {
		// This is technically valid, but is stupid, so disallow it.
		return nil, ErrNoPayload
	}

	// Receive/Decode the peer's response payload body.
	//
	// By virtue of this succeding, the server can be considered authenticated
	// as they know the private component of serverPublicKey.
	//
	// Note: ~128 bits classical security for the authentication.  You lose
	// if they have a quantum computer and are mounting a man in the middle
	// attack.  Likewise, the contents of both obfuscated ciphertexts should
	// be assumed not to be secret assuming a quantum computer is in the
	// picture, or if the servers static obfuscation/authentication key is
	// compromised.
	//
	// There's nothing stopping someone from adding extra authentication
	// (eg: the encrypted ciphertexts could transmit a SIGMA-I key exchange)
	// but that is beyond the scope of what this layer provides.
	respBody := make([]byte, want)
	if _, err := io.ReadFull(rw, respBody); err != nil {
		return nil, err
	}
	return dec.DecodeRecordBody(respBody)
}

// reset sanitizes private values from the client handshake obfuscator state.
func (o *clientObfsCtx) reset() {
	crypto.Memwipe(o.privKey[:])
	crypto.Memwipe(o.sharedSecret[:])
}

// newClientObfs creates a new client side handshake obfuscator instance, for
// bootstrapping communication with a given peer, identified by a public key.
//
// Note: Due to the rejection sampling in Elligator 2 keypair generation, this
// should be done offline.  The timing variation only leaks information about
// the obfuscation method, and does not compromise secrecy or integrity.
func newClientObfs(rand io.Reader, serverPublicKey *identity.PublicKey) (*clientObfsCtx, error) {
	o := new(clientObfsCtx)
	o.serverPublicKey = serverPublicKey

	// Generate a Curve25519 keypair, along with an Elligator 2 uniform
	// random representative of the public key.
	var publicKey [32]byte // Don't need our public key past validation.
	if err := elligator2.GenerateKey(rand, &publicKey, &o.repr, &o.privKey); err != nil {
		return nil, err
	}
	if crypto.MemIsZero(publicKey[:]) {
		return nil, ErrInvalidPoint
	}

	// Calculate a shared secret with our ephemeral key, and the server's
	// long term public key.
	curve25519.ScalarMult(&o.sharedSecret, &o.privKey, &o.serverPublicKey.KEXPublicKey)
	if crypto.MemIsZero(o.sharedSecret[:]) {
		return nil, ErrInvalidPoint
	}

	return o, nil
}

type serverObfsCtx struct {
	clientPublicKey [32]byte

	keypair      *identity.PrivateKey
	sharedSecret [32]byte
	keyHash      sha3.ShakeHash
}

// reset sanitizes private values from the server handshake obfuscator state.
func (o *serverObfsCtx) reset() {
	o.keypair = nil // It's a pointer. >.>
	crypto.Memwipe(o.sharedSecret[:])
	if o.keyHash != nil {
		o.keyHash.Reset()
	}
}

func (o *serverObfsCtx) recvHandshakeReq(rw io.ReadWriter) ([]byte, error) {
	// Read the client representative.
	var repr [32]byte
	if _, err := io.ReadFull(rw, repr[:]); err != nil {
		return nil, err
	}

	// Read/Validate the client mark, allowing for +- 1h clock difference
	// between the client and server.
	var mark [32]byte
	if _, err := io.ReadFull(rw, mark[:]); err != nil {
		return nil, err
	}
	eh := getEpochHour()
	markOk := false
	for _, v := range []uint64{eh - 1, eh, eh + 1} {
		// This is kind of expensive. :(
		var epochHour [8]byte
		binary.BigEndian.PutUint64(epochHour[:], v)

		markHash := sha3.New256()
		markHash.Write(obfsMarkTweak[:])
		markHash.Write(o.keypair.KEXPublicKey[:])
		markHash.Write(repr[:])
		markHash.Write(epochHour[:])

		derivedMark := markHash.Sum(nil)
		if subtle.ConstantTimeCompare(derivedMark[:], mark[:]) == 1 {
			markOk = true
		}
	}
	if !markOk {
		// Invalid mark, either the clock skew is too large or the peer
		// isn't supposed to be connecting to us.
		return nil, ErrInvalidMark
	}

	// XXX: Replay check the mark.

	// Calculate the shared secret, with the client's representative and our
	// long term private key.
	elligator2.RepresentativeToPublicKey(&o.clientPublicKey, &repr)
	if !o.keypair.ScalarMult(&o.sharedSecret, &o.clientPublicKey) {
		return nil, ErrInvalidPoint
	}

	// Derive the handshake symmetric keys, and initialize the frame decoder
	// used to decode the handshake request.  As this function is split,
	// initializing/keying the frame encoder happens when the response is
	// sent.
	o.keyHash = sha3.NewShake256()
	o.keyHash.Write(obfsKdfTweak)
	o.keyHash.Write(o.sharedSecret[:])
	o.keyHash.Write(mark[:]) // Include the mark in the KDF input.
	dec, err := tentp.NewDecoderFromKDF(o.keyHash)
	if err != nil {
		return nil, err
	}
	defer dec.Reset()

	// Read/Decode client request header.
	var reqHdr [tentp.FramingOverhead]byte
	if _, err := io.ReadFull(rw, reqHdr[:]); err != nil {
		return nil, err
	}
	reqCmd, want, err := dec.DecodeRecordHdr(reqHdr[:])
	if err != nil {
		return nil, err
	}
	if reqCmd != framing.CmdHandshake {
		return nil, ErrInvalidCmd
	}
	if want == 0 {
		// This is technically valid, but is stupid, so disallow it.
		return nil, ErrNoPayload
	}

	// Read/Decode client request body.
	reqBody := make([]byte, want)
	if _, err := io.ReadFull(rw, reqBody); err != nil {
		return nil, err
	}
	return dec.DecodeRecordBody(reqBody)
}

func (o *serverObfsCtx) sendHandshakeResp(rw io.ReadWriter, msg []byte, padLen int) error {
	// Initialize the frame encoder used to send the response.
	defer o.keyHash.Reset()
	enc, err := tentp.NewEncoderFromKDF(o.keyHash)
	if err != nil {
		return err
	}
	defer enc.Reset()

	// Encode the response message.
	frame, err := enc.EncodeRecord(framing.CmdServer|framing.CmdHandshake, msg, padLen)
	if err != nil {
		return err
	}

	// Send the response blob.
	if _, err := rw.Write(frame); err != nil {
		return err
	}
	return nil
}

func newServerObfs(staticObfsKeypair *identity.PrivateKey) (*serverObfsCtx, error) {
	o := new(serverObfsCtx)
	o.keypair = staticObfsKeypair

	// The paranoid thing to do would be to validate that the public key
	// actually comes from the private key, but this is an internal API,
	// so just assume it's correct and save a scalar basepoint multiply.

	return o, nil
}

// getEpochHour returns the number of hours since the UNIX epoch.
func getEpochHour() uint64 {
	return uint64(time.Now().Unix() / 3600)
}
