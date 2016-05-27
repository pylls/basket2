// handshake_test.go - Handshake tests.
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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"git.schwanenlied.me/yawning/basket2.git/crypto/ecdh"
)

var (
	// The old obfuscation tests used Nietzsche.  The new handshake tests
	// use John Stuart Mill.  I think they both had a point.
	clientExtData = []byte("The peculiar evil of silencing the expression of an opinion is, that it is robbing the human race; posterity as well as the existing generation; those who dissent from the opinion, still more than those who hold it.")
	serverExtData = []byte("If the opinion is right, they are deprived of the opportunity of exchanging error for truth: if wrong, they lose, what is almost as great a benefit, the clearer perception and livelier impression of truth, produced by its collision with error.")

	kexMethods = []KEXMethod{X25519NewHope, X448NewHope}
)

type testState struct {
	sync.WaitGroup
	kexMethod KEXMethod

	bobKeypair ecdh.PrivateKey
	replay     ReplayFilter

	aliceCh, bobCh     chan error
	alicePipe, bobPipe net.Conn
	aliceRw, bobRw     *countingReadWriter
	kdfCh              chan *SessionKeys
}

func (s *testState) initPipes() {
	s.alicePipe, s.bobPipe = net.Pipe()
	s.aliceRw = &countingReadWriter{s.alicePipe, 0, 0}
	s.bobRw = &countingReadWriter{s.bobPipe, 0, 0}
}

func (s *testState) aliceRoutine() {
	defer s.Done()
	defer s.alicePipe.Close()

	s.alicePipe.SetDeadline(time.Now().Add(5 * time.Second))

	hs, err := NewClientHandshake(rand.Reader, s.kexMethod, s.bobKeypair.PublicKey())
	if err != nil {
		s.aliceCh <- err
		return
	}

	padLen := MinHandshakeSize - (MessageSize + len(clientExtData))
	k, extData, err := hs.Handshake(s.aliceRw, clientExtData, padLen)
	if err != nil {
		s.aliceCh <- err
		return
	}

	if !bytes.Equal(extData, serverExtData) {
		s.aliceCh <- fmt.Errorf("client: serverExtData mismatch")
		return
	}

	s.kdfCh <- k
}

func (s *testState) bobRoutine() {
	defer s.Done()
	defer s.bobPipe.Close()

	s.bobPipe.SetDeadline(time.Now().Add(5 * time.Second))

	hs, err := NewServerHandshake(rand.Reader, kexMethods, s.replay, s.bobKeypair)
	if err != nil {
		s.bobCh <- err
		return
	}

	extData, err := hs.RecvHandshakeReq(s.bobRw)
	if err != nil {
		s.bobCh <- err
		return
	}

	if !bytes.Equal(extData, clientExtData) {
		s.bobCh <- fmt.Errorf("server: clientExtData mismatch")
		return
	}

	padLen := MinHandshakeSize - (MessageSize + len(serverExtData))
	k, err := hs.SendHandshakeResp(s.bobRw, serverExtData, padLen)
	if err != nil {
		s.bobCh <- err
		return
	}

	s.kdfCh <- k
}

func (s *testState) oneIter() error {
	s.initPipes()
	s.Add(2)
	go s.aliceRoutine()
	go s.bobRoutine()

	s.Wait()
	if len(s.aliceCh) > 0 {
		return <-s.aliceCh
	}
	if len(s.bobCh) > 0 {
		return <-s.bobCh
	}

	kdf1 := <-s.kdfCh
	kdf2 := <-s.kdfCh
	if !bytes.Equal(kdf1.TranscriptDigest, kdf2.TranscriptDigest) {
		return fmt.Errorf("transcript digest mismach")
	}

	var kdfOut1, kdfOut2 [32]byte
	io.ReadFull(kdf1.KDF, kdfOut1[:])
	io.ReadFull(kdf2.KDF, kdfOut2[:])
	if !bytes.Equal(kdfOut1[:], kdfOut2[:]) {
		return fmt.Errorf("kdf output mismatch")
	}

	// Sanity check to ensure that the amount of data sent on the wire each
	// way is identical.
	if s.aliceRw.bytesWrite != s.bobRw.bytesWrite {
		return fmt.Errorf("bytes written count mismatch")
	}

	return nil
}

func TestHandshakeSmoke(t *testing.T) {
	s, err := newTestState()
	if err != nil {
		t.Fatalf("failed to generate test state: %v", err)
	}

	for _, v := range kexMethods {
		s.kexMethod = v
		if err := s.oneIter(); err != nil {
			t.Fatalf("handshake failed: %v", err)
		}
	}
}

func benchmarkHandshake(b *testing.B, m KEXMethod) {
	s, err := newTestState()
	if err != nil {
		b.Fatalf("failed to generate benchmark state: %v", err)
	}
	s.kexMethod = m

	// This benchmarks both sides, with a certain amount of extra overhead in
	// sanity checks and what not.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.oneIter(); err != nil {
			b.Fatalf("handshake failed: %v", err)
		}
	}
}

func BenchmarkHandshakeAliceAndBobX25519(b *testing.B) {
	benchmarkHandshake(b, X25519NewHope)
}

func BenchmarkHandshakeAliceAndBobX448(b *testing.B) {
	benchmarkHandshake(b, X448NewHope)
}

func newTestState() (*testState, error) {
	var err error

	s := new(testState)
	s.aliceCh, s.bobCh = make(chan error), make(chan error)
	s.kdfCh = make(chan *SessionKeys, 2)

	s.bobKeypair, err = ecdh.New(rand.Reader, IdentityCurve, true)
	if err != nil {
		return nil, err
	}
	s.replay, err = NewSmallReplayFilter()
	if err != nil {
		return nil, err
	}

	return s, nil
}

type countingReadWriter struct {
	impl io.ReadWriter

	bytesWrite uint64
	bytesRead  uint64
}

func (rw *countingReadWriter) reset() {
	rw.bytesWrite, rw.bytesRead = 0, 0
}

func (rw *countingReadWriter) Read(p []byte) (int, error) {
	n, err := rw.impl.Read(p)
	if n != 0 {
		rw.bytesRead += uint64(n)
	}
	return n, err
}

func (rw *countingReadWriter) Write(p []byte) (int, error) {
	n, err := rw.impl.Write(p)
	if n != 0 {
		rw.bytesWrite += uint64(n)
	}
	return n, err
}
