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
	"net"
	"sync"
	"testing"

	"git.schwanenlied.me/yawning/a2filter.git"
	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
)

var (
	clientExtData = []byte("The peculiar evil of silencing the expression of an opinion is, that it is robbing the human race; posterity as well as the existing generation; those who dissent from the opinion, still more than those who hold it.")
	serverExtData = []byte("If the opinion is right, they are deprived of the opportunity of exchanging error for truth: if wrong, they lose, what is almost as great a benefit, the clearer perception and livelier impression of truth, produced by its collision with error.")
)

type testState struct {
	sync.WaitGroup

	bobKeypair *identity.PrivateKey
	replay     *a2filter.A2Filter

	aliceCh, bobCh     chan error
	alicePipe, bobPipe net.Conn
}

func (s *testState) aliceRoutine() {
	defer s.Done()

	hs, err := NewClientHandshake(rand.Reader, &s.bobKeypair.PublicKey)
	if err != nil {
		s.aliceCh <- err
		return
	}

	k, extData, err := hs.Handshake(s.alicePipe, clientExtData, 0)
	if err != nil {
		s.aliceCh <- err
		return
	}

	if !bytes.Equal(extData, serverExtData) {
		s.aliceCh <- fmt.Errorf("client: serverExtData mismatch")
		return
	}

	_ = k
}

func (s *testState) bobRoutine() {
	defer s.Done()

	hs, err := NewServerHandshake(s.replay, s.bobKeypair)
	if err != nil {
		s.bobCh <- err
		return
	}

	extData, err := hs.RecvHandshakeReq(s.bobPipe)
	if err != nil {
		s.bobCh <- err
		return
	}

	if !bytes.Equal(extData, clientExtData) {
		s.bobCh <- fmt.Errorf("server: clientExtData mismatch")
		return
	}

	k, err := hs.SendHandshakeResp(rand.Reader, s.bobPipe, serverExtData, 0)
	if err != nil {
		s.bobCh <- err
	}

	_ = k
}

func TestHandshakeSmoke(t *testing.T) {
	s, err := newTestState()
	if err != nil {
		t.Fatalf("failed to generate test state: %v", err)
	}
	defer s.alicePipe.Close()
	defer s.bobPipe.Close()

	s.Add(2)
	go s.aliceRoutine()
	go s.bobRoutine()

	s.Wait()
	if len(s.aliceCh) > 0 {
		err := <-s.aliceCh
		t.Errorf("alice: %v", err)
	}
	if len(s.bobCh) > 0 {
		err := <-s.bobCh
		t.Errorf("bob: %v", err)
	}
}

func newTestState() (*testState, error) {
	var err error

	s := new(testState)
	s.aliceCh, s.bobCh = make(chan error), make(chan error)
	s.alicePipe, s.bobPipe = net.Pipe()

	s.bobKeypair, err = identity.NewPrivateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.replay, err = NewReplay()
	if err != nil {
		return nil, err
	}

	return s, nil
}
