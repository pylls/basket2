// obfuscation_test.go - Handshake message obfsucator tests.
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

	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
)

var (
	smokeReqMsg  = []byte("It is the stillest words that bring on the storm.  Thoughts that come on doves' feet guide the world.")
	smokeRespMsg = []byte("Everyone wants the same, everyone is the same: whoever feels different goes wilingly into the madhouse.")
)

func TestObfuscationSmoke(t *testing.T) {
	// Generate Bob's long term identity keypair.
	bobKeys, err := identity.NewPrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate bobSk: %v", err)
	}

	// Launch Alice and Bob's portions in their own go routines.
	var wg sync.WaitGroup
	aliceCh := make(chan error)
	bobCh := make(chan error)
	alicePipe, bobPipe := net.Pipe()
	defer alicePipe.Close()
	defer bobPipe.Close()
	aliceTestFn := func() {
		defer wg.Done()
		if err := aliceSmokeTestFn(alicePipe, &bobKeys.PublicKey); err != nil {
			aliceCh <- err
			alicePipe.Close()
		}
		return
	}
	bobTestFn := func() {
		defer wg.Done()
		if err := bobSmokeTestFn(bobPipe, bobKeys); err != nil {
			bobCh <- err
			bobPipe.Close()
		}
		return
	}
	wg.Add(2)
	go aliceTestFn()
	go bobTestFn()

	// Wait for the handshake to complete, collect/handle errors.
	wg.Wait()
	if len(aliceCh) > 0 {
		err := <-aliceCh
		t.Errorf("alice go routine failure: %v", err)
	}
	if len(bobCh) > 0 {
		err := <-bobCh
		t.Errorf("bob go routine faulure: %v", err)
	}
}

func aliceSmokeTestFn(conn net.Conn, bobPk *identity.PublicKey) error {
	obfs, err := newClientObfs(rand.Reader, bobPk)
	if err != nil {
		return err
	}
	resp, err := obfs.handshake(conn, smokeReqMsg, 0)
	if err != nil {
		return err
	}
	if !bytes.Equal(smokeRespMsg, resp) {
		return fmt.Errorf("response mismatch")
	}
	return nil
}

func bobSmokeTestFn(conn net.Conn, keys *identity.PrivateKey) error {
	obfs, err := newServerObfs(keys)
	if err != nil {
		return err
	}
	req, err := obfs.recvHandshakeReq(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(smokeReqMsg, req) {
		return fmt.Errorf("request mismatch")
	}
	if err := obfs.sendHandshakeResp(conn, smokeRespMsg, 0); err != nil {
		return err
	}
	return nil
}
