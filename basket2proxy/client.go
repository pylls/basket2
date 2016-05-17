// client.go - Tor Pluggable Transport client implementation.
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

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"git.schwanenlied.me/yawning/basket2.git"
	"git.schwanenlied.me/yawning/basket2.git/basket2proxy/internal/log"
	"git.schwanenlied.me/yawning/basket2.git/basket2proxy/internal/proxyextras"
	"git.schwanenlied.me/yawning/basket2.git/crypto/identity"
	"git.schwanenlied.me/yawning/basket2.git/handshake"

	"git.torproject.org/pluggable-transports/goptlib.git"

	"golang.org/x/net/proxy"
)

const (
	clientHandshakeTimeout = time.Duration(60) * time.Second
)

type clientState struct {
	ln       *pt.SocksListener
	proxyURL *url.URL
}

func (s *clientState) parseBridgeArgs(args *pt.Args) (*basket2.ClientConfig, error) {
	argStr, ok := args.Get(transportArg)
	if !ok {
		return nil, fmt.Errorf("required argument '%s' missing", transportArg)
	}

	splitArgs := strings.Split(argStr, ":")
	if len(splitArgs) != 3 {
		return nil, fmt.Errorf("failed to parse the argument")
	}

	// Validate the protocol version.
	if splitArgs[0] != fmt.Sprintf("%X", basket2.ProtocolVersion) {
		return nil, fmt.Errorf("invalid protocol version '%v'", splitArgs[0])
	}

	cfg := new(basket2.ClientConfig)
	cfg.KEXMethod = handshake.KEXInvalid

	// Parse the supported KEXMethods, and pick the "best" one.
	kexMethods, err := hex.DecodeString(splitArgs[1])
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize KEX methods: %v", err)
	}
	for _, m := range kexMethods {
		method := handshake.KEXMethod(m)
		if isEnabledKEXMethod(method) {
			cfg.KEXMethod = method
			break
		}
	}
	if cfg.KEXMethod == handshake.KEXInvalid {
		return nil, fmt.Errorf("no compatible KEX methods")
	}

	// Parse out the bridge's identity key.
	if cfg.ServerPublicKey, err = identity.PublicKeyFromString(splitArgs[2]); err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}

	return cfg, nil
}

func (s *clientState) acceptLoop() error {
	defer s.ln.Close()

	for {
		conn, err := s.ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		go s.connHandler(conn)
	}
}

func (s *clientState) connHandler(socksConn *pt.SocksConn) error {
	termMon.OnHandlerStart()
	defer termMon.OnHandlerFinish()
	defer socksConn.Close()
	defer func() {
		// Shouldn't happen, but avoid killing the entire process on failure.
		if r := recover(); r != nil {
			log.Errorf("Recovering from client handler panic: %v", r)
		}
	}()

	addrStr := log.ElideAddr(socksConn.Req.Target)
	log.Infof("%s: New client connection", addrStr)

	// Parse out the bridge arguments.
	cfg, err := s.parseBridgeArgs(&socksConn.Req.Args)
	if err != nil {
		log.Errorf("%s: Invalid bridge line: %v", addrStr, err)
		socksConn.Reject()
		return err
	}
	cfg.PaddingMethods = append(cfg.PaddingMethods, enabledPaddingMethods...)

	log.Debugf("%s: Using KEX: %s", addrStr, cfg.KEXMethod.ToString())

	// Intialize the basket2 state.
	bConn, err := basket2.NewClientConn(cfg)
	if err != nil {
		log.Errorf("%s: Failed to initialize bakset2 client conn: %v", addrStr, err)
		socksConn.Reject()
		return err
	}
	if copyBufferSize != 0 {
		bConn.SetCopyBufferSize(copyBufferSize)
	}

	// Handle the proxy.
	dialFn := proxy.Direct.Dial
	if s.proxyURL != nil {
		dialer, err := proxy.FromURL(s.proxyURL, proxy.Direct)
		if err != nil {
			log.Errorf("%s: Failed to obtain proxy dialer: %v", addrStr, log.ElideError(err))
			socksConn.Reject()
			return err
		}
		dialFn = dialer.Dial
	}

	// Connect to the bridge.
	conn, err := dialFn("tcp", socksConn.Req.Target)
	if err != nil {
		log.Errorf("%s: Failed to connect to the bridge: %v", addrStr, log.ElideError(err))
		socksConn.RejectReason(errorToSocksReplyCode(err))
		return err
	}
	defer conn.Close()

	log.Debugf("%s: Connected to upstream", addrStr)

	// Handshake.
	if err = conn.SetDeadline(time.Now().Add(clientHandshakeTimeout)); err != nil {
		socksConn.Reject()
		return err
	}
	if err = bConn.Handshake(conn); err != nil {
		log.Errorf("%s: Handshake failed: %v", addrStr, log.ElideError(err))
		socksConn.RejectReason(errorToSocksReplyCode(err))
		return err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		socksConn.Reject()
		return err
	}

	log.Debugf("%s: Handshaked with peer", addrStr)
	log.Debugf("%s: Using padding: %s", addrStr, bConn.PaddingMethod().ToString())

	// Signal to the client that the connection is ready for traffic.
	if err = socksConn.Grant(nil); err != nil {
		return err
	}

	// Shuffle bytes back and forth.
	copyLoop(bConn, socksConn, addrStr)

	return nil
}

func clientInit() []net.Listener {
	ci, err := pt.ClientSetup(nil)
	if err != nil {
		log.Errorf("Failed to initialize as client: %v", err)
		return nil
	}

	// Validate the Proxy URL.
	if ci.ProxyURL != nil {
		if !proxyextras.IsURLValid(ci.ProxyURL) {
			pt.ProxyError("proxy URL is invalid")

			log.Errorf("Invalid proxy URL")

			return nil
		}
		pt.ProxyDone()
	}

	// Iterate over the requested transports and spawn SOCKS listeners.
	var listeners []net.Listener
	for _, name := range ci.MethodNames {
		if name != transportName {
			pt.CmethodError(name, "no such transport is supported")
			continue
		}

		state := &clientState{
			proxyURL: ci.ProxyURL,
		}

		state.ln, err = pt.ListenSocks("tcp", socksAddr)
		if err != nil {
			pt.CmethodError(name, err.Error())
			continue
		}

		go state.acceptLoop()

		pt.Cmethod(name, state.ln.Version(), state.ln.Addr())
		listeners = append(listeners, state.ln)
	}
	pt.CmethodsDone()

	return listeners
}

func errorToSocksReplyCode(err error) byte {
	opErr, ok := err.(*net.OpError)
	if !ok {
		return pt.SocksRepGeneralFailure
	}

	errno, ok := opErr.Err.(syscall.Errno)
	if !ok {
		return pt.SocksRepGeneralFailure
	}
	switch errno {
	case syscall.EADDRNOTAVAIL:
		return pt.SocksRepAddressNotSupported
	case syscall.ETIMEDOUT:
		return pt.SocksRepTTLExpired
	case syscall.ENETUNREACH:
		return pt.SocksRepNetworkUnreachable
	case syscall.EHOSTUNREACH:
		return pt.SocksRepHostUnreachable
	case syscall.ECONNREFUSED, syscall.ECONNRESET:
		return pt.SocksRepConnectionRefused
	default:
		return pt.SocksRepGeneralFailure
	}
}
