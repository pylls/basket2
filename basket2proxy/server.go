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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"time"

	"github.com/pylls/basket2"
	"github.com/pylls/basket2/basket2proxy/internal/log"
	"github.com/pylls/basket2/crypto"
	"github.com/pylls/basket2/crypto/ecdh"
	"github.com/pylls/basket2/crypto/rand"
	"github.com/pylls/basket2/framing/tentp"
	"github.com/pylls/basket2/handshake"

	"git.torproject.org/pluggable-transports/goptlib.git"
)

const (
	bridgeFile             = "basket2_bridgeline.txt"
	bridgeParamsFile       = "basket2_params.json"
	privateIdentityFile    = "basket2_x25519.priv"
	privateIdentityPEMType = "X25519 PRIVATE KEY"
	fileMode               = 0600

	serverHandshakeTimeout = time.Duration(30) * time.Second
	maxCloseDelayBytes     = handshake.MaxHandshakeSize
	maxCloseDelay          = 60
)

var (
	errInvalidKey = errors.New("identity: deserialized key is invalid")

	useLargeReplayFilter bool
	disableReplayFilter  bool
)

type serverState struct {
	config *basket2.ServerConfig
	info   *pt.ServerInfo
	ln     net.Listener

	paddingParams map[basket2.PaddingMethod][]byte

	closeDelayBytes int
	closeDelay      int
}

func (s *serverState) getPtArgs() (*pt.Args, error) {
	pkStr := base64.RawStdEncoding.EncodeToString(s.config.ServerPrivateKey.PublicKey().ToBytes())

	var kexStr string
	for _, m := range s.config.KEXMethods {
		kexStr += m.ToHexString()
	}

	argStr := fmt.Sprintf("%X:%s:%s", basket2.ProtocolVersion, kexStr, pkStr)
	args := &pt.Args{}
	args.Add(transportArg, argStr)

	// While we're here, write out the bridge line to a file.
	const prefix = "# basket2 torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current basket2proxy configuration.  EDITING IT WILL HAVE\n" +
		"# NO EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your obfs4 bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your obfs4 bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n\n"

	bridgeLine := fmt.Sprintf("Bridge basket2 <IP ADDRESS>:<PORT> <FINGERPRINT> %s=%s\n", transportArg, argStr)

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, fileMode); err != nil {
		return nil, err
	}

	return args, nil
}

func (s *serverState) initPaddingParams() error {
	// We need sensible padding parameters for *all* supported algorithms.
	methods := []basket2.PaddingMethod{
		basket2.PaddingObfs4Burst,
		basket2.PaddingObfs4BurstIAT,
		basket2.PaddingObfs4PacketIAT,
	}

	paramsFile := path.Join(stateDir, bridgeParamsFile)
	jsonBlob, err := ioutil.ReadFile(paramsFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("Failed to load padding param file: %v", err)
			return err
		}

		for _, m := range methods {
			s.paddingParams[m], err = basket2.DefaultPaddingParams(m)
			if err != nil {
				log.Errorf("Failed to generate params for '%v': %v", m.ToString(), err)
				return err
			}
		}

		return s.savePaddingParams(paramsFile)
	}

	// Deserialize the JSON blob.
	jsonMap := make(map[string][]byte)
	if err = json.Unmarshal(jsonBlob, &jsonMap); err != nil {
		log.Errorf("Failed to deserialize padding params: %v", err)
		return err
	}

	// Ensure that the serialized param file has all of the algorithms that
	// are needed, and generate if neccecary.
	dirty := false
	for _, m := range methods {
		mStr := m.ToString()
		if params, ok := jsonMap[mStr]; ok {
			s.paddingParams[m] = params
		} else {
			log.Infof("Serialized padding params missing for '%v' generating", mStr)
			s.paddingParams[m], err = basket2.DefaultPaddingParams(m)
			if err != nil {
				log.Errorf("Failed to generate params for '%v': %v", mStr, err)
			}
			dirty = true
		}
	}

	if dirty {
		return s.savePaddingParams(paramsFile)
	}

	return nil
}

func (s *serverState) savePaddingParams(paramsFile string) error {
	// Serialize the padding parameters.
	jsonMap := make(map[string][]byte)
	for k, v := range s.paddingParams {
		jsonMap[k.ToString()] = v
	}

	jsonBlob, err := json.Marshal(jsonMap)
	if err != nil {
		log.Errorf("Failed to serialize padding params: %v", err)
		return err
	}
	return ioutil.WriteFile(paramsFile, jsonBlob, os.ModeExclusive|fileMode)
}

func (s *serverState) getPaddingParams(method basket2.PaddingMethod) ([]byte, error) {
	switch method {
	case basket2.PaddingNull, basket2.PaddingTamaraw, basket2.PaddingTamarawBulk, basket2.PaddingApe:
		// These algorithms are unparameterized.
		return nil, nil
	default:
		params, ok := s.paddingParams[method]
		if !ok {
			return nil, basket2.ErrInvalidPadding
		}
		return params, nil
	}
}

func (s *serverState) acceptLoop() error {
	defer s.ln.Close()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		go s.connHandler(conn)
	}
}

func (s *serverState) connHandler(conn net.Conn) error {
	termMon.OnHandlerStart()
	defer termMon.OnHandlerFinish()
	defer conn.Close()
	defer func() {
		// Shouldn't happen, but avoid killing the entire process on failure.
		if r := recover(); r != nil {
			log.Errorf("Recovering from server handler panic: %v", r)
		}
	}()

	addrStr := log.ElideAddr(conn.RemoteAddr().String())
	log.Infof("%s: New connection", addrStr)

	establishedAt := time.Now()

	// Create a new basket2 server handshake instance.
	bConn, err := basket2.NewServerConn(s.config)
	if err != nil {
		log.Errorf("%s: Failed to initialize basket2 server conn: %v", addrStr, err)
		return err
	}
	if copyBufferSize != 0 {
		bConn.SetCopyBufferSize(copyBufferSize)
	}

	// Handshake with the peer.
	if err = conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}
	if err = bConn.Handshake(conn); err != nil {
		log.Errorf("%s: Handshake failed: %v", addrStr, log.ElideError(err))
		s.closeAfterDelay(conn, establishedAt)
		return err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	log.Debugf("%s: Handshaked with peer", addrStr)

	// Connect to the caller's ExtOR Port.
	orConn, err := pt.DialOr(s.info, bConn.RemoteAddr().String(), transportName)
	if err != nil {
		log.Errorf("%s: Failed to connect to the OR port: %v", addrStr, log.ElideError(err))
		return err
	}
	defer orConn.Close()

	log.Debugf("%s: Connected to upstream", addrStr)

	// Shuffle bytes back and forth.
	copyLoop(bConn, orConn, addrStr)

	return nil
}

func (s *serverState) closeAfterDelay(conn net.Conn, establishedAt time.Time) {
	defer conn.Close()

	// Calculate the absolute timeout relative to when the connection
	// was established.  This essntially sets the delay to `30 + a`
	// seconds from the moment when the connection was established, where
	// `a` is [0, 60) seconds and is common across all connections.
	delay := time.Duration(s.closeDelay)*time.Second + serverHandshakeTimeout
	deadline := establishedAt.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	// Arm the close timeout.
	if err := conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Read and discard up to a preset amount of additional data.
	var b [tentp.MaxIdealIPv4Size]byte
	defer crypto.Memwipe(b[:])
	for discarded := 0; discarded < s.closeDelayBytes; {
		n, err := conn.Read(b[:])
		if err != nil {
			return
		}
		discarded += n
	}
}

func loadServerPrivateKey() (sk ecdh.PrivateKey, err error) {
	defer func() {
		if sk != nil {
			if err != nil {
				// Failed to init the listener, obliterate the private key.
				sk.Reset()
			} else {
				// If a private key is loaded, ensure it gets purged on
				// termination as part of cleanup.
				termHooks = append(termHooks, sk.Reset)
			}
		}
	}()

	// Load the PEM data from the file in one shot.
	privKeyFile := path.Join(stateDir, privateIdentityFile)
	blob, err := ioutil.ReadFile(privKeyFile)
	if err != nil {
		// Ensure that the failure is caused by no file, in all other cases
		// cowardly refuse to overwrite existing keying material and bail.
		if !os.IsNotExist(err) {
			log.Errorf("Failed to load private key: %v", err)
			return
		}

		// Failed to load a private key, generate it.
		sk, err = ecdh.New(rand.Reader, handshake.IdentityCurve, false)
		if err != nil {
			return
		}

		// Serialize the private key.
		block := &pem.Block{
			Type:  privateIdentityPEMType,
			Bytes: sk.ToBytes(),
		}
		blob = pem.EncodeToMemory(block)
		defer crypto.Memwipe(blob)
		err = ioutil.WriteFile(privKeyFile, blob, os.ModeExclusive|fileMode)
		return
	}
	defer crypto.Memwipe(blob)

	// Deserialize the private key.
	block, _ := pem.Decode(blob)
	if block == nil {
		return nil, errInvalidKey
	}
	defer crypto.Memwipe(block.Bytes)
	if block.Type != privateIdentityPEMType {
		return nil, errInvalidKey
	}
	return ecdh.PrivateKeyFromBytes(handshake.IdentityCurve, block.Bytes)
}

func initServerListener(si *pt.ServerInfo, bindaddr *pt.Bindaddr) (net.Listener, error) {
	// Instantiate a intenger random number generator.
	mRNG := rand.New()

	// Deserialize the identity key.
	sk, err := loadServerPrivateKey()
	if err != nil {
		return nil, err
	}

	// Create the replay prevention filter.
	var rf handshake.ReplayFilter
	if disableReplayFilter {
		rf, err = handshake.NewDisabledReplayFilter()
	} else if useLargeReplayFilter {
		rf, err = handshake.NewLargeReplayFilter()
	} else {
		rf, err = handshake.NewSmallReplayFilter()
	}
	if err != nil {
		return nil, err
	}

	// Extract the (optional) protocol parameterization from the options.
	cfg := &basket2.ServerConfig{
		ServerPrivateKey: sk,
		ReplayFilter:     rf,
		KEXMethods:       enabledKEXMethods,
		PaddingMethods:   enabledPaddingMethods,
	}

	state := &serverState{
		config:          cfg,
		info:            si,
		closeDelayBytes: mRNG.Intn(maxCloseDelayBytes),
		closeDelay:      mRNG.Intn(maxCloseDelay),
		paddingParams:   make(map[basket2.PaddingMethod][]byte),
	}

	// Deserialize the padding params, and set the parameterization hook.
	if err = state.initPaddingParams(); err != nil {
		return nil, err
	}
	cfg.PaddingParamFn = state.getPaddingParams

	// Synthesize the bridge transport args, and write out the bridge line.
	ptArgs, err := state.getPtArgs()
	if err != nil {
		return nil, err
	}

	// Create the listener.
	state.ln, err = net.ListenTCP("tcp", bindaddr.Addr)
	if err != nil {
		return nil, err
	}

	// Start the accept loop.
	go state.acceptLoop()

	pt.SmethodArgs(transportName, state.ln.Addr(), *ptArgs)

	return state.ln, nil
}

func serverInit() []net.Listener {
	si, err := pt.ServerSetup(nil)
	if err != nil {
		log.Errorf("Failed to initialize as server: %v", err)
		return nil
	}

	// Iterate over the requested transports and span listeners.
	var listeners []net.Listener
	for _, bindAddr := range si.Bindaddrs {
		name := bindAddr.MethodName
		if name != transportName {
			pt.SmethodError(name, "no such transport is supported")
			continue
		}

		ln, err := initServerListener(&si, &bindAddr)
		if err != nil {
			log.Errorf("Failed to initialize server: %v", err)

			pt.SmethodError(name, err.Error())
			continue
		}
		listeners = append(listeners, ln)

		log.Infof("Registered listener: %s", log.ElideAddr(ln.Addr().String()))
	}
	pt.SmethodsDone()

	return listeners
}

func init() {
	flag.BoolVar(&useLargeReplayFilter, "serverLargeReplayFilter", false, "Use (probabalistic) high capacity replay detection")
	flag.BoolVar(&disableReplayFilter, "disableReplayFilter", false,
		"Disable the replay filter")
}
