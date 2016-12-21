// main.go - Tor Pluggable Transport implementation.
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

// Tor Pluggable Transport that uses the `basket2` protocol.  Only works as a
// managed client/server.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/pylls/basket2"
	"github.com/pylls/basket2/basket2proxy/internal/log"
	"github.com/pylls/basket2/basket2proxy/internal/ptextras"
	"github.com/pylls/basket2/handshake"
)

const (
	basket2proxyVersion = "0.0.1-dev"
	basket2proxyLogFile = "basket2proxy.log"

	transportName = "basket2"
	socksAddr     = "127.0.0.1:0"

	transportArg = "basket2params"
)

var (
	stateDir string

	termMon   *ptextras.TermMonitor
	termHooks []func()

	enabledPaddingMethods []basket2.PaddingMethod
	enabledKEXMethods     []handshake.KEXMethod
	copyBufferSize        int
	clientForcePLPMTUD    bool
)

func isEnabledKEXMethod(m handshake.KEXMethod) bool {
	for _, v := range enabledKEXMethods {
		if m == v {
			return true
		}
	}
	return false
}

func getVersion() string {
	return "basket2proxy - " + basket2proxyVersion
}

func runTermHooks() {
	for _, fn := range termHooks {
		fn()
	}
}

func closeListeners(listeners []net.Listener) {
	for _, l := range listeners {
		l.Close()
	}
}

func copyLoop(bConn, orConn net.Conn, addrStr string) {
	errChan := make(chan error, 2)

	time.AfterFunc(time.Second*120, func() { logStats(bConn, addrStr) })
	var wg sync.WaitGroup
	wg.Add(2)
	go copyFromTo(orConn, bConn, &wg, errChan)
	go copyFromTo(bConn, orConn, &wg, errChan)
	wg.Wait()

	logStats(bConn, addrStr)

	var err error
	if len(errChan) > 0 {
		err = <-errChan
	}
	if err != nil {
		log.Warnf("%s: Closed connection: %v", addrStr, log.ElideError(err))
	} else {
		log.Infof("%s: Closed connection", addrStr)
	}
}

// log per-connection stats
func logStats(bConn net.Conn, addrStr string) {
	var statsStr, pm string
	switch c := bConn.(type) {
	case *basket2.ClientConn:
		statsStr = c.Stats().ToString()
		pm = c.PaddingMethod().ToString()
	case *basket2.ServerConn:
		statsStr = c.Stats().ToString()
		pm = c.PaddingMethod().ToString()
	}
	if statsStr != "" {
		log.Debugf("%s: %s PaddingMethod: %s", addrStr, statsStr, pm)
	}
}

func copyFromTo(dst, src net.Conn, wg *sync.WaitGroup, errChan chan error) {
	defer wg.Done()
	defer dst.Close()
	defer src.Close()

	var err error
	var buf []byte
	if copyBufferSize == 0 { // this is what io.Copy and io.CopyBuffer does
		buf = make([]byte, 32*1024)
	} else {
		buf = make([]byte, copyBufferSize)
	}

	_, err = io.CopyBuffer(dst, src, buf)
	errChan <- err
}

func overrideKEXMethods(s string) error {
	if s == "" {
		return nil
	}

	var methods []handshake.KEXMethod
	for _, mStr := range strings.Split(s, ",") {
		m := handshake.KEXMethodFromString(mStr)
		if m == handshake.KEXInvalid {
			return handshake.ErrInvalidKEXMethod
		}
		methods = append(methods, m)
	}
	if len(methods) == 0 {
		return fmt.Errorf("no valid KEX methods provided")
	}

	enabledKEXMethods = methods
	return nil
}

func overridePaddingMethods(s string, isClient bool) error {
	var methods []basket2.PaddingMethod

	if s == "" {
		// Disable some of the padding methods, that shouldn't be allowed
		// unless the admin knows what they are doing.
		for _, m := range enabledPaddingMethods {
			switch m {
			case basket2.PaddingNull, basket2.PaddingTamaraw, basket2.PaddingTamarawBulk, basket2.PaddingApe:
				// PaddingNull - Unobfuscated.
				// PaddingTamaraw, PaddingTamarawBulk - Extreme overhead.
				// PaddingApe - Experimental.
			case basket2.PaddingObfs4PacketIAT:
				// PaddingObfs4PacketIAT - Clients should use it if available,
				//   servers should not offer it by default.
				if isClient {
					methods = append(methods, m)
				}
			default:
				methods = append(methods, m)
			}
		}
	} else {
		// Parse the user specified methods.
		for _, mStr := range strings.Split(s, ",") {
			m := basket2.PaddingMethodFromString(mStr)
			if m == basket2.PaddingInvalid {
				return basket2.ErrInvalidPadding
			}
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		return fmt.Errorf("no valid padding methods provided")
	}

	enabledPaddingMethods = methods
	return nil
}

func main() {
	termMon = ptextras.NewTermMonitor()
	_, execName := path.Split(os.Args[0])

	// Parse and act on the command line arguments.
	showVersion := flag.Bool("version", false, "Show version and exit")
	enableLogging := flag.Bool("enableLogging", false, "Log to TOR_PT_STATE_LOCATION/"+basket2proxyLogFile)
	logLevelStr := flag.String("logLevel", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")
	showAlgorithms := flag.Bool("algorithms", false, "Show supported algorithms and exit")
	kexMethodsStr := flag.String("kexMethods", "", "Key exchange methods")
	paddingMethodsStr := flag.String("paddingMethods", "", "Padding methods")
	bufferSizeArg := flag.Int("bufferSize", 0, "Size of internal per connection buffers (32 KiB per direction)")
	forcePLPMTUD := flag.Bool("forcePLPMTUD", false, "Force enable Packetization Layer Path MTU Discovery (Client, not recommended)")
	flag.Parse()

	// Populate the lists of supported algorithms.
	enabledKEXMethods = handshake.SupportedKEXMethods()
	enabledPaddingMethods = basket2.SupportedPaddingMethods()

	if *showVersion {
		fmt.Printf("%s\n", getVersion())
		os.Exit(0)
	}
	if *showAlgorithms {
		fmt.Printf("%s\n", getVersion())

		fmt.Printf("\n Key Exchange Methods:\n")
		for _, m := range enabledKEXMethods {
			fmt.Printf("  %s - %s\n", m.ToHexString(), m.ToString())
		}

		fmt.Printf("\n Padding Methods:\n")
		for _, m := range enabledPaddingMethods {
			fmt.Printf("  %s - %s\n", m.ToHexString(), m.ToString())
		}
		os.Exit(0)
	}
	clientForcePLPMTUD = *forcePLPMTUD

	if err := overrideKEXMethods(*kexMethodsStr); err != nil {
		golog.Fatalf("%s: [ERROR]: Failed to set KEX methods: %v", execName, err)
	}
	if *bufferSizeArg != 0 {
		copyBufferSize = *bufferSizeArg
		if copyBufferSize < 8*1024 {
			golog.Fatalf("%s: [ERROR]: Buffer size must be at least 8 KiB", execName)
		}
	}

	// Common PT initialization (primarily for the stateDir).
	isClient, err := ptextras.IsClient()
	if err != nil {
		golog.Fatalf("%s: [ERROR]: Must be run as a managed transport", execName)
	}
	if stateDir, err = pt.MakeStateDir(); err != nil {
		golog.Fatalf("%s: [ERROR]: No state directory: %v", execName, err)
	}

	// Override the padding methods after it's know if this is a client or not.
	if err := overridePaddingMethods(*paddingMethodsStr, isClient); err != nil {
		golog.Fatalf("%s: [ERROR]: Failed to set padding methods: %v", execName, err)
	}

	// Bring file backed logging online.
	if *enableLogging {
		logFilePath := path.Join(stateDir, basket2proxyLogFile)
		logWriter, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			golog.Fatalf("%s: [ERROR]: Failed to open log file: %v", execName, err)
		}
		logger := golog.New(logWriter, execName+": ", golog.LstdFlags)
		log.SetLogger(logger)
		if err = log.SetLogLevel(*logLevelStr); err != nil {
			golog.Fatalf("%s: [ERROR]: Failed to set log level: %v", execName, err)
		}

		// Nothing should use the go log package, but redirect the output to
		// the writer so I can use it for development/testing.
		golog.SetOutput(logWriter)
	} else {
		golog.SetOutput(ioutil.Discard)
	}

	log.Noticef("%s - Launched", getVersion())
	defer func() {
		// Call the termination cleanup hooks.
		defer runTermHooks()

		log.Noticef("Terminated")
	}()

	// Initialize the listener(s) and complete the PT configuration protocol.
	var listeners []net.Listener
	if isClient {
		listeners = clientInit()
	} else {
		listeners = serverInit()
	}

	// If listeners were started, wait till the parent requests termination.
	if len(listeners) > 0 {
		defer closeListeners(listeners)

		if sig := termMon.Wait(false); sig == syscall.SIGTERM {
			return
		}

		// Explicitly close the listener(s) to block incoming connections.
		closeListeners(listeners)

		termMon.Wait(true)
	}
}
