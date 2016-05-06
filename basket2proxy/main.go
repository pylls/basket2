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
	golog "log"
	"net"
	"os"
	"path"
	"sync"
	"syscall"

	"git.schwanenlied.me/yawning/basket2.git"
	"git.schwanenlied.me/yawning/basket2.git/basket2proxy/internal/log"
	"git.schwanenlied.me/yawning/basket2.git/basket2proxy/internal/ptextras"
	"git.torproject.org/pluggable-transports/goptlib.git"
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

	defaultPaddingMethods = []basket2.PaddingMethod{
		basket2.PaddingNull,
	}
)

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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer orConn.Close()
		defer bConn.Close()
		_, err := io.Copy(orConn, bConn)
		errChan <- err
	}()
	go func() {
		defer wg.Done()
		defer bConn.Close()
		defer orConn.Close()
		_, err := io.Copy(bConn, orConn)
		errChan <- err
	}()

	wg.Wait()

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

func main() {
	termMon = ptextras.NewTermMonitor()
	_, execName := path.Split(os.Args[0])

	// Parse and act on the command line arguments.
	showVersion := flag.Bool("version", false, "Show version and exit.")
	enableLogging := flag.Bool("enableLogging", false, "Log to TOR_PT_STATE_LOCATION/"+basket2proxyLogFile)
	logLevelStr := flag.String("logLevel", "ERROR", "Log level (ERROR/WARN/INFO/DEBUG)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s\n", getVersion())
		os.Exit(0)
	}

	// Common PT initialization (primarily for the stateDir).
	isClient, err := ptextras.IsClient()
	if err != nil {
		golog.Fatalf("%s: [ERROR]: Must be run as a managed transport", execName)
	}
	if stateDir, err = pt.MakeStateDir(); err != nil {
		golog.Fatalf("%s: [ERROR]: No state directory: %v", execName, err)
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
			golog.Fatalf("%s: [ERROR]: Failed to set log level: %v", err)
		}
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
