// log.go - Simple leveled logging.
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

// Package log implements a simple leveled logging scheme.
package log

import (
	"flag"
	"fmt"
	golog "log"
	"net"
	"strings"
)

const (
	elidedAddr = "[scrubbed]"

	// LevelError is the ERROR log level (NOTICE/ERROR).
	LevelError = iota

	// LevelWarn is the WARN log level,  (NOTICE/ERROR/WARN).
	LevelWarn

	// LevelInfo is the INFO log level, (NOTICE/ERROR/WARN/INFO).
	LevelInfo

	// LevelDebug is the DEBUG log level, (NOTICE/ERROR/WARN/INFO/DEBUG).
	LevelDebug
)

var (
	logger        *golog.Logger
	logLevel      = LevelInfo
	enableLogging bool
	unsafeLogging bool
)

// SetLogger sets the logging backend to the specified log.Logger.
func SetLogger(l *golog.Logger) {
	logger = l
	enableLogging = (l != nil)
}

// SetLogLevel sets the log level to the value indicated by the given string
// (case-insensitive).
func SetLogLevel(logLevelStr string) error {
	switch strings.ToUpper(logLevelStr) {
	case "ERROR":
		logLevel = LevelError
	case "WARN":
		logLevel = LevelWarn
	case "INFO":
		logLevel = LevelInfo
	case "DEBUG":
		logLevel = LevelDebug
	default:
		return fmt.Errorf("invalid log level '%s'", logLevelStr)
	}
	return nil
}

// Noticef logs the given format string/arguments at the NOTICE log level.
// Unless logging is disabled, Noticef logs are always emitted.
func Noticef(format string, a ...interface{}) {
	if enableLogging {
		msg := fmt.Sprintf(format, a...)
		logger.Print("[NOTICE]: " + msg)
	}
}

// Errorf logs the given format string/arguments at the ERROR log level.
func Errorf(format string, a ...interface{}) {
	if enableLogging && logLevel >= LevelError {
		msg := fmt.Sprintf(format, a...)
		logger.Print("[ERROR]: " + msg)
	}
}

// Warnf logs the given format string/arguments at the WARN log level.
func Warnf(format string, a ...interface{}) {
	if enableLogging && logLevel >= LevelWarn {
		msg := fmt.Sprintf(format, a...)
		logger.Print("[WARN]: " + msg)
	}
}

// Infof logs the given format string/arguments at the INFO log level.
func Infof(format string, a ...interface{}) {
	if enableLogging && logLevel >= LevelInfo {
		msg := fmt.Sprintf(format, a...)
		logger.Print("[INFO]: " + msg)
	}
}

// Debugf logs the given format string/arguments at the DEBUG log level.
func Debugf(format string, a ...interface{}) {
	if enableLogging && logLevel >= LevelDebug {
		msg := fmt.Sprintf(format, a...)
		logger.Print("[DEBUG]: " + msg)
	}
}

// ElideError transforms the string representation of the provided error
// based on the unsafeLogging setting.  Callers that wish to log errors
// returned from Go's net package should use ElideError to sanitize the
// contents first.
func ElideError(err error) string {
	// Go's net package is somewhat rude and includes IP address and port
	// information in the string representation of net.Errors.  Figure out if
	// this is the case here, and sanitize the error messages as needed.
	if unsafeLogging {
		return err.Error()
	}

	// If err is not a net.Error, just return the string representation,
	// presumably transport authors know what they are doing.
	netErr, ok := err.(net.Error)
	if !ok {
		return err.Error()
	}

	switch t := netErr.(type) {
	case *net.AddrError:
		return t.Err + " " + elidedAddr
	case *net.DNSError:
		return "lookup " + elidedAddr + " on " + elidedAddr + ": " + t.Err
	case *net.InvalidAddrError:
		return "invalid address error"
	case *net.UnknownNetworkError:
		return "unknown network " + elidedAddr
	case *net.OpError:
		return t.Op + ": " + t.Err.Error()
	default:
		// For unknown error types, do the conservative thing and only log the
		// type of the error instead of assuming that the string representation
		// does not contain sensitive information.
		return fmt.Sprintf("network error: <%T>", t)
	}
}

// ElideAddr transforms the string representation of the provided address based
// on the unsafeLogging setting.  Callers that wish to log IP addreses should
// use ElideAddr to sanitize the contents first.
func ElideAddr(addrStr string) string {
	if unsafeLogging {
		return addrStr
	}

	// Only scrub off the address so that it's easier to track connections
	// in logs by looking at the port.
	if _, port, err := net.SplitHostPort(addrStr); err == nil {
		return elidedAddr + ":" + port
	}
	return elidedAddr
}

func init() {
	flag.BoolVar(&unsafeLogging, "unsafeLogging", false, "Disable the address scrubber")
}
