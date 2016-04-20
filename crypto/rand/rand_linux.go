// rand_linux.go - Linux syscall random number generator.
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

package rand

import (
	"bytes"
	"io"
	"io/ioutil"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"golang.org/x/crypto/sha3"
)

//
// At least as of Go 1.6.1,  Go's crypto/rand does some horrific bullshit that
// defeats the point of getrandom(2), namedly, it cowardly refuses to use the
// syscall based entropy source if it would have blocked on the first call.
//
// This is absolutely retarded.  The correct thing to do for something named
// "crypto/rand" is to fucking BLOCK if the entropy pool isn't there and not
// to pull poor quality entropy by falling back to doing blocking reads on
// "/dev/urandom".
//
// This was brought up in https://github.com/golang/go/issues/11833
// and dismissed, I think they're wrong, I'm fixing it on common systems
// that I care about.
//

var (
	getrandomTrap   uintptr
	getentropyTweak = []byte("basket2-getentropy-tweak")
)

// Mimic OpenBSD's getentropy semantics.
//
// This means:
//  * BLOCK like god intended it, if the system entropy source isn't
//    initialized.
//  * Don't ever return truncated reads, even if signal handlers are involved.
//  * Reject reads over 256 bytes long.
//
func getentropy(b []byte) error {
	if len(b) <= 256 {
		var buf, buflen, flags uintptr
		buf = uintptr(unsafe.Pointer(&b[0]))
		buflen = uintptr(len(b))
		flags = 0

		r1, _, err := syscall.Syscall(getrandomTrap, buf, buflen, flags)
		if err < 0 {
			return err
		}
		if r1 == buflen {
			return nil
		}
	}

	return syscall.EIO
}

type nonShitRandReader struct{}

func (r *nonShitRandReader) Read(b []byte) (int, error) {
	blen := len(b)
	if blen == 0 {
		return 0, nil
	} else if blen <= 256 {
		// For short reads, use getentropy directly.
		if err := getentropy(b); err != nil {
			return 0, err
		}
		return blen, nil
	} else {
		// For large requests used a tweaked SHAKE256 instance initialized
		// with 256 bytes of entropy.
		h := sha3.NewShake256()
		defer h.Reset()
		h.Write(getentropyTweak[:])

		var seed [256]byte
		defer crypto.Memwipe(seed[:])
		if err := getentropy(seed[:]); err != nil {
			return 0, err
		}
		h.Write(seed[:])

		return io.ReadFull(h, b)
	}
}

func waitOnUrandomSanity() error {
	for {
		// Use the /proc interface to query the entropy estimate.
		buf, err := ioutil.ReadFile("/proc/sys/kernel/random/entropy_avail")
		if err != nil {
			return err
		}
		entropy, err := strconv.ParseInt(string(bytes.TrimSpace(buf)), 10, 0)
		if err != nil {
			return err
		}

		// The kernel considers an entropy pool initialized if it ever
		// exceeds 128 bits of entropy.  Since we can't tell if this has
		// happened in the past for the nonblocking pool, wait till we
		// see the threshold has been exceeded.
		if entropy > 128 {
			return nil
		}

		// Don't busy wait.
		time.Sleep(1 * time.Second)
	}
}

// Detect support for getrandom(2).
func initGetrandom() error {
	switch runtime.GOARCH {
	case "amd64":
		getrandomTrap = 318
	case "386":
		getrandomTrap = 355
	case "arm":
		getrandomTrap = 384
	case "arm64":
		getrandomTrap = 278
	default:
		// Your platform is the most special snowflake of them all.
		return syscall.ENOSYS
	}

	var err error
	var tmp [1]byte
	for {
		err = getentropy(tmp[:])
		switch err {
		case nil:
			return nil
		case syscall.EINTR:
			// Interrupted by a signal handler while waiting for the entropy
			// pool to initialize, try again.
		default:
			return err
		}
	}
}

func init() {
	if err := initGetrandom(); err == nil {
		// getrandom(2) appears to work, and is initialized.
		usingImprovedSyscallEntropy = true
		Reader = &nonShitRandReader{}
	} else {
		// The system is likely older than Linux 3.17, which while
		// prehistoric, is still used on things.
		//
		// Wait till the system entropy pool is sufficiently initialized,
		// such that crypto/rand.Reader returns quality results.
		if err = waitOnUrandomSanity(); err != nil {
			panic("rand: failed to get a sane /dev/urandom: " + err.Error())
		}
	}
}
