// a2filter.go - A2 bloom filter
//
// To the extent possible under law, the Yawning Angel waived all copyright
// and related or neighboring rights to a2filter, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package a2filter implements a SipHash-2-4 based Active-Active Bloom Filter.
// It is designed to be stable over time even when filled to max capacity by
// implementing the active-active buffering (A2 buffering) scheme presented in
// "Aging Bloom Filter with Two Active Buffers for Dynamic Sets" (MyungKeun
// Yoon).
//
// Note that none of the operations on the filter are constant time, and the
// the max backing Bloom Filter size is limited to 2^31 bytes.  This package is
// threadsafe.
package a2filter

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/dchest/siphash"
)

const (
	ln2         = 0.69314718055994529
	ln2Sq       = 0.48045301391820139
	maxMln2     = 31
	maxNrHashes = 32
)

// A2Filter is an Active-Active Bloom Filter.
type A2Filter struct {
	sync.Mutex
	k1, k2 uint64

	nrEntries    int
	nrEntriesMax int

	nrHashes int
	hashMask uint32
	active1  []byte
	active2  []byte
}

// New constructs a new A2Filter with a filter set size 2^mLn2, and false
// postive rate p.  The actual in memory footprint of the datastructure will be
// approximately 2^(mLn2+1) bits due to the double buffered nature of the
// filter.
func New(rand io.Reader, mLn2 int, p float64) (*A2Filter, error) {
	var key [16]byte
	if _, err := io.ReadFull(rand, key[:]); err != nil {
		return nil, err
	}

	if mLn2 > maxMln2 {
		return nil, fmt.Errorf("requested filter too large: %d", mLn2)
	}

	m := 1 << uint32(mLn2)
	n := -1.0 * float64(m) * ln2Sq / math.Log(p)
	k := int((float64(m) * ln2 / n) + 0.5)

	f := new(A2Filter)
	f.k1 = binary.BigEndian.Uint64(key[0:8])
	f.k2 = binary.BigEndian.Uint64(key[8:16])
	f.nrEntriesMax = int(n)
	f.nrHashes = k
	f.hashMask = uint32(m - 1)
	if f.nrHashes < 2 {
		f.nrHashes = 2
	}
	if f.nrHashes > maxNrHashes {
		return nil, fmt.Errorf("requested parameters need too many hashes")
	}
	f.active1 = make([]byte, m/8)
	f.active2 = make([]byte, m/8)
	return f, nil
}

// TestAndSet tests the A2Filter for a given value's membership, adds the
// value to the filter and returns if it was present at the time of the call.
func (f *A2Filter) TestAndSet(b []byte) bool {
	hashes := f.getHashes(b)

	f.Lock()
	defer f.Unlock()

	// If the member is present in Active1, just return.
	if f.testCache(f.active1, hashes) {
		return true
	}

	// Test Active2 for membership, and add the value to Active1.
	ret := f.testCache(f.active2, hashes)
	if f.nrEntries++; f.nrEntries > f.nrEntriesMax {
		// Active1 is full, clear Active2 and swap the buffers, this leaves
		// Active1 empty, and Active2 populated to saturation, immediately
		// after the tested entry will be added to Active1.
		f.active2 = make([]byte, len(f.active2))
		f.active1, f.active2 = f.active2, f.active1
		f.nrEntries = 1
	}
	f.addActive1(hashes)
	return ret
}

// MaxEntries returns the maximum capacity of the A2Filter.  This value is
// usually an underestimate as the filter is double buffered, however entry
// count accounting is only done for Active1, so Active2 should be ignored in
// calculations.
func (f *A2Filter) MaxEntries() int {
	return f.nrEntriesMax
}

func (f *A2Filter) testCache(cache []byte, hashes []uint32) bool {
	for i := 0; i < f.nrHashes; i++ {
		idx := hashes[i] & f.hashMask
		if 0 == cache[idx/8]&(1<<(idx&7)) {
			// Break out early if there is a miss.
			return false
		}
	}
	return true
}

func (f *A2Filter) addActive1(hashes []uint32) {
	for i := 0; i < f.nrHashes; i++ {
		idx := hashes[i] & f.hashMask
		f.active1[idx/8] |= (1 << (idx & 7))
	}
}

func (f *A2Filter) getHashes(b []byte) []uint32 {
	// Per "Less Hashing, Same Performance: Building a Better Bloom Filter"
	// (Kirsch and Miteznmacher), with a suitably good PRF, only two calls to
	// the hash algorithm are needed.  As SipHash-2-4 returns a 64 bit digest,
	// and we use 32 bit hashes for the filter, this results in only one
	// invocation of SipHash-2-4.

	hashes := make([]uint32, f.nrHashes)
	baseHash := siphash.Hash(f.k1, f.k2, b)
	hashes[0] = uint32(baseHash & math.MaxUint32)
	hashes[1] = uint32(baseHash >> 32)
	for i := 2; i < f.nrHashes; i++ {
		hashes[i] = hashes[0] + uint32(i)*hashes[1]
	}
	return hashes
}
