// replayfilter.go - Handshake message replay prevention.
// Copyright (C) 2016 Yawning Angel.
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
	"hash"
	"io"
	"sync"
	"time"

	"git.schwanenlied.me/yawning/a2filter.git"
	"git.schwanenlied.me/yawning/basket2.git/crypto"
	"git.schwanenlied.me/yawning/basket2.git/crypto/rand"

	"github.com/dchest/siphash"
)

const (
	maxFilterSize       = 10 * 1000
	fullCompactInterval = 60 * time.Minute

	// This allows for at least 1.4 million entries.
	replayLargeSize = 25      // 2^25 bits (4 MiB per buffer)
	replayLargeRate = 0.00001 // 1/100k (False positive rate)
)

// ReplayFilter is the replay filter interface.
type ReplayFilter interface {
	// TestAndSet adds the provided byte slice to the replay filter, and
	// returns true iff it was already present.  The implementation MUST
	// be thread safe.
	TestAndSet([]byte) bool
}

// NewLargeReplayFilter creates a new high capacity replay filter suitable
// for extremely busy servers.  It is backed by an active-active bloom
// filter, and thus has false positives, though the rate is low enough that
// such occurences should be relatively rare.
func NewLargeReplayFilter() (ReplayFilter, error) {
	return a2filter.New(rand.Reader, replayLargeSize, replayLargeRate)
}

type smallReplayFilter struct {
	sync.Mutex

	h      hash.Hash64
	filter map[uint64]uint64

	lastCompactAt time.Time
	compactTimer  *time.Timer
}

func (f *smallReplayFilter) TestAndSet(b []byte) bool {
	now := getEpochHour()
	f.Lock()
	defer f.Unlock()

	f.h.Write(b)
	digest := f.h.Sum64()
	f.h.Reset()

	// Test first, if it's present there's nothing more to do.
	_, present := f.filter[digest]
	if present {
		return true
	}

	// If the filter is full...
	if len(f.filter) >= maxFilterSize {
		// Attempt a compaction early.
		if !f.compactLocked() {
			// Failed to evict.  We can either evict one at random and hope
			// nothing evil is going on, or treat everything as a hit till
			// we have the capacity to prevent replays.  Both options kind
			// of suck, but opt for "Deny new connections till replay
			// prevention is possible again".
			return true
		}
	}

	// AFTER epochHour() + 1, the mark will no longer be considered valid,
	// so that's the latest we need to keep the entry in the filter.
	f.filter[digest] = now + 1

	return false
}

func (f *smallReplayFilter) compactLocked() bool {
	now := getEpochHour()

	// Iterate over the filter.
	for k, v := range f.filter {
		// The filter stores the epoch hour which the entry was accepted + 1,
		// which is the last possible interval at which the given entry is
		// considered valid.
		if v < now {
			delete(f.filter, k)
		}
	}
	return len(f.filter) < maxFilterSize
}

func (f *smallReplayFilter) fullCompact() {
	now := time.Now()

	f.Lock()
	defer f.Unlock()

	if now.Before(f.lastCompactAt) {
		// What the fuck, the system time jumped backwards by more than the
		// compaction interval.  NTP is a thing, people should use it.  Since
		// it's not really possible for the filter to be "sane", just dump
		// the whole thing.  The compaction interval is such that minor clock
		// updates due to NTP should not trigger this safeguard.
		f.filter = make(map[uint64]uint64)
	} else {
		// Attempt to prune all stale entries from the filter.
		f.compactLocked()
	}

	// Schedule the next compaction.
	f.lastCompactAt = now
	f.compactTimer = time.AfterFunc(fullCompactInterval, f.fullCompact)
}

// NewSmallReplayFilter creates a new "small" capacity replay filter.  It is
// backed by a map, and has no false positives, but will reject connections
// if the filter ever fills up (10k entries) till space is made by older
// entries expiring.
func NewSmallReplayFilter() (ReplayFilter, error) {
	var k [16]byte
	defer crypto.Memwipe(k[:])
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, err
	}

	f := new(smallReplayFilter)
	f.h = siphash.New(k[:])
	f.filter = make(map[uint64]uint64)
	f.compactTimer = time.AfterFunc(fullCompactInterval, f.fullCompact)
	return f, nil
}
