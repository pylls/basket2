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

	"git.schwanenlied.me/yawning/basket2.git/crypto"

	"github.com/dchest/siphash"
)

const (
	maxFilterSize       = 100 * 1024
	fullCompactInterval = 60 * time.Minute
)

type replayFilter struct {
	sync.Mutex

	h hash.Hash64

	filter map[uint64]uint64

	lastCompactAt time.Time
	compactTimer  *time.Timer
}

func newReplayFilter(rand io.Reader) (*replayFilter, error) {
	var k [16]byte
	defer crypto.Memwipe(k[:])
	if _, err := io.ReadFull(rand, k[:]); err != nil {
		return nil, err
	}

	f := new(replayFilter)
	f.h = siphash.New(k[:])
	f.filter = make(map[uint64]uint64)
	f.compactTimer = time.AfterFunc(fullCompactInterval, f.fullCompact)
	return f, nil
}

func (f *replayFilter) testAndSet(mark *[32]byte, epochHour uint64) bool {
	f.Lock()
	defer f.Unlock()

	f.h.Write(mark[:])
	mh := f.h.Sum64()
	f.h.Reset()

	_, present := f.filter[mh]
	if present {
		// Hit.
		return true
	}

	// The filter is full, make room for a single entry by deleting one at
	// "random".  This should essentially never happen, unless I
	// catastropically undersized the max filter size.
	if len(f.filter) >= maxFilterSize {
		// This is kind of stupid, but the interation order is semi-random.
		// In theory the filter is sized quite large and is compacted
		// periodically, so this shouldn't get triggered ever, so the kludgey
		// nature of "random" should be ok...
		for victim := range f.filter {
			delete(f.filter, victim)
			break
		}
	}

	// Miss, add the mark to the filter.
	f.filter[mh] = epochHour
	return false
}

func (f *replayFilter) fullCompact() {
	now := time.Now()
	eh := getEpochHour()

	f.Lock()
	defer f.Unlock()

	if now.Before(f.lastCompactAt) {
		// What the fuck, the system time jumped backwards by more than the
		// compaction interval.  NTP is a thing, people should use it.  Since
		// it's not really possible for the filter to be "sane", just dump
		// the whole thing.
		f.filter = make(map[uint64]uint64)
	}

	// Iterate over the entire filter, purging entries older than the current
	// epoch - 1, since they will no longer be accepted.
	for k, v := range f.filter {
		if v < eh-1 {
			delete(f.filter, k)
		}
	}

	// Schedule the next compaction.
	f.lastCompactAt = now
	f.compactTimer = time.AfterFunc(fullCompactInterval, f.fullCompact)
}
