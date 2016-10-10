// discrete_dist_test.go - Discrete distribution sampling test.
// Copyright (C) 2014,2016  Yawning Angel.
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

package discretedist

import (
	"fmt"
	"testing"

	"github.com/pylls/basket2/crypto/rand"
)

func TestUniformDist(t *testing.T) {
	const (
		debug    = false
		nrTrials = 100000
	)

	rng := rand.New()

	// Generate a new uniform distribution.
	d := NewUniform(rng, 0, 999, 100, true)
	if debug {
		fmt.Printf("d: %v", d)
	}

	// Sample and fill up the histogram.
	hist := make([]int, 1000)
	for i := 0; i < nrTrials; i++ {
		v := d.Sample(rng)
		hist[v]++
	}

	if debug {
		fmt.Println("Generated:")
		for v, c := range hist {
			if c != 0 {
				p := float64(c) / float64(nrTrials)
				fmt.Printf(" [%d]: %f (%d)\n", v, p, c)
			}
		}
	}
}
