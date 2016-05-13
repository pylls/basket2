// discrete_dist.go - Discrete distribution sampling.
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

// Package discretedist implements finite discrete distribution sampling
// suitable for protocol parameterization.
package discretedist

import (
	"bytes"
	"container/list"
	"fmt"
	mrand "math/rand"
)

// DiscreteDist is a finite discrete distribution.
type DiscreteDist struct {
	values  []int
	weights []float64

	alias []int
	prob  []float64
}

// String returns a the probability distribution as a string, with entries p <
// 0.01 omitted for brevity.
func (d *DiscreteDist) String() string {
	var b bytes.Buffer

	wSum := 0.0
	for _, v := range d.weights {
		wSum += v
	}

	b.WriteString("[ ")
	for i, v := range d.values {
		pRaw := d.weights[i]
		pScaled := pRaw / wSum
		if pScaled >= 0.01 { // Squelch tiny probabilities.
			b.WriteString(fmt.Sprintf("%d: %v ", v, pScaled))
		}
	}
	b.WriteString("]")
	return b.String()
}

// precomputeTables calculates the alias and probability tables used for
// Vose's alias method sampling.  The algorithm is the numerically stable
// variant taken from http://www.keithschwarz.com/darts-dice-coins/.
func (d *DiscreteDist) precomputeTables() {
	n := len(d.weights)
	var sum float64
	for _, weight := range d.weights {
		sum += weight
	}

	// Create arrays $Alias$ and $Prob$, each of size $n$.
	alias := make([]int, n)
	prob := make([]float64, n)

	// Create two worklists, $Small$ and $Large$.
	small := list.New()
	large := list.New()

	scaled := make([]float64, n)
	for i, weight := range d.weights {
		// Multiply each probability by $n$.
		p_i := weight * float64(n) / sum
		scaled[i] = p_i

		// For each scaled probability $p_i$:
		if scaled[i] < 1.0 {
			// If $p_i < 1$, add $i$ to $Small$.
			small.PushBack(i)
		} else {
			// Otherwise ($p_i \ge 1$), add $i$ to $Large$.
			large.PushBack(i)
		}
	}

	// While $Small$ and $Large$ are not empty: ($Large$ might be emptied first)
	for small.Len() > 0 && large.Len() > 0 {
		// Remove the first element from $Small$; call it $l$.
		l := small.Remove(small.Front()).(int)
		// Remove the first element from $Large$; call it $g$.
		g := large.Remove(large.Front()).(int)

		// Set $Prob[l] = p_l$.
		prob[l] = scaled[l]
		// Set $Alias[l] = g$.
		alias[l] = g

		// Set $p_g := (p_g + p_l) - 1$. (This is a more numerically stable option.)
		scaled[g] = (scaled[g] + scaled[l]) - 1.0

		if scaled[g] < 1.0 {
			// If $p_g < 1$, add $g$ to $Small$.
			small.PushBack(g)
		} else {
			// Otherwise ($p_g \ge 1$), add $g$ to $Large$.
			large.PushBack(g)
		}
	}

	// While $Large$ is not empty:
	for large.Len() > 0 {
		// Remove the first element from $Large$; call it $g$.
		g := large.Remove(large.Front()).(int)
		// Set $Prob[g] = 1$.
		prob[g] = 1.0
	}

	// While $Small$ is not empty: This is only possible due to numerical instability.
	for small.Len() > 0 {
		// Remove the first element from $Small$; call it $l$.
		l := small.Remove(small.Front()).(int)
		// Set $Prob[l] = 1$.
		prob[l] = 1.0
	}

	d.prob = prob
	d.alias = alias
}

// Sample generates a random value according to the distribution with the
// provided entropy source.
func (d *DiscreteDist) Sample(r *mrand.Rand) int {
	var idx int

	// Generate a fair die roll from an $n$-sided die; call the side $i$.
	i := mrand.Intn(len(d.values))
	// Flip a biased coin that comes up heads with probability $Prob[i]$.
	if mrand.Float64() <= d.prob[i] {
		// If the coin comes up "heads," return $i$.
		idx = i
	} else {
		// Otherwise, return $Alias[i]$.
		idx = d.alias[i]
	}

	return d.values[idx]
}

// NewUniform creates a new uniform discrete distribution, optionally with
// biased probabilities.
func NewUniform(r *mrand.Rand, minValue, maxValue, maxN int, biased bool) *DiscreteDist {
	d := new(DiscreteDist)

	if maxN == 0 || minValue-maxValue > 0 {
		panic("discretedist: invalid parameters for uniform distribution")
	}

	// Determine the number of discrete entries in the distribution.
	n := r.Intn(maxN) + 1

	// Generate the random values and weights such that
	// the values fall into [minValue, maxValue].
	vRange := (maxValue + 1) - minValue
	values := r.Perm(vRange) // Random permutation [0, vRange)
	for i := 0; i < n; i++ {
		values[i] += minValue // Shift to [minValue, maxValue].
	}
	d.values = values[:n]

	// Generate random weights [0, 1) for each value.  The precomputation
	// step will handle converting them to probabilities.
	d.weights = make([]float64, n) // Preallocate probability table.
	if !biased {                   // Uniform
		for i := 0; i < n; i++ {
			d.weights[i] = r.Float64()
		}
	} else {
		// This is better for a more "nautral" histogram since the uniform
		// generation ends up being rather random.
		culmProb := 0.0
		for i := 0; i < n; i++ {
			p := (1.0 - culmProb) * r.Float64()
			d.weights[i] = p
			culmProb += p
		}
	}

	// Generate the probability and alias tables.
	d.precomputeTables()

	return d
}
