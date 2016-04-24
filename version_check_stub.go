// version_check.go - Version check
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

// +build !go1.6 gccgo

package basket2

// If you are hitting this at test/runtime, this means your Go is kind of old.
// How to work around this check is blatantly obvious, however the authors
// will provide even less than the expected non-existent support for binaries
// built that way, though clean patches that do not massively complicate the
// code will likely be merged.
func isRecentEnoughGo() bool {
	return false
}
