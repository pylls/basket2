// proxy_extras.go - Proxy extensions.
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

package proxyextras

import (
	"sync"

	"golang.org/x/net/proxy"
)

func InitBackends() {
	var once sync.Once
	once.Do(func() {
        proxy.RegisterDialerType("http", newHTTP)
		proxy.RegisterDialerType("socks4a", newSOCKS4)
	})
}
