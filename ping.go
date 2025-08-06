// Copyright 2025 icmpkt Author. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package icmpkt

import (
	"fmt"
	logpkg "log"
	"os"
	"sync"
	"time"
)

var (
	pingDebug = os.Getenv("PING_DEBUG") == "T"
	pingTrace = os.Getenv("PING_TRACE") == "T"
)

type ping = traceroute

func Ping(address string, count int) *ping {
	return PingDuration(address, count, time.Millisecond*500, time.Millisecond*500, time.Millisecond*500)
}

func PingDuration(address string, count int, ttl0Dur, ttl1Dur, readDur time.Duration) *ping {
	p := &ping{
		address: address,
		maxTTL:  1,
		maxHop:  1,
		count:   count,
		ttl0Dur: ttl0Dur,
		ttl1Dur: ttl1Dur,
		readDur: readDur,
		wc:      make(chan *Proto, 1),
		rc:      make(chan *Proto, 1),
		hc:      make(chan *Proto, 1),
		id:      make([]int, 1),
		recv:    make([]int, 1),
		ic:      make([]chan *Proto, 1),
		wg:      &sync.WaitGroup{},
	}
	p.addr, p.ip4 = ip4(address)
	if pingDebug || pingTrace {
		p.lo = logpkg.New(os.Stdout, fmt.Sprintf("[ping:%-24s] ", p.address), logpkg.LstdFlags)
	}
	return p
}
