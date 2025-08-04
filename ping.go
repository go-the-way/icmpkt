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

import "time"

type ping = traceroute

func Ping(address string, count int) *ping {
	return PingDuration(address, count, time.Millisecond*500, time.Millisecond*500)
}

func PingDuration(address string, count int, hopDur, readDur time.Duration) *ping {
	p := &ping{
		address: address,
		addr:    ip4(address),

		maxTTL: 1,
		maxHop: 1,
		count:  count,

		hopDur:  hopDur,
		readDur: readDur,

		wc: make(chan *Proto, 1),
		rc: make(chan *Proto, 1),

		id: make([]int, 1),
		ic: make([]chan *Proto, 1),
	}
	return p
}
