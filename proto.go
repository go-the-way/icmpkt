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
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Proto struct {
	TTL, ID, Seq int
	Addr         net.Addr
	Rtt          time.Duration
}

func pingProto(ttl, id, seq int, addr net.Addr) *Proto {
	return &Proto{TTL: ttl, ID: id, Seq: seq, Addr: addr}
}

func pongProto(ttl, id, seq int, addr net.Addr, rtt time.Duration) *Proto {
	return &Proto{TTL: ttl, ID: id, Seq: seq, Addr: addr, Rtt: rtt}
}

func timeoutProto(ttl, id, seq int) *Proto { return &Proto{TTL: ttl, ID: id, Seq: seq} }

func (p *Proto) String() string {
	return fmt.Sprintf("TTL: %d, ID: %d, Seq: %d, Addr: %v, Rtt: %v", p.TTL, p.ID, p.Seq, p.Addr, p.Rtt)
}

func (p *Proto) buf() []byte {
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:  p.ID,
			Seq: p.Seq,
		},
	}
	buf, _ := msg.Marshal(nil)
	return buf
}
