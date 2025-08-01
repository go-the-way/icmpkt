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
	"context"
	"net"
	"os"
	"sync/atomic"
	"time"
)

var icmpId = uint32(os.Getpid() & 0xffff)

func nextIcmpId() uint32 { return atomic.AddUint32(&icmpId, 1) }

type (
	traceroute struct {
		address               string
		addr                  net.Addr
		maxTTL, maxHop, count int
		writeDur              time.Duration
		wc                    chan *Proto
		rc                    chan *Proto
		id, seq               []int
		send, recv            []int
		run, exit             bool
		pongHandler           func(pong *Proto)

		ctx     context.Context
		ctxDone chan struct{}
		packet  *packet
	}
)

func Traceroute(address string, maxTTL, count int, writeDur time.Duration) *traceroute {
	tr := &traceroute{
		address:  address,
		addr:     addr0(address),
		maxTTL:   maxTTL,
		maxHop:   maxTTL,
		count:    count,
		writeDur: writeDur,
		wc:       make(chan *Proto, 1),
		rc:       make(chan *Proto, 1),
		id:       make([]int, maxTTL+1),
		seq:      make([]int, maxTTL+1),
		send:     make([]int, maxTTL+1),
		recv:     make([]int, maxTTL+1),
	}
	return tr
}

func (tr *traceroute) init() {
	for ttl := 1; ttl <= tr.maxTTL; ttl++ {
		tr.id[ttl] = int(nextIcmpId())
	}
}

func (tr *traceroute) Addr() string { return tr.addr.String() }

func (tr *traceroute) Context(ctx context.Context) {
	tr.ctx = ctx
	tr.ctxDone = make(chan struct{}, 1)
}

func (tr *traceroute) PongHandler(handler func(pong *Proto)) { tr.pongHandler = handler }

func (tr *traceroute) Run() {
	if tr.run {
		return
	}
	tr.run = true
	tr.packet = newPacket(tr.rc, tr.wc)
	tr.init()
	tr.startRead()
	tr.startCtx()
	tr.startWrite()
	tr.Stop()
}

func (tr *traceroute) Stop() {
	if tr.exit {
		return
	}
	tr.exit = true
	if tr.packet != nil {
		tr.packet.stop()
	}
	close(tr.wc)
	close(tr.rc)
}

func (tr *traceroute) startRead() {
	go func() {
		for {
			if tr.exit {
				return
			}
			pto, ok := <-tr.rc
			if ok {
				tr.read(pto)
			}
		}
	}()
}

func (tr *traceroute) read(pto *Proto) {
	if pto.Addr.String() == tr.addr.String() && tr.maxHop > pto.TTL {
		tr.maxHop = pto.TTL
	}
	if tr.pongHandler != nil {
		tr.pongHandler(pto)
	}
	tr.recv[pto.TTL]++
}

func (tr *traceroute) startCtx() {
	if tr.ctx == nil {
		return
	}
	go func() {
		for {
			select {
			case <-tr.ctxDone:
				close(tr.ctxDone)
				return
			case _, _ = <-tr.ctx.Done():
				tr.Stop()
				return
			}
		}
	}()
}

func (tr *traceroute) write(ping *Proto) { tr.wc <- ping }

func (tr *traceroute) startWrite() {
	for hop := 1; hop <= tr.count; hop++ {
		for ttl := 1; ttl <= tr.maxTTL; ttl++ {
			if tr.exit {
				return
			}
			if ttl > tr.maxHop {
				continue
			}
			tr.seq[ttl]++
			proto := tr.ping(ttl)
			tr.write(proto)
			if tr.send[ttl] > tr.recv[ttl] {
				tr.read(timeout(ttl, proto.ID, proto.Seq-1, tr.addr))
			}
			tr.send[ttl]++
			time.Sleep(tr.writeDur)
		}
	}
}

func (tr *traceroute) ping(ttl int) *Proto {
	return ping(ttl, tr.id[ttl], tr.seq[ttl], addr0(tr.address))
}

func addr0(s string) (addr net.Addr) {
	addr, _ = net.ResolveIPAddr("ip4", s)
	return
}
