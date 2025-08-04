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
	"sync"
	"sync/atomic"
	"time"
)

var icmpId = uint32(os.Getpid() & 0xffff)

func nextIcmpId() uint32 { return atomic.AddUint32(&icmpId, 1) }

type traceroute struct {
	address                 string
	addr                    net.Addr
	maxTTL, maxHop, count   int
	ttlDur, hopDur, readDur time.Duration
	wc, rc                  chan *Proto
	id                      []int
	ic                      []chan *Proto
	run, exit               bool
	pongHandler             func(pong *Proto)
	ctx                     context.Context
	ctxDone                 chan struct{}
	packet                  *packet
	troute                  bool
}

func Traceroute(address string, maxTTL, count int) *traceroute {
	return TracerouteDuration(address, maxTTL, count, time.Millisecond*100, time.Millisecond*500, time.Millisecond*500)
}

func TracerouteDuration(address string, maxTTL, count int, hopDur, ttlDur, readDur time.Duration) *traceroute {
	tr := &traceroute{
		address: address,
		addr:    ip4(address),
		maxTTL:  maxTTL,
		maxHop:  maxTTL,
		count:   count,
		hopDur:  hopDur,
		ttlDur:  ttlDur,
		readDur: readDur,
		wc:      make(chan *Proto, 1),
		rc:      make(chan *Proto, 1),
		id:      make([]int, maxTTL),
		ic:      make([]chan *Proto, maxTTL),
		troute:  true,
	}
	return tr
}

func (tr *traceroute) Addr() string                          { return tr.addr.String() }
func (tr *traceroute) Context(ctx context.Context)           { tr.ctx = ctx; tr.ctxDone = make(chan struct{}, 1) }
func (tr *traceroute) PongHandler(handler func(pong *Proto)) { tr.pongHandler = handler }

func (tr *traceroute) Run() {
	if tr.run {
		return
	}
	tr.run = true
	tr.packet = newPacket(tr.rc, tr.wc)
	tr.startPong()
	tr.startPing()
	tr.startCtx()
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

// traceroute <- packet
func (tr *traceroute) pong(pto *Proto) {
	if tr.troute {
		tr.ic[pto.TTL-1] <- pto
	} else {
		tr.ic[0] <- pto
	}
}

func (tr *traceroute) startPong() {
	go func() {
		for {
			if pong, ok := <-tr.rc; ok {
				if tr.troute {
					if pong.Addr.String() == tr.addr.String() && tr.maxHop > pong.TTL {
						tr.maxHop = pong.TTL
					}
				}
				tr.pong(pong)
			}
		}
	}()
}

// traceroute -> packet
func (tr *traceroute) ping(pto *Proto) { tr.wc <- pto }
func (tr *traceroute) startPing() {
	for seq := 1; seq <= tr.count; seq++ {
		wg := &sync.WaitGroup{}
		for ttl := 0; ttl < tr.maxHop; ttl++ {
			tr.ic[ttl] = make(chan *Proto, 1)
			if tr.exit {
				return
			}
			if tr.id[ttl] == 0 {
				tr.id[ttl] = int(nextIcmpId())
			}
			id := tr.id[ttl]
			ttl0 := ttl
			if tr.troute {
				ttl0++
			}
			tr.ping(pingProto(ttl0, id, seq, tr.addr))
			wg.Add(1)
			go tr.readTTL(wg, ttl, id, seq)
			if tr.troute {
				time.Sleep(tr.ttlDur)
			}
		}
		wg.Wait()
		time.Sleep(tr.hopDur)
	}
}

func (tr *traceroute) readTTL(wg *sync.WaitGroup, ttl, id, seq int) {
	defer wg.Done()
	var pong *Proto
loop:
	for {
		select {
		case pong = <-tr.ic[ttl]:
			close(tr.ic[ttl])
			break loop
		case <-time.After(tr.readDur):
			ttl0 := ttl
			if tr.troute {
				ttl0++
			}
			pong = timeoutProto(ttl0, id, seq)
			break loop
		}
	}
	if pong != nil && tr.pongHandler != nil {
		tr.pongHandler(pong)
	}
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

func ip4(s string) (addr net.Addr) { addr, _ = net.ResolveIPAddr("ip4", s); return }
