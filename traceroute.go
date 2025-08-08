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
	"fmt"
	logpkg "log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	icmpId          = uint32(os.Getpid() & 0xffff)
	tracerouteDebug = os.Getenv("TRACEROUTE_DEBUG") == "T"
	tracerouteTrace = os.Getenv("TRACEROUTE_TRACE") == "T"
)

func nextIcmpId() uint32 { return atomic.AddUint32(&icmpId, 1) % (2 << 15) }

type traceroute struct {
	lo                    *logpkg.Logger
	address               string
	addr                  net.Addr
	ip4                   string
	maxTTL, maxHop, count int
	writeDur, readDur     time.Duration
	wc, rc, hc            chan *Proto
	id                    []int
	ic                    []chan *Proto
	pec, hec, cec         chan struct{}
	runOnce, stopOnce     *sync.Once
	exit                  bool
	pongHandler           func(pong *Proto)
	ctx                   context.Context
	packet                *packet
	wg                    *sync.WaitGroup
	traceroute            bool
}

func Traceroute(address string, maxTTL, count int) *traceroute {
	return TracerouteDuration(address, maxTTL, count, time.Millisecond*500, time.Millisecond*500)
}

func TracerouteDuration(address string, maxTTL, count int, writeDur, readDur time.Duration) *traceroute {
	return newTraceroute(address, maxTTL, count, writeDur, readDur, true)
}

func newTraceroute(address string, maxTTL, count int, writeDur, readDur time.Duration, route bool) *traceroute {
	tr := &traceroute{
		address:    address,
		maxTTL:     maxTTL,
		maxHop:     maxTTL,
		count:      count,
		writeDur:   writeDur,
		readDur:    readDur,
		wc:         make(chan *Proto, 1),
		rc:         make(chan *Proto, 1),
		hc:         make(chan *Proto, 1),
		id:         make([]int, maxTTL),
		ic:         make([]chan *Proto, maxTTL),
		pec:        make(chan struct{}, 1),
		hec:        make(chan struct{}, 1),
		runOnce:    &sync.Once{},
		stopOnce:   &sync.Once{},
		wg:         &sync.WaitGroup{},
		traceroute: route,
	}
	tr.addr, tr.ip4 = ip4(address)
	if !route && (pingDebug || pingTrace) {
		tr.lo = logpkg.New(os.Stdout, fmt.Sprintf("[ping:%-24s] ", tr.address), logpkg.LstdFlags)
	}
	if route && (tracerouteDebug || tracerouteTrace) {
		tr.lo = logpkg.New(os.Stdout, fmt.Sprintf("[route:%-23s] ", tr.address), logpkg.LstdFlags)
	}
	return tr
}

func (tr *traceroute) debug(format string, arg ...any) {
	if tr.traceroute && tracerouteDebug {
		tr.lo.Println(fmt.Sprintf(format, arg...))
	}

	if !tr.traceroute && pingDebug {
		tr.lo.Println(fmt.Sprintf(format, arg...))
	}
}

func (tr *traceroute) trace(format string, arg ...any) {
	if tr.traceroute && tracerouteTrace {
		tr.lo.Println(fmt.Sprintf(format, arg...))
	}

	if !tr.traceroute && pingTrace {
		tr.lo.Println(fmt.Sprintf(format, arg...))
	}
}

func (tr *traceroute) Addr() net.Addr                        { return tr.addr }
func (tr *traceroute) Ip4() string                           { return tr.ip4 }
func (tr *traceroute) Context(ctx context.Context)           { tr.ctx = ctx; tr.cec = make(chan struct{}, 1) }
func (tr *traceroute) PongHandler(handler func(pong *Proto)) { tr.pongHandler = handler }

func (tr *traceroute) Run() {
	fn := func() {
		tr.trace("Run() start")
		defer tr.trace("Run() end")
		tr.packet = newPacket(tr.rc, tr.wc)
		go tr.startPong()
		go tr.startHandler()
		go tr.startCtx()
		tr.runPing()
		tr.Stop()
	}
	tr.runOnce.Do(fn)
}

func (tr *traceroute) Stop() {
	fn := func() {
		tr.trace("Stop() start")
		defer tr.trace("Stop() end")
		tr.exit = true
		tr.packet.stop()
		tr.pec <- struct{}{}
		close(tr.pec)
		tr.trace("Stop() closed pec")
		tr.hec <- struct{}{}
		close(tr.hec)
		tr.trace("Stop() closed hec")
		if tr.cec != nil {
			tr.cec <- struct{}{}
			close(tr.cec)
			tr.trace("Stop() closed cec")
		}
		tr.closes()
	}
	tr.stopOnce.Do(fn)
}

func (tr *traceroute) pong(pto *Proto) {
	tr.trace("pong() start")
	defer tr.trace("pong() end")
	ttl := pto.TTL
	if tr.traceroute {
		ttl--
	}
	tr.ic[ttl] <- pto
}

func (tr *traceroute) startPong() {
	tr.trace("startPong() start")
	defer tr.trace("startPong() end")
	for {
		select {
		case <-tr.pec:
			return
		case pto, ok := <-tr.rc:
			if !ok {
				return
			}
			tr.debug("packet->>>>>>: %s", pto.String())
			if tr.traceroute && pto.Ip4 == tr.ip4 && tr.maxHop > pto.TTL {
				tr.trace("found max hop: %d", pto.TTL)
				tr.maxHop = pto.TTL
			}
			tr.pong(pto)
		}
	}
}

func (tr *traceroute) handler(pto *Proto) {
	if tr.exit {
		return
	}
	tr.hc <- pto
	tr.debug("handler<<<<<-: %s", pto)
}

func (tr *traceroute) startHandler() {
	tr.trace("startHandler() start")
	defer tr.trace("startHandler() end")
	for {
		select {
		case <-tr.hec:
			return
		case pto, ok := <-tr.hc:
			if !ok {
				return
			}
			if tr.pongHandler != nil && pto != nil {
				tr.pongHandler(pto)
			}
		}
	}
}

func (tr *traceroute) closes() {
	for ttl, ic := range tr.ic {
		if ic != nil {
			close(ic)
			if tr.traceroute {
				tr.trace("closes() closed ic ttl: %d", ttl+1)
			} else {
				tr.trace("closes() closed ic")
			}
		}
	}
}

func (tr *traceroute) ping(pto *Proto) {
	if tr.exit {
		return
	}
	tr.wc <- pto
	tr.debug("packet<<<<<<-: %s", pto)
}

func (tr *traceroute) runPing() {
	tr.trace("runPing() start")
	defer tr.trace("runPing() end")

	closes := func() {
		close(tr.wc)
		tr.trace("runPing() closed wc")
		close(tr.hc)
		tr.trace("runPing() closed hc")
	}

	for ttl := 0; ttl < tr.maxHop; ttl++ {
		if tr.id[ttl] == 0 {
			tr.id[ttl] = int(nextIcmpId())
			tr.ic[ttl] = make(chan *Proto, 1)
		}
		id := tr.id[ttl]
		ttl0 := ttl
		if tr.traceroute {
			ttl0++
		}
		if tr.exit {
			closes()
			return
		}
		tr.ping(pingProto(ttl0, id, 0, tr.addr, tr.ip4))
		tr.handler(tr.readTTL(ttl, id, 0))
		tr.wg.Add(1)
		go tr.runTTL(ttl, tr.count)
		if !tr.traceroute {
			break
		}
	}
	tr.wg.Wait()
	closes()
}

func (tr *traceroute) runTTL(ttl, count int) {
	ttl0 := ttl
	if tr.traceroute {
		ttl0++
	}
	tr.trace("runTTL() start ttl: %d count: %d", ttl0, count)
	defer tr.trace("runTTL() end ttl: %d count: %d", ttl0, count)
	defer tr.wg.Done()
	for seq := 1; seq < count; seq++ {
		if tr.exit {
			return
		}
		tr.ping(pingProto(ttl0, tr.id[ttl], seq, tr.addr, tr.ip4))
		tr.handler(tr.readTTL(ttl, tr.id[ttl], seq))
	}
}

func (tr *traceroute) readTTL(ttl, id, seq int) (pto *Proto) {
	now := time.Now()
	ttl0 := ttl
	if tr.traceroute {
		ttl0++
	}
	tr.trace("readTTL() start ttl: %d id: %d seq: %d", ttl0, id, seq)
	defer tr.trace("readTTL() end ttl: %d id: %d seq: %d", ttl0, id, seq)
	for {
		select {
		case pto = <-tr.ic[ttl]:
			if seq > 0 {
				time.Sleep(tr.writeDur - time.Since(now))
			}
			return
		case <-time.After(tr.readDur):
			pto = timeoutProto(ttl0, id, seq)
			tr.trace("readTTL() timeout ttl: %d id: %d seq: %d", ttl0, id, seq)
			tr.debug("timeout->>>>>: %s", pto)
			return
		}
	}
}

func (tr *traceroute) startCtx() {
	if tr.ctx == nil {
		return
	}
	tr.trace("startCtx() start")
	defer tr.trace("startCtx() end")
	go func() {
		for {
			select {
			case <-tr.cec:
				return
			case <-tr.ctx.Done():
				tr.Stop()
				return
			}
		}
	}()
}

func ip4(s string) (net.Addr, string) {
	if ip := net.ParseIP(s); ip != nil {
		return &net.IPAddr{IP: ip}, s
	}
	addr, _ := net.ResolveIPAddr("ip4", s)
	return addr, aip4(addr)
}

func aip4(a net.Addr) (ip4 string) {
	if a == nil {
		return
	}
	ipa, ok := a.(*net.IPAddr)
	if !ok || ipa == nil {
		return
	}
	return ipa.String()
}
