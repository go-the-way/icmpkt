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
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	listenNetwork = "ip4:icmp"
	listenAddress = "0.0.0.0"
)

type (
	ttlOpt struct {
		ttl  int
		time time.Time
	}
	packet struct {
		lo         *logpkg.Logger
		packetConn *icmp.PacketConn

		wc chan<- *Proto
		rc <-chan *Proto

		mu *sync.Mutex
		m  map[int]ttlOpt

		exit bool
	}
)

func newPacket(wc chan<- *Proto, rc <-chan *Proto) *packet {
	return (&packet{
		lo: logpkg.New(os.Stdout, "[icmp-packet] ", logpkg.LstdFlags|logpkg.Lshortfile),
		wc: wc,
		rc: rc,
		mu: &sync.Mutex{},
		m:  make(map[int]ttlOpt),
	}).run()
}

func (p *packet) debug(format string, arg ...any) {
	if debug {
		p.lo.Printf(format, arg...)
	}
}

func (p *packet) log(format string, arg ...any) { p.debug(format, arg...) }

func (p *packet) panic(format string, arg ...any) { p.lo.Panicf(format, arg...) }

func (p *packet) listen() {
	var err error
	p.packetConn, err = icmp.ListenPacket(listenNetwork, listenAddress)
	if err != nil {
		panic(fmt.Sprintf("listen on[%s:%s] error: %v\n", listenNetwork, listenAddress, err))
		return
	}
	p.log("listen on[%s:%s] ok\n", listenNetwork, listenAddress)
}

func (p *packet) run() *packet { p.listen(); p.start(); return p }

func (p *packet) start() {
	go p.startWrite()
	go p.startRead()
}

func (p *packet) stop() {
	p.exit = true
	if p.packetConn != nil {
		_ = p.packetConn.Close()
	}
	p.log("stop packet")
}

func (p *packet) startWrite() {
	p.log("start write")
	defer p.log("stop write")
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if p.exit {
				return
			}
		case pto, ok := <-p.rc:
			if ok {
				isTtl := pto.TTL > 0
				if isTtl {
					_ = p.packetConn.IPv4PacketConn().SetTTL(pto.TTL)
				}
				n, err := p.packetConn.WriteTo(pto.buf(), pto.Addr)
				if err != nil {
					p.debug("write to dstAddr[%s] ttl[%d] id[%d] seq[%d] error: %v\n", pto.Addr.String(), pto.TTL, pto.ID, pto.Seq, err)
				} else {
					p.debug("write to dstAddr[%s] ttl[%d] id[%d] seq[%d] ok len: %d\n", pto.Addr.String(), pto.TTL, pto.ID, pto.Seq, n)
					p.setTTL(pto.TTL, pto.ID, pto.Seq)
				}
			}
		}
	}
}

func (p *packet) startRead() {
	p.log("start read")
	defer p.log("stop read")
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	buf := make([]byte, 128)
	for {
		select {
		case <-ticker.C:
			if p.exit {
				return
			}
		default:
			_ = p.packetConn.SetReadDeadline(time.Now().Add(time.Millisecond * 10))
			n, srcAddr, _ := p.packetConn.ReadFrom(buf)
			if n > 0 && srcAddr != nil {
				buf2 := buf[:n]
				if msg, _ := icmp.ParseMessage(1, buf2); msg != nil {
					if pto := p.messageRead(msg, srcAddr); pto != nil {
						p.debug("read from srcAddr[%s] id[%d] seq[%d] rtt[%v] ok len: %d\n", srcAddr.String(), pto.ID, pto.Seq, pto.Rtt, n)
						p.wc <- pto
					}
				}
			}
		}
	}
}

func (p *packet) messageRead(msg *icmp.Message, srcAddr net.Addr) (pto *Proto) {
	parseEcho := func(ec *icmp.Echo) (pto *Proto) {
		if ec != nil && ec.ID > 0 && ec.Seq > 0 {
			if ttl, rtt := p.getTTL(ec); rtt > 0 {
				pto = pongProto(ttl, ec.ID, ec.Seq, srcAddr, rtt)
			}
		}
		return
	}

	switch msg.Type {

	case ipv4.ICMPTypeEchoReply:
		return parseEcho(msg.Body.(*icmp.Echo))

	case ipv4.ICMPTypeTimeExceeded:
		ee, ok := msg.Body.(*icmp.TimeExceeded)
		if !ok {
			return
		}
		msg0, _ := icmp.ParseMessage(1, ee.Data[20:])
		if msg0 == nil {
			return
		}
		msgBody := msg0.Body
		if msgBody == nil {
			return
		}
		return parseEcho(msgBody.(*icmp.Echo))

	}
	return
}

func (p *packet) setTTL(ttl, id, seq int) {
	p.mu.Lock()
	p.m[id<<16|seq] = ttlOpt{ttl, time.Now()}
	p.mu.Unlock()
}

func (p *packet) getTTL(ec *icmp.Echo) (ttl int, rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := ec.ID<<16 | ec.Seq
	t, ok := p.m[k]
	if !ok {
		return
	}
	delete(p.m, k)
	return t.ttl, time.Since(t.time)
}
