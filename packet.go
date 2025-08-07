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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	listenNetwork = "ip4:icmp"
	listenAddress = "0.0.0.0"
)

var (
	icmpktDebug = os.Getenv("ICMPKT_DEBUG") == "T"
	icmpktTrace = os.Getenv("ICMPKT_TRACE") == "T"
)

type (
	ttlOpt struct {
		ttl  int
		unix int64
	}
	packet struct {
		lo         *logpkg.Logger
		packetConn *icmp.PacketConn
		wc         chan<- *Proto
		rc         <-chan *Proto
		mu         *sync.Mutex
		m          map[string]ttlOpt
		wec, rec   chan struct{}
	}
)

func newPacket(wc chan<- *Proto, rc <-chan *Proto) *packet {
	pkt := &packet{
		wc:  wc,
		rc:  rc,
		mu:  &sync.Mutex{},
		m:   make(map[string]ttlOpt),
		wec: make(chan struct{}, 1),
		rec: make(chan struct{}, 1),
	}
	if icmpktDebug || icmpktTrace {
		pkt.lo = logpkg.New(os.Stdout, fmt.Sprintf("[icmp-packet%0-18s] ", ""), logpkg.LstdFlags)
	}
	pkt.run()
	return pkt
}

func (p *packet) debug(format string, arg ...any) {
	if icmpktDebug {
		p.lo.Println(fmt.Sprintf(format, arg...))
	}
}

func (p *packet) trace(format string, arg ...any) {
	if icmpktTrace {
		p.lo.Println(fmt.Sprintf(format, arg...))
	}
}

func (p *packet) listen() {
	p.trace("listen() start")
	defer p.trace("listen() end")
	var err error
	p.packetConn, err = icmp.ListenPacket(listenNetwork, listenAddress)
	if err != nil {
		panic(fmt.Sprintf("listen() listen on[%s:%s] error:%v", listenNetwork, listenAddress, err))
		return
	}
	p.trace("listen() listen on %s:%s", listenNetwork, listenAddress)
}

func (p *packet) run() {
	p.trace("run() start")
	defer p.trace("run() end")
	p.listen()
	p.start()
}

func (p *packet) start() {
	p.trace("start() start")
	defer p.trace("start() end")
	go p.startWrite()
	go p.startRead()
}

func (p *packet) stop() {
	p.trace("stop() start")
	defer p.trace("stop() end")
	p.wec <- struct{}{}
	close(p.wec)
	p.rec <- struct{}{}
	close(p.rec)
	if p.packetConn != nil {
		_ = p.packetConn.Close()
	}
}

func (p *packet) startWrite() {
	p.trace("startWrite() start")
	defer p.trace("startWrite() end")
	for {
		select {
		case <-p.wec:
			return
		case pto, ok := <-p.rc:
			if !ok {
				return
			}
			setTtl := pto.TTL > 0
			if setTtl {
				if err := p.packetConn.IPv4PacketConn().SetTTL(pto.TTL); p.closed(err) {
					return
				}
			}
			_, err := p.packetConn.WriteTo(pto.buf(), pto.Addr)
			if err != nil {
				p.debug("conn<<<<<<-err: %s, %v", pto, err)
				if p.closed(err) {
					return
				}
			} else {
				p.debug("conn<<<<<<-ok: %s", pto)
				p.setTTL(pto.TTL, pto.ID, pto.Seq)
			}
		}
	}
}

func (p *packet) startRead() {
	p.trace("startRead() start")
	defer p.trace("startRead() end")
	buf := make([]byte, 64)
	for {
		select {
		case <-p.rec:
			close(p.wc)
			p.trace("startRead() closed wc")
			return
		default:
			if err := p.packetConn.SetReadDeadline(time.Now().Add(time.Millisecond * 10)); p.closed(err) {
				close(p.wc)
				p.trace("startRead() closed wc")
				return
			}
			n, srcAddr, err := p.packetConn.ReadFrom(buf)
			if p.closed(err) {
				close(p.wc)
				p.trace("startRead() closed wc")
				return
			}
			if n > 0 && srcAddr != nil {
				buf2 := buf[:n]
				if msg, _ := icmp.ParseMessage(1, buf2); msg != nil {
					if pto := p.messageRead(msg, srcAddr); pto != nil {
						p.debug("conn->>>>>>ok: %s", pto.String())
						p.wc <- pto
					}
				}
			}
		}
	}
}

func (p *packet) messageRead(msg *icmp.Message, srcAddr net.Addr) (pto *Proto) {
	parseEcho := func(ec *icmp.Echo) (pto *Proto) {
		if ec != nil && ec.ID > 0 {
			if ttl, rtt := p.getTTL(ec); rtt > 0 {
				pto = pongProto(ttl, ec.ID, ec.Seq, srcAddr, aip4(srcAddr), rtt)
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
	defer p.mu.Unlock()
	k := fmt.Sprintf("%d-%d", id, seq)
	now := time.Now().UnixMilli()
	p.m[k] = ttlOpt{ttl, now}
}

func (p *packet) getTTL(ec *icmp.Echo) (ttl int, rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := fmt.Sprintf("%d-%d", ec.ID, ec.Seq)
	opt, ok := p.m[k]
	if !ok {
		return
	}
	delete(p.m, k)
	now := time.Now().UnixMilli()
	ms := now - opt.unix
	if ms == 0 {
		ms = 1
	}
	return opt.ttl, time.Duration(ms) * time.Millisecond
}

func (p *packet) closed(err error) (closed bool) {
	return err != nil && strings.HasSuffix(err.Error(), "use of closed network connection")
}
