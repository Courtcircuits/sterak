package turn

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// peerListener is a UDP socket standing in for the TURN peer. A session
// registers the payload it is about to send with expect and then waits for it
// to come out of the relay, byte for byte. Payloads are random per session, so
// concurrent sessions are told apart by content.
type peerListener struct {
	pc net.PacketConn

	mu         sync.Mutex
	waiting    map[string][]chan time.Time // payload -> waiters, FIFO
	unmatched  int                         // datagrams nobody was waiting for
	lastLen    int
	lastSource net.Addr
}

func newPeerListener(addr string) (*peerListener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen as TURN peer on %q: %w", addr, err)
	}
	p := &peerListener{pc: pc, waiting: map[string][]chan time.Time{}}
	go p.serve()
	return p, nil
}

func (p *peerListener) Addr() *net.UDPAddr { return p.pc.LocalAddr().(*net.UDPAddr) }

func (p *peerListener) Close() error { return p.pc.Close() }

func (p *peerListener) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := p.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		p.deliver(buf[:n], from, time.Now())
	}
}

func (p *peerListener) deliver(b []byte, from net.Addr, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := string(b)
	if ws := p.waiting[key]; len(ws) > 0 {
		ws[0] <- at // buffered(1), one send per waiter
		p.waiting[key] = ws[1:]
		if len(ws) == 1 {
			delete(p.waiting, key)
		}
		return
	}
	p.unmatched++
	p.lastLen, p.lastSource = len(b), from
}

// expectation is one registered payload awaiting arrival.
type expectation struct {
	p   *peerListener
	key string
	ch  chan time.Time
}

// expect must be called before the payload is sent, or a fast relay can win
// the race.
func (p *peerListener) expect(payload []byte) *expectation {
	e := &expectation{p: p, key: string(payload), ch: make(chan time.Time, 1)}
	p.mu.Lock()
	p.waiting[e.key] = append(p.waiting[e.key], e.ch)
	p.mu.Unlock()
	return e
}

// cancel unregisters the expectation (no-op once it has been delivered).
func (e *expectation) cancel() {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	ws := e.p.waiting[e.key]
	for i, ch := range ws {
		if ch == e.ch {
			ws = append(ws[:i:i], ws[i+1:]...)
			break
		}
	}
	if len(ws) == 0 {
		delete(e.p.waiting, e.key)
	} else {
		e.p.waiting[e.key] = ws
	}
}

// wait returns the arrival time of the payload, or an error naming what the
// listener saw instead when it does not arrive within timeout.
func (e *expectation) wait(timeout time.Duration) (time.Time, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case at := <-e.ch:
		return at, nil
	case <-t.C:
	}
	e.cancel()
	select { // delivered between the timeout and cancel
	case at := <-e.ch:
		return at, nil
	default:
	}

	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	if e.p.unmatched > 0 {
		return time.Time{}, fmt.Errorf("peer did not receive the payload within %s (%d other datagram(s) arrived, last %d bytes from %s)",
			timeout, e.p.unmatched, e.p.lastLen, e.p.lastSource)
	}
	return time.Time{}, fmt.Errorf("peer received nothing within %s", timeout)
}
