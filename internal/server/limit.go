package server

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// loginFreeFailures is the number of failed sign-ins a client can make
	// before it has to wait.
	loginFreeFailures = 5
	loginMaxWait      = time.Minute
	// loginForget drops a client's failures after this long without one.
	loginForget = 15 * time.Minute
)

// loginLimiter delays sign-ins from a client address after repeated failures:
// each failure past loginFreeFailures doubles the wait, from 1s up to
// loginMaxWait. Without trusted proxies, clients behind one proxy share an
// address, so the wait stays short.
// IPv6 clients are counted by their /64 prefix, since one host can use any
// address of its prefix. ponytail: in memory and per replica, pruned at most
// once per loginPrune; fine for the single-replica server.
type loginLimiter struct {
	mu      sync.Mutex
	clients map[string]*loginFailures
	pruned  time.Time
}

// loginPrune is the least time between two prunings of forgotten clients.
const loginPrune = time.Minute

// limitKey returns the key a client address is counted under: an IPv4 address
// as is, an IPv6 address as its /64 prefix.
func limitKey(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	a = a.Unmap()
	if !a.Is6() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

type loginFailures struct {
	count int
	last  time.Time
	until time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{clients: map[string]*loginFailures{}}
}

// wait returns how long the client must wait before its next sign-in.
func (l *loginLimiter) wait(addr string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.clients[limitKey(addr)]; ok && now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

func (l *loginLimiter) fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.pruned) >= loginPrune {
		for a, f := range l.clients {
			if now.Sub(f.last) > loginForget {
				delete(l.clients, a)
			}
		}
		l.pruned = now
	}
	addr = limitKey(addr)
	f, ok := l.clients[addr]
	if !ok {
		f = &loginFailures{}
		l.clients[addr] = f
	}
	f.count++
	f.last = now
	if over := f.count - loginFreeFailures; over > 0 {
		f.until = now.Add(min(time.Second<<min(over-1, 10), loginMaxWait))
	}
}

func (l *loginLimiter) succeed(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, limitKey(addr))
}
