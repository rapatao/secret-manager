package server

import (
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
// ponytail: in memory and per replica, pruned on each failure; fine for the
// single-replica server.
type loginLimiter struct {
	mu      sync.Mutex
	clients map[string]*loginFailures
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
	if f, ok := l.clients[addr]; ok && now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

func (l *loginLimiter) fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for a, f := range l.clients {
		if now.Sub(f.last) > loginForget {
			delete(l.clients, a)
		}
	}
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
	delete(l.clients, addr)
}
