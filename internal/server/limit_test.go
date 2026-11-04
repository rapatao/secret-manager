package server

import (
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for range loginFreeFailures {
		l.fail("a", now)
	}
	if w := l.wait("a", now); w != 0 {
		t.Fatalf("wait after free failures = %s", w)
	}
	l.fail("a", now)
	if w := l.wait("a", now); w != time.Second {
		t.Fatalf("wait after one more failure = %s", w)
	}
	l.fail("a", now)
	if w := l.wait("a", now); w != 2*time.Second {
		t.Fatalf("wait doubles: %s", w)
	}
	for range 20 {
		l.fail("a", now)
	}
	if w := l.wait("a", now); w != loginMaxWait {
		t.Fatalf("wait capped: %s", w)
	}
	if w := l.wait("b", now); w != 0 {
		t.Fatalf("other client waits %s", w)
	}
	if w := l.wait("a", now.Add(loginMaxWait)); w != 0 {
		t.Fatalf("wait after it passed = %s", w)
	}
	l.succeed("a")
	l.fail("a", now)
	if w := l.wait("a", now); w != 0 {
		t.Fatalf("success did not reset: %s", w)
	}
	l.fail("b", now.Add(loginForget+time.Second))
	if _, ok := l.clients["a"]; ok {
		t.Fatal("old failures not forgotten")
	}
}
