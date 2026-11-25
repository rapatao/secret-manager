package server

import (
	"testing"
	"time"
)

func TestLimitKey(t *testing.T) {
	for _, c := range [][2]string{
		{"192.0.2.1", "192.0.2.1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"not-an-address", "not-an-address"},
	} {
		if got := limitKey(c[0]); got != c[1] {
			t.Errorf("limitKey(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestLoginLimiterIPv6Prefix(t *testing.T) {
	l := newLoginLimiter()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for range loginFreeFailures + 1 {
		l.fail("2001:db8:1:2::1", now)
	}
	if w := l.wait("2001:db8:1:2:ffff::9", now); w != time.Second {
		t.Fatalf("same /64 does not share the wait: %s", w)
	}
	if w := l.wait("2001:db8:1:3::1", now); w != 0 {
		t.Fatalf("another /64 waits %s", w)
	}
	l.succeed("2001:db8:1:2::77")
	if w := l.wait("2001:db8:1:2::1", now); w != 0 {
		t.Fatalf("success did not reset the prefix: %s", w)
	}
}

func TestLoginLimiterPrunesOncePerInterval(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	l.fail("a", t0)
	l.fail("b", t0.Add(loginForget))
	l.fail("c", t0.Add(loginForget+loginPrune/2))
	if _, ok := l.clients["a"]; !ok {
		t.Fatal("pruned again before the interval passed")
	}
	l.fail("d", t0.Add(loginForget+loginPrune))
	if _, ok := l.clients["a"]; ok {
		t.Fatal("forgotten client kept after the interval")
	}
}

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
