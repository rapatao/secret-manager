package server

import (
	"net/http"
	"testing"
)

func TestClientAddr(t *testing.T) {
	proxies, err := ParsePrefixes("10.42.0.0/16, 192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{TrustedProxies: proxies}
	cases := []struct {
		name, remote string
		forwarded    []string
		want         string
	}{
		{"direct client", "203.0.113.9:1234", nil, "203.0.113.9"},
		{"untrusted sender ignores header", "203.0.113.9:1234", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted proxy", "10.42.0.23:5000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client entry on the left is ignored", "10.42.0.23:5000", []string{"1.2.3.4, 198.51.100.7"}, "198.51.100.7"},
		{"header lines are joined in order", "10.42.0.23:5000", []string{"1.2.3.4", "198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies", "10.42.0.23:5000", []string{"198.51.100.7, 192.168.1.5"}, "198.51.100.7"},
		{"entries with ports", "10.42.0.23:5000", []string{"198.51.100.7:4444"}, "198.51.100.7"},
		{"ipv6", "10.42.0.23:5000", []string{"[2001:db8::1]:4444"}, "2001:db8::1"},
		{"garbage stops at the last good hop", "10.42.0.23:5000", []string{"198.51.100.7, nonsense, 192.168.1.5"}, "192.168.1.5"},
		{"trusted proxy without header", "10.42.0.23:5000", nil, "10.42.0.23"},
		{"only trusted hops", "10.42.0.23:5000", []string{"10.42.0.1"}, "10.42.0.1"},
	}
	for _, tc := range cases {
		r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{"X-Forwarded-For": tc.forwarded}}
		if got := s.clientAddr(r); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
	if got := (&Server{}).clientAddr(&http.Request{RemoteAddr: "10.42.0.23:5000", Header: http.Header{"X-Forwarded-For": {"1.2.3.4"}}}); got != "10.42.0.23" {
		t.Errorf("without trusted proxies: got %s", got)
	}
	for _, bad := range []string{"10.42.0.0/99", "not-an-ip"} {
		if _, err := ParsePrefixes(bad); err == nil {
			t.Errorf("ParsePrefixes(%q) accepted", bad)
		}
	}
}
