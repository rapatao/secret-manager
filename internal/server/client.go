package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of CIDRs or single
// addresses.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (s *Server) trusted(addr netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseHop parses an address from RemoteAddr or X-Forwarded-For, with or
// without a port.
func parseHop(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap(), true
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = host
	}
	addr, err := netip.ParseAddr(strings.Trim(v, "[]"))
	return addr.Unmap(), err == nil
}

// clientAddr returns the address of the client that sent r. When the
// connection comes from a trusted proxy, it is the rightmost X-Forwarded-For
// entry that is not a trusted proxy: entries further left were written by
// the client and are ignored.
func (s *Server) clientAddr(r *http.Request) string {
	remote, ok := parseHop(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	client := remote
	if s.trusted(remote) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, ok := parseHop(hops[i])
			if !ok {
				break
			}
			client = hop
			if !s.trusted(hop) {
				break
			}
		}
	}
	return client.String()
}
