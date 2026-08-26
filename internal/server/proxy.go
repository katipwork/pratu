package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Forwarded headers are honored only when the request physically comes
// from a configured trusted proxy — otherwise anyone could spoof their
// way past per-IP rate limits or fake session device metadata.
var trustedProxies []netip.Prefix

// SetTrustedProxies installs the trusted proxy ranges; called once at
// startup.
func SetTrustedProxies(prefixes []netip.Prefix) {
	trustedProxies = prefixes
}

// ParseProxies parses CIDR ranges (bare IPs mean a single address).
func ParseProxies(specs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func isTrusted(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func fromTrustedProxy(r *http.Request) bool {
	return len(trustedProxies) > 0 && isTrusted(remoteIP(r))
}

// clientIP keys per-IP limits and session device metadata. When the
// request arrives via a trusted proxy, X-Forwarded-For is walked right
// to left past trusted hops: the first untrusted address is the client.
// Otherwise forwarded headers are ignored entirely.
func clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if !fromTrustedProxy(r) {
		return remote
	}
	var hops []string
	for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
		if part = strings.TrimSpace(part); part != "" {
			hops = append(hops, part)
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if _, err := netip.ParseAddr(hops[i]); err != nil {
			return remote // malformed header: fall back hard
		}
		if !isTrusted(hops[i]) {
			return hops[i]
		}
	}
	if len(hops) > 0 {
		return hops[0] // every hop trusted: the leftmost is the origin
	}
	return remote
}

// requestSecure reports whether the client connection is HTTPS, either
// directly or as asserted by a trusted proxy that terminated TLS.
func requestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return fromTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
