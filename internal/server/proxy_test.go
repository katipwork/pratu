package server

import (
	"net/http"
	"testing"
)

func req(remote, xff, proto string) *http.Request {
	r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if proto != "" {
		r.Header.Set("X-Forwarded-Proto", proto)
	}
	return r
}

func TestClientIP(t *testing.T) {
	proxies, err := ParseProxies([]string{"10.0.0.0/8", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		proxies bool
		remote  string
		xff     string
		want    string
	}{
		{"no proxies configured: spoof ignored", false, "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"untrusted source: spoof ignored", true, "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"trusted proxy: forwarded honored", true, "10.1.2.3:1234", "198.51.100.7", "198.51.100.7"},
		{"multi-hop: rightmost untrusted wins", true, "10.1.2.3:1234", "1.2.3.4, 198.51.100.7, 10.9.9.9", "198.51.100.7"},
		{"client-supplied prefix not trusted", true, "10.1.2.3:1234", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"all hops trusted: leftmost origin", true, "10.1.2.3:1234", "10.5.5.5", "10.5.5.5"},
		{"empty header from proxy", true, "10.1.2.3:1234", "", "10.1.2.3"},
		{"malformed header: hard fallback", true, "10.1.2.3:1234", "geo{spoof}", "10.1.2.3"},
		{"ipv6 loopback proxy", true, "[::1]:1234", "198.51.100.7", "198.51.100.7"},
	}
	for _, c := range cases {
		if c.proxies {
			SetTrustedProxies(proxies)
		} else {
			SetTrustedProxies(nil)
		}
		if got := clientIP(req(c.remote, c.xff, "")); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
	SetTrustedProxies(nil)
}

func TestRequestSecure(t *testing.T) {
	proxies, _ := ParseProxies([]string{"10.0.0.0/8"})
	SetTrustedProxies(proxies)
	defer SetTrustedProxies(nil)

	if !requestSecure(req("10.1.2.3:1234", "", "https")) {
		t.Error("trusted proxy asserting https must count as secure")
	}
	if requestSecure(req("203.0.113.9:1234", "", "https")) {
		t.Error("untrusted source asserting https must not count as secure")
	}
	if requestSecure(req("10.1.2.3:1234", "", "")) {
		t.Error("no TLS and no assertion is not secure")
	}
}

func TestParseProxiesRejectsGarbage(t *testing.T) {
	if _, err := ParseProxies([]string{"not-a-cidr"}); err == nil {
		t.Error("expected error for invalid spec")
	}
}
