package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// NAT64 (RFC 6052 / RFC 8215) synthesizes IPv6 addresses that embed an IPv4
// address in the low 32 bits. net.IP.To4 does not unwrap them, so before the
// prefixes were added to the deny set these all passed.

func TestResolveAndPin_BlocksNAT64SynthesizedIMDS(t *testing.T) {
	for name, raw := range map[string]string{
		"wkp-imds":              "64:ff9b::a9fe:a9fe",
		"wkp-imds-dotted":       "64:ff9b::169.254.169.254",
		"wkp-rfc1918":           "64:ff9b::a00:1",
		"wkp-loopback":          "64:ff9b::7f00:1",
		"wkp-cgnat-alibaba":     "64:ff9b::6464:64c8",
		"wkp-unspecified-embed": "64:ff9b::",
		"localuse-imds":         "64:ff9b:1::a9fe:a9fe",
		"localuse-high-bits":    "64:ff9b:1:ffff:ffff:ffff:a9fe:a9fe",
	} {
		t.Run(name, func(t *testing.T) {
			for _, allowLocalhost := range []bool{false, true} {
				_, err := ResolveAndPin(context.Background(), stubResolver(raw), "dns64.example", allowLocalhost)
				if !errors.Is(err, ErrSSRFBlocked) {
					t.Errorf("ResolveAndPin(%s, allowLocalhost=%v) error = %v, want ErrSSRFBlocked", raw, allowLocalhost, err)
				}
			}
		})
	}
}

func TestResolveAndPin_NAT64PrefixBoundaries(t *testing.T) {
	// Neighboring prefixes are not NAT64 and must stay reachable.
	for _, raw := range []string{"64:ff9a::a9fe:a9fe", "64:ff9c::1", "64:ff9b:2::1", "64:ff9b:0:1::1"} {
		if _, err := ResolveAndPin(context.Background(), stubResolver(raw), "x.example", false); err != nil {
			t.Errorf("ResolveAndPin(%s) = %v, want allowed", raw, err)
		}
	}
}

func TestGuard_DialContext_BlocksNAT64SynthesizedIMDS(t *testing.T) {
	rd := &recordingDialer{}
	g := &Guard{Resolver: stubResolver("64:ff9b::a9fe:a9fe"), Dialer: rd.dial}
	if _, err := g.DialContext(context.Background(), "tcp", "dns64.attacker.example:80"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("error = %v, want ErrSSRFBlocked", err)
	}
	if len(rd.got()) != 0 {
		t.Fatalf("dialer invoked: %v", rd.got())
	}
}

func TestProxy_CONNECT_BlocksNAT64SynthesizedIMDS(t *testing.T) {
	var denyReason atomic.Value
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"meta.example.com"},
		Resolver:       stubResolver("64:ff9b::a9fe:a9fe"),
		OnDeny:         func(_, reason string) { denyReason.Store(reason) },
	})
	conn, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT meta.example.com:443 HTTP/1.1\r\nHost: meta.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got, _ := denyReason.Load().(string); got != "ssrf" {
		t.Errorf("OnDeny reason = %q, want ssrf", got)
	}
}
