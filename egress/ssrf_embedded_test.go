package egress

import (
	"context"
	"errors"
	"testing"
)

// IPv6 transition forms carry an IPv4 the sender picks (CW-20261001-0077,
// the lib half of CW-20260930-0028; reference: Nanite internal/ssrf
// embeddedIPv4s, nanite#357). The IPv4 is read out and judged by the IPv4
// deny set, so a denied IPv4 cannot ride an IPv6 answer past it, and a public
// one (DNS64 egress) is not refused for its wrapping.
func TestResolveAndPin_JudgesEmbeddedIPv4(t *testing.T) {
	cases := []struct {
		form, addr string
		denied     bool
	}{
		// NAT64 well-known prefix (RFC 6052): IPv4 in the last 32 bits.
		{"nat64 imds", "64:ff9b::a9fe:a9fe", true},
		{"nat64 rfc1918", "64:ff9b::a00:1", true},
		{"nat64 public (DNS64 egress)", "64:ff9b::808:808", false},
		{"nat64 public dotted", "64:ff9b::1.1.1.1", false},
		// 6to4 (RFC 3056): IPv4 in bits 16-47.
		{"6to4 imds", "2002:a9fe:a9fe::1", true},
		{"6to4 loopback", "2002:7f00:1::1", true},
		{"6to4 rfc1918", "2002:c0a8:101::1", true},
		{"6to4 public", "2002:808:808::1", false},
		// Teredo (RFC 4380): server IPv4 in bits 32-63, client IPv4
		// XORed with 0xffffffff in the last 32 bits.
		{"teredo server imds", "2001:0:a9fe:a9fe::fefe:fefe", true},
		{"teredo client rfc1918 (10.0.0.1)", "2001:0:808:808::f5ff:fffe", true},
		{"teredo client imds (169.254.169.254)", "2001:0:808:808::5601:5601", true},
		{"teredo public server and client (1.1.1.1)", "2001:0:808:808::fefe:fefe", false},
		// IPv4-compatible (RFC 4291, deprecated): IPv4 in the last 32 bits.
		{"ipv4-compatible imds", "::169.254.169.254", true},
		{"ipv4-compatible public", "::8.8.8.8", false},
		// IPv4-mapped: compared as IPv4.
		{"ipv4-mapped imds", "::ffff:169.254.169.254", true},
		{"ipv4-mapped public", "::ffff:8.8.8.8", false},
	}
	for _, c := range cases {
		t.Run(c.form, func(t *testing.T) {
			_, err := ResolveAndPin(context.Background(), stubResolver(c.addr), "v6.example", false)
			if c.denied && !errors.Is(err, ErrSSRFBlocked) {
				t.Errorf("ResolveAndPin(%s) = %v, want ErrSSRFBlocked", c.addr, err)
			}
			if !c.denied && err != nil {
				t.Errorf("ResolveAndPin(%s) = %v, want allowed", c.addr, err)
			}
		})
	}
}

// AllowLocalhost permits this host's loopback, not a loopback address
// reached through a translator or tunnel: embedded loopback stays denied.
func TestResolveAndPin_EmbeddedLoopbackDeniedEvenWithAllowLocalhost(t *testing.T) {
	for _, addr := range []string{"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:7f00:1::fefe:fefe", "::127.0.0.1"} {
		if _, err := ResolveAndPin(context.Background(), stubResolver(addr), "v6.example", true); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ResolveAndPin(%s, allowLocalhost) = %v, want ErrSSRFBlocked", addr, err)
		}
	}
	// :: and ::1 are IPv6 unspecified and loopback, not IPv4-compatible
	// 0.0.0.0 and 0.0.0.1: ::1 follows AllowLocalhost.
	if _, err := ResolveAndPin(context.Background(), stubResolver("::1"), "localhost6.example", true); err != nil {
		t.Errorf("::1 with AllowLocalhost = %v, want allowed", err)
	}
	if _, err := ResolveAndPin(context.Background(), stubResolver("::"), "x.example", true); !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf(":: = %v, want ErrSSRFBlocked", err)
	}
}

// Special-purpose ranges the deny set was missing, and their neighbors.
func TestResolveAndPin_SpecialPurposeRanges(t *testing.T) {
	for _, addr := range []string{
		"255.255.255.255", // limited broadcast
		"240.0.0.1",       // reserved 240/4
		"250.1.2.3",
		"198.18.0.1", // benchmarking 198.18/15
		"198.19.255.254",
		"192.0.0.1",   // IETF protocol assignments 192.0.0/24
		"192.0.0.170", // NAT64 discovery
		"192.88.99.1", // 6to4 relay anycast
		"fec0::1",     // deprecated site-local fec0::/10
		"feff::1",
		"64:ff9b:1::808:808", // NAT64 local-use prefix: still denied whole
	} {
		if _, err := ResolveAndPin(context.Background(), stubResolver(addr), "x.example", false); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ResolveAndPin(%s) = %v, want ErrSSRFBlocked", addr, err)
		}
	}
	for _, addr := range []string{"198.17.255.254", "198.20.0.1", "192.0.1.1", "239.255.255.254", "fe7f::1"} {
		if _, err := ResolveAndPin(context.Background(), stubResolver(addr), "x.example", false); err != nil {
			t.Errorf("ResolveAndPin(%s) = %v, want allowed", addr, err)
		}
	}
}
