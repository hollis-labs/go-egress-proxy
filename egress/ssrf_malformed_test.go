package egress

import (
	"context"
	"errors"
	"net"
	"testing"
)

// A resolver answer holding a nil or wrong-length net.IP cannot be
// range-checked. The whole answer must be refused with ErrSSRFBlocked, never
// returned and never turned into a dial string like "<nil>:80".

func malformedIPs() map[string]net.IP {
	return map[string]net.IP{
		"nil":      nil,
		"empty":    {},
		"1-byte":   {1},
		"3-bytes":  {1, 2, 3},
		"5-bytes":  {1, 2, 3, 4, 5},
		"15-bytes": make(net.IP, 15),
		"17-bytes": make(net.IP, 17),
		"20-bytes": make(net.IP, 20),
	}
}

func TestResolveAndPin_MalformedIPFailsClosed(t *testing.T) {
	pub := net.ParseIP("203.0.113.10")
	for name, bad := range malformedIPs() {
		answers := map[string][]net.IP{
			"alone":       {bad},
			"bad-then-ok": {bad, pub},
			"ok-then-bad": {pub, bad},
			"ok-bad-ok":   {pub, bad, pub},
		}
		for shape, ips := range answers {
			t.Run(name+"/"+shape, func(t *testing.T) {
				r := func(context.Context, string) ([]net.IP, error) { return ips, nil }
				for _, allowLocalhost := range []bool{false, true} {
					ip, err := ResolveAndPin(context.Background(), r, "x.example", allowLocalhost)
					if !errors.Is(err, ErrSSRFBlocked) {
						t.Fatalf("error = %v (ip %v), want ErrSSRFBlocked", err, ip)
					}
					if ip != nil {
						t.Fatalf("returned ip %v alongside an error", ip)
					}
				}
			})
		}
	}
}

func TestResolveAndPin_EmptyAnswerListUnchanged(t *testing.T) {
	for _, ips := range [][]net.IP{nil, {}} {
		r := func(context.Context, string) ([]net.IP, error) { return ips, nil }
		if _, err := ResolveAndPin(context.Background(), r, "x.example", false); !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("empty answer error = %v, want ErrSSRFBlocked", err)
		}
	}
}

func TestResolveAndPin_WellFormedLengthsStillAccepted(t *testing.T) {
	for _, ip := range []net.IP{net.IPv4(203, 0, 113, 10), net.IPv4(203, 0, 113, 10).To4(), net.ParseIP("2606:4700::1111")} {
		r := func(context.Context, string) ([]net.IP, error) { return []net.IP{ip}, nil }
		if _, err := ResolveAndPin(context.Background(), r, "x.example", false); err != nil {
			t.Errorf("ResolveAndPin(%v) = %v, want allowed", ip, err)
		}
	}
}

func TestGuard_DialContext_MalformedIPNeverDials(t *testing.T) {
	pub := net.ParseIP("203.0.113.10")
	for name, bad := range malformedIPs() {
		t.Run(name, func(t *testing.T) {
			for _, ips := range [][]net.IP{{bad}, {bad, pub}, {pub, bad}} {
				rd := &recordingDialer{}
				g := &Guard{Resolver: func(context.Context, string) ([]net.IP, error) { return ips, nil }, Dialer: rd.dial}
				if _, err := g.DialContext(context.Background(), "tcp", "x.example:80"); !errors.Is(err, ErrSSRFBlocked) {
					t.Fatalf("error = %v, want ErrSSRFBlocked", err)
				}
				if len(rd.got()) != 0 {
					t.Fatalf("dialer invoked: %v", rd.got())
				}
			}
		})
	}
}

func TestProxy_resolveAndPin_MalformedIPFailsClosed(t *testing.T) {
	pub := net.ParseIP("203.0.113.10")
	for name, bad := range malformedIPs() {
		t.Run(name, func(t *testing.T) {
			p := New(Config{Resolver: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{pub, bad}, nil
			}})
			if _, err := p.resolveAndPin(context.Background(), "x.example"); !errors.Is(err, ErrSSRFBlocked) {
				t.Fatalf("error = %v, want ErrSSRFBlocked", err)
			}
		})
	}
}
