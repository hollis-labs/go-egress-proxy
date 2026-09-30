package egress_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/hollis-labs/go-egress-proxy/egress"
)

// ExampleResolveAndPin shows the pinning contract: validate every address
// the resolver returns, then dial the returned literal.
func ExampleResolveAndPin() {
	resolver := func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "api.example.com":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		default: // a hostname an attacker points at cloud metadata
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
	}

	ip, err := egress.ResolveAndPin(context.Background(), resolver, "api.example.com", false)
	fmt.Println(ip, err)

	_, err = egress.ResolveAndPin(context.Background(), resolver, "metadata.attacker.example", false)
	fmt.Println(errors.Is(err, egress.ErrSSRFBlocked))
	// Output:
	// 203.0.113.10 <nil>
	// true
}

// ExampleGuard_DialContext plugs a Guard into an http.Transport. Leave
// Transport.Proxy nil so the guard sees the origin, and reuse the same client
// for redirects so every hop is re-validated.
func ExampleGuard_DialContext() {
	g := &egress.Guard{
		// Resolver, Dialer and DialTimeout are optional; the zero Guard uses
		// the system resolver and a 10 second dial timeout.
		Resolver: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		},
	}
	client := &http.Client{Transport: &http.Transport{DialContext: g.DialContext}}

	_, err := client.Get("http://metadata.attacker.example/latest/meta-data/")
	fmt.Println(errors.Is(err, egress.ErrSSRFBlocked))
	// Output:
	// true
}

func ExampleIsLocalhostName() {
	fmt.Println(egress.IsLocalhostName("LocalHost."), egress.IsLocalhostName("app.localhost"), egress.IsLocalhostName("localhost.example"))
	// Output:
	// true true false
}

func ExampleDefaultResolver() {
	// An IP literal resolves to itself without a DNS query.
	ips, err := egress.DefaultResolver(context.Background(), "203.0.113.10")
	fmt.Println(ips, err)
	// Output:
	// [203.0.113.10] <nil>
}
