package egress

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultResolver resolves host with the system resolver
// (net.DefaultResolver.LookupIP) and returns every address in the answer.
// It is what ResolveAndPin and Guard use when their Resolver is nil.
//
// Encoded IPv4 spellings ("2852039166", "0251.0376.0251.0376",
// "0xa9fea9fe") are not IP literals to Go's parser, so they reach the
// resolver as hostnames. Whether they then resolve depends on the platform
// resolver: the pure-Go resolver treats them as unknown names, while a
// libc-backed lookup (observed on macOS) may return the address they encode
// (169.254.169.254 for all three). Either way ResolveAndPin is safe, because
// it validates the addresses the resolver returns rather than the host
// string. A caller that rewrites or normalizes the host string itself must
// still route the result through ResolveAndPin.
func DefaultResolver(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// IsLocalhostName reports whether host is "localhost" or a subdomain of
// ".localhost" (RFC 6761). The match is case-insensitive and ignores a
// single trailing dot.
func IsLocalhostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// ResolveAndPin resolves host with resolver (DefaultResolver when nil),
// rejects the ENTIRE answer if any returned address is in the SSRF deny set
// (or in the loopback ranges, unless allowLocalhost is true), and returns
// the first validated address. Rejections wrap ErrSSRFBlocked; resolver
// errors are returned as-is.
//
// Callers MUST dial the returned IP literal, never host again. Dialing the
// literal is what pins the DNS answer that was checked and closes the
// DNS-rebinding window. Using ResolveAndPin as a pre-flight check and then
// dialing by hostname elsewhere reopens that window; for that reason this
// package deliberately offers no check-only "is this URL safe" helper. Most
// callers should use Guard, which does the pinning for them.
//
// An answer that contains a nil net.IP, or one whose length is not 4 or 16
// bytes, is rejected whole with ErrSSRFBlocked, like a denied address: the
// result is either a valid, checked address or an error.
//
// host must be a bare host, without port or brackets. The deny set is
// applied to the addresses the resolver returns (IPv4-mapped IPv6 forms are
// compared as their IPv4 value); see DefaultResolver for how encoded
// literals are treated.
func ResolveAndPin(ctx context.Context, resolver Resolver, host string, allowLocalhost bool) (net.IP, error) {
	if !allowLocalhost && IsLocalhostName(host) {
		return nil, fmt.Errorf("%w: localhost name %q", ErrSSRFBlocked, host)
	}
	if resolver == nil {
		resolver = DefaultResolver
	}
	ips, err := resolver(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IPs for %q", ErrSSRFBlocked, host)
	}
	// A nil or wrong-length net.IP cannot be range-checked and would dial as
	// the string "<nil>" or similar. Reject the whole answer, as for a
	// denied address, before any other check.
	for _, ip := range ips {
		if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
			return nil, fmt.Errorf("%w: malformed IP (%d bytes) in answer for %q", ErrSSRFBlocked, len(ip), host)
		}
	}
	for _, ip := range ips {
		if !allowLocalhost {
			for _, block := range builtinLoopbackCIDRs {
				if block.Contains(ip) {
					return nil, fmt.Errorf("%w: loopback %s", ErrSSRFBlocked, ip)
				}
			}
		}
		for _, block := range builtinDeniedCIDRs {
			if block.Contains(ip) {
				return nil, fmt.Errorf("%w: %s in %s", ErrSSRFBlocked, ip, block)
			}
		}
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("%w: unspecified %s", ErrSSRFBlocked, ip)
		}
	}
	return ips[0], nil
}

// Guard is an SSRF-safe dial policy for a caller's own outbound HTTP
// client, with no Proxy involved. The zero value is ready to use: system
// resolver, a net.Dialer with a 10 second timeout, loopback denied.
//
// A Guard is safe for concurrent use as long as its fields are not modified
// after first use.
type Guard struct {
	// Resolver resolves target hostnames. Nil uses DefaultResolver.
	Resolver Resolver

	// Dialer dials the validated IP literal. Nil uses a net.Dialer with
	// DialTimeout.
	Dialer Dialer

	// AllowLocalhost permits 127.0.0.0/8, ::1 and localhost names. It does
	// not open any other range of the deny set.
	AllowLocalhost bool

	// DialTimeout caps a dial made with the default Dialer. Zero uses 10
	// seconds. It is ignored when Dialer is set.
	DialTimeout time.Duration
}

// DialContext has the signature of http.Transport.DialContext. It splits
// addr, validates the host with ResolveAndPin, and dials the validated IP
// literal joined with the original port. A blocked destination returns an
// error wrapping ErrSSRFBlocked.
//
//	g := &egress.Guard{}
//	client := &http.Client{Transport: &http.Transport{DialContext: g.DialContext}}
//
// Redirects are re-validated only because http.Client sends the redirected
// request through the same Transport, and therefore through this
// DialContext again. Do not build a second http.Transport, or call net.Dial,
// from a CheckRedirect handler or anywhere else that handles the redirected
// request: that path bypasses the guard entirely.
//
// Two limits to be aware of. First, an http.Transport that has a Proxy
// configured (including the ProxyFromEnvironment default of
// http.DefaultTransport) dials the proxy, not the origin, through
// DialContext, so the origin is never checked; leave Transport.Proxy nil
// when the guard is meant to protect the origin. Second, a Transport with
// DialTLSContext set does not use DialContext for HTTPS.
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		// net.Dialer treats an empty host as the local machine.
		return nil, fmt.Errorf("%w: empty host in %q", ErrSSRFBlocked, addr)
	}
	pinned, err := ResolveAndPin(ctx, g.Resolver, host, g.AllowLocalhost)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(pinned.String(), port)
	if g.Dialer != nil {
		return g.Dialer(ctx, network, target)
	}
	timeout := g.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, target)
}
