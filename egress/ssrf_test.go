package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// literalResolver resolves any host that is an IP literal to itself and
// fails everything else, so tests never touch real DNS.
func literalResolver(_ context.Context, host string) ([]net.IP, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("test resolver: not an IP literal: " + host)
	}
	return []net.IP{ip}, nil
}

func TestResolveAndPin_RejectsAnyDeniedDNSAnswer(t *testing.T) {
	_, err := ResolveAndPin(context.Background(), stubResolver("203.0.113.10", "169.254.169.254"), "catalog.example", false)
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("mixed answer error = %v, want ErrSSRFBlocked", err)
	}
	// Order must not matter.
	_, err = ResolveAndPin(context.Background(), stubResolver("169.254.169.254", "203.0.113.10"), "catalog.example", false)
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("mixed answer (denied first) error = %v, want ErrSSRFBlocked", err)
	}
}

func TestResolveAndPin_RejectsDeniedRanges(t *testing.T) {
	tests := map[string]string{
		"rfc1918-10":       "10.1.2.3",
		"rfc1918-172":      "172.16.1.2",
		"rfc1918-172-top":  "172.31.255.255",
		"rfc1918-192":      "192.168.1.2",
		"ipv4-loopback":    "127.0.0.2",
		"ipv6-loopback":    "::1",
		"imds-link-local":  "169.254.169.254",
		"ipv6-link-local":  "fe80::1",
		"cgnat":            "100.64.0.1",
		"alibaba-metadata": "100.100.100.200",
		"ipv6-ula":         "fd00::1",
		"aws-imds-ipv6":    "fd00:ec2::254",
		"ipv4-unspecified": "0.0.0.0",
		"ipv4-this-net":    "0.1.2.3",
		"ipv6-unspecified": "::",
	}
	for name, rawIP := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ResolveAndPin(context.Background(), stubResolver(rawIP), "catalog.example", false)
			if !errors.Is(err, ErrSSRFBlocked) {
				t.Fatalf("ResolveAndPin(%s) error = %v, want ErrSSRFBlocked", rawIP, err)
			}
		})
	}
}

func TestResolveAndPin_ReturnsValidatedLiteral(t *testing.T) {
	want := net.ParseIP("203.0.113.10")
	got, err := ResolveAndPin(context.Background(), stubResolver("203.0.113.10"), "catalog.example", false)
	if err != nil {
		t.Fatalf("ResolveAndPin: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("ResolveAndPin = %s, want %s", got, want)
	}
}

func TestResolveAndPin_LocalhostOptInDoesNotOpenOtherRanges(t *testing.T) {
	resolver := func(_ context.Context, host string) ([]net.IP, error) {
		if host == "localhost" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("10.0.0.1")}, nil
	}
	if _, err := ResolveAndPin(context.Background(), resolver, "localhost", true); err != nil {
		t.Fatalf("localhost opt-in rejected loopback: %v", err)
	}
	if _, err := ResolveAndPin(context.Background(), resolver, "private.example", true); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("private range with opt-in error = %v, want ErrSSRFBlocked", err)
	}
	// Loopback stays blocked without the opt-in, by name and by address.
	if _, err := ResolveAndPin(context.Background(), resolver, "localhost", false); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("localhost without opt-in error = %v, want ErrSSRFBlocked", err)
	}
	if _, err := ResolveAndPin(context.Background(), stubResolver("127.0.0.1"), "evil.example", false); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("loopback answer without opt-in error = %v, want ErrSSRFBlocked", err)
	}
}

func TestResolveAndPin_EmptyAnswerFailsClosed(t *testing.T) {
	empty := func(context.Context, string) ([]net.IP, error) { return nil, nil }
	if _, err := ResolveAndPin(context.Background(), empty, "x.example", false); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("empty answer error = %v, want ErrSSRFBlocked", err)
	}
}

func TestResolveAndPin_ResolverErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	failing := func(context.Context, string) ([]net.IP, error) { return nil, boom }
	if _, err := ResolveAndPin(context.Background(), failing, "x.example", false); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want resolver error", err)
	}
}

func TestResolveAndPin_BlocksIPv4MappedIMDS(t *testing.T) {
	for _, raw := range []string{"::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:100.100.100.200"} {
		_, err := ResolveAndPin(context.Background(), stubResolver(raw), "x.example", false)
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ResolveAndPin(%s) error = %v, want ErrSSRFBlocked", raw, err)
		}
	}
	// A mapped public address must remain reachable.
	if _, err := ResolveAndPin(context.Background(), stubResolver("::ffff:203.0.113.10"), "x.example", false); err != nil {
		t.Errorf("mapped public address rejected: %v", err)
	}
}

func TestResolveAndPin_BlocksIPv4MappedRawBytes(t *testing.T) {
	// A resolver may hand back a 16-byte slice for an IPv4 address rather
	// than the 4-byte form; both must be caught.
	for _, ip := range []net.IP{
		net.IPv4(169, 254, 169, 254),                                   // 16-byte
		net.IPv4(169, 254, 169, 254).To4(),                             // 4-byte
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254}, // explicit mapped
		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},         // fe80::1
	} {
		r := func(context.Context, string) ([]net.IP, error) { return []net.IP{ip}, nil }
		if _, err := ResolveAndPin(context.Background(), r, "x.example", false); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ResolveAndPin(%v) error = %v, want ErrSSRFBlocked", []byte(ip), err)
		}
	}
}

func TestIsLocalhostName(t *testing.T) {
	yes := []string{"localhost", "LOCALHOST", "Localhost.", "a.localhost", "a.b.LocalHost", "a.localhost."}
	no := []string{"", "localhost.example", "notlocalhost", "xlocalhost", "local.host", "127.0.0.1", "example.com"}
	for _, h := range yes {
		if !IsLocalhostName(h) {
			t.Errorf("IsLocalhostName(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if IsLocalhostName(h) {
			t.Errorf("IsLocalhostName(%q) = true, want false", h)
		}
	}
}

func TestResolveAndPin_LocalhostNameBlockedBeforeResolving(t *testing.T) {
	called := false
	r := func(context.Context, string) ([]net.IP, error) { called = true; return nil, nil }
	for _, h := range []string{"localhost", "LOCALHOST.", "svc.localhost"} {
		if _, err := ResolveAndPin(context.Background(), r, h, false); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ResolveAndPin(%q) error = %v, want ErrSSRFBlocked", h, err)
		}
	}
	if called {
		t.Error("resolver invoked for a localhost name that should be refused up front")
	}
}

// TestResolveAndPin_LiteralHostForms drives the real DefaultResolver with IP
// literals, which the Go resolver answers without any DNS query, to pin
// bracket-free literal handling, zone IDs and trailing dots.
func TestResolveAndPin_LiteralHostForms(t *testing.T) {
	blocked := []string{
		"169.254.169.254",
		"127.0.0.1",
		"::1",
		"fe80::1%en0", // zone ID must not defeat the fe80::/10 check
		"::ffff:169.254.169.254",
		"10.0.0.1",
	}
	for _, h := range blocked {
		if _, err := ResolveAndPin(context.Background(), nil, h, false); err == nil {
			t.Errorf("ResolveAndPin(%q) with DefaultResolver = nil error, want a rejection", h)
		}
	}
	got, err := ResolveAndPin(context.Background(), nil, "203.0.113.10", false)
	if err != nil || !got.Equal(net.ParseIP("203.0.113.10")) {
		t.Errorf("public literal: got %v, %v", got, err)
	}
}

// recordingDialer records dial targets and hands back one end of a pipe.
type recordingDialer struct {
	mu      sync.Mutex
	targets []string
}

func (d *recordingDialer) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, addr)
	d.mu.Unlock()
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func (d *recordingDialer) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

func TestGuard_DialContext_BlocksIMDS(t *testing.T) {
	rd := &recordingDialer{}
	g := &Guard{Resolver: stubResolver("169.254.169.254"), Dialer: rd.dial}
	_, err := g.DialContext(context.Background(), "tcp", "metadata.attacker.example:80")
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("error = %v, want ErrSSRFBlocked", err)
	}
	if len(rd.got()) != 0 {
		t.Fatalf("dialer invoked for a blocked target: %v", rd.got())
	}
}

func TestGuard_DialContext_PinsValidatedIP(t *testing.T) {
	// DNS rebinding: the first answer is public, every later one is IMDS.
	// The guard must resolve once and dial the validated literal, never the
	// hostname.
	var calls int
	var mu sync.Mutex
	rebinding := func(context.Context, string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	rd := &recordingDialer{}
	g := &Guard{Resolver: rebinding, Dialer: rd.dial}
	conn, err := g.DialContext(context.Background(), "tcp", "rebind.example:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	if got := rd.got(); len(got) != 1 || got[0] != "203.0.113.10:8080" {
		t.Fatalf("dial targets = %v, want [203.0.113.10:8080]", got)
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", calls)
	}
}

func TestGuard_DialContext_FailsClosedOnMixedIPs(t *testing.T) {
	rd := &recordingDialer{}
	g := &Guard{Resolver: stubResolver("203.0.113.10", "10.0.0.5"), Dialer: rd.dial}
	if _, err := g.DialContext(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("error = %v, want ErrSSRFBlocked", err)
	}
	if len(rd.got()) != 0 {
		t.Fatalf("dialer invoked: %v", rd.got())
	}
}

func TestGuard_DialContext_AllowLocalhostDoesNotOpenRFC1918(t *testing.T) {
	rd := &recordingDialer{}
	g := &Guard{Resolver: stubResolver("10.0.0.5"), Dialer: rd.dial, AllowLocalhost: true}
	if _, err := g.DialContext(context.Background(), "tcp", "internal.example:80"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("RFC1918 with AllowLocalhost error = %v, want ErrSSRFBlocked", err)
	}
	g = &Guard{Resolver: stubResolver("127.0.0.1"), Dialer: rd.dial, AllowLocalhost: true}
	conn, err := g.DialContext(context.Background(), "tcp", "localhost:80")
	if err != nil {
		t.Fatalf("loopback with AllowLocalhost: %v", err)
	}
	_ = conn.Close()
	g = &Guard{Resolver: stubResolver("127.0.0.1"), Dialer: rd.dial}
	if _, err := g.DialContext(context.Background(), "tcp", "localhost:80"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("loopback without AllowLocalhost error = %v, want ErrSSRFBlocked", err)
	}
}

func TestGuard_DialContext_BadAddr(t *testing.T) {
	rd := &recordingDialer{}
	g := &Guard{Resolver: stubResolver("203.0.113.10"), Dialer: rd.dial}
	for _, addr := range []string{"", "example.com", "/var/run/docker.sock", ":", "[::1"} {
		if _, err := g.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("DialContext(%q) = nil error, want failure", addr)
		}
	}
	if len(rd.got()) != 0 {
		t.Fatalf("dialer invoked for malformed addr: %v", rd.got())
	}
}

func TestGuard_DialContext_ZeroValueUsesRealDialerOnPinnedLiteral(t *testing.T) {
	// Zero-value Guard with the default dialer: a literal-IP target that is
	// blocked must never open a socket. A refused loopback listener proves
	// the block happens before any connect attempt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, acceptErr := ln.Accept(); acceptErr == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	var g Guard
	if _, dialErr := g.DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(dialErr, ErrSSRFBlocked) {
		t.Fatalf("zero-value Guard to loopback error = %v, want ErrSSRFBlocked", dialErr)
	}
	select {
	case <-accepted:
		t.Fatal("listener saw a connection from a blocked dial")
	case <-time.After(100 * time.Millisecond):
	}
	g = Guard{AllowLocalhost: true, DialTimeout: 2 * time.Second}
	conn, err := g.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("AllowLocalhost Guard: %v", err)
	}
	_ = conn.Close()
}

// TestGuard_HTTPClient_RevalidatesRedirects proves the redirect contract:
// with the guard on the Transport, an open redirect from an allowed host to
// a metadata host is blocked at dial time by the same DialContext.
func TestGuard_HTTPClient_RevalidatesRedirects(t *testing.T) {
	metadataHit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "public.example":
			http.Redirect(w, r, "http://metadata.example/latest/meta-data/", http.StatusFound)
		default:
			metadataHit <- struct{}{}
			_, _ = w.Write([]byte("secret"))
		}
	}))
	defer srv.Close()
	srvAddr := srv.Listener.Addr().String()

	resolver := func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "public.example":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		case "metadata.example":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, errors.New("unexpected host " + host)
	}
	var mu sync.Mutex
	var dialed []string
	// The fake dialer receives the pinned literal and routes it to the
	// httptest server so the request completes without external network.
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, srvAddr)
	}
	g := &Guard{Resolver: resolver, Dialer: dialer}
	client := &http.Client{
		Transport: &http.Transport{DialContext: g.DialContext},
		Timeout:   5 * time.Second,
	}
	_, err := client.Get("http://public.example/start")
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("redirect to metadata: error = %v, want ErrSSRFBlocked", err)
	}
	select {
	case <-metadataHit:
		t.Fatal("metadata handler was reached through the redirect")
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 1 || dialed[0] != "203.0.113.10:80" {
		t.Fatalf("dialed = %v, want only the first hop's pinned literal", dialed)
	}
}

func TestGuard_HTTPClient_AllowedRequestSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	g := &Guard{Resolver: literalResolver, AllowLocalhost: true}
	client := &http.Client{Transport: &http.Transport{DialContext: g.DialContext}, Timeout: 5 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestGuard_HTTPClient_URLHostForms feeds URL spellings of blocked
// destinations through a real http.Client + Transport wired to a Guard whose
// resolver only understands IP literals, so no DNS is performed. Every
// spelling must fail closed without reaching the dialer.
func TestGuard_HTTPClient_URLHostForms(t *testing.T) {
	urls := []string{
		"http://169.254.169.254/",
		"http://169.254.169.254./", // trailing dot: not a literal, resolver refuses
		"http://[::ffff:169.254.169.254]/",
		"http://[::ffff:a9fe:a9fe]/",
		"http://[fe80::1%25en0]/",
		"http://[::1]:8080/",
		"http://127.0.0.1:8080/",
		"http://user:pass@169.254.169.254/",
		"http://allowed.example@169.254.169.254/", // userinfo trick: real host is after @
		"http://169.254.169.254:80@allowed.example/",
		"http://2852039166/",          // decimal
		"http://0251.0376.0251.0376/", // octal
		"http://0xa9fea9fe/",          // hex
		"http://0xa9.0xfe.0xa9.0xfe/",
		"http://localhost/",
		"http://LOCALHOST./",
		"http://foo.localhost/",
		"http://10.0.0.1/",
		"http://%31%36%39.254.169.254/", // percent-encoded host
		"http://169.254.169.254%2f@allowed.example/",
	}
	rd := &recordingDialer{}
	// literalResolver answers only for IP literals, mirroring a resolver that
	// gives no help to encoded spellings (they fail rather than resolve).
	g := &Guard{Resolver: literalResolver, Dialer: rd.dial}
	client := &http.Client{Transport: &http.Transport{DialContext: g.DialContext}, Timeout: 2 * time.Second}
	for _, raw := range urls {
		t.Run(raw, func(t *testing.T) {
			resp, err := client.Get(raw)
			if err == nil {
				_ = resp.Body.Close()
			}
		})
	}
	for _, target := range rd.got() {
		if strings.HasPrefix(target, "169.254.") || strings.HasPrefix(target, "127.") || strings.HasPrefix(target, "10.") {
			t.Errorf("dialer reached with %s", target)
		}
	}
}

// refBlocked is an independent (netip-based) statement of the documented
// deny set, used as the oracle for the fuzz tests. It is intentionally not
// derived from builtinDeniedCIDRs or embeddedIPv4s.
var refDeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use, denied whole
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("fec0::/10"),
}

func refBlocked(a netip.Addr, allowLocalhost bool) bool {
	a = a.Unmap().WithZone("")
	if refBlockedPlain(a, allowLocalhost) {
		return true
	}
	// An IPv6 transition form is judged by the IPv4 it carries; embedded
	// loopback is denied even with allowLocalhost.
	for _, v4 := range refEmbeddedIPv4(a) {
		if refBlockedPlain(v4, false) {
			return true
		}
	}
	return false
}

func refBlockedPlain(a netip.Addr, allowLocalhost bool) bool {
	if a.IsUnspecified() {
		return true
	}
	if !allowLocalhost && a.IsLoopback() {
		return true
	}
	if a.IsLinkLocalUnicast() || a.IsPrivate() {
		return true
	}
	for _, p := range refDeniedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 0 { // 0.0.0.0/8
			return true
		}
		if b[0] == 100 && b[1]&0xc0 == 64 { // 100.64.0.0/10
			return true
		}
	}
	return false
}

// refEmbeddedIPv4 reads the IPv4 an IPv6 transition form carries: NAT64
// well-known (last 32 bits), 6to4 (bits 16-47), Teredo (server, and the
// client XORed with 0xffffffff), IPv4-compatible (last 32 bits, but not ::
// or ::1).
func refEmbeddedIPv4(a netip.Addr) []netip.Addr {
	if !a.Is6() {
		return nil
	}
	b := a.As16()
	at := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]}) }
	switch {
	case netip.MustParsePrefix("64:ff9b::/96").Contains(a):
		return []netip.Addr{at(12)}
	case netip.MustParsePrefix("2002::/16").Contains(a):
		return []netip.Addr{at(2)}
	case netip.MustParsePrefix("2001::/32").Contains(a):
		return []netip.Addr{at(4), netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]})}
	case netip.MustParsePrefix("::/96").Contains(a) && a != netip.IPv6Unspecified() && a != netip.IPv6Loopback():
		return []netip.Addr{at(12)}
	}
	return nil
}

func FuzzResolveAndPin(f *testing.F) {
	for _, s := range []string{
		"169.254.169.254", "127.0.0.1", "::1", "::", "0.0.0.0", "10.1.1.1", "172.16.0.1", "192.168.0.1",
		"100.64.0.1", "fd00::1", "fe80::1", "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "203.0.113.10",
		"2001:db8::1", "fe80::1%eth0", "a", "abc", "abcde", "abcdefghijklmno", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "", "not-an-ip", "0:0:0:0:0:ffff:a9fe:a9fe", "256.1.1.1",
		"64:ff9b::808:808", "2002:a9fe:a9fe::1", "2002:808:808::1", "2001:0:808:808::f5ff:fffe", "2001:0:808:808::fefe:fefe",
		"::169.254.169.254", "::8.8.8.8", "255.255.255.255", "198.18.0.1", "192.88.99.1", "fec0::1",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, allowLocalhost bool) {
		r := func(context.Context, string) ([]net.IP, error) {
			if ip := net.ParseIP(s); ip != nil {
				return []net.IP{ip}, nil
			}
			// Raw byte form of any length, including empty (nil) and
			// wrong-length slices; the answer may also carry a valid public
			// address first.
			var raw net.IP
			if s != "" {
				raw = net.IP([]byte(s))
			}
			if len(s)%2 == 0 {
				return []net.IP{net.ParseIP("203.0.113.10"), raw}, nil
			}
			return []net.IP{raw}, nil
		}
		ip, err := ResolveAndPin(context.Background(), r, "fuzz.example", allowLocalhost)
		if err != nil {
			return
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			t.Fatalf("allowed an unparseable IP %v", []byte(ip))
		}
		if refBlocked(addr, allowLocalhost) {
			t.Fatalf("allowed blocked address %s (input %q, allowLocalhost=%v)", addr, s, allowLocalhost)
		}
	})
}

func FuzzGuardMalformedIP(f *testing.F) {
	for _, b := range [][]byte{nil, {}, {1}, {1, 2, 3}, {1, 2, 3, 4, 5}, make([]byte, 15), make([]byte, 17), {169, 254, 169, 254}, make([]byte, 16)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var dialed []string
		g := &Guard{
			Resolver: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.IP(raw)}, nil
			},
			Dialer: func(_ context.Context, _, target string) (net.Conn, error) {
				dialed = append(dialed, target)
				return nil, errors.New("stop")
			},
		}
		_, _ = g.DialContext(context.Background(), "tcp", "fuzz.example:80")
		for _, target := range dialed {
			host, _, err := net.SplitHostPort(target)
			a, perr := netip.ParseAddr(host)
			if err != nil || perr != nil {
				t.Fatalf("dialer reached with non-literal target %q (raw %v)", target, raw)
			}
			if len(raw) != 4 && len(raw) != 16 {
				t.Fatalf("dialer reached for malformed IP %v: %q", raw, target)
			}
			if refBlocked(a, false) {
				t.Fatalf("dialer reached with blocked address %q", target)
			}
		}
	})
}

func FuzzGuardDialContext(f *testing.F) {
	for _, s := range []string{
		"169.254.169.254:80", "[::1]:80", "[::ffff:169.254.169.254]:443", "localhost:80", "example.com:80",
		"[fe80::1%en0]:80", "10.0.0.1:1", "2852039166:80", "0251.0376.0251.0376:80", "169.254.169.254.:80",
		"a@169.254.169.254:80", "[::ffff:a9fe:a9fe]:80", "[64:ff9b::a9fe:a9fe]:80", "[64:ff9b::169.254.169.254]:80", "", ":", "[::", "127.1:80",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		var dialed []string
		g := &Guard{
			Resolver: literalResolver,
			Dialer: func(_ context.Context, _, target string) (net.Conn, error) {
				dialed = append(dialed, target)
				return nil, errors.New("stop")
			},
		}
		_, _ = g.DialContext(context.Background(), "tcp", addr)
		for _, target := range dialed {
			host, _, err := net.SplitHostPort(target)
			if err != nil {
				t.Fatalf("dialer got malformed target %q", target)
			}
			a, err := netip.ParseAddr(host)
			if err != nil {
				t.Fatalf("dialer got non-literal host %q (addr %q): pinning broken", host, addr)
			}
			if refBlocked(a, false) {
				t.Fatalf("dialer reached with blocked address %s (input %q)", target, addr)
			}
		}
	})
}
