package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver returns a Resolver that resolves any host to ips.
func stubResolver(ips ...string) Resolver {
	return func(_ context.Context, _ string) ([]net.IP, error) {
		parsed := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("test bug: invalid IP %q", s)
			}
			parsed = append(parsed, ip)
		}
		return parsed, nil
	}
}

func newTestProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	p := New(cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p
}

func TestProxy_AllowedHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok from target"))
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)

	p := newTestProxy(t, Config{
		AllowedDomains: []string{targetURL.Hostname()},
		AllowLocalhost: true, // httptest binds 127.0.0.1
	})

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(target.URL + "/get")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok from target" {
		t.Errorf("body = %q", body)
	}
}

func TestProxy_DeniedHTTP_FiresOnDeny(t *testing.T) {
	var denyHost atomic.Value // string
	var denyReason atomic.Value
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"allowed.example.com"},
		OnDeny: func(host, reason string) {
			denyHost.Store(host)
			denyReason.Store(reason)
		},
	})

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://denied.example.com/foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got, _ := denyHost.Load().(string); got != "denied.example.com" {
		t.Errorf("OnDeny host = %q, want denied.example.com", got)
	}
	if got, _ := denyReason.Load().(string); got != "domain" {
		t.Errorf("OnDeny reason = %q, want domain", got)
	}
}

func TestProxy_CONNECTAllowed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls ok"))
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	targetHost := targetURL.Host

	p := newTestProxy(t, Config{
		AllowedDomains:    []string{targetURL.Hostname()},
		AllowLocalhost:    true,
		ExtraCONNECTPorts: []string{targetURL.Port()},
	})

	conn, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHost, targetHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = targetURL.Hostname()
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write tls req: %v", err)
	}
	tlsResp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("tls response: %v", err)
	}
	defer tlsResp.Body.Close()
	body, _ := io.ReadAll(tlsResp.Body)
	if string(body) != "tls ok" {
		t.Errorf("body = %q", body)
	}
}

func TestProxy_CONNECTDenied(t *testing.T) {
	p := newTestProxy(t, Config{AllowedDomains: []string{"allowed.example.com"}})

	conn, err := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_WildcardMatching(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		host    string
		want    bool
	}{
		{"exact match", []string{"api.github.com"}, "api.github.com", true},
		{"exact mismatch", []string{"api.github.com"}, "evil.github.com", false},
		{"wildcard match", []string{"*.github.com"}, "api.github.com", true},
		{"wildcard deep", []string{"*.github.com"}, "sub.api.github.com", true},
		{"wildcard root denied", []string{"*.github.com"}, "github.com", false},
		{"wildcard mismatch", []string{"*.github.com"}, "api.gitlab.com", false},
		{"case insensitive", []string{"API.GitHub.COM"}, "api.github.com", true},
		{"multiple", []string{"httpbin.org", "*.github.com"}, "api.github.com", true},
		{"multiple exact", []string{"httpbin.org", "*.github.com"}, "httpbin.org", true},
		{"multiple denied", []string{"httpbin.org", "*.github.com"}, "evil.com", false},
		{"not a subdomain", []string{"*.example.com"}, "notexample.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(Config{AllowedDomains: tt.domains})
			if got := p.domainAllowed(tt.host); got != tt.want {
				t.Errorf("domainAllowed(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestProxy_StopCleansUp(t *testing.T) {
	p := New(Config{AllowedDomains: []string{"example.com"}})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := p.Addr()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("connect before stop: %v", err)
	}
	conn.Close()

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	conn, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("proxy still accepting after Stop")
	}
}

// SSRF: stubbed resolver returning an IMDS link-local address must block CONNECT.
func TestProxy_CONNECT_BlocksIMDS(t *testing.T) {
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"meta.example.com"},
		Resolver:       stubResolver("169.254.169.254"),
	})
	conn, _ := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT meta.example.com:443 HTTP/1.1\r\nHost: meta.example.com:443\r\n\r\n")
	resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// SSRF: CONNECT must be restricted to TLS ports even when the host is
// allowlisted. Without the gate, CONNECT allowed.example.com:22 tunneled
// raw SSH out of the sandbox.
func TestProxy_CONNECT_RejectsNonTLSPort(t *testing.T) {
	var denyReason atomic.Value
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"allowed.example.com"},
		OnDeny:         func(_, reason string) { denyReason.Store(reason) },
	})
	conn, _ := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT allowed.example.com:22 HTTP/1.1\r\nHost: allowed.example.com:22\r\n\r\n")
	resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got, _ := denyReason.Load().(string); got != "port" {
		t.Errorf("OnDeny reason = %q, want port", got)
	}
}

// SSRF: validated public IP gets dialed; pinned addr is the validated IP,
// not the original hostname (DNS-rebinding defense).
func TestProxy_CONNECT_PinsValidatedIP(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("public ok"))
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)

	var dialed atomic.Value
	p := newTestProxy(t, Config{
		AllowedDomains:    []string{"public.example.com"},
		ExtraCONNECTPorts: []string{targetURL.Port()},
		Resolver:          stubResolver("203.0.113.9"),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.Store(addr)
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, targetURL.Host)
		},
	})

	conn, _ := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT public.example.com:%s HTTP/1.1\r\nHost: public.example.com:%s\r\n\r\n",
		targetURL.Port(), targetURL.Port())
	resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	got, _ := dialed.Load().(string)
	if !strings.HasPrefix(got, "203.0.113.9:") {
		t.Errorf("pinned dial = %q, want 203.0.113.9:*", got)
	}
}

// SSRF: a resolver returning a mix of private + public must fail closed.
func TestProxy_CONNECT_FailsClosedOnMixedIPs(t *testing.T) {
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"mixed.example.com"},
		Resolver:       stubResolver("10.0.0.5", "203.0.113.9"),
	})
	conn, _ := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT mixed.example.com:443 HTTP/1.1\r\nHost: mixed.example.com:443\r\n\r\n")
	resp, _ := http.ReadResponse(bufio.NewReader(conn), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_HTTP_BlocksRFC1918(t *testing.T) {
	p := newTestProxy(t, Config{
		AllowedDomains: []string{"intranet.example.com"},
		Resolver:       stubResolver("10.0.0.5"),
	})
	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://intranet.example.com/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_HTTP_RejectsLocalhostByName(t *testing.T) {
	p := newTestProxy(t, Config{AllowedDomains: []string{"localhost"}})
	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://localhost:6379/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_MissingHost(t *testing.T) {
	p := newTestProxy(t, Config{AllowedDomains: []string{"example.com"}})
	// Hit the proxy directly with a non-proxy request shape.
	req, _ := http.NewRequest("GET", "http://"+p.Addr()+"/foo", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProxy_HTTP_HostHeaderNotForwarded(t *testing.T) {
	var upstreamHost atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost.Store(r.Host)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)

	p := newTestProxy(t, Config{
		AllowedDomains: []string{targetURL.Hostname()},
		AllowLocalhost: true,
	})

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	req, _ := http.NewRequest("GET", target.URL+"/", nil)
	req.Header.Set("Host", "internal.example")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	got, _ := upstreamHost.Load().(string)
	if got == "internal.example" {
		t.Fatalf("upstream saw client-supplied Host %q", got)
	}
	if !strings.Contains(got, targetURL.Host) {
		t.Errorf("upstream Host = %q, want containing %q", got, targetURL.Host)
	}
}

func TestProxy_StopIdempotent(t *testing.T) {
	p := New(Config{AllowedDomains: []string{"example.com"}})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second Stop hung")
	}
}

// Stop must drain even when CONNECT tunnel goroutines are parked in
// io.Copy against a stalled upstream. Before the conn-tracking + lifecycle
// drain pattern, this would block forever because http.Server.Shutdown
// does not touch hijacked connections.
func TestProxy_Stop_DrainsStalledCONNECT(t *testing.T) {
	stalled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stalled upstream: %v", err)
	}
	defer stalled.Close()
	go func() {
		for {
			c, err := stalled.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(30 * time.Second)
			}(c)
		}
	}()

	stalledHost, stalledPort, _ := net.SplitHostPort(stalled.Addr().String())
	p := New(Config{
		AllowedDomains:    []string{"stalled.example.com"},
		AllowLocalhost:    true,
		ExtraCONNECTPorts: []string{stalledPort},
		CONNECTDeadline:   200 * time.Millisecond,
		Resolver:          stubResolver(stalledHost),
	})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT stalled.example.com:%s HTTP/1.1\r\nHost: stalled.example.com:%s\r\n\r\n",
		stalledPort, stalledPort)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Wait for hijacked conns to register.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.connsMu.Lock()
		n := len(p.conns)
		p.connsMu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed > defaultStopDrainWindow+2*time.Second {
		t.Fatalf("Stop took %v", elapsed)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.tunnels.activeCount() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := p.tunnels.activeCount(); n != 0 {
		t.Fatalf("active tunnels = %d after Stop, want 0", n)
	}
}

func TestProxy_EnvVars(t *testing.T) {
	p := newTestProxy(t, Config{AllowedDomains: []string{"example.com"}})
	env := p.EnvVars()
	want := "http://" + p.Addr()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[k] != want {
			t.Errorf("env[%q] = %q, want %q", k, env[k], want)
		}
	}
}

// Unsupported scheme on the plain-HTTP path should be 403'd before any
// dial attempt.
func TestProxy_HTTP_RejectsNonHTTPScheme(t *testing.T) {
	p := newTestProxy(t, Config{AllowedDomains: []string{"example.com"}})
	conn, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// file:// scheme via raw absolute-form URI.
	fmt.Fprintf(conn, "GET file://example.com/etc/passwd HTTP/1.0\r\nHost: example.com\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "403") {
		t.Errorf("response = %q, want 403", string(buf[:n]))
	}
}
