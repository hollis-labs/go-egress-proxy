package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver resolves a hostname to IP addresses. Tests replace this to
// control what IPs the proxy pins against without real DNS lookups.
type Resolver func(ctx context.Context, host string) ([]net.IP, error)

// Dialer dials a network address and returns the underlying connection.
// Tests replace this with a stub that records the dial target without
// opening a real socket.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Logger is the minimal slog-shaped surface this package logs through.
// nil falls back to slog.Default.
type Logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Config configures a Proxy. All fields are optional except AllowedDomains.
type Config struct {
	// AllowedDomains is the list of domain patterns this proxy will forward.
	// Each entry is either an exact host ("api.github.com") or a wildcard
	// prefix ("*.example.com"). Wildcard "*.example.com" matches
	// "sub.example.com" and "deep.sub.example.com" but does NOT match
	// "example.com" itself. Match is case-insensitive.
	AllowedDomains []string

	// ListenAddr is the host:port the proxy listens on. Empty defaults to
	// "127.0.0.1:0" (random port on loopback).
	ListenAddr string

	// AllowLocalhost permits connections to 127.0.0.0/8 and ::1/128 once
	// the resolver returns one. Off by default; callers that legitimately
	// need to reach localhost services set this explicitly.
	AllowLocalhost bool

	// ExtraCONNECTPorts augments the built-in CONNECT port allowlist
	// (443, 8443). Used by tests that need to tunnel to httptest TLS
	// servers on dynamic ports; production callers normally leave this
	// empty.
	ExtraCONNECTPorts []string

	// CONNECTDeadline caps each CONNECT tunnel's lifetime. Zero uses the
	// default of 5 minutes.
	CONNECTDeadline time.Duration

	// DialTimeout caps a single CONNECT dial. Zero uses 10 seconds.
	DialTimeout time.Duration

	// HTTPClientTimeout caps the upstream HTTP request lifetime for the
	// plain-HTTP forward path. Zero uses 60 seconds.
	HTTPClientTimeout time.Duration

	// StopDrainWindow is how long Stop waits for in-flight CONNECT tunnels
	// to drain before returning. Zero uses 5 seconds.
	StopDrainWindow time.Duration

	// Resolver overrides the system DNS resolver used for SSRF pinning.
	// Nil falls back to net.DefaultResolver.LookupIP.
	Resolver Resolver

	// Dialer overrides the low-level dial function used once the IP has
	// been validated. Nil uses net.Dialer with DialTimeout.
	Dialer Dialer

	// OnDeny, if non-nil, is invoked whenever a request is rejected. The
	// host argument is the unresolved target hostname. Reason is a short
	// machine-readable token: "domain", "port", "ssrf", "scheme", "host".
	// Called from the request goroutine — must be cheap and non-blocking.
	OnDeny func(host, reason string)

	// Logger receives Warn/Error events for denials and serve errors.
	// Nil falls back to slog.Default().
	Logger Logger
}

// Proxy is a host-side, domain-allowlisted HTTP proxy that enforces
// SSRF protection on every dial. See package doc for the threat model.
type Proxy struct {
	cfg Config

	allowedDomains []string
	deniedCIDRs    []*net.IPNet
	loopbackCIDRs  []*net.IPNet
	allowedPorts   map[string]struct{}

	listener net.Listener
	server   *http.Server
	addr     string

	tunnels *tunnels // tracks CONNECT-spawned goroutines

	connsMu sync.Mutex
	conns   map[net.Conn]struct{} // hijacked conns Stop must force-close

	wg sync.WaitGroup // serve goroutine

	stopped atomic.Bool
}

// Sentinel returned wrapped (via fmt.Errorf %w) when the SSRF guard
// rejects a destination. errors.Is callers can distinguish guard
// rejections from transport errors.
var ErrSSRFBlocked = errors.New("egress: blocked destination")

const (
	defaultCONNECTDeadline   = 5 * time.Minute
	defaultDialTimeout       = 10 * time.Second
	defaultHTTPClientTimeout = 60 * time.Second
	defaultStopDrainWindow   = 5 * time.Second
)

// builtinDeniedCIDRs is the SSRF deny set every Proxy enforces.
// Loopback is gated separately so AllowLocalhost can permit it without
// weakening the rest.
var builtinDeniedCIDRs = mustParseCIDRs([]string{
	"169.254.0.0/16", // link-local incl. cloud IMDS (AWS, GCP, Azure)
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"0.0.0.0/8",      // unspecified
	"100.64.0.0/10",  // CGNAT
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
	"::/128",         // IPv6 unspecified
})

var builtinLoopbackCIDRs = mustParseCIDRs([]string{
	"127.0.0.0/8",
	"::1/128",
})

var builtinCONNECTPorts = map[string]struct{}{
	"443":  {},
	"8443": {},
}

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, block, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("egress: invalid built-in CIDR %q: %v", c, err))
		}
		out = append(out, block)
	}
	return out
}

// New creates a Proxy from cfg. Call (*Proxy).Start to begin listening.
func New(cfg Config) *Proxy {
	allowed := make(map[string]struct{}, len(cfg.ExtraCONNECTPorts)+len(builtinCONNECTPorts))
	for p := range builtinCONNECTPorts {
		allowed[p] = struct{}{}
	}
	for _, p := range cfg.ExtraCONNECTPorts {
		allowed[p] = struct{}{}
	}
	return &Proxy{
		cfg:            cfg,
		allowedDomains: append([]string(nil), cfg.AllowedDomains...),
		deniedCIDRs:    builtinDeniedCIDRs,
		loopbackCIDRs:  builtinLoopbackCIDRs,
		allowedPorts:   allowed,
		conns:          make(map[net.Conn]struct{}),
	}
}

// Start begins listening on the configured address. After Start returns
// successfully, (*Proxy).Addr returns the bound address.
func (p *Proxy) Start() error {
	addr := p.cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("egress: listen: %w", err)
	}
	p.listener = ln
	p.addr = ln.Addr().String()
	p.tunnels = newTunnels()

	p.server = &http.Server{
		Handler: http.HandlerFunc(p.handle),
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger().Error("egress: serve error", "err", err)
		}
	}()
	return nil
}

// Addr returns the bound listener address (host:port). Empty before Start.
func (p *Proxy) Addr() string { return p.addr }

// EnvVars returns the HTTP_PROXY / HTTPS_PROXY pair callers should merge
// into the *exec.Cmd's environment before applying a go-sandbox Profile
// with Net=false. NO_PROXY is left to the caller — sandboxed children
// generally don't need it, but consumers that talk to localhost services
// alongside the proxy can set their own.
func (p *Proxy) EnvVars() map[string]string {
	url := "http://" + p.addr
	return map[string]string{
		"HTTP_PROXY":  url,
		"HTTPS_PROXY": url,
		"http_proxy":  url,
		"https_proxy": url,
	}
}

// Stop gracefully shuts the proxy down. Cancels in-flight CONNECT
// tunnels, force-closes hijacked conns (http.Server.Shutdown is
// documented not to touch them), waits up to StopDrainWindow for tunnel
// goroutines, then returns. Safe to call multiple times.
func (p *Proxy) Stop() error {
	if p.server == nil {
		return nil
	}
	if !p.stopped.CompareAndSwap(false, true) {
		return nil
	}

	// Phase 1: cancel tunnel ctx so CONNECT goroutines see Done; force
	// hijacked conns closed so io.Copy returns instead of parking forever.
	p.connsMu.Lock()
	for c := range p.conns {
		_ = c.SetDeadline(time.Unix(1, 0))
		_ = c.Close()
	}
	p.connsMu.Unlock()

	// Phase 2: stop accepting new connections. Shutdown does not touch
	// hijacked conns — the explicit close above handles those.
	drain := p.cfg.StopDrainWindow
	if drain <= 0 {
		drain = defaultStopDrainWindow
	}
	ctx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	shutdownErr := p.server.Shutdown(ctx)

	// Phase 3: drain tunnel goroutines.
	p.tunnels.shutdown(drain)

	// Phase 4: wait for the Serve goroutine.
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drain):
	}
	return shutdownErr
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) logger() Logger {
	if p.cfg.Logger != nil {
		return p.cfg.Logger
	}
	return slog.Default()
}

func (p *Proxy) onDeny(host, reason string) {
	if p.cfg.OnDeny != nil {
		p.cfg.OnDeny(host, reason)
	}
}

// domainAllowed reports whether host matches any pattern in allowedDomains.
// Exact match: case-insensitive equality. Wildcard "*.example.com" matches
// "sub.example.com" and "deep.sub.example.com" but NOT "example.com".
func (p *Proxy) domainAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range p.allowedDomains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && host != suffix[1:] {
				return true
			}
		} else if host == pattern {
			return true
		}
	}
	return false
}

// connectPortAllowed reports whether port is in the built-in TLS allowlist
// or in ExtraCONNECTPorts.
func (p *Proxy) connectPortAllowed(port string) bool {
	_, ok := p.allowedPorts[port]
	return ok
}

// resolveAndPin resolves host, rejects every returned IP that falls in
// the SSRF deny set (and loopback unless AllowLocalhost), and returns the
// first validated IP. The caller dials the IP literal so DNS cannot rebind
// between validation and dial.
func (p *Proxy) resolveAndPin(ctx context.Context, host string) (net.IP, error) {
	if isLocalhostName(host) && !p.cfg.AllowLocalhost {
		return nil, fmt.Errorf("%w: localhost name %q", ErrSSRFBlocked, host)
	}
	resolver := p.cfg.Resolver
	if resolver == nil {
		resolver = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolver(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no IPs for %q", ErrSSRFBlocked, host)
	}
	for _, ip := range ips {
		if !p.cfg.AllowLocalhost {
			for _, block := range p.loopbackCIDRs {
				if block.Contains(ip) {
					return nil, fmt.Errorf("%w: loopback %s", ErrSSRFBlocked, ip)
				}
			}
		}
		for _, block := range p.deniedCIDRs {
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

func (p *Proxy) innerDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.cfg.Dialer != nil {
		return p.cfg.Dialer(ctx, network, addr)
	}
	timeout := p.cfg.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// isLocalhostName matches "localhost" and any subdomain of ".localhost"
// (RFC 6761). Case-insensitive.
func isLocalhostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// splitHostPort splits a host:port string. If no port is present, returns
// the host as-is with an empty port string.
func splitHostPort(hostport string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		if !strings.Contains(hostport, ":") {
			return hostport, "", nil
		}
		return "", "", err
	}
	return host, port, nil
}

func (p *Proxy) trackConn(c net.Conn) {
	p.connsMu.Lock()
	if p.conns == nil {
		p.conns = make(map[net.Conn]struct{})
	}
	p.conns[c] = struct{}{}
	p.connsMu.Unlock()
}

func (p *Proxy) untrackConn(c net.Conn) {
	p.connsMu.Lock()
	delete(p.conns, c)
	p.connsMu.Unlock()
}

func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}
	if !p.connectPortAllowed(port) {
		p.logger().Warn("egress: denied CONNECT (port not in TLS allowlist)", "host", r.Host, "port", port)
		p.onDeny(host, "port")
		http.Error(w, "CONNECT only allowed to TLS ports (443, 8443)", http.StatusForbidden)
		return
	}
	if !p.domainAllowed(host) {
		p.logger().Warn("egress: denied CONNECT", "host", r.Host)
		p.onDeny(host, "domain")
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}

	pinned, err := p.resolveAndPin(r.Context(), host)
	if err != nil {
		p.logger().Warn("egress: blocked CONNECT", "host", r.Host, "err", err)
		p.onDeny(host, "ssrf")
		http.Error(w, fmt.Sprintf("blocked: %v", err), http.StatusForbidden)
		return
	}

	dialTimeout := p.cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	target, err := p.innerDial(dialCtx, "tcp", net.JoinHostPort(pinned.String(), port))
	if err != nil {
		http.Error(w, fmt.Sprintf("dial target: %v", err), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = target.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = target.Close()
		http.Error(w, fmt.Sprintf("hijack: %v", err), http.StatusInternalServerError)
		return
	}

	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	p.trackConn(client)
	p.trackConn(target)

	deadline := p.cfg.CONNECTDeadline
	if deadline <= 0 {
		deadline = defaultCONNECTDeadline
	}
	abs := time.Now().Add(deadline)
	_ = client.SetDeadline(abs)
	_ = target.SetDeadline(abs)

	p.runTunnel(client, target)
}

// runTunnel copies bytes bidirectionally between client and target. It
// returns as soon as either direction finishes, after closing both ends so
// the other direction unblocks. Both goroutines are drained before return.
//
// Tracked via p.tunnels so Proxy.Stop can cancel the root context; conns
// themselves are force-closed separately by Stop to unblock io.Copy parked
// in a read.
func (p *Proxy) runTunnel(client, target net.Conn) {
	defer func() {
		_ = client.Close()
		_ = target.Close()
		p.untrackConn(client)
		p.untrackConn(target)
	}()

	errCh := make(chan error, 2)
	copyOne := func(label string, dst, src net.Conn) {
		p.tunnels.go_(label, func(ctx context.Context) {
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-ctx.Done():
					_ = dst.SetDeadline(time.Unix(1, 0))
					_ = src.SetDeadline(time.Unix(1, 0))
				case <-done:
				}
			}()
			_, err := io.Copy(dst, src)
			errCh <- err
		})
	}
	copyOne("connect.copy-to-target", target, client)
	copyOne("connect.copy-to-client", client, target)

	<-errCh
	_ = client.Close()
	_ = target.Close()
	<-errCh
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "missing host in request", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "" && r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		p.onDeny(r.URL.Host, "scheme")
		http.Error(w, fmt.Sprintf("unsupported scheme %q", r.URL.Scheme), http.StatusForbidden)
		return
	}

	host, _, err := splitHostPort(r.URL.Host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	if !p.domainAllowed(host) {
		p.logger().Warn("egress: denied", "method", r.Method, "host", r.URL.Host)
		p.onDeny(host, "domain")
		http.Error(w, "domain not allowed", http.StatusForbidden)
		return
	}

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialHost, dialPort, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return nil, splitErr
		}
		pinned, err := p.resolveAndPin(ctx, dialHost)
		if err != nil {
			return nil, err
		}
		return p.innerDial(ctx, network, net.JoinHostPort(pinned.String(), dialPort))
	}
	transport := &http.Transport{
		DialContext:           dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("build request: %v", err), http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")
	// Scrub the client-supplied Host header — Go's http.Client sets the
	// request line from req.Host / req.URL.Host, but a future change or a
	// hijacking transport could read the Header entry directly. Setting
	// outReq.Host to the validated URL host keeps the policy explicit.
	outReq.Header.Del("Host")
	outReq.Host = r.URL.Host

	timeout := p.cfg.HTTPClientTimeout
	if timeout <= 0 {
		timeout = defaultHTTPClientTimeout
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	resp, err := client.Do(outReq)
	if err != nil {
		if errors.Is(err, ErrSSRFBlocked) {
			p.onDeny(host, "ssrf")
			http.Error(w, fmt.Sprintf("blocked: %v", err), http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf("upstream: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
