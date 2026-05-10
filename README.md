# go-egress-proxy

`go-egress-proxy` is a small, standalone Go library that runs a host-side, domain-allowlisted HTTP proxy intended for sandboxed child processes. It is the network-policy half of the picture deliberately excluded from [`go-sandbox`](https://github.com/hollis-labs/go-sandbox).

The proxy spawns on `127.0.0.1` (random port by default), exposes its address via `(*Proxy).EnvVars` for callers to merge into the child's `HTTP_PROXY` / `HTTPS_PROXY`, and enforces a domain allowlist plus an SSRF deny set on every request before any dial. CONNECT is restricted to TLS ports (443, 8443) by default.

## Status

Pre-1.0 (`v0.1.0`) — API may shift before `v1`, but the security-critical
behaviours (SSRF guard, CONNECT TLS-port allowlist, hijacked-conn drain on
`Stop`, `Host`-header scrub) are non-optional and covered by tests. See
[godoc](https://pkg.go.dev/github.com/hollis-labs/go-egress-proxy/egress)
for the package reference.

## Install

```bash
go get github.com/hollis-labs/go-egress-proxy
```

## Usage

```go
package main

import (
    "log"
    "os"
    "os/exec"

    "github.com/hollis-labs/go-egress-proxy/egress"
    // import "github.com/hollis-labs/go-sandbox/sandbox" — see examples/
)

func main() {
    proxy := egress.New(egress.Config{
        AllowedDomains: []string{
            "api.anthropic.com",
            "*.githubusercontent.com",
        },
        OnDeny: func(host, reason string) {
            log.Printf("egress denied %s (%s)", host, reason)
        },
    })
    if err := proxy.Start(); err != nil {
        log.Fatal(err)
    }
    defer proxy.Stop()

    cmd := exec.Command("claude", "--print", "hello")
    cmd.Stdout = os.Stdout

    // Merge proxy env into the child BEFORE applying the sandbox.
    env := append([]string(nil), os.Environ()...)
    for k, v := range proxy.EnvVars() {
        env = append(env, k+"="+v)
    }
    cmd.Env = env

    // sandbox.Apply(cmd, sandbox.Profile{Net: false, ...}, ws) ...
    if err := cmd.Run(); err != nil {
        log.Fatal(err)
    }
}
```

A complete working example (with the go-sandbox call site stubbed for cheap CI compilation) lives in `examples/sandbox_integration`.

## What this library is — and isn't

**This is a lib, not a framework.**

In:

- `Config{AllowedDomains, AllowLocalhost, ExtraCONNECTPorts, CONNECTDeadline, DialTimeout, HTTPClientTimeout, StopDrainWindow, Resolver, Dialer, OnDeny, Logger, ListenAddr}`
- `New(cfg) *Proxy`, `(*Proxy).Start() error`, `(*Proxy).Addr() string`, `(*Proxy).Stop() error`, `(*Proxy).EnvVars() map[string]string`
- Domain allowlist with exact + wildcard semantics (see "Wildcard semantics" below)
- SSRF deny set: link-local incl. cloud IMDS (169.254/16), RFC1918, CGNAT, IPv6 ULA / link-local, unspecified — applied to every resolved IP before any dial
- DNS-rebinding defense: validate every IP from the resolver, then dial the IP literal so DNS cannot rebind between check and dial
- `AllowLocalhost` flag for callers that legitimately need to reach loopback services; off by default
- CONNECT restricted to TLS ports (443, 8443) by default; `ExtraCONNECTPorts` extends for tests
- Per-CONNECT-tunnel deadline (5min default) and a tracked-conn drain in `Stop` so a stalled upstream cannot wedge shutdown — `http.Server.Shutdown` is documented not to touch hijacked conns; we close them explicitly
- `Host`-header scrub on the plain-HTTP forward path (audit finding 04c regression test)
- `OnDeny(host, reason)` callback with reason ∈ `{"domain", "port", "ssrf", "scheme"}` and a pluggable `Logger` interface — caller's choice for observability
- `EnvVars()` helper returning the `HTTP_PROXY`/`HTTPS_PROXY` pair (both upper- and lower-case) so callers can merge into `*exec.Cmd.Env` before applying a sandbox
- Stdlib-only — no third-party dependencies (no OTel pull-in)

Out (intentionally):

- **Hot-reload of the allowlist.** v0.1.0 is restart-to-update. Consumers that need per-tenant or per-task allowlists spin a new `Proxy` per child process — that's already the dominant pattern and it keeps `Config` immutable.
- **Command policy / shell-denylist matching.** Pre-flight checks against shell-command denylists (`rm -rf`, `dd`, `mkfs`, ...) belong in a separate library, not here.
- **Auth.** No upstream HTTP auth, no client-side proxy auth (`Proxy-Authorization` is stripped). The threat model is "host-side proxy for trusted-but-confined children"; if you need auth, run the proxy behind one.
- **Caching, response inspection, body size limits.** The proxy is a pass-through. If you need to gate response bodies (say, blocking a 5GB download), wrap your own `Logger` that observes `OnDeny` and `slog` events, or interpose between the child and the proxy with a different abstraction.
- **Distributed / multi-instance state.** `Proxy` is per-process. Each consumer process runs its own.
- **Windows and other platforms.** The proxy itself is `GOOS`-agnostic — it's standard `net/http` — but `go-sandbox` is darwin/linux only, so the realistic deployment surface is the same.

## Wildcard semantics

`*.example.com` matches `sub.example.com` and `deep.sub.example.com`. It does **not** match `example.com` itself. To allow both, list both (`example.com`, `*.example.com`). Match is case-insensitive.

## Hardening posture

The SSRF guard, CONNECT port restriction, conn-tracking-on-`Stop`, and `Host`-header scrub each address a concrete attack the proxy must close. Each fix is pinned by a regression test (listed below).

- **DNS-based SSRF.** A resolver returning `169.254.169.254` for an allowlisted hostname could exfiltrate cloud instance metadata. Fix: validate every IP from the resolver against the deny set, fail closed if any private IP is in the result, pin the dial to the validated IP.
- **CONNECT to non-TLS ports.** `CONNECT allowed.example.com:22` tunneled raw SSH out of the sandbox. Fix: built-in port allowlist `{443, 8443}`; `ExtraCONNECTPorts` is opt-in.
- **Stalled-upstream Stop wedge.** `http.Server.Shutdown` does not touch hijacked connections. Tunnel goroutines parked in `io.Copy` against a slow upstream blocked Stop forever. Fix: track every hijacked conn; force-close on Stop with a bounded drain window.
- **Forwarded `Host` header.** A naive proxy forwards the client's `Host` header verbatim to upstream — leaking internal hostnames or confusing vhost-based routing. Fix: scrub `Host` from the outgoing request and set `outReq.Host` to the validated URL host.

These regressions are pinned by tests:

- `TestProxy_CONNECT_BlocksIMDS`
- `TestProxy_CONNECT_RejectsNonTLSPort`
- `TestProxy_CONNECT_PinsValidatedIP`
- `TestProxy_CONNECT_FailsClosedOnMixedIPs`
- `TestProxy_HTTP_BlocksRFC1918`
- `TestProxy_HTTP_RejectsLocalhostByName`
- `TestProxy_HTTP_HostHeaderNotForwarded`
- `TestProxy_Stop_DrainsStalledCONNECT`

## Repository layout

```
go-egress-proxy/
├── go.mod
├── LICENSE                            # MIT
├── README.md
├── egress/                            # main package
│   ├── doc.go
│   ├── proxy.go                       # Proxy, Config, handlers, SSRF guard
│   ├── tunnels.go                     # tracked-goroutine coordinator (stdlib)
│   └── proxy_test.go                  # full feature + regression suite
└── examples/
    └── sandbox_integration/           # env-var injection into a sandboxed *exec.Cmd
        └── main.go
```

## Contributing

Issues and PRs welcome. Please run `go test -race ./...` before opening a
PR; the regression tests pinned in [Hardening posture](#hardening-posture)
must stay green.

## License

MIT — see `LICENSE`.
