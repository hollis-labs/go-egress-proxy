# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, the public API may change between minor
versions; breaking changes are called out in the relevant entry.

## v0.1.0 — 2026-05-10

Initial public release. Establishes the host-side, domain-allowlisted HTTP
proxy intended to be paired with a network-disabled sandbox (e.g.
[`go-sandbox`](https://github.com/hollis-labs/go-sandbox)) so confined
child processes can reach a small, audited set of upstream hosts and
nothing else.

### Added

- `egress.New(Config) *Proxy` — constructor, validates required fields.
- `(*Proxy).Start() error` — binds the listener (default `127.0.0.1:0`)
  and serves the HTTP/CONNECT handler.
- `(*Proxy).Stop() error` — graceful shutdown with a bounded drain window
  for hijacked CONNECT connections (`http.Server.Shutdown` does not
  touch hijacked conns).
- `(*Proxy).Addr() string` — bound `host:port` after `Start`.
- `(*Proxy).EnvVars() map[string]string` — `HTTP_PROXY` / `HTTPS_PROXY`
  pair (upper- and lower-case) for merging into a child `*exec.Cmd.Env`.
- `Config` fields: `AllowedDomains`, `ListenAddr`, `AllowLocalhost`,
  `ExtraCONNECTPorts`, `CONNECTDeadline`, `DialTimeout`,
  `HTTPClientTimeout`, `StopDrainWindow`, `Resolver`, `Dialer`,
  `OnDeny`, `Logger`.
- Domain allowlist with exact + wildcard semantics
  (`*.example.com` matches subdomains only, not the apex; case-insensitive).
- `OnDeny(host, reason)` callback with `reason` ∈
  `{"domain", "port", "ssrf", "scheme"}` and a pluggable `Logger`
  interface (defaults to `slog.Default`).
- Runnable example: `examples/sandbox_integration` — env-var injection
  into a sandboxed `*exec.Cmd` (the `go-sandbox` call site is stubbed
  so the example compiles in CI without pulling extra deps).

### Security

- **SSRF deny set** applied to every resolved IP before any dial:
  link-local incl. cloud IMDS (169.254/16), RFC1918, CGNAT (100.64/10),
  IPv6 ULA / link-local, and unspecified addresses are all rejected.
- **DNS-rebinding defense** — every IP returned by the resolver is
  validated against the deny set, then the dial is pinned to the
  validated IP literal so DNS cannot rebind between check and dial.
- **CONNECT TLS-port allowlist** — restricted to `{443, 8443}` by
  default; `ExtraCONNECTPorts` is opt-in for tests that tunnel to
  `httptest` TLS servers on dynamic ports.
- **Hijacked-conn drain on `Stop`** — every CONNECT tunnel is tracked
  and force-closed on shutdown with a bounded drain window so a stalled
  upstream cannot wedge `Stop` indefinitely.
- **`Host`-header scrub** on the plain-HTTP forward path — the client
  `Host` header is not propagated; `outReq.Host` is set to the validated
  URL host.
- `Proxy-Authorization` headers are stripped from forwarded requests.

### Tests pinning the security posture

- `TestProxy_CONNECT_BlocksIMDS`
- `TestProxy_CONNECT_RejectsNonTLSPort`
- `TestProxy_CONNECT_PinsValidatedIP`
- `TestProxy_CONNECT_FailsClosedOnMixedIPs`
- `TestProxy_HTTP_BlocksRFC1918`
- `TestProxy_HTTP_RejectsLocalhostByName`
- `TestProxy_HTTP_HostHeaderNotForwarded`
- `TestProxy_Stop_DrainsStalledCONNECT`

### Notes

- Stdlib-only — no third-party dependencies.
- Module path: `github.com/hollis-labs/go-egress-proxy`.
- Go directive: `go 1.26.1`.
