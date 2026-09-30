# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, the public API may change between minor
versions; breaking changes are called out in the relevant entry.

## Unreleased

### Security

- **`ResolveAndPin` now fails closed on a malformed resolver answer.** An
  answer containing a nil `net.IP`, or one whose length is not 4 or 16
  bytes, is rejected whole with an error wrapping `ErrSSRFBlocked`, like a
  denied address, so it can never be returned or turned into a dial string
  such as `<nil>:80`. `Guard.DialContext` and the proxy inherit this. Pinned
  by `TestResolveAndPin_MalformedIPFailsClosed`,
  `TestGuard_DialContext_MalformedIPNeverDials` and
  `TestProxy_resolveAndPin_MalformedIPFailsClosed`, and by the fuzz targets.
- Known gap, tracked as follow-up CW-20260930-0028 and not addressed here:
  addresses that embed an IPv4 address through 6to4 (`2002::/16`), Teredo
  (`2001::/32`) or the IPv4-compatible form (`::a.b.c.d`) are not denied.
- Possible future refinement, not planned: the NAT64 prefixes are denied
  wholesale. If a real NAT64/DNS64 consumer needs it, they could instead be
  allowed after applying the deny set to the embedded IPv4 address.

## v0.2.0 — 2026-09-29

### Added

- `egress.Guard` and `(*Guard).DialContext` — the SSRF guard as a drop-in
  `http.Transport.DialContext` for callers that make their own outbound
  requests and do not want a `Proxy`. Zero value is ready to use.
- `egress.ResolveAndPin(ctx, resolver, host, allowLocalhost) (net.IP, error)` —
  the validate-then-pin primitive, promoted from the unexported
  `(*Proxy).resolveAndPin`. `Proxy` now delegates to it, so there is a
  single copy of the policy; proxy behavior is unchanged.
- `egress.DefaultResolver` and `egress.IsLocalhostName` — the previously
  anonymous/unexported default resolver and RFC 6761 localhost matcher.
- Runnable `Example*` functions and a README section for standalone use.
- Fuzz targets `FuzzResolveAndPin` and `FuzzGuardDialContext`.

### Security

- **NAT64-synthesized addresses are now denied.** The deny set gains
  `64:ff9b::/96` (NAT64 well-known prefix, RFC 6052) and `64:ff9b:1::/48`
  (NAT64 local-use prefix, RFC 8215). Neither is unwrapped by
  `net.IP.To4`, so a DNS64 answer such as `64:ff9b::a9fe:a9fe` (which embeds
  the cloud metadata address 169.254.169.254) matched no existing CIDR and
  was accepted. This is a deny-set change and applies to `Proxy` and `Guard`
  alike. Consequence: hosts reachable only through a NAT64 gateway
  (IPv6-only networks with DNS64) are now refused. Pinned by
  `TestResolveAndPin_BlocksNAT64SynthesizedIMDS` and friends. Nanite's own
  `internal/ssrf` copy has the same gap and is tracked separately
  (Torque CW-20260930-0027); this repository's change does not touch it.

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
