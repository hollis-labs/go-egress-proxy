# go-egress-proxy

A host-side, domain-allowlisted HTTP proxy for sandboxed child processes. It is
the network-policy half deliberately left out of `go-sandbox`: it listens on
loopback, hands the child `HTTP_PROXY` / `HTTPS_PROXY` via `EnvVars`, and
enforces the allowlist plus an SSRF deny set on every resolved IP before any
dial. It confines network egress and nothing else — no filesystem or process
confinement, no traffic inspection.

## Start Here

- `README.md`'s "What this library is — and isn't" is the scope statement, and
  documents the wildcard semantics.
- `egress/doc.go` states the threat model.
- `egress/proxy.go` owns `Config`, `Start`/`Stop`, the allowlist and the SSRF
  guard; `builtinDeniedCIDRs` is the deny set.
- `egress/tunnels.go` owns CONNECT tunnels and the shutdown drain.
- `examples/sandbox_integration/main.go` shows the `go-sandbox` call site.

## Commands

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
```

There is no CI workflow in this repo, so these are the only gate.

## Boundaries

This is security-critical code and its guarantees are not optional. Every one
below has a named regression test; if you change the behavior, you are changing
the security posture, not refactoring.

Validate-then-pin defeats DNS rebinding: every IP the resolver returns is
checked against the deny set, then the dial targets the IP literal, so DNS
cannot rebind between check and dial. `TestProxy_CONNECT_PinsValidatedIP` and
`TestProxy_CONNECT_FailsClosedOnMixedIPs` hold this — note the second: a
hostname resolving to both an allowed and a denied IP fails closed.

The deny set covers link-local including cloud IMDS (169.254/16), RFC1918,
CGNAT, IPv6 ULA and link-local, and unspecified. `TestProxy_CONNECT_BlocksIMDS`
and `TestProxy_HTTP_BlocksRFC1918` are the ones to keep green.

Loopback is denied unless `AllowLocalhost` is set, and it is off by default —
`TestProxy_HTTP_RejectsLocalhostByName` covers reaching it by name rather than
by address.

CONNECT is restricted to TLS ports (443, 8443); `ExtraCONNECTPorts` exists for
tests, not for production widening.

`Stop` explicitly closes hijacked CONNECT connections. `http.Server.Shutdown`
is documented not to touch them, so without the tracked-conn drain a stalled
upstream wedges shutdown — `TestProxy_Stop_DrainsStalledCONNECT`.

The `Host` header is scrubbed on the plain-HTTP forward path. That is a
regression test for a prior audit finding, not a stylistic choice
(`TestProxy_HTTP_HostHeaderNotForwarded`).
