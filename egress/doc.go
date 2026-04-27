// Package egress provides a host-side, domain-allowlisted HTTP proxy for
// sandboxed child processes.
//
// The proxy listens on 127.0.0.1 on a random port chosen by the kernel.
// Sandboxed processes connect to it via the standard HTTP_PROXY /
// HTTPS_PROXY environment variables — see (*Proxy).EnvVars. Each request's
// target domain is matched against an allowlist; the resolved IP is
// validated against the SSRF denylist (RFC1918, link-local incl. cloud
// IMDS, CGNAT, IPv6 ULA / link-local) before any dial; CONNECT is
// restricted to TLS ports (443, 8443) by default. Denied requests receive
// HTTP 403.
//
// The library is composition-ready with go-sandbox: a consumer that wants
// allowlisted egress starts a Proxy, calls EnvVars to get the env-var
// pair, merges those into the *exec.Cmd's environment, and then applies
// a go-sandbox Profile with Net=false. The sandboxed child has no direct
// network access — it can only reach hosts via the proxy, which enforces
// the policy.
//
// This package has no third-party dependencies.
package egress
