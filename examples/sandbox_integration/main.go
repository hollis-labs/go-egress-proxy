// Example: starting an egress proxy and merging its env vars into a
// sandboxed *exec.Cmd.
//
// This file is illustrative — it does not import go-sandbox so the
// example stays cheap to compile in CI. Replace the `applySandbox`
// stub with an actual go-sandbox call site.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/hollis-labs/go-egress-proxy/egress"
)

// applySandbox is a placeholder for go-sandbox.Apply. In real consumer
// code, replace this with:
//
//	cleanup, err := sandbox.Apply(cmd, profile, workspace)
//
// where profile.Net is false. The egress proxy is the only network path
// the sandboxed child can reach.
func applySandbox(cmd *exec.Cmd) (cleanup func(), err error) {
	return func() {}, nil
}

func main() {
	proxy := egress.New(egress.Config{
		AllowedDomains: []string{
			"api.anthropic.com",
			"*.githubusercontent.com",
		},
		OnDeny: func(host, reason string) {
			log.Printf("egress: denied %s (%s)", host, reason)
		},
		CONNECTDeadline: 2 * time.Minute,
	})
	if err := proxy.Start(); err != nil {
		log.Fatalf("egress: start: %v", err)
	}
	defer proxy.Stop()

	cmd := exec.Command("claude", "--print", "hello")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Merge proxy env vars into the child's environment. Order matters —
	// these must be set BEFORE applying go-sandbox, so the sandboxed child
	// inherits them.
	env := append([]string(nil), os.Environ()...)
	for k, v := range proxy.EnvVars() {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	cleanup, err := applySandbox(cmd)
	if err != nil {
		log.Fatalf("sandbox: %v", err)
	}
	defer cleanup()

	if err := cmd.Run(); err != nil {
		log.Fatalf("run: %v", err)
	}
}
