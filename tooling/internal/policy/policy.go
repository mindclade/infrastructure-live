// Package policy executes the repository's Rego verification suite fail closed.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Result is a canonical summary of policy verification.
type Result struct {
	Engine   string `json:"engine"`
	Verified bool   `json:"verified"`
}

// Verify runs conftest's embedded OPA verifier. Missing tooling is a failure.
func Verify(root string) (Result, error) {
	policyRoot, err := filepath.Abs(filepath.Join(root, "policy"))
	if err != nil {
		return Result{}, err
	}
	binary, err := exec.LookPath("conftest")
	if err != nil {
		return Result{}, fmt.Errorf("conftest is required for policy verification: %w", err)
	}
	command := exec.Command(binary, "verify", "--policy", policyRoot, "--output", "json")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		return Result{Engine: "conftest", Verified: false}, fmt.Errorf("policy verification failed: %s", message)
	}
	if len(bytes.TrimSpace(stdout.Bytes())) != 0 {
		var value any
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			return Result{}, fmt.Errorf("conftest returned non-JSON output: %w", err)
		}
	}
	return Result{Engine: "conftest", Verified: true}, nil
}
