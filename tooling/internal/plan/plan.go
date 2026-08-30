// Package plan classifies OpenTofu JSON plans without exposing provider values.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Change is a redacted, deterministic resource action.
type Change struct {
	Address string `json:"address"`
	Action  string `json:"action"`
}

// Report describes plan risk without copying any before/after values.
type Report struct {
	Digest   string   `json:"digest"`
	Creates  int      `json:"creates"`
	Updates  int      `json:"updates"`
	Deletes  int      `json:"deletes"`
	Replaces int      `json:"replaces"`
	Reads    int      `json:"reads"`
	NoOps    int      `json:"noOps"`
	Safe     bool     `json:"safe"`
	Changes  []Change `json:"changes"`
}

type document struct {
	FormatVersion   string           `json:"format_version"`
	ResourceChanges []resourceChange `json:"resource_changes"`
}

type resourceChange struct {
	Address string `json:"address"`
	Change  struct {
		Actions []string `json:"actions"`
	} `json:"change"`
}

// ClassifyFile classifies a `tofu show -json` output file.
func ClassifyFile(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	return Classify(data)
}

// Classify returns an error for malformed or unknown action combinations.
func Classify(data []byte) (Report, error) {
	var parsed document
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Report{}, fmt.Errorf("parse OpenTofu plan JSON: %w", err)
	}
	if parsed.FormatVersion == "" {
		return Report{}, fmt.Errorf("OpenTofu plan is missing format_version")
	}
	digest, err := canonicalDigest(data)
	if err != nil {
		return Report{}, err
	}
	report := Report{Digest: digest, Safe: true, Changes: []Change{}}
	for _, resource := range parsed.ResourceChanges {
		if resource.Address == "" {
			return Report{}, fmt.Errorf("plan contains a resource change without an address")
		}
		action, err := classifyActions(resource.Change.Actions)
		if err != nil {
			return Report{}, fmt.Errorf("%s: %w", resource.Address, err)
		}
		report.Changes = append(report.Changes, Change{Address: resource.Address, Action: action})
		switch action {
		case "create":
			report.Creates++
		case "update":
			report.Updates++
		case "delete":
			report.Deletes++
			report.Safe = false
		case "replace":
			report.Replaces++
			report.Safe = false
		case "read":
			report.Reads++
		case "no-op":
			report.NoOps++
		}
	}
	sort.Slice(report.Changes, func(i, j int) bool {
		if report.Changes[i].Address == report.Changes[j].Address {
			return report.Changes[i].Action < report.Changes[j].Action
		}
		return report.Changes[i].Address < report.Changes[j].Address
	})
	return report, nil
}

// canonicalDigest binds approval to all plan content except the top-level
// generation timestamp. JSON object order and insignificant whitespace are
// normalized, so recreating an otherwise identical plan produces one digest.
func canonicalDigest(data []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("normalize OpenTofu plan JSON: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("OpenTofu plan JSON must be an object")
	}
	delete(object, "timestamp")
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("normalize OpenTofu plan JSON: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func classifyActions(actions []string) (string, error) {
	set := map[string]bool{}
	for _, action := range actions {
		set[action] = true
	}
	switch {
	case len(actions) == 1 && set["no-op"]:
		return "no-op", nil
	case len(actions) == 1 && set["read"]:
		return "read", nil
	case len(actions) == 1 && set["create"]:
		return "create", nil
	case len(actions) == 1 && set["update"]:
		return "update", nil
	case len(actions) == 1 && set["delete"]:
		return "delete", nil
	case len(actions) == 2 && set["delete"] && set["create"]:
		return "replace", nil
	default:
		return "", fmt.Errorf("unsupported action sequence %v", actions)
	}
}
