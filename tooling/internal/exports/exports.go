// Package exports emits the sole versioned handoff from infrastructure-live to GitOps.
package exports

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	APIVersion = "infrastructure.mindclade.dev/v1"
	Kind       = "InfrastructureExport"
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,126}$`)
	rootPattern   = regexp.MustCompile(`^opentofu/live/(development|staging|production|restricted)/(foundation|network|artifacts|data-services|clusters|ci-execution|observability)$`)
)

var validEnvironments = map[string]bool{"development": true, "staging": true, "production": true, "restricted": true}
var validStacks = map[string]bool{"foundation": true, "network": true, "artifacts": true, "data-services": true, "clusters": true, "ci-execution": true, "observability": true}
var validResourceKinds = map[string]bool{
	"project": true, "network": true, "subnetwork": true, "private-dns-zone": true,
	"artifact-registry": true, "artifact-bucket": true, "database-instance": true, "topic": true,
	"kms-key-reference": true, "cluster-membership": true, "workload-identity-pool": true,
	"build-execution-pool": true, "log-bucket": true, "metrics-scope": true, "argocd-prerequisite": true,
}

type Metadata struct {
	Environment      string `json:"environment"`
	Stack            string `json:"stack"`
	SourceRepository string `json:"sourceRepository"`
	SourceCommit     string `json:"sourceCommit"`
	Root             string `json:"root"`
	PlanDigest       string `json:"planDigest"`
	SchemaDigest     string `json:"schemaDigest"`
	GeneratedAt      string `json:"generatedAt"`
}

type Resource struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type Reference struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

type Evidence struct {
	Signature  Reference `json:"signature"`
	Provenance Reference `json:"provenance"`
}

type Spec struct {
	Resources []Resource `json:"resources"`
	Evidence  Evidence   `json:"evidence"`
}

// Document matches schemas/v1/infrastructure_export.schema.json.
type Document struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

// Input contains every operator-supplied immutable field.
type Input struct {
	Metadata  Metadata
	Resources []Resource
	Evidence  Evidence
}

// Emit validates and writes canonical compact JSON atomically.
func Emit(input Input, output string) (Document, error) {
	document := Document{APIVersion: APIVersion, Kind: Kind, Metadata: input.Metadata, Spec: Spec{Resources: input.Resources, Evidence: input.Evidence}}
	if err := Validate(document); err != nil {
		return Document{}, err
	}
	sort.Slice(document.Spec.Resources, func(i, j int) bool {
		left, right := document.Spec.Resources[i], document.Spec.Resources[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.URI < right.URI
	})
	data, err := json.Marshal(document)
	if err != nil {
		return Document{}, err
	}
	data = append(data, '\n')
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".infrastructure-export-*.json")
	if err != nil {
		return Document{}, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Document{}, err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return Document{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return Document{}, err
	}
	if err := temporary.Close(); err != nil {
		return Document{}, err
	}
	if err := os.Rename(temporaryName, output); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Validate rejects incomplete, mutable, secret-bearing, or cross-root evidence.
func Validate(document Document) error {
	metadata := document.Metadata
	if document.APIVersion != APIVersion || document.Kind != Kind {
		return fmt.Errorf("invalid infrastructure export type metadata")
	}
	if !validEnvironments[metadata.Environment] || !validStacks[metadata.Stack] {
		return fmt.Errorf("invalid environment or stack")
	}
	if metadata.SourceRepository != "mindclade/infrastructure-live" || !commitPattern.MatchString(metadata.SourceCommit) {
		return fmt.Errorf("source repository and full commit are required")
	}
	if metadata.Root != "opentofu/live/"+metadata.Environment+"/"+metadata.Stack || !rootPattern.MatchString(metadata.Root) {
		return fmt.Errorf("root does not match the environment and stack")
	}
	if !digestPattern.MatchString(metadata.PlanDigest) || !digestPattern.MatchString(metadata.SchemaDigest) {
		return fmt.Errorf("plan and schema SHA-256 digests are required")
	}
	parsedTime, err := time.Parse(time.RFC3339, metadata.GeneratedAt)
	if err != nil || parsedTime.Format(time.RFC3339) != metadata.GeneratedAt || !strings.HasSuffix(metadata.GeneratedAt, "Z") {
		return fmt.Errorf("generatedAt must be canonical RFC3339 UTC evidence time")
	}
	if len(document.Spec.Resources) == 0 {
		return fmt.Errorf("at least one non-sensitive resource reference is required")
	}
	seen := map[string]bool{}
	for _, resource := range document.Spec.Resources {
		if !validResourceKinds[resource.Kind] || !namePattern.MatchString(resource.Name) || !safeResourceURI(resource.URI) {
			return fmt.Errorf("every resource requires kind, name, and a safe URI")
		}
		identity := resource.Kind + "\x00" + resource.Name
		if seen[identity] {
			return fmt.Errorf("duplicate resource identity %s/%s", resource.Kind, resource.Name)
		}
		seen[identity] = true
	}
	for name, reference := range map[string]Reference{"signature": document.Spec.Evidence.Signature, "provenance": document.Spec.Evidence.Provenance} {
		if !safeEvidenceURI(reference.URI) || !digestPattern.MatchString(reference.Digest) {
			return fmt.Errorf("%s evidence requires a safe URI and SHA-256 digest", name)
		}
	}
	return nil
}

func safeResourceURI(raw string) bool {
	return safeURI(raw, true)
}

func safeEvidenceURI(raw string) bool {
	return safeURI(raw, false)
}

func safeURI(raw string, allowNetworkPath bool) bool {
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t?#") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return allowNetworkPath && parsed.Scheme == "" && strings.HasPrefix(raw, "//")
}
