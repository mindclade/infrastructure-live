// Package exports emits and verifies the sole versioned handoff from infrastructure-live to GitOps.
package exports

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/infrastructure-live/tooling/internal/catalog"
)

const (
	APIVersion = "infrastructure.mindclade.dev/v1"
	Kind       = "InfrastructureExport"
)

var (
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	lineagePattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,126}$`)
	rootPattern = regexp.MustCompile(`^opentofu/live/(development|staging|production|restricted)/(foundation|network|artifacts|data-services|clusters|ci-execution|observability)$`)
)

var validEnvironments = map[string]bool{"development": true, "staging": true, "production": true, "restricted": true}
var validStacks = map[string]bool{"foundation": true, "network": true, "artifacts": true, "data-services": true, "clusters": true, "ci-execution": true, "observability": true}

type Metadata struct {
	Environment        string `json:"environment"`
	Stack              string `json:"stack"`
	SourceRepository   string `json:"sourceRepository"`
	SourceCommit       string `json:"sourceCommit"`
	Root               string `json:"root"`
	PlanDigest         string `json:"planDigest"`
	ProviderLockDigest string `json:"providerLockDigest"`
	BackendStateDigest string `json:"backendStateDigest"`
	BackendLineage     string `json:"backendLineage"`
	BackendSerial      uint64 `json:"backendSerial"`
	SchemaDigest       string `json:"schemaDigest"`
	GeneratedAt        string `json:"generatedAt"`
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

// Signature is a detached Ed25519 signature over the canonical signed payload.
// The key identifier is the SHA-256 digest of the decoded 32-byte public key.
type Signature struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	PublicKey     string `json:"publicKey"`
	Value         string `json:"value"`
	PayloadDigest string `json:"payloadDigest"`
}

type Evidence struct {
	Signature  Signature `json:"signature"`
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

// Input contains every operator-supplied immutable field except the detached signature.
type Input struct {
	Metadata   Metadata
	Resources  []Resource
	Provenance Reference
}

type signedSpec struct {
	Resources  []Resource `json:"resources"`
	Provenance Reference  `json:"provenance"`
}

type signedPayload struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   Metadata   `json:"metadata"`
	Spec       signedSpec `json:"spec"`
}

// CanonicalPayload returns the exact bytes that an independently controlled
// Ed25519 signer must sign. The payload binds metadata, resource references,
// provenance, the source commit, saved-plan digest, provider lock, and backend state.
func CanonicalPayload(input Input) ([]byte, Document, error) {
	document := Document{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   input.Metadata,
		Spec: Spec{
			Resources: append([]Resource(nil), input.Resources...),
			Evidence:  Evidence{Provenance: input.Provenance},
		},
	}
	sortResources(document.Spec.Resources)
	if err := validateUnsigned(document); err != nil {
		return nil, Document{}, err
	}
	payload, err := canonicalSignedPayload(document)
	if err != nil {
		return nil, Document{}, err
	}
	return payload, document, nil
}

// WritePayload writes the canonical signer payload atomically with mode 0600.
func WritePayload(input Input, output string) (Document, error) {
	payload, document, err := CanonicalPayload(input)
	if err != nil {
		return Document{}, err
	}
	if err := atomicWrite(output, payload); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Emit verifies an actual detached signature against an independently supplied
// trusted key identifier and writes canonical compact JSON atomically.
func Emit(input Input, signature Signature, trustedKeyID, output string) (Document, error) {
	_, document, err := CanonicalPayload(input)
	if err != nil {
		return Document{}, err
	}
	document.Spec.Evidence.Signature = signature
	if !digestPattern.MatchString(trustedKeyID) || signature.KeyID != trustedKeyID {
		return Document{}, fmt.Errorf("signature keyId does not match the independently supplied trusted key ID")
	}
	if err := Validate(document); err != nil {
		return Document{}, err
	}
	data, err := json.Marshal(document)
	if err != nil {
		return Document{}, err
	}
	data = append(data, '\n')
	if err := atomicWrite(output, data); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Validate rejects incomplete, mutable, secret-bearing, cross-root, or unsigned evidence.
func Validate(document Document) error {
	if err := validateUnsigned(document); err != nil {
		return err
	}
	payload, err := canonicalSignedPayload(document)
	if err != nil {
		return err
	}
	signature := document.Spec.Evidence.Signature
	if signature.Algorithm != "Ed25519" {
		return fmt.Errorf("signature algorithm must be Ed25519")
	}
	publicKey, err := decodeCanonicalBase64(signature.PublicKey, ed25519.PublicKeySize, "signature public key")
	if err != nil {
		return err
	}
	signatureValue, err := decodeCanonicalBase64(signature.Value, ed25519.SignatureSize, "signature value")
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256(publicKey)
	expectedKeyID := "sha256:" + hex.EncodeToString(keyDigest[:])
	if signature.KeyID != expectedKeyID {
		return fmt.Errorf("signature keyId does not match the public key")
	}
	payloadHash := sha256.Sum256(payload)
	expectedPayloadDigest := "sha256:" + hex.EncodeToString(payloadHash[:])
	if signature.PayloadDigest != expectedPayloadDigest {
		return fmt.Errorf("signature payloadDigest does not match the canonical export payload")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signatureValue) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

func validateUnsigned(document Document) error {
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
	if !digestPattern.MatchString(metadata.PlanDigest) ||
		!digestPattern.MatchString(metadata.ProviderLockDigest) ||
		!digestPattern.MatchString(metadata.BackendStateDigest) ||
		!digestPattern.MatchString(metadata.SchemaDigest) {
		return fmt.Errorf("plan, provider-lock, backend-state, and schema SHA-256 digests are required")
	}
	if !lineagePattern.MatchString(metadata.BackendLineage) {
		return fmt.Errorf("a canonical backend lineage UUID is required")
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
		if !catalog.AllowsExportKind(metadata.Stack, resource.Kind) {
			return fmt.Errorf("resource kind %q is not allowed for stack %q", resource.Kind, metadata.Stack)
		}
		if !namePattern.MatchString(resource.Name) || !safeResourceURI(resource.URI) {
			return fmt.Errorf("every resource requires kind, name, and a safe URI")
		}
		identity := resource.Kind + "\x00" + resource.Name
		if seen[identity] {
			return fmt.Errorf("duplicate resource identity %s/%s", resource.Kind, resource.Name)
		}
		seen[identity] = true
	}
	provenance := document.Spec.Evidence.Provenance
	if !safeEvidenceURI(provenance.URI) || !digestPattern.MatchString(provenance.Digest) {
		return fmt.Errorf("provenance evidence requires a safe URI and SHA-256 digest")
	}
	return nil
}

func canonicalSignedPayload(document Document) ([]byte, error) {
	payload := signedPayload{
		APIVersion: document.APIVersion,
		Kind:       document.Kind,
		Metadata:   document.Metadata,
		Spec: signedSpec{
			Resources:  document.Spec.Resources,
			Provenance: document.Spec.Evidence.Provenance,
		},
	}
	return json.Marshal(payload)
}

func sortResources(resources []Resource) {
	sort.Slice(resources, func(i, j int) bool {
		left, right := resources[i], resources[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.URI < right.URI
	})
}

func decodeCanonicalBase64(value string, expectedLength int, name string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedLength || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical base64 encoding of exactly %d bytes", name, expectedLength)
	}
	return decoded, nil
}

func atomicWrite(output string, data []byte) error {
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".infrastructure-export-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, output)
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
