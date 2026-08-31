// Package exports emits and verifies the sole versioned handoff from infrastructure-live to GitOps.
package exports

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyVersionPattern = regexp.MustCompile(
		`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{5,})/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/[1-9][0-9]*$`,
	)
	lineagePattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	namePattern           = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,126}$`)
	projectIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	providerIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~%+:/-]*$`)
	provenancePattern     = regexp.MustCompile(`^https://github\.com/mindclade/infrastructure-live/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$`)
	bucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	locationPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	serviceAccountPattern = regexp.MustCompile(
		`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`,
	)
	providerPathPatterns = map[string]*regexp.Regexp{
		"network":              regexp.MustCompile(`^projects/[^/]+/global/networks/[^/]+$`),
		"subnetwork":           regexp.MustCompile(`^projects/[^/]+/regions/[^/]+/subnetworks/[^/]+$`),
		"private-dns-zone":     regexp.MustCompile(`^projects/[^/]+/managedZones/[^/]+$`),
		"artifact-registry":    regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/repositories/[^/]+$`),
		"database-instance":    regexp.MustCompile(`^projects/[^/]+/instances/[^/]+$`),
		"topic":                regexp.MustCompile(`^projects/[^/]+/topics/[^/]+$`),
		"kms-key-reference":    regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`),
		"gke-cluster":          regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/clusters/[^/]+$`),
		"cluster-membership":   regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/memberships/[^/]+$`),
		"build-execution-pool": regexp.MustCompile(`^projects/[^/]+/regions/[^/]+/instanceGroupManagers/[^/]+$`),
		"log-bucket":           regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/buckets/[^/]+$`),
	}
	providerHosts = map[string]string{
		"network": "compute.googleapis.com", "subnetwork": "compute.googleapis.com",
		"private-dns-zone": "dns.googleapis.com", "artifact-registry": "artifactregistry.googleapis.com",
		"database-instance": "sqladmin.googleapis.com", "topic": "pubsub.googleapis.com",
		"kms-key-reference": "cloudkms.googleapis.com", "gke-cluster": "container.googleapis.com",
		"cluster-membership": "gkehub.googleapis.com", "build-execution-pool": "compute.googleapis.com",
		"log-bucket": "logging.googleapis.com",
	}
	rootPattern = regexp.MustCompile(`^opentofu/live/(development|staging|production|restricted)/(foundation|network|artifacts|data-services|clusters|ci-execution|observability)$`)
)

var (
	validEnvironments = map[string]bool{"development": true, "staging": true, "production": true, "restricted": true}
	validStacks       = map[string]bool{"foundation": true, "network": true, "artifacts": true, "data-services": true, "clusters": true, "ci-execution": true, "observability": true}
)

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

// Signature is a detached GCP KMS HSM ECDSA P-256 signature over the canonical
// signed payload. KeyVersion and PublicKeyDigest are independently qualified
// bootstrap coordinates, while PublicKey embeds canonical PKIX SPKI DER.
type Signature struct {
	Algorithm       string `json:"algorithm"`
	KeyVersion      string `json:"keyVersion"`
	PublicKey       string `json:"publicKey"`
	PublicKeyDigest string `json:"publicKeyDigest"`
	Value           string `json:"value"`
	PayloadDigest   string `json:"payloadDigest"`
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

type foundationOutput struct {
	ProjectID       *string         `json:"project_id"`
	ProjectNumber   json.RawMessage `json:"project_number"`
	EnabledServices json.RawMessage `json:"enabled_services"`
}

type networkOutput struct {
	NetworkID                *string           `json:"network_id"`
	ServiceProjectIDs        json.RawMessage   `json:"service_project_ids"`
	SubnetworkIDs            map[string]string `json:"subnetwork_ids"`
	PrivateServiceConnection json.RawMessage   `json:"private_service_connection"`
	PrivateDNSZoneIDs        map[string]string `json:"private_dns_zone_ids"`
	EgressAddresses          json.RawMessage   `json:"egress_addresses"`
}

type artifactsOutput struct {
	RepositoryIDs     map[string]string `json:"repository_ids"`
	BucketIDs         map[string]string `json:"bucket_ids"`
	KMSKeyIDs         map[string]string `json:"kms_key_ids"`
	CIEvidenceArchive json.RawMessage   `json:"ci_evidence_archive"`
}

type dataServicesOutput struct {
	DatabaseInstanceID     *string           `json:"database_instance_id"`
	DatabaseConnectionName *string           `json:"database_connection_name"`
	TopicIDs               map[string]string `json:"topic_ids"`
	SubscriptionIDs        json.RawMessage   `json:"subscription_ids"`
	SecretReferences       json.RawMessage   `json:"secret_references"`
	KMSKeyIDs              map[string]string `json:"kms_key_ids"`
}

type clustersOutput struct {
	ClusterID                  *string           `json:"cluster_id"`
	ClusterName                json.RawMessage   `json:"cluster_name"`
	WorkloadIdentityPool       *string           `json:"workload_identity_pool"`
	NodePoolIDs                json.RawMessage   `json:"node_pool_ids"`
	WorkloadServiceAccounts    json.RawMessage   `json:"workload_service_accounts"`
	ArgoCDPrerequisiteIdentity *string           `json:"argocd_prerequisite_identity"`
	ClusterMembershipIDs       map[string]string `json:"cluster_membership_ids"`
}

type ciExecutionOutput struct {
	ServiceAccountEmail json.RawMessage `json:"service_account_email"`
	InstanceGroupID     *string         `json:"instance_group_id"`
}

type observabilityOutput struct {
	LogBucketID          *string         `json:"log_bucket_id"`
	MetricsScope         *string         `json:"metrics_scope"`
	SinkWriterIdentities json.RawMessage `json:"sink_writer_identities"`
	KMSKeyIDs            json.RawMessage `json:"kms_key_ids"`
}

type tofuOutputEnvelope struct {
	Sensitive *bool           `json:"sensitive"`
	Type      json.RawMessage `json:"type"`
	Value     json.RawMessage `json:"value"`
}

// ResourcesFromOutput converts the exact resources envelope from full
// `tofu output -json` into provider-free capability references. The full form
// is required so a sensitive or null resources output can never be mistaken
// for a safe value. Ignored provider values are never copied.
func ResourcesFromOutput(stack string, data []byte) ([]Resource, error) {
	if !validStacks[stack] {
		return nil, errors.New("invalid stack for resource derivation")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	value, err := exactResourcesValue(data)
	if err != nil {
		return nil, err
	}
	resources := []Resource{}
	switch stack {
	case "foundation":
		var output foundationOutput
		if err = decodeExactOutput(value, &output); err == nil {
			var projectID string
			projectID, err = requiredString(output.ProjectID, "project_id")
			if err == nil && !projectIDPattern.MatchString(projectID) {
				err = errors.New("project_id is not a canonical GCP project ID")
			}
			if err == nil {
				resources = append(resources, Resource{Kind: "project", Name: projectID, URI: "//cloudresourcemanager.googleapis.com/projects/" + projectID})
			}
		}
	case "network":
		var output networkOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendSingleton(resources, "network", "compute.googleapis.com", output.NetworkID)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "subnetwork", "compute.googleapis.com", output.SubnetworkIDs)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "private-dns-zone", "dns.googleapis.com", output.PrivateDNSZoneIDs)
		}
	case "artifacts":
		var output artifactsOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendResourceMap(resources, "artifact-registry", "artifactregistry.googleapis.com", output.RepositoryIDs)
		}
		if err == nil {
			resources, err = appendBucketMap(resources, output.BucketIDs)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "kms-key-reference", "cloudkms.googleapis.com", output.KMSKeyIDs)
		}
	case "data-services":
		var output dataServicesOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendDatabaseInstance(resources, output.DatabaseInstanceID, output.DatabaseConnectionName)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "topic", "pubsub.googleapis.com", output.TopicIDs)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "kms-key-reference", "cloudkms.googleapis.com", output.KMSKeyIDs)
		}
	case "clusters":
		var output clustersOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendSingleton(resources, "gke-cluster", "container.googleapis.com", output.ClusterID)
		}
		if err == nil {
			resources, err = appendResourceMap(resources, "cluster-membership", "gkehub.googleapis.com", output.ClusterMembershipIDs)
		}
		if err == nil {
			var workloadPool string
			workloadPool, err = requiredString(output.WorkloadIdentityPool, "workload_identity_pool")
			parts := strings.Split(workloadPool, ".svc.id.goog")
			if err == nil && (len(parts) != 2 || parts[1] != "" || !projectIDPattern.MatchString(parts[0])) {
				err = errors.New("workload_identity_pool is not a canonical GKE workload pool")
			}
			if err == nil {
				resources = append(resources, Resource{Kind: "workload-identity-pool", Name: "gke-workload-identity", URI: "//container.googleapis.com/workloadIdentityPools/" + workloadPool})
			}
		}
		if err == nil && output.ArgoCDPrerequisiteIdentity != nil {
			var identity string
			identity, err = requiredString(output.ArgoCDPrerequisiteIdentity, "argocd_prerequisite_identity")
			if err == nil && !serviceAccountPattern.MatchString(identity) {
				err = errors.New("argocd_prerequisite_identity is not a canonical service-account email")
			}
			if err == nil {
				resources = append(resources, Resource{Kind: "argocd-prerequisite", Name: "argocd-controller", URI: "//iam.googleapis.com/projects/-/serviceAccounts/" + identity})
			}
		}
	case "ci-execution":
		var output ciExecutionOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendSingleton(resources, "build-execution-pool", "compute.googleapis.com", output.InstanceGroupID)
		}
	case "observability":
		var output observabilityOutput
		if err = decodeExactOutput(value, &output); err == nil {
			resources, err = appendSingleton(resources, "log-bucket", "logging.googleapis.com", output.LogBucketID)
		}
		if err == nil {
			var projectID string
			projectID, err = requiredString(output.MetricsScope, "metrics_scope")
			if err == nil && !projectIDPattern.MatchString(projectID) {
				err = errors.New("metrics_scope is not a canonical GCP project ID")
			}
			if err == nil {
				resources = append(resources, Resource{Kind: "metrics-scope", Name: "metrics-scope", URI: "//monitoring.googleapis.com/locations/global/metricsScopes/" + projectID})
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if len(resources) == 0 {
		return nil, errors.New("actual resources output contains no exportable capability resources")
	}
	sortResources(resources)
	return resources, nil
}

// WriteResourcesFromOutput atomically writes only the redacted, typed resource array.
func WriteResourcesFromOutput(stack string, data []byte, output string) ([]Resource, error) {
	resources, err := ResourcesFromOutput(stack, data)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(resources)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(output, append(encoded, '\n')); err != nil {
		return nil, err
	}
	return resources, nil
}

// VerifyKMSReadiness binds the bootstrap-qualified public key to the exact key
// freshly observed from KMS and verifies a harmless pre-apply challenge signature.
// It writes canonical SPKI DER for later inclusion in the signed export envelope.
func VerifyKMSReadiness(trustedPEMBase64 string, observedPEM []byte, trustedDigest string, message, signature []byte, outputDER string) error {
	trustedPEM, err := base64.StdEncoding.Strict().DecodeString(trustedPEMBase64)
	if err != nil || base64.StdEncoding.EncodeToString(trustedPEM) != trustedPEMBase64 {
		return errors.New("bootstrap-qualified public key must be canonical base64")
	}
	trustedDER, trustedKey, err := parseP256PublicKey(trustedPEM, "bootstrap-qualified")
	if err != nil {
		return err
	}
	observedDER, observedKey, err := parseP256PublicKey(observedPEM, "KMS-observed")
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(trustedDER, observedDER) != 1 || !trustedKey.Equal(observedKey) {
		return errors.New("KMS-observed public key does not match the bootstrap-qualified key")
	}
	digest := sha256.Sum256(trustedDER)
	actualDigest := "sha256:" + hex.EncodeToString(digest[:])
	if !digestPattern.MatchString(trustedDigest) || subtle.ConstantTimeCompare([]byte(trustedDigest), []byte(actualDigest)) != 1 {
		return errors.New("canonical SPKI public-key digest does not match bootstrap qualification")
	}
	if len(message) == 0 || len(message) > 4096 || len(signature) < 8 || len(signature) > 256 {
		return errors.New("readiness challenge or signature has an invalid length")
	}
	messageDigest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(observedKey, messageDigest[:], signature) {
		return errors.New("KMS readiness challenge signature verification failed")
	}
	return atomicWrite(outputDER, trustedDER)
}

// CanonicalPayload returns the exact bytes that an independently controlled
// GCP KMS signer must sign. The payload binds metadata, resource references,
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
// exact KMS key version and public-key digest, then writes canonical compact JSON atomically.
func Emit(input Input, signature Signature, trustedKeyVersion, trustedPublicKeyDigest, output string) (Document, error) {
	_, document, err := CanonicalPayload(input)
	if err != nil {
		return Document{}, err
	}
	document.Spec.Evidence.Signature = signature
	if !keyVersionPattern.MatchString(trustedKeyVersion) ||
		subtle.ConstantTimeCompare([]byte(signature.KeyVersion), []byte(trustedKeyVersion)) != 1 {
		return Document{}, errors.New("signature keyVersion does not match the independently supplied trusted KMS key version")
	}
	if !digestPattern.MatchString(trustedPublicKeyDigest) ||
		subtle.ConstantTimeCompare([]byte(signature.PublicKeyDigest), []byte(trustedPublicKeyDigest)) != 1 {
		return Document{}, errors.New("signature publicKeyDigest does not match the independently supplied trusted public-key digest")
	}
	if validationErr := Validate(document); validationErr != nil {
		return Document{}, validationErr
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
	if signature.Algorithm != "EC_SIGN_P256_SHA256" {
		return errors.New("signature algorithm must be EC_SIGN_P256_SHA256")
	}
	if !keyVersionPattern.MatchString(signature.KeyVersion) {
		return errors.New("signature keyVersion must be the exact bootstrap infrastructure-export key version")
	}
	publicKeyDER, err := decodeCanonicalBase64Range(signature.PublicKey, 64, 512, "signature public key")
	if err != nil {
		return err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("signature public key must be canonical PKIX SubjectPublicKeyInfo: %w", err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("signature public key must be ECDSA P-256")
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || subtle.ConstantTimeCompare(canonicalDER, publicKeyDER) != 1 {
		return errors.New("signature public key must use canonical PKIX SubjectPublicKeyInfo DER")
	}
	signatureValue, err := decodeCanonicalBase64Range(signature.Value, 8, 256, "signature value")
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256(publicKeyDER)
	expectedPublicKeyDigest := "sha256:" + hex.EncodeToString(keyDigest[:])
	if subtle.ConstantTimeCompare([]byte(signature.PublicKeyDigest), []byte(expectedPublicKeyDigest)) != 1 {
		return errors.New("signature publicKeyDigest does not match the embedded public key")
	}
	payloadHash := sha256.Sum256(payload)
	expectedPayloadDigest := "sha256:" + hex.EncodeToString(payloadHash[:])
	if signature.PayloadDigest != expectedPayloadDigest {
		return errors.New("signature payloadDigest does not match the canonical export payload")
	}
	if !ecdsa.VerifyASN1(publicKey, payloadHash[:], signatureValue) {
		return errors.New("GCP KMS ECDSA P-256 signature verification failed")
	}
	return nil
}

func validateUnsigned(document Document) error {
	metadata := document.Metadata
	if document.APIVersion != APIVersion || document.Kind != Kind {
		return errors.New("invalid infrastructure export type metadata")
	}
	if !validEnvironments[metadata.Environment] || !validStacks[metadata.Stack] {
		return errors.New("invalid environment or stack")
	}
	if metadata.SourceRepository != "mindclade/infrastructure-live" || !commitPattern.MatchString(metadata.SourceCommit) {
		return errors.New("source repository and full commit are required")
	}
	if metadata.Root != "opentofu/live/"+metadata.Environment+"/"+metadata.Stack || !rootPattern.MatchString(metadata.Root) {
		return errors.New("root does not match the environment and stack")
	}
	if !digestPattern.MatchString(metadata.PlanDigest) ||
		!digestPattern.MatchString(metadata.ProviderLockDigest) ||
		!digestPattern.MatchString(metadata.BackendStateDigest) ||
		!digestPattern.MatchString(metadata.SchemaDigest) {
		return errors.New("plan, provider-lock, backend-state, and schema SHA-256 digests are required")
	}
	if !lineagePattern.MatchString(metadata.BackendLineage) {
		return errors.New("a canonical backend lineage UUID is required")
	}
	parsedTime, err := time.Parse(time.RFC3339, metadata.GeneratedAt)
	if err != nil || parsedTime.Format(time.RFC3339) != metadata.GeneratedAt || !strings.HasSuffix(metadata.GeneratedAt, "Z") {
		return errors.New("generatedAt must be canonical RFC3339 UTC evidence time")
	}
	if len(document.Spec.Resources) == 0 {
		return errors.New("at least one non-sensitive resource reference is required")
	}
	seen := map[string]bool{}
	for _, resource := range document.Spec.Resources {
		if !catalog.AllowsExportKind(metadata.Stack, resource.Kind) {
			return fmt.Errorf("resource kind %q is not allowed for stack %q", resource.Kind, metadata.Stack)
		}
		if !namePattern.MatchString(resource.Name) || !safeResourceURI(resource.URI) || !validCapabilityResourceURI(resource.Kind, resource.URI) {
			return errors.New("every resource requires kind, name, and a safe URI")
		}
		identity := resource.Kind + "\x00" + resource.Name
		if seen[identity] {
			return fmt.Errorf("duplicate resource identity %s/%s", resource.Kind, resource.Name)
		}
		seen[identity] = true
	}
	provenance := document.Spec.Evidence.Provenance
	if !safeEvidenceURI(provenance.URI) || !provenancePattern.MatchString(provenance.URI) || !digestPattern.MatchString(provenance.Digest) {
		return errors.New("provenance evidence requires a safe URI and SHA-256 digest")
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

func decodeCanonicalBase64Range(value string, minimumLength, maximumLength int, name string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimumLength || len(decoded) > maximumLength || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical base64 encoding of %d to %d bytes", name, minimumLength, maximumLength)
	}
	return decoded, nil
}

func parseP256PublicKey(publicPEM []byte, authority string) ([]byte, *ecdsa.PublicKey, error) {
	if len(publicPEM) == 0 || len(publicPEM) > 16*1024 {
		return nil, nil, fmt.Errorf("%s public key has an invalid length", authority)
	}
	block, trailing := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || strings.TrimSpace(string(trailing)) != "" {
		return nil, nil, fmt.Errorf("%s public key must contain exactly one PKIX PUBLIC KEY PEM block", authority)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s public key: %w", authority, err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("%s public key must be ECDSA P-256", authority)
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || subtle.ConstantTimeCompare(canonicalDER, block.Bytes) != 1 {
		return nil, nil, fmt.Errorf("%s public key must use canonical PKIX SubjectPublicKeyInfo DER", authority)
	}
	return canonicalDER, publicKey, nil
}

func exactResourcesValue(data []byte) ([]byte, error) {
	var outputs map[string]json.RawMessage
	if err := json.Unmarshal(data, &outputs); err != nil || outputs == nil {
		return nil, errors.New("parse full tofu output: expected one JSON object")
	}
	rawEnvelope, ok := outputs["resources"]
	if !ok {
		return nil, errors.New("full tofu output omits the resources envelope")
	}
	var envelope tofuOutputEnvelope
	if err := decodeExactOutput(rawEnvelope, &envelope); err != nil {
		return nil, fmt.Errorf("parse resources envelope: %w", err)
	}
	if envelope.Sensitive == nil || *envelope.Sensitive {
		return nil, errors.New("resources output must be explicitly non-sensitive")
	}
	outputType := bytes.TrimSpace(envelope.Type)
	value := bytes.TrimSpace(envelope.Value)
	if len(outputType) < 2 || outputType[0] != '[' || bytes.Equal(outputType, []byte("null")) {
		return nil, errors.New("resources output must have an explicit object type")
	}
	if len(value) < 2 || value[0] != '{' || bytes.Equal(value, []byte("null")) {
		return nil, errors.New("resources output value must be a non-null object")
	}
	return value, nil
}

func decodeExactOutput(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("parse actual resources output: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("actual resources output contains multiple JSON values")
		}
		return fmt.Errorf("parse trailing actual resources output: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("actual resources output contains a duplicate or invalid object key")
				}
				seen[key] = true
				if walkErr := walk(); walkErr != nil {
					return walkErr
				}
			}
		case '[':
			for decoder.More() {
				if walkErr := walk(); walkErr != nil {
					return walkErr
				}
			}
		default:
			return errors.New("actual resources output has invalid JSON structure")
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return fmt.Errorf("parse actual resources output: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("actual resources output contains multiple JSON values")
		}
		return fmt.Errorf("parse trailing actual resources output: %w", err)
	}
	return nil
}

func requiredString(value *string, field string) (string, error) {
	if value == nil || *value == "" || strings.TrimSpace(*value) != *value {
		return "", fmt.Errorf("actual resources output %s must be a nonempty, non-sensitive string", field)
	}
	return *value, nil
}

func appendSingleton(resources []Resource, kind, host string, value *string) ([]Resource, error) {
	raw, err := requiredString(value, kind)
	if err != nil {
		return nil, err
	}
	uri, name, err := canonicalProviderResource(kind, host, raw)
	if err != nil {
		return nil, err
	}
	return append(resources, Resource{Kind: kind, Name: name, URI: uri}), nil
}

func appendResourceMap(resources []Resource, kind, host string, values map[string]string) ([]Resource, error) {
	if values == nil {
		return nil, fmt.Errorf("actual resources output %s map must not be null or omitted", kind)
	}
	if len(values) == 0 {
		return resources, nil
	}
	for name, raw := range values {
		if !namePattern.MatchString(name) || raw == "" || strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("actual resources output %s contains an empty or unsafe entry", kind)
		}
		uri, _, err := canonicalProviderResource(kind, host, raw)
		if err != nil {
			return nil, err
		}
		resources = append(resources, Resource{Kind: kind, Name: name, URI: uri})
	}
	return resources, nil
}

func appendBucketMap(resources []Resource, values map[string]string) ([]Resource, error) {
	if values == nil {
		return nil, errors.New("actual resources output artifact-bucket map must not be null or omitted")
	}
	if len(values) == 0 {
		return resources, nil
	}
	for name, bucket := range values {
		if !namePattern.MatchString(name) || !bucketPattern.MatchString(bucket) {
			return nil, errors.New("actual resources output artifact-bucket contains an empty or unsafe entry")
		}
		resources = append(resources, Resource{Kind: "artifact-bucket", Name: name, URI: "//storage.googleapis.com/" + bucket})
	}
	return resources, nil
}

func appendDatabaseInstance(resources []Resource, instanceID, connectionName *string) ([]Resource, error) {
	if instanceID == nil && connectionName == nil {
		return resources, nil
	}
	instance, err := requiredString(instanceID, "database_instance_id")
	if err != nil {
		return nil, err
	}
	connection, err := requiredString(connectionName, "database_connection_name")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(connection, ":")
	if len(parts) != 3 || !projectIDPattern.MatchString(parts[0]) ||
		!locationPattern.MatchString(parts[1]) || !namePattern.MatchString(parts[2]) {
		return nil, errors.New("database_connection_name is not a canonical Cloud SQL connection name")
	}
	canonicalPath := "projects/" + parts[0] + "/instances/" + parts[2]
	if instance != canonicalPath && instance != parts[0]+"/"+parts[2] && instance != parts[2] {
		return nil, errors.New("database_instance_id does not identify the actual Cloud SQL connection name")
	}
	uri, name, err := canonicalProviderResource("database-instance", "sqladmin.googleapis.com", canonicalPath)
	if err != nil {
		return nil, err
	}
	return append(resources, Resource{Kind: "database-instance", Name: name, URI: uri}), nil
}

func canonicalProviderResource(kind, host, raw string) (string, string, error) {
	if len(raw) > 2048 || !providerIDPattern.MatchString(raw) || strings.Contains(raw, "//") || strings.HasPrefix(raw, "/") {
		return "", "", fmt.Errorf("actual resources output %s contains an unsafe provider ID", kind)
	}
	path := raw
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", fmt.Errorf("actual resources output %s contains an unsafe provider path", kind)
		}
	}
	pattern := providerPathPatterns[kind]
	if pattern == nil || !pattern.MatchString(path) {
		return "", "", fmt.Errorf("actual resources output %s does not match its canonical provider resource shape", kind)
	}
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	if !namePattern.MatchString(name) {
		return "", "", fmt.Errorf("actual resources output %s has an unsafe resource name", kind)
	}
	uri := "//" + host + "/" + path
	if !safeResourceURI(uri) {
		return "", "", fmt.Errorf("actual resources output %s produced an unsafe URI", kind)
	}
	return uri, name, nil
}

func atomicWrite(output string, data []byte) error {
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".infrastructure-export-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryName) // Best-effort cleanup after rename or failure.
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, output)
}

func safeResourceURI(raw string) bool {
	return safeURI(raw, true)
}

func validCapabilityResourceURI(kind, raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || !strings.HasPrefix(raw, "//") {
		return false
	}
	path := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if pattern := providerPathPatterns[kind]; pattern != nil {
		return parsed.Hostname() == providerHosts[kind] && pattern.MatchString(path)
	}
	switch kind {
	case "project":
		return parsed.Hostname() == "cloudresourcemanager.googleapis.com" &&
			strings.HasPrefix(path, "projects/") && projectIDPattern.MatchString(strings.TrimPrefix(path, "projects/"))
	case "artifact-bucket":
		return parsed.Hostname() == "storage.googleapis.com" && bucketPattern.MatchString(path)
	case "workload-identity-pool":
		value := strings.TrimPrefix(path, "workloadIdentityPools/")
		project := strings.TrimSuffix(value, ".svc.id.goog")
		return parsed.Hostname() == "container.googleapis.com" && value != path && project != value && projectIDPattern.MatchString(project)
	case "argocd-prerequisite":
		identity := strings.TrimPrefix(path, "projects/-/serviceAccounts/")
		return parsed.Hostname() == "iam.googleapis.com" && identity != path && serviceAccountPattern.MatchString(identity)
	case "metrics-scope":
		project := strings.TrimPrefix(path, "locations/global/metricsScopes/")
		return parsed.Hostname() == "monitoring.googleapis.com" && project != path && projectIDPattern.MatchString(project)
	default:
		return false
	}
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
