// infractl is the fail-closed interface for source validation and immutable infrastructure evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mindclade/infrastructure-live/tooling/internal/catalog"
	"github.com/mindclade/infrastructure-live/tooling/internal/drift"
	"github.com/mindclade/infrastructure-live/tooling/internal/exports"
	"github.com/mindclade/infrastructure-live/tooling/internal/plan"
	"github.com/mindclade/infrastructure-live/tooling/internal/policy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_ = emit(os.Stderr, map[string]any{"ok": false, "error": err.Error()})
		var classified interface{ ExitCode() int }
		if errors.As(err, &classified) {
			os.Exit(classified.ExitCode())
		}
		os.Exit(1)
	}
}

type outcomeError struct {
	message string
	code    int
}

func (e outcomeError) Error() string { return e.message }
func (e outcomeError) ExitCode() int { return e.code }

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: infractl domain operation")
	}
	switch args[0] + " " + args[1] {
	case "catalog validate":
		flags := flag.NewFlagSet("catalog validate", flag.ContinueOnError)
		root := flags.String("root", ".", "repository root")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		result, err := catalog.ValidateRepository(*root)
		_ = emit(os.Stdout, result)
		return err
	case "plan classify":
		flags := flag.NewFlagSet("plan classify", flag.ContinueOnError)
		input := flags.String("input", "", "OpenTofu plan JSON")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if *input == "" {
			return fmt.Errorf("--input is required")
		}
		report, err := plan.ClassifyFile(*input)
		if err != nil {
			return err
		}
		if err := emit(os.Stdout, report); err != nil {
			return err
		}
		if !report.Safe {
			return outcomeError{message: "plan contains delete or replacement actions", code: 2}
		}
		return nil
	case "policy verify":
		flags := flag.NewFlagSet("policy verify", flag.ContinueOnError)
		root := flags.String("root", ".", "repository root")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		result, err := policy.Verify(*root)
		_ = emit(os.Stdout, result)
		return err
	case "drift classify":
		flags := flag.NewFlagSet("drift classify", flag.ContinueOnError)
		desired := flags.String("desired", "", "desired JSON")
		observed := flags.String("observed", "", "observed JSON")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if *desired == "" || *observed == "" {
			return fmt.Errorf("--desired and --observed are required")
		}
		report, err := drift.ClassifyFiles(*desired, *observed)
		if err != nil {
			return err
		}
		if err := emit(os.Stdout, report); err != nil {
			return err
		}
		if !report.Clean {
			return outcomeError{message: "drift detected", code: 2}
		}
		return nil
	case "reconciliation verify":
		flags := flag.NewFlagSet("reconciliation verify", flag.ContinueOnError)
		desired := flags.String("desired", "", "reviewed pre-apply reconciliation JSON")
		observed := flags.String("observed", "", "refreshed post-failure reconciliation JSON")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if *desired == "" || *observed == "" {
			return fmt.Errorf("--desired and --observed are required")
		}
		report, err := drift.ReconcileFiles(*desired, *observed)
		if err != nil {
			return err
		}
		if err := emit(os.Stdout, report); err != nil {
			return err
		}
		if !report.Clean {
			return outcomeError{message: "partial apply requires refresh/import comparison and a new plan", code: 2}
		}
		return nil
	case "exports emit":
		return writeExport(args[2:], true)
	case "exports payload":
		return writeExport(args[2:], false)
	case "exports resources":
		return writeExportResources(args[2:])
	case "exports kms-readiness":
		return verifyKMSReadiness(args[2:])
	default:
		return fmt.Errorf("unknown command %q", strings.Join(args[:2], " "))
	}
}

func writeExport(args []string, signed bool) error {
	operation := "payload"
	if signed {
		operation = "emit"
	}
	flags := flag.NewFlagSet("exports "+operation, flag.ContinueOnError)
	environment := flags.String("environment", "", "catalog environment")
	stack := flags.String("stack", "", "stack name")
	commit := flags.String("source-commit", "", "full source commit")
	planDigest := flags.String("plan-digest", "", "sha256 plan digest")
	providerLockDigest := flags.String("provider-lock-digest", "", "sha256 transient provider-lock digest")
	backendStateDigest := flags.String("backend-state-digest", "", "sha256 canonical backend-state digest")
	backendLineage := flags.String("backend-lineage", "", "canonical backend lineage UUID")
	backendSerial := flags.Uint64("backend-serial", 0, "exact backend state serial used by the plan")
	schemaDigest := flags.String("schema-digest", "", "sha256 schema digest")
	generatedAt := flags.String("generated-at", "", "canonical RFC3339 evidence time")
	resourcesPath := flags.String("resources", "", "JSON resource reference array")
	provenanceURI := flags.String("provenance-uri", "", "immutable provenance URI")
	provenanceDigest := flags.String("provenance-digest", "", "provenance SHA-256 digest")
	signaturePath := flags.String("signature", "", "detached GCP KMS ECDSA signature envelope JSON")
	trustedKeyVersion := flags.String("trusted-key-version", "", "independently supplied exact GCP KMS key version")
	trustedPublicKeyDigest := flags.String("trusted-public-key-digest", "", "independently supplied canonical SPKI SHA-256 digest")
	output := flags.String("output", "", "output JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *resourcesPath == "" || *output == "" {
		return fmt.Errorf("--resources and --output are required")
	}
	data, err := readBoundedInput(*resourcesPath, 8*1024*1024)
	if err != nil {
		return err
	}
	var resources []exports.Resource
	if err := json.Unmarshal(data, &resources); err != nil {
		return fmt.Errorf("parse resources: %w", err)
	}
	root := "opentofu/live/" + *environment + "/" + *stack
	input := exports.Input{
		Metadata: exports.Metadata{
			Environment: *environment, Stack: *stack, SourceRepository: "mindclade/infrastructure-live",
			SourceCommit: *commit, Root: root, PlanDigest: *planDigest,
			ProviderLockDigest: *providerLockDigest, BackendStateDigest: *backendStateDigest,
			BackendLineage: *backendLineage, BackendSerial: *backendSerial,
			SchemaDigest: *schemaDigest, GeneratedAt: *generatedAt,
		},
		Resources:  resources,
		Provenance: exports.Reference{URI: *provenanceURI, Digest: *provenanceDigest},
	}
	if !signed {
		document, err := exports.WritePayload(input, *output)
		if err != nil {
			return err
		}
		return emit(os.Stdout, map[string]any{"ok": true, "output": *output, "environment": document.Metadata.Environment, "stack": document.Metadata.Stack})
	}
	if *signaturePath == "" || *trustedKeyVersion == "" || *trustedPublicKeyDigest == "" {
		return fmt.Errorf("--signature, --trusted-key-version, and --trusted-public-key-digest are required for exports emit")
	}
	signatureData, err := readBoundedInput(*signaturePath, 16*1024)
	if err != nil {
		return err
	}
	var signature exports.Signature
	if err := json.Unmarshal(signatureData, &signature); err != nil {
		return fmt.Errorf("parse detached signature: %w", err)
	}
	document, err := exports.Emit(input, signature, *trustedKeyVersion, *trustedPublicKeyDigest, *output)
	if err != nil {
		return err
	}
	return emit(os.Stdout, map[string]any{"ok": true, "output": *output, "environment": document.Metadata.Environment, "stack": document.Metadata.Stack})
}

func writeExportResources(args []string) error {
	flags := flag.NewFlagSet("exports resources", flag.ContinueOnError)
	stack := flags.String("stack", "", "stack name")
	input := flags.String("input", "", "full tofu output -json document, or - for stdin")
	output := flags.String("output", "", "redacted typed resource array path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *stack == "" || *input == "" || *output == "" {
		return fmt.Errorf("--stack, --input, and --output are required")
	}
	data, err := readBoundedInput(*input, 8*1024*1024)
	if err != nil {
		return err
	}
	resources, err := exports.WriteResourcesFromOutput(*stack, data, *output)
	if err != nil {
		return err
	}
	return emit(os.Stdout, map[string]any{"ok": true, "output": *output, "stack": *stack, "resources": len(resources)})
}

func verifyKMSReadiness(args []string) error {
	flags := flag.NewFlagSet("exports kms-readiness", flag.ContinueOnError)
	trustedPublicKey := flags.String("trusted-public-key-base64", "", "bootstrap-qualified PKIX public-key PEM as canonical base64")
	observedPublicKey := flags.String("observed-public-key", "", "public-key PEM fetched from the exact KMS key version")
	trustedPublicKeyDigest := flags.String("trusted-public-key-digest", "", "bootstrap-qualified canonical SPKI SHA-256 digest")
	message := flags.String("message", "", "harmless readiness challenge path")
	signature := flags.String("signature", "", "detached KMS challenge signature path")
	outputDER := flags.String("output-public-key-der", "", "qualified canonical SPKI DER output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *trustedPublicKey == "" || *observedPublicKey == "" || *trustedPublicKeyDigest == "" ||
		*message == "" || *signature == "" || *outputDER == "" {
		return fmt.Errorf("exports kms-readiness requires the complete trusted key, observed key, digest, challenge, signature, and DER output set")
	}
	observed, err := readBoundedInput(*observedPublicKey, 16*1024)
	if err != nil {
		return err
	}
	challenge, err := readBoundedInput(*message, 4096)
	if err != nil {
		return err
	}
	detached, err := readBoundedInput(*signature, 256)
	if err != nil {
		return err
	}
	if err := exports.VerifyKMSReadiness(*trustedPublicKey, observed, *trustedPublicKeyDigest, challenge, detached, *outputDER); err != nil {
		return err
	}
	return emit(os.Stdout, map[string]any{"ok": true, "algorithm": "EC_SIGN_P256_SHA256", "publicKeyDigest": *trustedPublicKeyDigest})
}

func readBoundedInput(path string, maximum int64) ([]byte, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > maximum {
			return nil, fmt.Errorf("input %s must be a bounded regular file", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() > maximum {
			return nil, fmt.Errorf("input %s changed identity or exceeded its bound while opening", path)
		}
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > maximum {
		return nil, fmt.Errorf("input %s must contain 1 to %d bytes", path, maximum)
	}
	return data, nil
}

func emit(writer *os.File, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
