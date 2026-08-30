// infractl is the fail-closed interface for source validation and immutable infrastructure evidence.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	signaturePath := flags.String("signature", "", "detached Ed25519 signature envelope JSON")
	trustedKeyID := flags.String("trusted-key-id", "", "independently supplied trusted Ed25519 public-key digest")
	output := flags.String("output", "", "output JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *resourcesPath == "" || *output == "" {
		return fmt.Errorf("--resources and --output are required")
	}
	data, err := os.ReadFile(*resourcesPath)
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
	if *signaturePath == "" || *trustedKeyID == "" {
		return fmt.Errorf("--signature and --trusted-key-id are required for exports emit")
	}
	signatureData, err := os.ReadFile(*signaturePath)
	if err != nil {
		return err
	}
	var signature exports.Signature
	if err := json.Unmarshal(signatureData, &signature); err != nil {
		return fmt.Errorf("parse detached signature: %w", err)
	}
	document, err := exports.Emit(input, signature, *trustedKeyID, *output)
	if err != nil {
		return err
	}
	return emit(os.Stdout, map[string]any{"ok": true, "output": *output, "environment": document.Metadata.Environment, "stack": document.Metadata.Stack})
}

func emit(writer *os.File, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
