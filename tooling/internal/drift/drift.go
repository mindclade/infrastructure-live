// Package drift compares canonical JSON observations without leaking values.
package drift

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const ReconciliationAPIVersion = "infrastructure.mindclade.dev/partial-apply-reconciliation/v1"

var (
	reconciliationCommitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reconciliationDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reconciliationLineagePattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	reconciliationOperationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$`)
	reconciliationRootPattern      = regexp.MustCompile(`^opentofu/live/(development|staging|production|restricted)/(foundation|network|artifacts|data-services|clusters|ci-execution|observability)$`)
	reconciliationAddressPattern   = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.\[\]"/-]{0,511}$`)
)

// Finding identifies only a JSON path and disposition; values remain redacted.
type Finding struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// Report is deterministic for the same desired and observed documents.
type Report struct {
	DesiredDigest  string    `json:"desiredDigest"`
	ObservedDigest string    `json:"observedDigest"`
	Clean          bool      `json:"clean"`
	Findings       []Finding `json:"findings"`
}

type ReconciliationBackend struct {
	Lineage string `json:"lineage"`
	Serial  uint64 `json:"serial"`
}

type ReconciliationResource struct {
	Address     string `json:"address"`
	ProviderID  string `json:"providerId"`
	StateDigest string `json:"stateDigest"`
}

// ReconciliationDocument is a redacted, provider-identity-aware state observation.
type ReconciliationDocument struct {
	APIVersion   string                   `json:"apiVersion"`
	Kind         string                   `json:"kind"`
	Root         string                   `json:"root"`
	SourceCommit string                   `json:"sourceCommit"`
	PlanDigest   string                   `json:"planDigest"`
	OperationID  string                   `json:"operationId"`
	Backend      ReconciliationBackend    `json:"backend"`
	Resources    []ReconciliationResource `json:"resources"`
}

// ReconciliationReport never authorizes replay of an ambiguously interrupted apply.
type ReconciliationReport struct {
	Root                  string    `json:"root"`
	PlanDigest            string    `json:"planDigest"`
	PriorBackendSerial    uint64    `json:"priorBackendSerial"`
	ObservedBackendSerial uint64    `json:"observedBackendSerial"`
	Clean                 bool      `json:"clean"`
	ResumeAllowed         bool      `json:"resumeAllowed"`
	NextAction            string    `json:"nextAction"`
	Findings              []Finding `json:"findings"`
}

// ClassifyFiles compares JSON documents and ignores no fields.
func ClassifyFiles(desiredPath, observedPath string) (Report, error) {
	desired, err := os.ReadFile(desiredPath)
	if err != nil {
		return Report{}, err
	}
	observed, err := os.ReadFile(observedPath)
	if err != nil {
		return Report{}, err
	}
	return Classify(desired, observed)
}

// Classify reports missing, unmanaged, and changed paths without their content.
func Classify(desiredData, observedData []byte) (Report, error) {
	desired, err := decodeJSON(desiredData)
	if err != nil {
		return Report{}, fmt.Errorf("parse desired JSON: %w", err)
	}
	observed, err := decodeJSON(observedData)
	if err != nil {
		return Report{}, fmt.Errorf("parse observed JSON: %w", err)
	}
	desiredDigest := sha256.Sum256(desiredData)
	observedDigest := sha256.Sum256(observedData)
	report := Report{
		DesiredDigest:  "sha256:" + hex.EncodeToString(desiredDigest[:]),
		ObservedDigest: "sha256:" + hex.EncodeToString(observedDigest[:]),
		Findings:       []Finding{},
	}
	compare("$", desired, observed, &report.Findings)
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Path == report.Findings[j].Path {
			return report.Findings[i].Kind < report.Findings[j].Kind
		}
		return report.Findings[i].Path < report.Findings[j].Path
	})
	report.Clean = len(report.Findings) == 0
	return report, nil
}

// ReconcileFiles compares structured pre-apply and post-failure state snapshots.
func ReconcileFiles(desiredPath, observedPath string) (ReconciliationReport, error) {
	desired, err := os.ReadFile(desiredPath)
	if err != nil {
		return ReconciliationReport{}, err
	}
	observed, err := os.ReadFile(observedPath)
	if err != nil {
		return ReconciliationReport{}, err
	}
	return Reconcile(desired, observed)
}

// Reconcile requires exact transaction identity, bounded backend advancement,
// and stable provider resource identities before classifying partial state.
func Reconcile(desiredData, observedData []byte) (ReconciliationReport, error) {
	var desired, observed ReconciliationDocument
	if err := decodeStrictJSON(desiredData, &desired); err != nil {
		return ReconciliationReport{}, fmt.Errorf("parse desired reconciliation document: %w", err)
	}
	if err := decodeStrictJSON(observedData, &observed); err != nil {
		return ReconciliationReport{}, fmt.Errorf("parse observed reconciliation document: %w", err)
	}
	desiredResources, err := validateReconciliationDocument(desired)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("invalid desired reconciliation document: %w", err)
	}
	observedResources, err := validateReconciliationDocument(observed)
	if err != nil {
		return ReconciliationReport{}, fmt.Errorf("invalid observed reconciliation document: %w", err)
	}
	if desired.Root != observed.Root || desired.SourceCommit != observed.SourceCommit ||
		desired.PlanDigest != observed.PlanDigest || desired.OperationID != observed.OperationID {
		return ReconciliationReport{}, fmt.Errorf("observed reconciliation transaction identity does not match the reviewed plan")
	}
	if desired.Backend.Lineage != observed.Backend.Lineage {
		return ReconciliationReport{}, fmt.Errorf("backend lineage changed; manual recovery review is required")
	}
	if observed.Backend.Serial < desired.Backend.Serial || observed.Backend.Serial > desired.Backend.Serial+1 {
		return ReconciliationReport{}, fmt.Errorf("backend serial advanced outside the single interrupted apply boundary")
	}

	findings := []Finding{}
	addresses := make([]string, 0, len(desiredResources))
	for address := range desiredResources {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		expected := desiredResources[address]
		actual, ok := observedResources[address]
		if !ok {
			findings = append(findings, Finding{Path: address, Kind: "missing"})
			continue
		}
		if expected.ProviderID != actual.ProviderID || expected.StateDigest != actual.StateDigest {
			findings = append(findings, Finding{Path: address, Kind: "changed"})
		}
	}
	for address := range observedResources {
		if _, ok := desiredResources[address]; !ok {
			findings = append(findings, Finding{Path: address, Kind: "unmanaged"})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].Path < findings[j].Path
	})
	nextAction := "replan-from-refreshed-state"
	if len(findings) > 0 {
		nextAction = "refresh-import-compare-then-replan"
	}
	return ReconciliationReport{
		Root:                  desired.Root,
		PlanDigest:            desired.PlanDigest,
		PriorBackendSerial:    desired.Backend.Serial,
		ObservedBackendSerial: observed.Backend.Serial,
		Clean:                 len(findings) == 0,
		ResumeAllowed:         false,
		NextAction:            nextAction,
		Findings:              findings,
	}, nil
}

func validateReconciliationDocument(document ReconciliationDocument) (map[string]ReconciliationResource, error) {
	if document.APIVersion != ReconciliationAPIVersion || document.Kind != "PartialApplyReconciliation" {
		return nil, fmt.Errorf("invalid reconciliation type metadata")
	}
	if !reconciliationRootPattern.MatchString(document.Root) || !reconciliationCommitPattern.MatchString(document.SourceCommit) ||
		!reconciliationDigestPattern.MatchString(document.PlanDigest) || !reconciliationOperationPattern.MatchString(document.OperationID) ||
		!reconciliationLineagePattern.MatchString(document.Backend.Lineage) {
		return nil, fmt.Errorf("root, source commit, plan digest, operation, and backend lineage must be canonical")
	}
	if len(document.Resources) == 0 {
		return nil, fmt.Errorf("at least one provider resource observation is required")
	}
	resources := make(map[string]ReconciliationResource, len(document.Resources))
	for _, resource := range document.Resources {
		if !reconciliationAddressPattern.MatchString(resource.Address) ||
			len(resource.ProviderID) == 0 || len(resource.ProviderID) > 2048 || strings.TrimSpace(resource.ProviderID) != resource.ProviderID ||
			strings.ContainsAny(resource.ProviderID, "\r\n\t") || !reconciliationDigestPattern.MatchString(resource.StateDigest) {
			return nil, fmt.Errorf("resource address, provider ID, and redacted state digest must be canonical")
		}
		if _, exists := resources[resource.Address]; exists {
			return nil, fmt.Errorf("duplicate resource address %q", resource.Address)
		}
		resources[resource.Address] = resource
	}
	return resources, nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func compare(path string, desired, observed any, findings *[]Finding) {
	if reflect.TypeOf(desired) != reflect.TypeOf(observed) {
		*findings = append(*findings, Finding{Path: path, Kind: "changed"})
		return
	}
	switch expected := desired.(type) {
	case map[string]any:
		actual := observed.(map[string]any)
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			actualValue, ok := actual[key]
			if !ok {
				*findings = append(*findings, Finding{Path: path + "." + key, Kind: "missing"})
				continue
			}
			compare(path+"."+key, expected[key], actualValue, findings)
		}
		for key := range actual {
			if _, ok := expected[key]; !ok {
				*findings = append(*findings, Finding{Path: path + "." + key, Kind: "unmanaged"})
			}
		}
	case []any:
		actual := observed.([]any)
		if len(expected) != len(actual) {
			*findings = append(*findings, Finding{Path: path, Kind: "changed"})
			return
		}
		for index := range expected {
			compare(fmt.Sprintf("%s[%d]", path, index), expected[index], actual[index], findings)
		}
	default:
		if !reflect.DeepEqual(desired, observed) {
			*findings = append(*findings, Finding{Path: path, Kind: "changed"})
		}
	}
}
