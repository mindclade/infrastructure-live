// Package drift compares canonical JSON observations without leaking values.
package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
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
	var desired, observed any
	if err := json.Unmarshal(desiredData, &desired); err != nil {
		return Report{}, fmt.Errorf("parse desired JSON: %w", err)
	}
	if err := json.Unmarshal(observedData, &observed); err != nil {
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
