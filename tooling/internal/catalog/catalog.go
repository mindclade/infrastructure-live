// Package catalog validates the versioned, provider-free infrastructure catalogs.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

var catalogSchemas = map[string]string{
	"catalog/environments.yaml":         "schemas/v1/environment.schema.json",
	"catalog/regions.yaml":              "schemas/v1/region.schema.json",
	"catalog/project-classes.yaml":      "schemas/v1/project_class.schema.json",
	"catalog/data-classes.yaml":         "schemas/v1/data_class.schema.json",
	"catalog/resource-profiles.yaml":    "schemas/v1/resource_profile.schema.json",
	"catalog/accelerator-profiles.yaml": "schemas/v1/accelerator_profile.schema.json",
	"catalog/service-capabilities.yaml": "schemas/v1/service_capability.schema.json",
}

var prohibitedKey = regexp.MustCompile(`(?i)^(password|token|credential|credentials|private[_-]?key|secret[_-]?value|kubeconfig)$`)

var liveStacks = []string{
	"foundation",
	"network",
	"artifacts",
	"data-services",
	"clusters",
	"ci-execution",
	"observability",
}

var requiredAPIsByStack = map[string][]string{
	"foundation":    {"cloudbilling.googleapis.com", "cloudresourcemanager.googleapis.com", "iam.googleapis.com", "serviceusage.googleapis.com"},
	"network":       {"compute.googleapis.com", "dns.googleapis.com", "servicenetworking.googleapis.com"},
	"artifacts":     {"artifactregistry.googleapis.com", "cloudkms.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com", "storage.googleapis.com", "storageinsights.googleapis.com"},
	"data-services": {"cloudkms.googleapis.com", "pubsub.googleapis.com", "secretmanager.googleapis.com", "sqladmin.googleapis.com"},
	"clusters":      {"binaryauthorization.googleapis.com", "cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com", "container.googleapis.com", "gkehub.googleapis.com", "iam.googleapis.com", "secretmanager.googleapis.com"},
	"ci-execution":  {"cloudresourcemanager.googleapis.com", "compute.googleapis.com", "iam.googleapis.com", "secretmanager.googleapis.com"},
	"observability": {"cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com"},
}

var exportKindsByStack = map[string][]string{
	"foundation":    {"project"},
	"network":       {"network", "subnetwork", "private-dns-zone"},
	"artifacts":     {"artifact-registry", "artifact-bucket", "kms-key-reference"},
	"data-services": {"database-instance", "topic", "kms-key-reference"},
	"clusters":      {"gke-cluster", "cluster-membership", "workload-identity-pool", "argocd-prerequisite"},
	"ci-execution":  {"build-execution-pool"},
	"observability": {"log-bucket", "metrics-scope"},
}

// AllowsExportKind reports whether a stack owns the resource kind in the
// immutable producer contract validated against the service catalog and schema.
func AllowsExportKind(stack, kind string) bool {
	for _, allowed := range exportKindsByStack[stack] {
		if kind == allowed {
			return true
		}
	}
	return false
}

// Result is safe to print in CI; it never includes catalog values.
type Result struct {
	Catalogs int      `json:"catalogs"`
	Schemas  int      `json:"schemas"`
	Errors   []string `json:"errors,omitempty"`
}

// ValidateRepository validates every catalog against its paired Draft 2020-12 schema
// and applies semantic checks that JSON Schema alone cannot express safely.
func ValidateRepository(root string) (Result, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	result := Result{Catalogs: len(catalogSchemas), Schemas: len(catalogSchemas) + 1}
	documents := map[string]any{}
	paths := make([]string, 0, len(catalogSchemas))
	for path := range catalogSchemas {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		document, err := validateDocument(root, path, catalogSchemas[path])
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
		} else {
			documents[path] = document
		}
	}
	if err := compileSchema(filepath.Join(root, "schemas/v1/infrastructure_export.schema.json")); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	if len(documents) == len(catalogSchemas) {
		if err := validateReferences(documents); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
		if err := validateActivationBindings(root, documents); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
		if err := validateCapabilities(root, documents); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}
	if len(result.Errors) != 0 {
		return result, errors.New(strings.Join(result.Errors, "; "))
	}
	return result, nil
}

func validateCapabilities(root string, documents map[string]any) error {
	capabilities, err := namedCatalog(documents, "catalog/service-capabilities.yaml", "serviceCapabilities")
	if err != nil {
		return err
	}
	var problems []string
	if len(capabilities) != len(liveStacks) {
		problems = append(problems, "service capability catalog must cover exactly seven live stacks")
	}
	catalogExportKinds := map[string]bool{}
	for _, stack := range liveStacks {
		capability, exists := capabilities[stack]
		if !exists {
			problems = append(problems, "service capability catalog is missing stack "+stack)
			continue
		}
		if !sameStringSet(stringSlice(capability["requiredApis"]), requiredAPIsByStack[stack]) {
			problems = append(problems, fmt.Sprintf("service capability %s requiredApis must match the approved complete set", stack))
		}
		kinds := stringSlice(capability["exportKinds"])
		if !sameStringSet(kinds, exportKindsByStack[stack]) {
			problems = append(problems, fmt.Sprintf("service capability %s exportKinds must match the producer contract", stack))
		}
		for _, kind := range kinds {
			catalogExportKinds[kind] = true
		}
	}
	schemaExportKinds, schemaErr := infrastructureExportKinds(filepath.Join(root, "schemas/v1/infrastructure_export.schema.json"))
	if schemaErr != nil {
		problems = append(problems, schemaErr.Error())
	} else if !sameBoolSet(catalogExportKinds, schemaExportKinds) {
		problems = append(problems, "service capability exportKinds must exactly cover the infrastructure export schema enum")
	}
	if len(problems) != 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func infrastructureExportKinds(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read infrastructure export schema kinds: %w", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("parse infrastructure export schema kinds: %w", err)
	}
	properties, _ := schema["properties"].(map[string]any)
	spec, _ := properties["spec"].(map[string]any)
	specProperties, _ := spec["properties"].(map[string]any)
	resources, _ := specProperties["resources"].(map[string]any)
	items, _ := resources["items"].(map[string]any)
	itemProperties, _ := items["properties"].(map[string]any)
	kind, _ := itemProperties["kind"].(map[string]any)
	values, _ := kind["enum"].([]any)
	result := map[string]bool{}
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return nil, errors.New("infrastructure export schema kind enum must contain nonempty strings")
		}
		result[text] = true
	}
	if len(result) == 0 {
		return nil, errors.New("infrastructure export schema kind enum is missing")
	}
	return result, nil
}

func sameStringSet(left, right []string) bool {
	leftSet := map[string]bool{}
	rightSet := map[string]bool{}
	for _, value := range left {
		leftSet[value] = true
	}
	for _, value := range right {
		rightSet[value] = true
	}
	return sameBoolSet(leftSet, rightSet)
}

func sameBoolSet(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

// validateActivationBindings makes the environment catalog the activation
// authority for every isolated state root. A root cannot be enabled (or left
// disabled) independently of its exact catalog environment entry.
func validateActivationBindings(root string, documents map[string]any) error {
	environments, err := namedCatalog(documents, "catalog/environments.yaml", "environments")
	if err != nil {
		return err
	}

	var problems []string
	environmentNames := make([]string, 0, len(environments))
	for name := range environments {
		environmentNames = append(environmentNames, name)
	}
	sort.Strings(environmentNames)
	for _, environmentName := range environmentNames {
		catalogEnabled, ok := environments[environmentName]["enabled"].(bool)
		if !ok {
			problems = append(problems, fmt.Sprintf("catalog environment %s has no boolean enabled state", environmentName))
			continue
		}
		canonicalIAMPrincipals := ""
		canonicalIAMPrincipalsSet := false
		for _, stack := range liveStacks {
			relativePath := filepath.ToSlash(filepath.Join("opentofu/live", environmentName, stack, "environment.auto.tfvars.json"))
			data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relativePath)))
			if readErr != nil {
				problems = append(problems, fmt.Sprintf("read %s: %v", relativePath, readErr))
				continue
			}
			var binding struct {
				Environment string `json:"environment"`
				Enabled     *bool  `json:"enabled"`
			}
			var rawBinding map[string]any
			if decodeErr := json.Unmarshal(data, &binding); decodeErr != nil {
				problems = append(problems, fmt.Sprintf("parse %s: %v", relativePath, decodeErr))
				continue
			}
			if decodeErr := json.Unmarshal(data, &rawBinding); decodeErr != nil {
				problems = append(problems, fmt.Sprintf("parse %s authority: %v", relativePath, decodeErr))
				continue
			}
			if binding.Environment != environmentName {
				problems = append(problems, fmt.Sprintf("%s environment must equal %s", relativePath, environmentName))
			}
			if binding.Enabled == nil {
				problems = append(problems, relativePath+" must declare enabled")
			} else if *binding.Enabled != catalogEnabled {
				problems = append(problems, fmt.Sprintf("%s enabled state must equal catalog environment %s", relativePath, environmentName))
			}
			iamPrincipals, iamErr := exactStringSetKey(rawBinding["approved_iam_principals"])
			if iamErr != nil {
				problems = append(problems, fmt.Sprintf("%s approved_iam_principals: %v", relativePath, iamErr))
			} else if !canonicalIAMPrincipalsSet {
				canonicalIAMPrincipals = iamPrincipals
				canonicalIAMPrincipalsSet = true
			} else if iamPrincipals != canonicalIAMPrincipals {
				problems = append(problems, relativePath+" approved_iam_principals must equal the environment-wide set")
			}
			if _, referenceErr := exactStringSetKey(rawBinding["approved_resource_references"]); referenceErr != nil {
				problems = append(problems, fmt.Sprintf("%s approved_resource_references: %v", relativePath, referenceErr))
			}
			if catalogEnabled {
				regions, regionErr := namedCatalog(documents, "catalog/regions.yaml", "regions")
				if regionErr != nil {
					problems = append(problems, regionErr.Error())
					continue
				}
				regionName := stringField(environments[environmentName], "regionProfile")
				primaryLocation := stringField(regions[regionName], "primaryLocation")
				problems = append(problems, validateLiveLocationBinding(relativePath, stack, rawBinding, primaryLocation)...)
			}
		}
	}
	if len(problems) != 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateLiveLocationBinding(path, stack string, binding map[string]any, primary string) []string {
	if stack == "foundation" {
		return nil
	}
	config, _ := binding["config"].(map[string]any)
	locationField := "region"
	if stack == "artifacts" || stack == "observability" {
		locationField = "location"
	}
	var problems []string
	if stringField(config, locationField) != primary {
		problems = append(problems, fmt.Sprintf("%s config.%s must equal catalog primaryLocation %s", path, locationField, primary))
	}
	if stack == "network" {
		for name, subnet := range objectMap(config["subnets"]) {
			if stringField(subnet, "region") != primary {
				problems = append(problems, fmt.Sprintf("%s subnet %s region must equal catalog primaryLocation %s", path, name, primary))
			}
		}
	}
	if stack == "artifacts" {
		for collectionName, value := range map[string]any{"repository": config["repositories"], "bucket": config["buckets"]} {
			for name, resource := range objectMap(value) {
				if stringField(resource, "location") != primary {
					problems = append(problems, fmt.Sprintf("%s %s %s location must equal catalog primaryLocation %s", path, collectionName, name, primary))
				}
			}
		}
	}
	if stack == "clusters" {
		for _, zone := range stringSlice(config["node_locations"]) {
			if !strings.HasPrefix(zone, primary+"-") {
				problems = append(problems, fmt.Sprintf("%s node location %s must be a zone in catalog primaryLocation %s", path, zone, primary))
			}
		}
	}
	return problems
}

func objectMap(value any) map[string]map[string]any {
	values, _ := value.(map[string]any)
	result := make(map[string]map[string]any, len(values))
	for name, value := range values {
		object, _ := value.(map[string]any)
		result[name] = object
	}
	return result
}

func exactStringSetKey(value any) (string, error) {
	values, ok := value.([]any)
	if !ok {
		return "", errors.New("must be an explicit array")
	}
	unique := map[string]bool{}
	items := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" {
			return "", errors.New("must contain only nonempty strings")
		}
		if unique[text] {
			return "", errors.New("must not contain duplicate values")
		}
		unique[text] = true
		items = append(items, text)
	}
	sort.Strings(items)
	return strings.Join(items, "\x00"), nil
}

func validateDocument(root, catalogPath, schemaPath string) (any, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(catalogPath)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", catalogPath, err)
	}
	var decoded any
	if decodeErr := yaml.Unmarshal(data, &decoded); decodeErr != nil {
		return nil, fmt.Errorf("parse %s: %w", catalogPath, decodeErr)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("normalize %s: %w", catalogPath, err)
	}
	var document any
	if decodeErr := json.Unmarshal(encoded, &document); decodeErr != nil {
		return nil, fmt.Errorf("normalize %s: %w", catalogPath, decodeErr)
	}
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("file://" + filepath.ToSlash(filepath.Join(root, schemaPath)))
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", schemaPath, err)
	}
	if err := schema.Validate(document); err != nil {
		return nil, fmt.Errorf("validate %s: %w", catalogPath, err)
	}
	var problems []string
	inspect(document, catalogPath, &problems)
	if len(problems) != 0 {
		sort.Strings(problems)
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return document, nil
}

func validateReferences(documents map[string]any) error {
	regions, err := namedCatalog(documents, "catalog/regions.yaml", "regions")
	if err != nil {
		return err
	}
	projects, err := namedCatalog(documents, "catalog/project-classes.yaml", "projectClasses")
	if err != nil {
		return err
	}
	dataClasses, err := namedCatalog(documents, "catalog/data-classes.yaml", "dataClasses")
	if err != nil {
		return err
	}
	resourceProfiles, err := namedCatalog(documents, "catalog/resource-profiles.yaml", "resourceProfiles")
	if err != nil {
		return err
	}
	accelerators, err := namedCatalog(documents, "catalog/accelerator-profiles.yaml", "acceleratorProfiles")
	if err != nil {
		return err
	}
	environments, err := namedCatalog(documents, "catalog/environments.yaml", "environments")
	if err != nil {
		return err
	}

	var problems []string
	enabledRegions := map[string]bool{}
	enabledAccelerators := map[string]bool{}
	for environmentName, environment := range environments {
		regionName := stringField(environment, "regionProfile")
		region, regionExists := regions[regionName]
		if !regionExists {
			problems = append(problems, fmt.Sprintf("environment %s references unknown regionProfile %s", environmentName, regionName))
		}
		projectName := stringField(environment, "projectClass")
		project, projectExists := projects[projectName]
		if !projectExists {
			problems = append(problems, fmt.Sprintf("environment %s references unknown projectClass %s", environmentName, projectName))
		} else if !containsString(project["allowedEnvironmentTiers"], environmentName) {
			problems = append(problems, fmt.Sprintf("projectClass %s does not allow environment tier %s", projectName, environmentName))
		}
		resourceProfile := stringField(environment, "resourceProfile")
		if _, exists := resourceProfiles[resourceProfile]; !exists {
			problems = append(problems, fmt.Sprintf("environment %s references unknown resourceProfile %s", environmentName, resourceProfile))
		}
		for _, dataClass := range stringSlice(environment["dataClasses"]) {
			if _, exists := dataClasses[dataClass]; !exists {
				problems = append(problems, fmt.Sprintf("environment %s references unknown dataClass %s", environmentName, dataClass))
			}
		}
		acceleratorNames := stringSlice(environment["acceleratorProfiles"])
		for _, acceleratorName := range acceleratorNames {
			if _, exists := accelerators[acceleratorName]; !exists {
				problems = append(problems, fmt.Sprintf("environment %s references unknown acceleratorProfile %s", environmentName, acceleratorName))
			}
		}

		enabled, _ := environment["enabled"].(bool)
		if !enabled {
			continue
		}
		if !regionExists || !boolField(region, "enabled") {
			problems = append(problems, fmt.Sprintf("enabled environment %s requires enabled regionProfile %s", environmentName, regionName))
			continue
		}
		primaryLocation := stringField(region, "primaryLocation")
		recoveryLocation := stringField(region, "recoveryLocation")
		if !strings.HasPrefix(primaryLocation, "us-") {
			problems = append(problems, fmt.Sprintf("enabled regionProfile %s primaryLocation must satisfy US residency", regionName))
		}
		if recoveryLocation != "" {
			if recoveryLocation == primaryLocation {
				problems = append(problems, fmt.Sprintf("regionProfile %s recoveryLocation must differ from primaryLocation", regionName))
			}
			if !strings.HasPrefix(recoveryLocation, "us-") {
				problems = append(problems, fmt.Sprintf("enabled regionProfile %s recoveryLocation must satisfy US residency", regionName))
			}
		}
		if boolField(environment, "productionLike") && recoveryLocation == "" {
			problems = append(problems, fmt.Sprintf("production-like environment %s requires a catalog recoveryLocation", environmentName))
		}
		enabledRegions[regionName] = true
		for _, acceleratorName := range acceleratorNames {
			accelerator, exists := accelerators[acceleratorName]
			if !exists {
				continue
			}
			if !boolField(accelerator, "enabled") {
				problems = append(problems, fmt.Sprintf("enabled environment %s requires enabled acceleratorProfile %s", environmentName, acceleratorName))
				continue
			}
			enabledAccelerators[acceleratorName] = true
			if stringField(accelerator, "regionBinding") != primaryLocation {
				problems = append(problems, fmt.Sprintf("acceleratorProfile %s region binding does not match environment %s", acceleratorName, environmentName))
			}
			if stringField(accelerator, "quotaBinding") == "" {
				problems = append(problems, fmt.Sprintf("acceleratorProfile %s requires a quota binding", acceleratorName))
			}
		}
	}
	for name, region := range regions {
		if boolField(region, "enabled") && !enabledRegions[name] {
			problems = append(problems, fmt.Sprintf("enabled regionProfile %s is not used by an enabled environment", name))
		}
	}
	for name, accelerator := range accelerators {
		if boolField(accelerator, "enabled") && !enabledAccelerators[name] {
			problems = append(problems, fmt.Sprintf("enabled acceleratorProfile %s is not used by an enabled environment", name))
		}
	}
	if len(problems) != 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func namedCatalog(documents map[string]any, path, collection string) (map[string]map[string]any, error) {
	document, ok := documents[path].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	entries, ok := document[collection].([]any)
	if !ok {
		return nil, fmt.Errorf("%s.%s must be an array", path, collection)
	}
	result := make(map[string]map[string]any, len(entries))
	for _, entry := range entries {
		object, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s.%s entries must be objects", path, collection)
		}
		name := stringField(object, "name")
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("%s.%s contains duplicate name %q", path, collection, name)
		}
		result[name] = object
	}
	return result, nil
}

func stringField(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func boolField(object map[string]any, key string) bool {
	value, _ := object[key].(bool)
	return value
}

func stringSlice(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func containsString(value any, expected string) bool {
	for _, candidate := range stringSlice(value) {
		if candidate == expected {
			return true
		}
	}
	return false
}

func compileSchema(path string) error {
	compiler := jsonschema.NewCompiler()
	if _, err := compiler.Compile("file://" + filepath.ToSlash(path)); err != nil {
		return fmt.Errorf("compile %s: %w", filepath.ToSlash(path), err)
	}
	return nil
}

func inspect(value any, path string, problems *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if prohibitedKey.MatchString(key) && child != nil && child != "" {
				*problems = append(*problems, fmt.Sprintf("%s.%s contains sensitive material", path, key))
			}
			inspect(child, path+"."+key, problems)
		}
	case []any:
		seen := map[string]bool{}
		for index, child := range typed {
			if object, ok := child.(map[string]any); ok {
				if name, ok := object["name"].(string); ok {
					if seen[name] {
						*problems = append(*problems, fmt.Sprintf("%s contains duplicate name %q", path, name))
					}
					seen[name] = true
				}
			}
			inspect(child, fmt.Sprintf("%s[%d]", path, index), problems)
		}
	}
}
