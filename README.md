# Mindclade infrastructure live

This repository is the reviewed source of truth for environment-specific Google
Cloud infrastructure composition. It owns OpenTofu roots, plan evidence, drift
classification, and non-sensitive infrastructure exports for development,
staging, production, and restricted environments.

All environments are initially disabled. Passing source checks proves only that
the repository is internally coherent; it is not evidence that GitHub controls,
Google Cloud identities, state backends, quotas, resources, recovery, or GitOps
reconciliation are deployed or qualified.

## Authority boundary

- `bootstrap` owns state buckets, root workload federation, signing roots,
  break-glass foundations, and their recovery controls.
- This repository owns cloud resources, environment/stack state boundaries,
  reviewed plans, drift disposition, and infrastructure export records.
- `gitops` consumes signed exports and exclusively owns Argo CD and in-cluster
  desired state. OpenTofu here must not create Kubernetes or Argo CD resources.
- Product repositories build artifacts. Infrastructure and GitOps promote only
  immutable artifacts and evidence; neither rebuilds them.

The normal dependency direction is `bootstrap` → `infrastructure-live` →
`gitops`. A backward dependency or a second state owner is a blocking error.

## Repository model

- `catalog/` defines logical environments, regions, project/data classes,
  resource and accelerator profiles, and service capabilities.
- `schemas/v1/` closes every public input and the infrastructure-export handoff.
- `opentofu/modules/gcp/` contains provider-facing primitives; `stacks/`
  composes them; every environment-and-stack root has isolated state.
- `policy/` denies unsafe plans for identity, network, encryption, recovery,
  GKE, accelerators, organization controls, and cost.
- `tooling/` provides the canonical `infractl` interface.
- `tests/` and `runbooks/` exercise and operate failure, drift, recovery, and
  capacity paths.

Catalogs and source code contain no organization, project, backend, service
account, cluster, secret, or partner-specific live binding. Activation requires
those reviewed bindings through protected configuration and a plan for the
exact source commit.

The immutable root environment is passed into every stack and overwrites the
environment label on governed resources. Shared VPC activation requires
explicit, distinct service-project IDs. Cloud NAT is paired with a logged
default-deny egress firewall and reviewed, named TCP/UDP destination-and-port
rules; an empty rule set, default-route destination, or protocol wildcard cannot
activate. Accelerator node pools resolve an enabled, environment-authorized,
region/quota-bound catalog profile and cannot use the mutable latest driver
setting. Foundation, data-service, and cluster roots resolve their project or
resource profile from the exact catalog environment; folder and billing
binding, deletion protection, Cloud SQL HA/retention, and regional GKE zone
minimums are provider preconditions. Data resources require a catalog data class, and bucket
retention is enforced at that class's minimum. Restricted bucket activation and
every irreversible retention-lock transition are intentionally unreachable:
operator-authored catalog fields or receipts cannot prove independent approval.
A future activation must first add a separately rooted cryptographic verifier.

CI execution additionally uses a dedicated network target tag whose firewall-only
boundary is complete before an agent template can activate. Four named allows are
mandatory (`buildkite-control-plane`, `source-control`, `google-apis`, and
`dependency-mirror`), with those allows at higher precedence than the
workload-scoped default deny for all other egress. The agent container accepts exactly one job, uses an empty
tmpfs workspace, disconnects, and powers off. Its canonical mirror manifest
covers Bazel registry/cache, Buf, Go, Nix, npm, OCI, Python, and Rust routes and
contains only credential-free HTTPS endpoints. All mirror URLs, destination
CIDRs, private-network references, immutable images, and contract-verification
flags remain null, empty, or false in source, so cold-cache and egress readiness
require a reviewed connected plan and independent qualification.
Centralized logs require delegated CMEK and at
least 30 days retention in development, 90 in staging/production, and 365 in
restricted.

The production resource profile also owns the sole non-regional storage
exception: a disabled CI-evidence archive in `NAM4`. Its exact Standard/default
replication, software-CMEK, 2,555-day retention, 30-day soft-delete,
versioning-disabled, and Archive lifecycle settings are catalog-controlled.
The production artifacts root derives its bucket and key names from the bound
target project. The target and identity projects, alert channels, inventory
schedule, and reviewed audit-sink writer remain null or empty activation
blockers in source. Once those authorities are bound, the target project's
numeric project number derives the exact Storage and Storage Insights service
agents, while the identity project derives only the named `ci-evidence-writer`
and `ci-evidence-verifier` service accounts. Storage Data Access logs, a
unique-writer audit sink, a mutation/denial alert, and daily object inventory
activate with the archive. Retention remains unlocked. The module, schema, plan
policy, and tests all reject a lock even when an operator supplies a perfectly
formed receipt, because self-asserted evidence cannot authorize an irreversible
provider mutation.

The environment catalog is an activation authority, not descriptive metadata.
Every module receives `enabled=false` unless both the root and its catalog
environment are enabled; location-bearing stacks additionally require their
selected region profile to be enabled. The catalog primary location overrides
operator-supplied locations, while its recovery location remains an explicit
recovery authority. These conditions are applied at the module edge so a
targeted OpenTofu plan cannot prune the checks.

## `infractl` interface

```text
infractl catalog validate --root .
infractl plan classify --input plan.json
infractl policy verify --root .
infractl drift classify --desired desired.json --observed observed.json
infractl reconciliation verify --desired reviewed-state.json \
  --observed refreshed-state.json
tofu -chdir="$ROOT" output -json | infractl exports resources \
  --stack foundation --input - --output resources.json
infractl exports kms-readiness \
  --trusted-public-key-base64 "$BOOTSTRAP_EXPORT_PUBLIC_KEY_PEM_B64" \
  --observed-public-key kms-public-key.pem \
  --trusted-public-key-digest "$BOOTSTRAP_EXPORT_PUBLIC_KEY_DIGEST" \
  --message readiness.json --signature readiness.sig \
  --output-public-key-der qualified-public-key.der
infractl exports payload --environment development --stack foundation \
  --source-commit "$SOURCE_COMMIT" --plan-digest "$PLAN_DIGEST" \
  --provider-lock-digest "$PROVIDER_LOCK_DIGEST" \
  --backend-state-digest "$BACKEND_STATE_DIGEST" \
  --backend-lineage "$BACKEND_LINEAGE" --backend-serial "$BACKEND_SERIAL" \
  --schema-digest "$SCHEMA_DIGEST" --generated-at "$EVIDENCE_TIME" \
  --resources resources.json \
  --provenance-uri "$PROVENANCE_URI" \
  --provenance-digest "$PROVENANCE_DIGEST" --output export.payload.json
# The exact bootstrap-owned infrastructure-export HSM key version signs the
# canonical payload with EC_SIGN_P256_SHA256.
infractl exports emit <the-same-immutable-inputs> \
  --signature "$DETACHED_SIGNATURE_JSON" \
  --trusted-key-version "$BOOTSTRAP_EXPORT_KMS_KEY_VERSION" \
  --trusted-public-key-digest "$BOOTSTRAP_EXPORT_PUBLIC_KEY_DIGEST" \
  --output export.json
```

The named environment variables above are required operator inputs and have no
repository defaults. Validation errors return `1`.
Plan deletion/replacement, detected drift, and a non-clean partial-apply
reconciliation return `2`. Reconciliation compares exact transaction identity,
backend lineage and serial, resource addresses, provider IDs, and redacted state
digests; it always requires a new plan after an interrupted apply. Output is
canonical, machine-readable JSON and omits provider values. Export emission
requires an explicit evidence timestamp, transient provider-lock digest, exact
backend state binding, an independently supplied exact KMS key version and
canonical SPKI digest, and a detached HSM ECDSA P-256 signature that verifies over the
canonical metadata, resources, provenance, plan digest, and source commit. It
writes atomically with owner-only permissions.

For every environment, connected governance must publish the exact
`INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_<ENVIRONMENT>`,
`INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_<ENVIRONMENT>`, and
`INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_<ENVIRONMENT>` variables. The version
must name bootstrap's `us-central1/bootstrap-signing/infrastructure-export`
cryptoKeyVersion; the digest is SHA-256 over canonical SPKI DER, independent of
PEM formatting. The corresponding environment apply service account must have
only key-version-scoped signing/public-key access through its exact apply WIF
source and audience. Until bootstrap enables that IAM and all three values are
qualified, protected apply fails before any OpenTofu mutation.

The export is the only supported infrastructure-to-GitOps interface. It
contains resource URIs, never secret values or OpenTofu state. The embedded
public key proves cryptographic consistency; GitOps must additionally bind its
key version and SPKI digest to the independently governed bootstrap signing root before it verifies
schema, signature, provenance, plan, source commit, provider lock, backend state,
and environment. Source alone does not manufacture that trust binding.

Protected apply derives the export resource list only from the full post-apply
`tofu output -json` resources envelope, requires that output to be explicitly
non-sensitive, and rejects null, unknown, empty, or unsafe exported values. It
re-pulls and compares the exact state around derivation, binds the byte digest of
the canonical apply receipt as export provenance, locally verifies the KMS
signature, and uploads only the signed export and bound receipt together.

## Local verification

The repository-local `flake.nix` and `flake.lock`, constrained by the
checked-in generated estate policy, are the system-toolchain authority for
supported `aarch64-darwin`, `aarch64-linux`, and `x86_64-linux` hosts. The
flake exposes the reviewed toolchain package, identical default/CI shell
closures, formatter, and toolchain/source checks while preserving Go modules,
OpenTofu provider locks, and Bazel as their native dependency authorities:

```sh
nix build --no-accept-flake-config --no-update-lock-file .#toolchain
nix flake check --no-accept-flake-config --no-update-lock-file
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just ci
```

The four files under `generated/` are immutable local copies of the
`mindclade/.github` policy projection pinned to implementation revision
`49a015c2c0cdd6a75a5756eb8c1e95b49d117917`; evaluation never imports mutable
remote policy. Source, Nix, and Bazel checks verify their exact byte digests,
authority, internal lock digest, supported systems, and projected Bazel rc.

`MODULE.bazel.lock` is reviewed source and normal Bazel commands fail instead
of updating it. Remote Bazel execution and remote caching are intentionally
disabled; either requires workers with the exact reviewed Nix store paths or
an immutable, digest-pinned image built from this toolchain closure.

The root developer-quality interface is `just format`, `just format-check`,
`just lint`, and `just check`. Formatting is limited to handwritten source and
configuration, including committed environment variable JSON; generated plans,
state, exports, and evidence remain under their owning commands.

The canonical supported entrypoints execute inside `devShells.ci`. Focused
native commands remain available there for diagnosis:

```sh
just validate
just test
just ci
```

Focused checks include:

```sh
just validate-catalog
just validate-policy
just validate-tofu
just lint-ci
just test-go
just test-python
just test-bazel
```

OpenTofu validation copies the OpenTofu and catalog trees to a temporary
directory so provider caches and lock files cannot alter the reviewed source. No supported
local recipe applies infrastructure, imports state, migrates backends, or
forces locks.

## Protected plans and applies

`CODEOWNERS` routes every source path to platform-operations and Security but is
not the cumulative approval authority. The `github-config` catalog owns the no-bypass
`infrastructure-source` ruleset: it requires two distinct approvals, code-owner
review, last-push approval, resolved review threads, merge queue, and the exact
`Pull request / required` check from `.github/workflows/pull-request.yml`.
The Security team and its enforceable review path remain connected-activation
blockers until observed and qualified; declaring correct source ownership does
not manufacture external approval.

Pull requests and merge queues receive no cloud identity. Connected drift uses
a read-only, exact-workflow Workload Identity Federation principal. A protected
apply is manual-dispatch only from the exact `main` commit and requires:

1. a non-secret activation flag and complete backend/WIF bindings;
2. a fresh plan created for one environment/stack state boundary;
3. the canonical plan-content digest emitted by `infractl plan classify`
   matching the approved dispatch input;
4. no delete or replacement action;
5. policy and source validation;
6. plan approval through `trusted-build`, followed by a separate
   `infrastructure-apply` approval after the redacted plan coordinates exist,
   with the selected catalog environment still bound into source, state prefix,
   qualification digests, identities, and receipt; and
7. post-apply zero-drift verification and a retained redacted receipt.

Plan and apply use separate identities. A plan, source test, artifact upload,
or environment approval alone never authorizes mutation. Production and
restricted changes remain manual and cannot be promoted by a scheduled job.
The canonical digest removes only the top-level plan generation timestamp and
JSON key order/whitespace; it covers every other plan field. The plan job creates
one six-hour artifact containing only the binary saved plan, transient provider
lock, and canonical bundle manifest. The apply job downloads that same-run
artifact, checks every file digest, recreates the provider installation with the
lock in read-only mode, and requires current backend lineage, serial, and
canonical state digest to equal the pre-plan snapshot before it applies the saved
plan. A material configuration, provider, or state race therefore fails before
mutation.

Two protected qualification digests bind externally approved authority to the
exact recreated plan. The IAM preimage is canonical compact JSON containing the
environment and sorted `approvedIamPrincipals`; every one of the seven roots in
an environment must carry that same environment-wide set. Its expected digest
is `INFRASTRUCTURE_IAM_PRINCIPALS_DIGEST`. The resource-reference preimage is
canonical compact JSON containing the environment, stack, and sorted
`approvedResourceReferences`. Its expected digest is selected from
`INFRASTRUCTURE_RESOURCE_REFERENCES_<STACK>_DIGEST` (`DATA_SERVICES` and
`CI_EXECUTION` use underscores). Both values use the form
`sha256:<64 lowercase hexadecimal characters>`. The workflow recomputes and
compares them before policy evaluation and records the matched values in the
receipt. This environment-and-stack binding prevents a qualified list from
being replayed into another authority boundary.

The receipt is a redacted locator bound to source, environment, stack, plan,
saved-plan, transient provider-lock, pre/post backend serial and state digests,
classification, policy, IAM-qualification and resource-reference digests, both
identity-binding names, and the workflow run. It contains no credentials,
state, plans, provider values, or reviewer identities. The protected GitHub environment and workflow run record,
not the receipt by itself, are authoritative for identity bindings, approval,
and retention.

The repository-wide activation flag is `INFRASTRUCTURE_CONNECTED_READY`.
Read-only drift identity and state bindings live in the canonical
`trusted-build` governance environment. The distinct mutation identity and
state bindings live in `infrastructure-apply`. Those two catalog-owned
environments provide the variables appropriate to their role:

- `INFRASTRUCTURE_STATE_BUCKET` and `INFRASTRUCTURE_STATE_PREFIX`;
- `GCP_WIF_PROVIDER_INFRASTRUCTURE_LIVE_<ENVIRONMENT>_PLAN` and
  `GCP_SERVICE_ACCOUNT_INFRASTRUCTURE_LIVE_<ENVIRONMENT>_PLAN` in
  `trusted-build`; and
- `GCP_WIF_PROVIDER_INFRASTRUCTURE_LIVE_<ENVIRONMENT>_APPLY` and
  `GCP_SERVICE_ACCOUNT_INFRASTRUCTURE_LIVE_<ENVIRONMENT>_APPLY` in
  `infrastructure-apply`.

`<ENVIRONMENT>` is `DEVELOPMENT`, `STAGING`, `PRODUCTION`, or `RESTRICTED`.
Provider IDs end in the corresponding `<environment>-plan` or
`<environment>-apply`, service accounts use the same local part, and each auth
exchange requires the exact audience
`https://github.mindclade.io/oidc/infrastructure-live/<environment>/<phase>`.
These bindings match the eight unique `github-config` authority IDs
`infrastructure-live-<environment>-<phase>`; a shared audience or identity is
rejected.

They must be configured by the appropriate authority for every selected catalog
environment and state prefix. This source cannot prove that the external gates,
reviewers, or bindings exist, so connected readiness remains blocking until
both governance environments and every environment-specific resource binding
are qualified. Static service-account keys are prohibited. Workflows fail
closed if a required value is absent.

The qualitative catalog `costGuardrail` selects an externally qualified budget
control; financial amounts and notification bindings are intentionally not
invented in source. The `infrastructure-apply` gate must set
`INFRASTRUCTURE_FINOPS_BUDGET_READY=true` only after its budget, thresholds, and
alert recipients are independently verified. Protected apply blocks otherwise.

Shared VPC service-project numbers and their Google-managed GKE service-agent
principals are live bindings and are not guessed here. The
`infrastructure-apply` gate must set
`INFRASTRUCTURE_SHARED_VPC_GKE_IAM_READY=true` only after host-subnet Network
User access and the required service-agent roles have been reviewed and verified
for the exact selected environment; protected apply blocks otherwise.

External and newly delegated CMEKs also depend on exact Google-managed service
agents, including the GKE service agent for application-layer secrets
encryption. `INFRASTRUCTURE_CMEK_SERVICE_AGENT_BINDINGS_READY=true` is permitted
only after every resource in the reviewed plan has its qualified
encrypter/decrypter binding; protected apply blocks otherwise. Likewise,
`INFRASTRUCTURE_BINARY_AUTHORIZATION_READY=true` is permitted only after the
environment's project-singleton Binary Authorization policy, qualified
attestors, and deny behavior have been independently verified. Enabling the GKE
evaluation mode alone is not treated as supply-chain qualification.

Each service-capability catalog entry is also an activation authority for its
required Google APIs. Because stack projects can differ and source contains no
live project identifiers, the protected apply environment must qualify the
selected stack's exact API set and set its corresponding
`INFRASTRUCTURE_REQUIRED_APIS_<STACK>_READY=true` gate variable (`DATA_SERVICES`
and `CI_EXECUTION` use underscores). The workflow selects the variable from the
dispatch stack and fails closed; an empty foundation `services` set is never
treated as proof that another project's APIs are enabled.

All IAM member resources are checked against the exact environment-wide
`approved_iam_principals` list in the selected live root. Catalog validation
requires the list to be identical across all seven roots for that environment.
The list is covered by both the reviewed canonical plan digest and its separate
environment-bound qualification digest and defaults to empty, so an omitted,
revoked, unknown, or cross-environment principal fails policy even when its
managed resource is otherwise a no-op. Set
`INFRASTRUCTURE_IAM_PRINCIPALS_READY=true` only after the protected
environment's authority has verified the provenance and intended role of every
listed service account, Workload Identity principal, principal set, and group;
the apply workflow blocks when that external qualification is absent.

Every live root also carries an exact `approved_resource_references` list.
Provider-shaped policy checks project and hierarchy targets, networks and
subnets, service projects and accounts, immutable images and versioned secrets,
CMEKs, repositories, buckets, topics, clusters, sink destinations, and other
governed external links against that stack-qualified list. Unknown and revoked
no-op references fail closed. Set
`INFRASTRUCTURE_RESOURCE_REFERENCES_READY=true` only after the protected
environment authority has verified each reference and configured the matching
stack digest; a readiness Boolean without the digest match is insufficient.

Logging sink writers use a narrow two-phase exception to the usual one-pass
activation because Google assigns each unique identity only when its sink is
created. A reviewed observability apply must explicitly select `discover`,
which creates no IAM grant and exposes the provider-issued identities in the
stack output. A follow-up change returns to the default `enforce` mode, records
one identity per exact source project in `sink_writer_identities` and
`approved_iam_principals`, and grants access only after an OpenTofu precondition
matches that input to both a plan-time read of the previously created sink and
the current managed provider value. Enforcement fails during planning when the
sink does not already exist. Unknown computed IAM members remain policy
violations; discovery is never authorization to grant one.

Buildkite execution uses a checksum-reviewed immutable COS boot image and a
startup script, not the retired container-declaration mechanism. The exact
digest-pinned agent image is a custom contract: it must resolve
`BUILDKITE_TOKEN_SECRET_RESOURCE` through Application Default Credentials,
must never log or persist the token, and must run the Buildkite agent as its
entrypoint. The secret reference includes an explicit numeric Secret Manager
version. All OpenTofu values embedded in the root startup script are
base64-encoded before interpolation and decoded only at runtime; the image and
secret resource also use strict, shell-safe grammars.

One-job behavior is a separate, blocking runtime contract. The agent is passed
disconnect-after-job and bounded disconnect-after-idle settings, and the VM
shutdown runs from an EXIT trap on success or failure. Qualification must also
prove that jobs execute outside the agent credential context, cannot reach VM
metadata or Secret Manager, cannot read the long-lived registration token, use
job acquisition tokens without fallback, and cause one-job VM lifecycle.
Docker flags alone do not prove those properties. The root values
`agent_image_secret_contract_verified=true` and
`agent_job_isolation_contract_verified=true`, plus protected gates
`INFRASTRUCTURE_BUILDKITE_IMAGE_CONTRACT_READY=true` and
`INFRASTRUCTURE_BUILDKITE_JOB_ISOLATION_READY=true`, are required only after
testing that exact image digest and execution design; stock-image compatibility
is never assumed.

## Recovery and security

The disaster-recovery workflow's scheduled and default path verifies source and
recovery contracts only. A separate manual, environment-approved CI-evidence
job may read one generation-qualified object and test its effective permissions
without mutation after activation; it is disabled by default and is not a
restore. Database, artifact, state, network, cluster, and regional recovery
require their runbook, live evidence, a reviewed change, and the same protected
authority used for the affected resource.

The contents are proprietary and confidential under [LICENSE](LICENSE).
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.
