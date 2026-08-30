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
retention is enforced at that class's minimum. Restricted bucket retention is
also irreversibly locked; enabling it requires explicit review because the lock
cannot be removed or shortened. Centralized logs require delegated CMEK and at
least 30 days retention in development, 90 in staging/production, and 365 in
restricted.

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
infractl exports emit --environment development --stack foundation \
  --source-commit "$SOURCE_COMMIT" --plan-digest "$PLAN_DIGEST" \
  --schema-digest "$SCHEMA_DIGEST" --generated-at "$EVIDENCE_TIME" \
  --resources resources.json --signature-uri "$SIGNATURE_URI" \
  --signature-digest "$SIGNATURE_DIGEST" \
  --provenance-uri "$PROVENANCE_URI" \
  --provenance-digest "$PROVENANCE_DIGEST" --output export.json
```

The named environment variables above are required operator inputs and have no
repository defaults. Validation errors return `1`.
Plan deletion/replacement and detected drift return `2`. Output is canonical,
machine-readable JSON and omits provider values. Export emission requires an
explicit evidence timestamp and writes atomically with owner-only permissions.

The export is the only supported infrastructure-to-GitOps interface. It
contains resource URIs, never secret values or OpenTofu state. GitOps verifies
its schema, signature, provenance, plan digest, source commit, and environment
before use.

## Local verification

The supported entry points are:

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

Pull requests and merge queues receive no cloud identity. Connected drift uses
a read-only, exact-workflow Workload Identity Federation principal. A protected
apply is manual-dispatch only from the exact `main` commit and requires:

1. a non-secret activation flag and complete backend/WIF bindings;
2. a fresh plan created for one environment/stack state boundary;
3. the canonical plan-content digest emitted by `infractl plan classify`
   matching the approved dispatch input;
4. no delete or replacement action;
5. policy and source validation;
6. approval through the environment-specific protected gate
   (`infrastructure-development-apply`, `infrastructure-staging-apply`,
   `infrastructure-production-apply`, or `infrastructure-restricted-apply`); and
7. post-apply zero-drift verification and a retained redacted receipt.

Plan and apply use separate identities. A plan, source test, artifact upload,
or environment approval alone never authorizes mutation. Production and
restricted changes remain manual and cannot be promoted by a scheduled job.
The canonical digest removes only the top-level plan generation timestamp and
JSON key order/whitespace; it covers every other plan field. The apply workflow
recreates the plan against the exact approved source and current isolated state,
compares that digest, and applies that same saved plan. A material configuration
or state race therefore changes the digest or causes saved-plan apply to fail.

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
classification, policy, IAM-qualification and resource-reference digests, plus
the workflow run. It contains no credentials, state, plans, provider values, or
reviewer identities. The protected GitHub environment and workflow run record,
not the receipt by itself, are authoritative for identity bindings, approval,
and retention.

The repository-wide activation flag is `INFRASTRUCTURE_CONNECTED_READY`.
Read-only drift identities and state bindings live in
`infrastructure-development-plan`, `infrastructure-staging-plan`,
`infrastructure-production-plan`, and `infrastructure-restricted-plan`.
Mutation identities and state bindings live separately in the corresponding
`infrastructure-development-apply`, `infrastructure-staging-apply`,
`infrastructure-production-apply`, and `infrastructure-restricted-apply`
gates. Those environments provide the variables appropriate to their role:

- `INFRASTRUCTURE_STATE_BUCKET` and `INFRASTRUCTURE_STATE_PREFIX`;
- `GCP_WIF_PROVIDER_INFRASTRUCTURE_PLAN` and
  `GCP_SERVICE_ACCOUNT_INFRASTRUCTURE_PLAN`; and
- `GCP_WIF_PROVIDER_INFRASTRUCTURE_APPLY` and
  `GCP_SERVICE_ACCOUNT_INFRASTRUCTURE_APPLY`.

They must be configured by the appropriate authority. This source cannot prove
that the external gates, reviewers, or bindings exist, so connected readiness
remains blocking until each environment is qualified. Static service-account
keys are prohibited. Workflows fail closed if a required value is absent.

The qualitative catalog `costGuardrail` selects an externally qualified budget
control; financial amounts and notification bindings are intentionally not
invented in source. Every environment apply gate must set
`INFRASTRUCTURE_FINOPS_BUDGET_READY=true` only after its budget, thresholds, and
alert recipients are independently verified. Protected apply blocks otherwise.

Shared VPC service-project numbers and their Google-managed GKE service-agent
principals are live bindings and are not guessed here. Each apply gate must set
`INFRASTRUCTURE_SHARED_VPC_GKE_IAM_READY=true` only after host-subnet Network
User access and the required service-agent roles have been reviewed and verified
for that exact environment; protected apply blocks otherwise.

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
live project identifiers, each protected environment must qualify the selected
stack's exact API set and set its corresponding
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
matches that input to the provider value. Unknown computed IAM members remain
policy violations; discovery is never authorization to grant one.

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

The disaster-recovery workflow verifies source and recovery contracts only; it
does not restore data or mutate resources. Database, artifact, state, network,
cluster, and regional recovery require their runbook, live evidence, a reviewed
change, and the same protected authority used for the affected resource.

The contents are proprietary and confidential under [LICENSE](LICENSE).
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.
