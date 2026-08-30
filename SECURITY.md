# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting or an approved private Mindclade
security channel. Do not open a public issue. Never include credentials,
identity tokens, private keys, state, saved plans, kubeconfigs, secret payloads,
partner data, restricted biological data, private infrastructure identifiers,
or unredacted cloud observations in a report.

Provide the minimum safe evidence:

- affected source commit, environment class, stack, and path;
- expected and observed authority or policy behavior;
- whether identity, state, networking, encryption, recovery, or runtime access
  might have changed;
- a synthetic reproduction where possible; and
- the relevant workflow run and redacted evidence digest.

If compromise is suspected, stop the affected workflow and follow the relevant
runbook. Do not rotate, revoke, restore, fail over, or alter production from an
unprotected workstation or agent session.

## Supported source

Only the current protected `main` branch is supported. Plans, state, provider
caches, observations, temporary exports, and local lock files are not release
artifacts. An apply receipt is a redacted locator bound to its exact source
commit, environment, stack, plan digest, policy and classification digests,
IAM-principal qualification digest, resource-reference qualification digest,
and workflow run. It contains neither identity bindings nor approval evidence
and is not live-system proof by itself. The protected workflow and GitHub
environment record are authoritative for plan/apply identities, approval, and
artifact retention.

## Security invariants

- Pull-request code receives no privileged cloud identity or trusted cache.
- Workloads and automation use short-lived federation; static service-account
  keys are prohibited.
- Provider values, state, secret payloads, and credentials never enter catalog,
  policy output, plan classification, workflow artifacts, or GitOps exports.
- Every live root has an isolated backend prefix and one state owner.
- Public access, wildcard principals, basic roles, unencrypted protected data,
  unrestricted egress, public GKE control planes, and untainted accelerators are
  denied by policy.
- Production/restricted deletion and replacement are denied by the protected
  workflow. Any exceptional destructive operation requires a separate reviewed
  recovery or migration procedure outside that workflow.
- Unknown, partially observed, unsigned, mutable, expired, or mismatched
  evidence fails closed.
- Source validation is never represented as live-system qualification.

## Response boundary

Bootstrap owns root identity, backend, signing, and break-glass response.
Infrastructure Live owns cloud-resource containment and recovery. GitOps owns
in-cluster rollback. Product owners retain artifact and application incident
responsibility. Coordinate through evidence and references without copying
credentials or state between repositories.
