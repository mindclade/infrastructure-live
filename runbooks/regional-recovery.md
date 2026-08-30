# Regional recovery

Owner: `@mindclade/infrastructure`
Incident command coordinates Security, Platform, Data, and product owners.

Regional recovery is a protected, multi-stack operation. Do not declare a
region unavailable from one failed probe, and do not create a second active
state owner or bidirectional normal-operation dependency during recovery.

## Declare and freeze

1. Confirm provider status and independent service, network, data, cluster, and
   user-visible evidence. Declare incident scope, target RTO/RPO, data classes,
   and recovery authority.
2. Freeze applies and GitOps promotions for affected environments. Preserve
   source commits, state generations, infrastructure exports, release digests,
   audit evidence, and traffic/DNS state.
3. Confirm the recovery region, quotas, IP ranges, service availability,
   accelerator capacity, KMS access, data residency, and cost authorization.
4. Fence writers and traffic before activating a recovery data plane. Split
   brain is a stop condition.

## Recovery order

Recover through reviewed state boundaries in dependency order: foundation,
network/private DNS/egress, artifacts and keys, data services, clusters,
observability, CI prerequisites, then GitOps bootstrap and workload promotion.
Use signed infrastructure exports to hand cloud references to GitOps. Never
copy OpenTofu state or credentials into GitOps.

For each stage require a reviewed plan, protected approval, health evidence,
and an explicit rollback or forward-correction decision. Production and
restricted remain manual. Accelerator activation additionally requires quota,
topology, isolation, and budget evidence.

## Traffic and service verification

Canary DNS/routes and a small workload slice before broader traffic. Verify
identity allow/deny cases, private connectivity, encryption, data integrity and
freshness, application SLOs, logs/metrics/traces, alert routing, cost signals,
and immutable release digests. Hold enhanced monitoring through the recovery
window.

## Return or remain

Failback is a separate regional recovery with the same fencing, data,
dependency, approval, and verification requirements. If the recovery region
becomes primary, reconcile source, state, catalogs, capacity, DR assumptions,
and runbooks through reviewed changes. Record observed RTO/RPO, data loss,
approvals, evidence digests, residual risks, and follow-up tests.
