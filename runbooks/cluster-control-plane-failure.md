# Cluster control-plane failure

Owner: `@mindclade/infrastructure`
In-cluster owner: `@mindclade/platform`

This repository owns the GKE cloud resource and access prerequisites. GitOps
owns Argo CD and in-cluster desired state. Do not use a cloud incident to create
Kubernetes resources from OpenTofu or to give CI a production kubeconfig.

## Triage and containment

1. Record cluster membership identity, region, control-plane health, node-pool
   health, first failure time, recent source/apply evidence, and provider status.
2. Distinguish private endpoint reachability, IAM/federation, DNS/network,
   control-plane health, node capacity, and GitOps reconciliation failures.
3. Freeze cluster, network, IAM, and GitOps promotions until the failed authority
   layer is known. Preserve audit, Kubernetes, and network evidence privately.
4. Escalate to Security for unexpected public endpoint access, credential use,
   Binary Authorization bypass, workload-identity failure, or audit loss.

## Recovery

- Restore private operator reachability through the approved access path; do
  not temporarily expose the endpoint publicly.
- Correct cloud prerequisites in this repository and in-cluster objects in
  GitOps. Never duplicate ownership to accelerate recovery.
- Replace or resize node pools only with quota/capacity evidence, disruption
  budgets, workload-owner coordination, and a rollback plan.
- Regional cluster recreation is a regional-recovery operation, not a routine
  retry. It requires state, data, DNS/traffic, GitOps bootstrap, and identity
  sequencing.

## Verify

Require private endpoint and authorized-network checks, expected IAM allow/deny
tests, healthy control-plane and node signals, Workload Identity, network
policy, Shielded Nodes, Binary Authorization, audit delivery, and GitOps
reconciliation from the approved source commit. Confirm user-visible SLOs and
cost/accelerator telemetry before ending the freeze.
