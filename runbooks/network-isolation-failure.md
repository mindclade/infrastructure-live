# Network isolation failure

Owner: `@mindclade/platform-operations`
Security escalation: `@mindclade/security`

Use this procedure for unexpected reachability, loss of required private
connectivity, route asymmetry, DNS failure, NAT exhaustion, firewall-policy
failure, or GKE control-plane isolation loss.

## Contain safely

1. Identify the exact source, destination, protocol, port, environment, data
   class, and affected service owner. Preserve flow logs, firewall decisions,
   route/DNS observations, and recent apply evidence.
2. For unintended public or cross-boundary reachability, page Security and
   restrict traffic through the approved emergency control. Do not create a
   broad deny that can sever identity, logging, or recovery paths without an
   assessed blast radius.
3. For loss of service, keep production traffic on known-good paths. Do not add
   `0.0.0.0/0`, `::/0`, wildcard principals, public control-plane access, or an
   unreviewed peering as a workaround.
4. Freeze competing route, firewall, DNS, NAT, load-balancer, and cluster-network
   changes until authority is clear.

## Diagnose read-only

- Compare the intended flow matrix with effective hierarchical firewall policy,
  VPC rules, routes, next hops, DNS answers, NAT allocation, and service health.
- Check IP overlap, secondary-range exhaustion, MTU, quota, asymmetric routing,
  Private Google Access, and Private Service Connect health.
- Correlate first failure time with infrastructure commits, provider events,
  certificate changes, and partner/hybrid maintenance.
- Treat missing flow logs or incomplete observation as an unresolved risk.

## Recover

Prefer a reviewed rollback to the last qualified network plan when state and
dependencies still match. Otherwise use a forward correction with route/DNS
canaries, bounded scope, monitoring, and an explicit reversal. Any emergency
mutation must be reconciled into source immediately and independently reviewed.

Verify required allow and deny cases, DNS authority, route convergence,
latency, throughput, control-plane access, audit/flow-log delivery, and cost.
Keep enhanced monitoring through the change window and attach only redacted
evidence to the incident record.
