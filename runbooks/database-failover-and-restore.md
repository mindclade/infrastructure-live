# Database failover and restore

Owner: `@mindclade/platform-operations`
Data owner approval is required for every restore.

A failover or restore changes live data availability and may overwrite newer
state. Source controls validate configuration only; they do not prove backup
integrity, point-in-time recoverability, or application correctness.

## Preconditions

1. Declare incident scope, data classification, target environment, database
   identity, RTO/RPO, requested recovery point, and authorized incident lead.
2. Verify backup/PITR inventory and transaction-log coverage through read-only
   provider evidence. Preserve audit logs and the current source/state identity.
3. Obtain Infrastructure, data-owner, and Security approval for production or
   restricted data. Confirm legal hold, retention, residency, and perimeter
   requirements.
4. Quiesce or fence writers using the application-owned procedure. Do not infer
   write safety from database health alone.

## Failover

Use provider-supported regional failover only after confirming replica health,
replication lag, application retry behavior, connection routing, and rollback.
Observe write availability, consistency, error rate, latency, and audit logs.
Do not reduce deletion protection, encryption, private networking, or TLS to
make failover succeed.

## Point-in-time restore

Restore first into an isolated, access-restricted recovery instance using the
approved recovery point. Never overwrite the source instance during
investigation. Validate checksums, schema and migration version, row/object
counts, critical business invariants, data-class controls, encryption, and
malware/compromise indicators. Application/data owners must sign off integrity
before any cutover.

Cut over with an explicit traffic and writer-fencing sequence. Retain the prior
instance according to approved retention so rollback remains possible. A
destructive cleanup is a later, separate change.

## Closure

Verify application SLOs, freshness/correctness, backups, PITR continuity,
private connectivity, audit delivery, monitoring, and a zero-drift plan. Record
recovery point, observed RPO/RTO, approvals, integrity evidence, cutover and
rollback results, and any residual data uncertainty without exposing data or
credentials.
