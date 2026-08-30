# Artifact storage recovery

Owner: `@mindclade/infrastructure`
Artifact provenance owner: `@mindclade/platform`

Use this procedure for deleted/corrupt objects, bucket unavailability,
retention or encryption alarms, replication failure, or loss of artifact
registry/bucket references. Never rebuild or republish a production artifact
under an existing digest as a recovery shortcut.

## Triage

1. Record environment, bucket or repository identity, object generation,
   immutable artifact digest, first failure time, data class, and consumers.
2. Preserve audit logs, soft-delete/version inventory, retention state,
   checksums, KMS health, and the last qualified infrastructure export.
3. Stop promotion of affected artifacts. For unauthorized access, retention
   weakening, key failure, or widespread corruption, page Security and preserve
   forensic evidence.
4. Do not disable retention, public-access prevention, uniform access, CMEK, or
   lifecycle policy to accelerate recovery.

Restricted bucket retention is locked at activation and is intentionally
irreversible. Recovery and cleanup must never assume that the lock can be
removed or that its period can be shortened; use a reviewed replacement or
forward-correction design that preserves every retained object.

## Recover non-destructively

- Prefer the exact object generation from versioning or soft delete and restore
  to an isolated recovery prefix or bucket first.
- Verify content checksum, signed artifact digest, provenance, SBOM, malware and
  vulnerability evidence, ownership, and expected metadata before release.
- If replication or a backup supplies the object, verify source location,
  residency, encryption, transfer checksum, and generation mapping.
- Publish a new immutable reference if bytes differ. Never overwrite a digest or
  mutable tag and claim continuity.

Cutover requires artifact-owner and Infrastructure approval; production or
restricted recovery also requires Security. Keep the old reference available
for rollback where retention permits. Cleanup is a separate reviewed change.

## Verify and record

Test authorized and denied reads, workload identity, checksums, signatures,
provenance, registry/bucket health, lifecycle/retention, audit delivery, egress,
and GitOps consumption by digest. Record generation and digest lineage,
approvals, recovery timing, and redacted evidence. Do not attach object content,
tokens, keys, or full access-policy exports.
