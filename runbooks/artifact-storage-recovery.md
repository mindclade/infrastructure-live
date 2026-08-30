# Artifact storage recovery

Owner: `@mindclade/platform-operations`
Artifact provenance owner: `@mindclade/platform-operations`

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

## Production CI evidence archive

The production CI evidence archive is a separate, internal-data bucket in the
production artifacts boundary. Its source profile is deliberately disabled and
all connected project and identity inputs are null. Source validation is not
evidence that the bucket, key, IAM, retention, or restore path exists.

The qualified design uses a deterministic
`<project-id>-production-ci-evidence` bucket in `NAM4`, Standard storage with
default asynchronous replication, and a NAM4 software CMEK rotated every 90
days. Uniform bucket-level access and public-access prevention are mandatory.
The key, bucket, and retention policy are deletion-protected; force destroy is
prohibited. Object versioning is disabled, soft delete is 30 days, bundles over
1 MiB transition to Archive after 90 days, and deletion is eligible only after
the 2,555-day retention period.

The keyless writer receives only `roles/storage.objectCreator`; the independent
recovery verifier receives only `roles/storage.objectViewer`. The Cloud Storage
service agent is the only archive-key encrypter/decrypter. Before activation,
bind all three exact principals and the project/resource references through the
protected production authority and prove that overwrite, list, read-by-writer,
write-by-verifier, delete, IAM administration, and public access are denied.

Create the bucket with `retentionLocked=false`. Qualify a canary upload using a
create-only generation precondition, record its generation and checksums, read
that exact generation through the verifier, and exercise isolated restore and
CMEK recovery. Retention lock is not an available source transition: schema,
module, policy, and tests reject it even when a catalog author fabricates a
generation-bound receipt. A future design must cryptographically verify evidence
and approval under an independently controlled trust root before the currently
unreachable mutation can be considered. Once locked it would be irreversible
and must never be represented as rollback-capable.

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

The scheduled disaster-recovery workflow validates this source contract only.
Its default job has no cloud identity, performs no connected read, and cannot
create a bucket, alter IAM, restore an object, or lock retention. Scheduled
runs never select the connected verifier job.

The same workflow contains a separate, fail-closed connected verifier job. It
runs only for a manual dispatch from `refs/heads/main`, after the source-only
job passes, when scope is `all` or `artifacts`, and when the operator explicitly
sets `connected_ci_evidence_verification=true`. The
existing `infrastructure-apply` governance environment must require independent
approval, explicitly allow `.github/workflows/disaster-recovery.yml`, and expose
exactly these qualified, non-secret variables. Reuse of this environment does
not broaden the verifier's read-only Google Cloud identity or authorize an
infrastructure mutation:

- `CI_EVIDENCE_VERIFIER_WIF_PROVIDER`: the full numeric-project provider name
  ending in `/workloadIdentityPools/github-ci-evidence/providers/verifier`;
- `CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT`: the dedicated
  `ci-evidence-verifier@<project>.iam.gserviceaccount.com` identity; and
- `CI_EVIDENCE_ARCHIVE_BUCKET`: the deterministic production archive bucket.

Do not configure those variables, approve the environment, or enable the
bootstrap federation until the protected source SHA, numeric repository IDs,
workflow SHA, provider output, service account, bucket IAM, and positive and
negative token exchanges have been independently qualified. The auth action
uses its default provider-resource audience; an operator-supplied audience is
not accepted.

Copy the central workflow's `archive_ref` and `archive_digest` outputs into the
manual dispatch as `ci_evidence_object_uri` and `ci_evidence_digest`. The URI
must be the exact `gs://.../ci-evidence.json#<generation>` reference under the
source-defined `ci-evidence/v1/mindclade/<approved-repository>/...` namespace,
and the digest must be `sha256:<64 lowercase hexadecimal characters>` over the
canonical JSON. The job describes and downloads only that generation, checks
the generation again, recomputes the canonical digest, and verifies that the
embedded source revision equals the immutable revision in the object path.

The verifier then calls the read-only Cloud Storage `testIamPermissions` API;
it never probes denial by attempting a mutation. The accepted matrix contains
only `storage.objects.get` and `storage.objects.list`, the two relevant
permissions inherent in the required predefined ObjectViewer role. The
workflow never lists objects despite that role capability. The queried denial
surface covers bucket deletion/update/restore/relocation, retention enablement,
IP-filter and IAM mutation, folder and managed-folder mutation, multipart
creation/abort, and object create/update/delete/move/restore, IAM, context, and
retention override. Every queried mutation permission must be absent. If
object-list denial becomes mandatory, replace ObjectViewer with a separately
qualified custom role before activation; do not claim that the predefined role
denies listing.

Retain only the redacted verification record: source commit, source revision,
generation, canonical evidence digest, a SHA-256 of the exact object reference,
run identity, and the authorization matrix. Do not retain the object URI,
bucket name, downloaded evidence bytes, access token, credentials, or metadata
response. This read-only check is connected qualification evidence; it is not
a restore, bucket mutation, IAM mutation, or retention lock. A restoration
still requires a separate approved procedure and isolated destination.
