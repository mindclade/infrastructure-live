# Nix cache recovery

Owner: `@mindclade/platform-operations`
Security reviewer: `@mindclade/security`

This procedure covers cache poisoning, signing-key compromise, unavailable
substituters, namespace corruption, and audit-delivery failure. The checked-in
cache boundary is disabled. Source validation is not connected qualification
and cache outputs are never build or release evidence.

## Isolate

1. Set the consumer boundary to `DISABLED`, remove the HTTPS substituter from
   the trusted Nix configuration, and perform a cacheless canary build.
2. Preserve the affected namespace epoch, object generations, `.narinfo`
   payloads, signatures, CMEK health, gateway logs, and external audit sink
   evidence. Do not download or record credentials or private signing bytes.
3. Revoke publisher impersonation before gateway read access. The publisher
   must have only `roles/storage.objectCreator`; the gateway must have only
   `roles/storage.objectViewer`.
4. Never repair poisoned objects in place. Uniform access, public access
   prevention, CMEK, retention, deletion protection, and the external audit
   boundary remain enabled throughout recovery.

## Recover

Create a new namespace epoch and new cache, health, and operation buckets.
Rebuild without any cache, verify every derivation output and NAR hash, then
publish only through a new reviewed create-only activation. The signing private
key remains in Secret Manager; source and evidence may contain only the
committed Ed25519 public key and its digest.

The 90-day cache-health bucket records canary and key-health evidence. The
400-day operation bucket records create-only activation and recovery evidence.
The cache writer cannot bind or rewrite the external audit sink destination.
Confirm audit delivery independently before permitting reads.

## Requalify

Record a new immutable source revision, toolchain digest, namespace epoch,
signer public-key digest, audit-sink digest, IAM qualification digest, cacheless
canary evidence, and poison-recovery evidence. Read mode requires an
`IAM_QUALIFIED` boundary and the exact authenticated
`https://nix-cache.mindclade.com` GET/HEAD gateway. Write mode additionally
requires a protected-trust namespace and a separately reviewed write activation
digest.

Security and Platform reviewers must approve disjoint evidence records. Do not
restore `cache-boundary.v1`, reuse the poisoned epoch, treat a cache hit as
evidence, or activate writes before the cacheless rebuild and recovery exercise
both pass.
