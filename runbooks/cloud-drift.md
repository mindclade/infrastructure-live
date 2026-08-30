# Cloud drift

Owner: `@mindclade/infrastructure`

Drift is a difference between reviewed source/state intent and observed cloud
state. A scheduled workflow failure may also be an identity, backend, provider,
or observation failure; unknown state is not clean state.

## Triage

1. Preserve the redacted drift evidence, workflow run, source commit,
   environment, stack, plan digest, and observation time.
2. Classify findings as missing, changed, unmanaged, or observation failure.
   Use `infractl drift classify` only on authorized, redacted documents.
3. Check recent protected applies, emergency changes, provider incidents, and
   audit events. Do not paste provider values or raw plan/state into tickets.
4. Escalate immediately for public exposure, wildcard IAM, key creation,
   encryption/retention weakening, disabled recovery, network boundary changes,
   or production/restricted deletion.

## Disposition

- **Expected but unmerged:** stop changes and merge the reviewed source before
  any apply; never normalize manual mutation as the new baseline informally.
- **Unauthorized manual change:** contain through the resource owner and
  Security, preserve audit evidence, and prepare a reviewed forward correction.
- **Missing resource:** determine whether deletion was intended, provider-side,
  or malicious. Recovery/deletion protection evidence decides the next path.
- **Unmanaged resource:** identify creator, purpose, data class, cost owner, and
  network/IAM exposure. Do not import or delete it without explicit approval.
- **Observation failure:** restore read-only access or provider health and rerun;
  do not suppress the finding or extend stale evidence.

## Correction and verification

Create a pull request for the smallest safe correction. Obtain a fresh plan for
the exact state boundary. Delete, replace, import, and state operations require
their own reviewed procedure. Verify zero drift, audit continuity, telemetry,
cost allocation, and workload health. Record residual exceptions with owner,
expiry, compensating control, and next review date.
