# Infrastructure apply failure

Owner: `@mindclade/infrastructure`
Security escalation: `@mindclade/security`

Use this procedure when the protected apply workflow exits after state was
locked, after one or more resources changed, or before zero-drift verification.
An apply failure is not authorization to retry, force-unlock, edit state, or
change cloud resources manually.

## Immediate containment

1. Stop additional applies for the affected environment and stack. Preserve
   the workflow run, source commit, reviewed plan digest, identity, and backend
   generation.
2. Determine whether the failure occurred before plan verification, during
   apply, or during post-apply verification. Never infer resource state from the
   workflow result alone.
3. If identity compromise, unexpected deletion, public exposure, or protected
   data impact is possible, page Security and begin the relevant containment
   procedure before further provider access.
4. Do not expose saved-plan, provider, or state contents in an issue or chat.

## Read-only diagnosis

- Confirm the exact `main` commit remains reviewed and the state boundary is
  the intended environment and stack.
- Inspect backend lock metadata through the approved operator identity. A live
  lock may represent an active or interrupted operation; do not force it.
- Run a fresh, read-only plan with locking enabled and classify its actions with
  `infractl plan classify`. Store only redacted action evidence.
- Compare provider audit events with workflow timestamps and distinguish
  desired changes, partial changes, external drift, and read failures.

## Recovery decision

- If no mutation occurred, correct the source or authority failure through a
  pull request and obtain a new reviewed plan.
- If a partial mutation occurred, prefer a reviewed forward correction that
  converges to the declared source. Do not replay the old plan after state or
  provider state has changed.
- If recovery requires import, state movement, backend migration, force-unlock,
  deletion, or replacement, stop. Create a separate change record with exact
  addresses, dependency order, backup evidence, rollback, and independent
  approval. The standard protected workflow intentionally denies these actions.
- Release an abandoned lock only after proving no active operation exists and
  receiving explicit authorization for the exact lock identifier.

## Verification and closure

Require a zero-change plan, policy pass, expected resource health, audit-log
continuity, and workload owner confirmation. Record source and state identities,
redacted before/after classifications, approvals, operator identities, and
follow-up monitoring. Close only after drift detection returns clean; never
label source validation as connected qualification.
