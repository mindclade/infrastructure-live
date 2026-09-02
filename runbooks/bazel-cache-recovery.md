# Bazel cache recovery

The Bazel HTTP cache is an accelerator. Nothing it serves is build or release
evidence, and `cache_outputs_are_evidence` is `false` in the boundary contract
and asserted by the module. Any incident below is therefore recoverable by
discarding cache state; no release evidence is ever reconstructed from it.

## Invariants

- Pull-request identities hold `roles/storage.objectViewer` on the cache bucket
  only. They cannot write, overwrite, or delete an entry.
- Protected-main writers hold `roles/storage.objectCreator`, never
  `objectAdmin`. A write can add an entry; it cannot replace a good entry with a
  poisoned one.
- Write principals exist only at `WRITE_ACTIVATED`. A read-qualified cache with
  a write principal fails the module preconditions.
- Reads are authenticated. The repositories are internal or private, so the
  bucket enforces public access prevention and is never anonymously readable.

## Suspected poisoned entry

1. Set `cache_mode` to `disabled` in the boundary contract and apply. Builds
   fall back to full local execution; correctness never depended on the cache.
2. Run the cacheless canary (`just ci-cacheless-canary` in the product
   repository). A green canary with a red cached build confirms the cache, not
   the source, is at fault.
3. Roll the namespace: increment `namespace.namespace_epoch`. The epoch is part
   of the bucket, key ring, and object namespace, so a new epoch is a new,
   empty cache. Do not attempt to delete individual objects; writers cannot
   delete, and selective deletion cannot prove the poisoned entry was the only
   one.
4. Re-qualify at `IAM_QUALIFIED` (read only), confirm reproducibility against
   the canary, and only then restore `WRITE_ACTIVATED`.

## Cache unavailable

No action is required. A cache miss is a cache miss: Bazel builds the target
locally. Confirm the build succeeded with `--remote_cache=` empty before
escalating; an unavailable cache must never fail a build.

## Unexpected write

The external audit sink records `ADMIN_READ`, `DATA_READ`, and `DATA_WRITE` for
both buckets into a separate audit bucket outside the cache project. Query it
for the writer principal, confirm whether the write came from the protected-main
writer identity, and if it did not, revoke the workload-identity binding before
rolling the namespace as above.

## Rollback

Object versioning is enabled and non-current versions are retained for seven
days, so an unintended lifecycle or retention change is reversible within that
window. Beyond it, roll the namespace epoch; a rebuilt cache costs build time
and nothing else.
