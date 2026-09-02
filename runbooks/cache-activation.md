# Cache activation

Both estate caches ship source-complete and inert: the Nix cache module
(`opentofu/modules/gcp/nix-cache`) and the Bazel HTTP cache module
(`opentofu/modules/gcp/bazel-cache`) are `qualification: DISABLED`, and the
Bazel consumption configs in `mindclade/.bazelrc` carry an empty
`--remote_cache=`. This runbook activates them.

Activation is not a code change. Everything below is a state transition plus the
population of endpoints and key material that cannot exist in source.

## Invariants that hold at every step

- `cache_outputs_are_evidence` is `false` and asserted by both modules. Nothing
  served from a cache is ever build or release evidence.
- A cache miss or an unavailable cache is never a build failure.
- Pull-request identities read; only protected-main writers publish, and they
  hold `objectCreator`, never `objectAdmin`, so no write can replace an entry.
- The cacheless canary must stay green throughout. If it diverges from a cached
  build, the cache is wrong, not the source.

## The recovery plane deliberately does not use these caches

`bootstrap/.github/workflows/recovery-verification.yml` asserts that
`nix config show` reports exactly the upstream substituter and key. **Leave it
that way.** Recovery must be reproducible from upstream alone, because the
incident being recovered from may be the cache itself.

This is safe to leave alone for a reason worth recording, since it is easy to
get wrong in both directions: that workflow pins `NIX_CONFIG` explicitly and sets
`accept-flake-config = false`, and a flake's `nixConfig` is **not applied** when
that is false. Verified directly:

```console
NIX_CONFIG='...accept-flake-config = false
substituters = https://cache.nixos.org/...'
# inside a flake declaring two substituters in nixConfig:
nix config show --json | jq .substituters
# => ["https://cache.nixos.org/"]
```

So adding a substituter to any `flake.nix` does not reach the recovery plane and
does not require widening that assertion. Adding one to a context that sets
`NIX_CONFIG` explicitly does.

## Nix cache

1. **Key material.** Generate an Ed25519 signing keypair
   (`nix key generate-secret --key-name mindclade-nix-cache-1`). Commit only the
   public half to `bootstrap/manifests/signing-roots.yaml` `publicKeys`, with its
   digest in `publicKeyDigest`. Store the private half as a write-only Secret
   Manager version of `nix-cache-signing-key`. The module precondition requires
   the private key's name to match the first committed public key, so the two
   cannot drift.
2. Set `nixCacheSigningRoot.state: ACTIVE` and `activationEnabled: true`, and
   clear the three blockers.
3. Move the cache boundary `DISABLED -> IAM_QUALIFIED`, populate
   `protected_inputs`, and apply. This grants read only.
4. Add the substituter and public key where `NIX_CONFIG` is set explicitly:
   `mindclade/.buildkite/hooks/environment` is the real consumption point. Keep
   `require-sigs = true`; the point of the signing root is that an unsigned path
   is rejected.
5. Verify a cache-hit build reproduces the cacheless canary bit for bit, then
   move to `WRITE_ACTIVATED` and `cache_mode: write`.

## Bazel cache

1. Move the boundary `DISABLED -> IAM_QUALIFIED` and populate
   `protected_inputs` in the `bazel_cache` stack variable. The default in
   `opentofu/stacks/artifacts/variables.tf` is the disabled state, so this is the
   first change that makes the module allocate anything.
2. Populate the endpoint in `mindclade/.bazelrc`. The two consumption modes are
   already declared and already carry their safety flags:

   ```
   build:cache-read  --remote_cache=https://<endpoint>
   build:cache-write --remote_cache=https://<endpoint>
   ```

   `cache-read` keeps `--remote_upload_local_results=false` and `cache-write`
   keeps `--google_default_credentials=true`. Do not add flags; only set the
   endpoint.
3. Use `--config=cache-read` on pull requests and `--config=cache-write` only on
   protected-main Buildkite jobs.
4. Declare the cacheable-target allowlist in `boundary.cacheable_targets`. A
   qualified cache with an empty allowlist fails module validation.
5. Move to `WRITE_ACTIVATED` only after a cache-hit build matches a cacheless
   build.

## Rollback

Set `cache_mode: disabled` and apply. Builds fall back to full local execution;
correctness never depended on the cache. For a suspected poisoned entry, follow
`runbooks/bazel-cache-recovery.md` or `runbooks/nix-cache-recovery.md` and roll
the namespace epoch rather than deleting objects.
