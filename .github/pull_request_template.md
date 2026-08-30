## Change summary

Describe the environment classes, stacks, catalogs, modules, policies, or
operational contracts affected and why this repository is the sole owner.

## Evidence

- [ ] `just validate` passes.
- [ ] `just test` passes.
- [ ] Plan evidence is tied to this exact commit and state boundary, or this is a provider-free source change.
- [ ] Create, update, delete, replace, IAM, exposure, encryption, availability, quota, and cost effects are summarized.
- [ ] No credential, secret payload, private identifier, state, kubeconfig, or unredacted plan is attached.

## Safety and recovery

- [ ] No OpenTofu apply, destroy, import, state mutation, backend migration, cloud mutation, or GitOps mutation was performed from this pull request.
- [ ] Authority remains `bootstrap` → `infrastructure-live` → `gitops`, with no duplicate owner.
- [ ] Production and restricted effects have independent security review.
- [ ] Rollback or forward-correction steps and post-change checks are identified.
- [ ] Any unresolved identity, backend, quota, capacity, recovery, or connected-qualification dependency is explicitly blocking.
