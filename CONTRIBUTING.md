# Contributing

Cloud Platform owns infrastructure composition; Security co-owns IAM, network,
encryption, audit, and restricted-environment controls. Changes must preserve
the one-way `bootstrap` to `infrastructure-live` to `gitops` authority flow.

Use the repository-root commands from the pinned Nix shell:

```text
just format
just format-check
just lint
just check
```

`just format` edits only handwritten source and configuration, including the
committed environment variable JSON. Generated plans, state, provider locks,
exports, evidence, and receipts remain under their owning commands. Lint
suppressions must name the exact rule and explain why the exception is safe.

Pyright is strict by default. Existing dynamic JSON, plan, and
infrastructure-contract modules carry an explicit file-level `basic` migration
directive with only the named dynamic checks disabled; newly added Python
modules inherit strict checking.

Passing local checks proves source qualification only. It does not authorize or
prove a cloud plan, apply, drift reconciliation, recovery, or production state.
