set dotenv-load := false
set positional-arguments
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

format:
    biome check --write .
    ruff format .
    cd tooling && golangci-lint fmt --config ../.golangci.yml
    opa fmt -w policy
    tofu fmt -recursive opentofu
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=fix
    nixfmt flake.nix
    just --fmt

format-check:
    biome check .
    ruff format --check .
    cd tooling && golangci-lint fmt --config ../.golangci.yml --diff
    opa fmt --fail policy >/dev/null
    tofu fmt -check -recursive opentofu
    git ls-files 'BUILD.bazel' 'MODULE.bazel' '*.bzl' | xargs buildifier -mode=check -lint=warn
    nixfmt --check flake.nix
    just --fmt --check

fmt: format

fmt-check: format-check

lint:
    biome lint .
    ruff check .
    pyright
    cd tooling && golangci-lint run --config ../.golangci.yml ./...
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml
    yamllint --config-file .yamllint.yaml .
    markdownlint-cli2

validate-catalog:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" catalog validate --root .

validate-policy:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" policy verify --root .

validate-tofu:
    @validation_dir="$(mktemp -d)"; trap 'rm -rf "$validation_dir"' EXIT; cp -R opentofu catalog "$validation_dir/"; mkdir -p "$validation_dir/plugin-cache" "$validation_dir/tofu-data"; \
      seed="$validation_dir/opentofu/live/development/foundation"; \
      TF_DATA_DIR="$validation_dir/tofu-data" TF_PLUGIN_CACHE_DIR="$validation_dir/plugin-cache" tofu -chdir="$seed" init -backend=false -input=false; \
      for root in "$validation_dir"/opentofu/live/*/*; do if [[ "$root" != "$seed" ]]; then cp "$seed/.terraform.lock.hcl" "$root/.terraform.lock.hcl"; fi; done; \
      for stack in foundation network artifacts data-services clusters ci-execution observability; do \
        for environment in development staging production restricted; do \
          root="$validation_dir/opentofu/live/$environment/$stack"; \
          if [[ "$root" != "$seed" ]]; then TF_DATA_DIR="$validation_dir/tofu-data" TF_PLUGIN_CACHE_DIR="$validation_dir/plugin-cache" tofu -chdir="$root" init -backend=false -input=false; fi; \
          TF_DATA_DIR="$validation_dir/tofu-data" TF_PLUGIN_CACHE_DIR="$validation_dir/plugin-cache" tofu -chdir="$root" validate; \
        done; \
      done

lint-ci:
    actionlint .github/workflows/*.yml
    zizmor --no-progress --offline .github/workflows/*.yml

test-go:
    cd tooling && go test ./... && go vet ./...

test-python:
    @for directory in tests/*; do PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$directory" -p 'test_*.py'; done

test-bazel:
    @bazel_args=(); if test -n "${MACOSX_DEPLOYMENT_TARGET:-}"; then bazel_args+=("--repo_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--action_env=MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET}" "--copt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}" "--linkopt=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"); fi; bazel test --config=ci ${bazel_args[@]+"${bazel_args[@]}"} //...

flake-check:
    nix flake check --no-accept-flake-config --no-build --no-update-lock-file

# Vulnerability scan of declared dependencies. Requires network access to the
# OSV database, so it is deliberately separate from the hermetic lint recipe.
security:
    osv-scanner scan source --recursive .

check: format-check lint validate-catalog validate-policy validate-tofu test security flake-check

validate: check

test: test-go test-python test-bazel

ci: check

plan-classify plan_json:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" plan classify --input "{{ plan_json }}"

policy-verify:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" policy verify --root .

drift-classify desired observed:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" drift classify --desired "{{ desired }}" --observed "{{ observed }}"

reconciliation-verify desired observed:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" reconciliation verify --desired "{{ desired }}" --observed "{{ observed }}"

export-payload args:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" exports payload {{ args }}

export-emit args:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" exports emit {{ args }}
