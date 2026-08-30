set dotenv-load := false
set positional-arguments := true
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt:
    tofu fmt -recursive opentofu
    gofmt -w tooling/cmd/infractl/main.go tooling/internal/*/*.go

fmt-check:
    tofu fmt -check -recursive opentofu
    @unformatted="$(gofmt -l tooling/cmd/infractl/main.go tooling/internal/*/*.go)"; test -z "$unformatted" || { printf '%s\n' "$unformatted"; exit 1; }

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

test-go:
    cd tooling && go test ./... && go vet ./...

test-python:
    @for directory in tests/*; do PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$directory" -p 'test_*.py'; done

test-bazel:
    @output_root="$(mktemp -d)"; cleanup() { chmod -R u+w "$output_root" 2>/dev/null || true; rm -rf -- "$output_root"; }; trap cleanup EXIT; if command -v bazelisk >/dev/null 2>&1; then bazel_bin="$(command -v bazelisk)"; else bazel_bin="$(command -v bazel)"; fi; USE_BAZEL_VERSION=9.2.0 "$bazel_bin" --batch --output_user_root="$output_root/user" test //... --lockfile_mode=off --test_output=errors --symlink_prefix="$output_root/symlink-"

validate: fmt-check validate-catalog validate-policy validate-tofu lint-ci

test: test-go test-python test-bazel

ci: validate test

plan-classify plan_json:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" plan classify --input "{{plan_json}}"

policy-verify:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" policy verify --root .

drift-classify desired observed:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" drift classify --desired "{{desired}}" --observed "{{observed}}"

reconciliation-verify desired observed:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" reconciliation verify --desired "{{desired}}" --observed "{{observed}}"

export-payload args:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" exports payload {{args}}

export-emit args:
    @binary="$(mktemp)"; trap 'rm -f "$binary"' EXIT; (cd tooling && go build -o "$binary" ./cmd/infractl); "$binary" exports emit {{args}}
