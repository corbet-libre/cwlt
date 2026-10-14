#!/usr/bin/env bash
set -euo pipefail
# Preserve actual compiler/test diagnostics in the kept job stream.
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-120}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

python3 .github/check-first-party.py --manifest-only
bash .ci/update-our-crates.sh
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
python3 .github/check-first-party.py --metadata dependency-metadata.json
python3 -B .github/test-engine-identity.py
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
# Reuse the resolved original verifier owner's pinned SDK environment unchanged.
python3 -B .ci/import-native-prover-sdk.py
CWLT_NATIVE_PROVER_FIXTURE="$(python3 -B .ci/prepare-native-prover-fixture.py)"
export CWLT_NATIVE_PROVER_FIXTURE
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo clippy --locked --workspace --all-targets --all-features -- -D warnings; cargo build --manifest-path engine/Cargo.toml --locked --features native-prover --example cwlt-account-worker --message-format=json > native-prover-build.json; CWLT_NATIVE_PROVER_WORKER="$(python3 -B .ci/native-prover-worker-path.py)"; export CWLT_NATIVE_PROVER_WORKER; cargo test --locked --workspace --all-features'
wasm-pack build --target web --release
node tests/wasm.mts
node tests/wave-wallet.mts
wasm-pack test --node --all-features

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
