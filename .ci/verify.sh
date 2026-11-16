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
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
python3 .github/check-first-party.py --metadata dependency-metadata.json
python3 -B .github/test-engine-identity.py
rustc --version
cargo fmt --check || { cargo fmt; git diff > formatting.patch; exit 1; }
# The committed .mjs under runtime/ must equal what tools/emit.mts generates from the .mts sources.
node tools/emit.mts --check
# Reuse the resolved original verifier owner's pinned SDK environment unchanged.
python3 -B .ci/import-native-prover-sdk.py
CWLT_NATIVE_PROVER_FIXTURE="$(python3 -B .ci/prepare-native-prover-fixture.py)"
export CWLT_NATIVE_PROVER_FIXTURE
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo clippy --locked --workspace --all-targets --all-features -- -D warnings; cargo build --manifest-path engine/Cargo.toml --locked --features native-prover --example cwlt-account-worker --message-format=json > native-prover-build.json; CWLT_NATIVE_PROVER_WORKER="$(python3 -B .ci/native-prover-worker-path.py)"; export CWLT_NATIVE_PROVER_WORKER; cargo test --locked --workspace --all-features'
wasm-pack build wasm --target web --release --out-dir ../pkg --out-name cwlt
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
# The coverage run executes the same native-prover tests as the test phase above, so it needs the same worker.
CWLT_NATIVE_PROVER_WORKER="$(python3 -B .ci/native-prover-worker-path.py)"
export CWLT_NATIVE_PROVER_WORKER
"$NIGHTLY_CARGO" llvm-cov --version
# One instrumented execution on the nightly toolchain, in ccid's private target directory; the [coverage]
# table of .ci/ccid.toml holds the flags and the gates (100% of emitted lines and branches, no exclusions).
ccid coverage run
