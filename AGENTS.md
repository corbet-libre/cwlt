# cwlt — agent notes

Commands (repo root, its own workspace; work in a lane, never edit `~/agents/scratch/ws`; lane-wide checks run via `cargo xtask check/test`):
- `bash .ci/update-our-crates.sh` first: advances internal crates to newest main; the `--locked` gates below assume it
- `cargo fmt --check`
- `node tools/emit.mts --check` (committed `runtime/*.mjs` must equal the generator output)
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo test --locked --workspace --all-features`

Hard invariants (enforcing check after each):
- Client-only: never runs on or trusts the server; the device check is local, `cvfy` is authoritative. Enforced by `src/voucher.rs` (server sees only unlinkable proofs/tags) + `engine/src/browser_prover/tests.rs` (`only_the_pinned_setup_sizes_the_origin_paths_and_the_bounds_are_accepted`).
- Openings never leave member devices (zeroizing buffers, no getters/clone/serialization of openings). Enforced by `engine/src/account/prepared/native/acceptance/tests.rs` and `engine/src/account/prepared/native/pending/tests.rs` (acceptance-gated adoption) + type-level absence of accessors in `engine/src/recipient.rs`.
- Policies arrive as data (published circuits/keys), never as imported code. Enforced by the pinned-setup browser-prover test above.
- A successor opening is adopted only after verified signed acceptance of the exact transcript; restored candidates still require it. Enforced by `engine/src/account/prepared/native/acceptance/tests.rs` (`actual_proof_accepts_only_the_exact_operator_signature_over_its_transcript`).
- Emitted JS matches the generator. Enforced by `node tools/emit.mts --check` (CI gate).

Pointers: `docs/CONTRACT.md`, `docs/COVERAGE.md`; witness engine in `engine/`; holder API in `src/`; emitted runtime in `runtime/*.mts`.
LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only code.
