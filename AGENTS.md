# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Wallet: the general client-side holder that keeps openings and creates proofs.
- Keeps openings, creates proofs, and checks counterpart proofs on the member's side.
- Client only: never runs on or trusts the server.
- Openings never leave the member's devices.
- Policies arrive as data (published circuits and keys), never as imported code.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
