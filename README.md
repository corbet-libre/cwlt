# cwlt

**Zero-knowledge accounting wallet (holder).**

`cwlt` is the holder in the issuer-verifier-holder schema: it keeps the member's openings and creates proofs for `cblc` and other gates. Any client speaking the protocol is a holder; `cmsg` embeds it, other products embed it in their own client.

Extension witnesses pass native/wasm planner tests and cblc's
[real-proof acceptance suite](https://github.com/corbet-libs/cblc/actions/runs/36743686840).
Activation requires an independently pinned verifier and a real genesis proof;
no production deployment or registry release is implied.

The Rust core prepares checked private balance/counter transitions on native and
wasm32. The JavaScript adapter builds authenticated map paths and Noir witnesses
using `czkp`'s pinned upstream Poseidon2 and proof backend. The published circuit
and verification keys arrive as authenticated data. Witness planning is not
itself a proof or an acceptance.

`ExtensionWitness` builds genesis, reservation, activation, settlement, punishment,
inbox-consumption, change and quorum-record candidates. It takes a `transition`
callback wrapping the native or wasm Rust `prepare` function. Callers keep old
openings until the issuer's signed acceptance is checked and saved atomically.
Raw witness objects and Rust JSON inputs/outputs must stay on member devices.

For an authorized outcome, retain its accepted opening and issuer certificate
until a deposit proof is recoverable or the deposit is accepted. A later account
update clears the current authorization field but cannot revoke a historically
accepted certificate. Keep private snapshots only on the member's devices.

To drain an inbox, call `consume` in the supplied chain order at one common proof
time, then append the intended normal action (or `reblind`). Prove every candidate
and submit the complete bundle to cblc. Intermediate candidates retain the old
issuer version and must never be adopted as independently accepted updates.
Adopt the final opening only after verifying the whole bundle's signed acceptance.
Established punishment can arrive before its earlier Answer deposit; both orders
produce the same burn and record, and a late Answer cannot refund punishment.

Cryptographic library selection: reuse Noir 1.0.0-beta.26 and Barretenberg 5.2.1
through `czkp`; no local hash permutation, signature scheme or prover. All security
predicates must also be checked by the pinned circuits. Client matching and key
release must honor the private block; a proof cannot force a modified client.

## Scope

Wallet is the device-side holder under Vault, used by Foyer and Inbox. It keeps
private openings, reservations, outcome evidence and accepted successors, creates
proofs, and checks counterpart proofs. It adopts an account successor only after
verified signed acceptance and the shared durable checkpoint. Unknown outcomes
reconcile the original request; pending obligations are consumed before other work.

Keys derives the global passport seed; Wallet holds the passport and creates
presentations through Pseudonyms. The optional `passport` feature exposes
`passport::Holder`, which consumes and wipes that dedicated seed and retains the
existing `cpsd` opaque engine. Its public outputs are issuance messages, signed
attributes, community pseudonyms and origin-authenticated presentations. It
exports no seed, pending opening or passport. Operations are available through
`Holder::with_session` and its private borrowed `PassportSession`; the session
cannot escape the callback, and no movable engine borrow is exposed. The host must freshly authorize
operations and drop custody on lock; Keys owns derivation and device lineage.

Wallet never runs on a server, reveals a counterpart or opening, treats planning
as proof, or resets lifetime genesis after rotation. Circuit and policy material
arrive as authenticated data. Welcome/introduction grants require the actual
accounting relation and its weekly cap/headroom; seats remain disabled. The
opaque extension-account engine and atomic Vault journal are not implemented by
the passport wrapper. G2 local currentness and G5 private settlement remain open.

## Boundaries

What it does:

- Keeps openings, creates proofs, and checks counterpart proofs on the member's side.

What it never does:

- Client only: never runs on or trusts the server.
- Openings never leave the member's devices.
- Policies arrive as data (published circuits and keys), never as imported code.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
