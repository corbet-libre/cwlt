# Internal Wallet engine

This unpublished workspace package remains inside the original Wallet repository
and licence. Manager decision2026-10-02 05:11 places pure witness custody below
Keys; it is not a new product or repository. Keys will depend on the original git
main package and reexport its opaque types. Upper Wallet must consume that SAME
reexport, avoiding a second local-path/git type identity in owner CI.

Implemented candidate: `Engine::from_seed_and_sealing_key(seed,key,context)` wipes
both inputs and binds a private maintained XChaCha20Poly1305 cipher once.
`seal()` draws its nonce with maintained getrandom (OS or browser WebCrypto) and
encodes only its own private state. `restored(&Sealed)` authenticates with the
original key/context and requires the same original root. `Sealed` exposes only
bounded ciphertext. There is no root getter, rekey, generic byte encryption,
caller-selected RNG or factory callback. Old unrelated StoreCipher formats are
not accepted; any needed migration must remain an explicit Keys-owned operation.

Current state is UNINITIALIZED ONLY. These methods grant no balance, reservation,
proof, signed acceptance, Store receipt or first-content permission. It must not
be integrated as an accepting replacement for Wallet.

`src/maps.rs` and `src/hash.rs` retain the in-progress Rust port of the original
`runtime/hashes.mjs`32-level indexed map and account hash input construction.
They remain unwired into the public engine until actual signed-state adoption is
complete. `src/poseidon.rs` calls maintained `pso-poseidon`0.5 `hash_noir` with
arkworks0.6 canonical field conversion; no permutation, constants or sponge is
implemented here. The dependency's other `hash` method uses different framing
for multiples of three and is deliberately not used. Its primary source is
https://github.com/psonet/pso-poseidon; compatibility is NOT assumed from its README.
`tests/maps.rs` executes that real Rust primitive and every Rust map operation
against a fresh transcript from original `runtime/hashes.mjs` and maintained BB.
CI generates that transcript before native and actual browser tests; no canned
hash callback is accepted. The source preserves predecessor-before-append ordering
and leaves the old map intact when any asynchronous hash fails. All Rust vectors
remain UNCOMPILED/UNEXECUTED pending genuine lower-main dependency qualification.

Remaining work: original enrollment and opening state, full ExtensionWitness
transitions/public and private ABI, concrete native/browser maintained-BB
execution, exact original request/acceptance/certificate validation, sealed
accepted+pending serialization, and parent Wallet's same-Store CAS contribution
with Waves/Contacts/Threads/Delivery. Preserve original accepted opening until
receipt-based adoption and actual uncertainty reconciliation. Qualify against
original JS-generated maintained-BB map/commitment vectors and actual Noir proofs;
no fake hashes, accepting verifier or peer proof can supply local state.

Native/browser sealing refusal vectors are written in tests/sealing.rs but
UNEXECUTED. Standalone rustfmt and whitespace checks are the only local checks.
The complete existing coverage/advisory/browser gates must include this package
before its first protected main release; then Keys can consume it, and Wallet can
integrate the Keys reexport. No candidate alias or Cargo patch is permitted.
