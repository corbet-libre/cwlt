# Internal Wallet engine

This unpublished workspace package remains inside the original Wallet repository
and licence. It ports the original opaque custody, sealing and epoch-cache owners
from preserved Wallet v01 source `c154a5ff6c317ce1eff6b37af60e7500fa9ee773`.
Keys initializes the immutable purpose-key binding. Upper Wallet must consume
the exact engine types reexported by Keys; local-path and git engine identities
must not be combined at that boundary. This stage does not wire that integration.

`Engine::from_seed_and_sealing_key(seed,key,context)` wipes both inputs and binds
a private maintained XChaCha20Poly1305 cipher once. `seal()` draws its nonce with
maintained getrandom and encodes only its own private state. `restored(&Sealed)`
authenticates with the original key/context and requires the same original root.
`Sealed` exposes only bounded ciphertext. There is no root getter, rekey, generic
byte encryption, caller-selected RNG or factory callback. Unrelated StoreCipher
formats are not accepted; migration must remain an explicit Keys-owned operation.

The account remains **uninitialized**. This engine grants no accepted balance,
reservation, signed state acceptance, Store receipt or first-content permission.
It does not implement native account witnesses, issuer-acceptance adoption or a
prover, and must not be used as an accepting replacement for those owners.

The record owner retains a fresh epoch-local Ed25519 key and a bounded public
proof cache. It validates the original issuer's real leaf certificate, epoch,
owner and presentation-key binding. Caching checks proof framing, not the proof
relation. `record_ready` means a cache exists for the exact live epoch; every
relying party still needs independently authenticated material and actual proof
verification. `present_record` performs only the cheap original challenge binding.
Wallet must persist the candidate through the original Store before lending it.

Original sealing and record tests exercise maintained cryptography, immutable
key/root/context binding, ciphertext mutations, epoch rollback and cache conflicts.
Synthetic proof hex is explicitly a storage/framing vector, never a valid proof
or proof-verification test. No local Cargo, resolver, native/browser execution or
CI qualification was performed for this source port.

The original unwired map/hash/Poseidon files and genuine external-vector tests
remain preserved in v01 for a separate accounting-relation stage. Original maps
use depth 20; current main's JavaScript map relation uses depth 32. This port does
not silently change that relation or claim cross-runtime hash/proof conformance.
Full accepted and pending opening custody, concrete maintained-BB proving, signed
acceptance validation and receipt-based atomic adoption remain required.
