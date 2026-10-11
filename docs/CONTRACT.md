# Wallet contract

The Rust transition planner and maintained JS/Noir witness builder produce private
candidates, never acceptance. The caller retains the original opening, pending
public request, accepted outcome certificates and complete maps until the shared
Vault checkpoint commits. Uncertain issuer or storage outcomes reconcile rather
than constructing a new request or lifetime genesis.

With the `passport` feature, `PassportHolder` (also `passport::Holder`) owns the existing opaque `cpsd`
engine. `from_seed(&mut [u8;32])` consumes and wipes a purpose-separated seed from
Keys. All issuance, pseudonym and presentation operations delegate unchanged to
Pseudonyms. Only public protocol messages and signed attributes leave the engine;
there is no raw holder/root/opening getter or serializable custody object.
Authenticated origin requests are mandatory. The embedding Keys/Vault runtime
owns fresh authorization, revocation and lock lifetime. This wrapper supplies no
new derivation, credential relation, transfer or recovery rule.

Native and actual Wasm tests execute maintained blind issuance and authenticated
presentation with the same deterministic pseudonym vector, reject wrong scope and
issuer, and preserve the last verified passport after failed renewal. The full
extension-account journal, encrypted restore and compound publication remain
integration work, separate from this passport engine.

`Holder::with_session<T>(impl for<'a> FnOnce(PassportSession<'a>) -> T) -> T`
is the sole operation port. The borrowed session exposes the existing protocol
operations but no engine reference or constructor; callers cannot move the owned
holder out with `mem::replace`, or return a session/reference beyond authorization.
Keys owns fresh authorization and lends this view through its callback. It must
not expose `&mut PassportHolder`. A common random identity root is equally wrapped
for each enrolled passkey by the Keys owner; Wallet does not choose a root recipe
or claim recovery after all local and DHT copies are lost.

## Original durable holder and record cache

`Holder::from_holder_seed` consumes only the freshly authorized Keys capability.
`DurableHolder` retains the original CPSD sealed holder and exactly matching
original CWST owner record. Explicit creation requires an absent holder record;
ordinary `open` refuses missing or wrong-scope state. Pending issuance, finish
and cancellation are separate private candidates. A public request or result
is released only after the actual compound Store CAS and its original matching
receipt prove the exact operation and sealed-record digest. Companion changes
cannot replace the holder namespace. Cancelled or uncertain writes require
reopening the actual Store and adopting its authenticated outcome; readback or
a version number cannot replace the original receipt barrier. An invalid issuer
answer consumes its opening only when that refused result has committed.

The staged `DurableRecord` similarly installs a candidate only after its exact
Store receipt. It consumes `ckmg::wallet_engine`, sharing the original main engine
and CZKP types; another engine dependency instance cannot substitute. Cached
proof framing supplies neither proof verification nor accepted-account authority.

This port preserves the original non-root v2 passport and sealed holder codecs.
Extended root-bearing holder state is refused intact by CPSD, with no implicit
migration or reencoding. Original real issuance, Memory/File Store, competing CAS,
lock, rejected-result and uncertain/cancelled write tests are authored. Cargo
tests have not run in this tranche. The shared CKMG dependency adoption and
complete native/browser custody and accounting acceptance remain unqualified.

The opaque `cwlt-engine::RecordRecipient` opens only the original whole shuffled
record-witness object. Keys supplies a separate immutable common-root purpose,
the original community coordinate and its current checked clock floor through a
borrowed synchronous capability. The receiver enforces the authenticated Epoch's
configured period, exclusive expiry, exact whole-object length/digest and packet
framing before HPKE. Exactly one opening must match the expected owner and the
original leaf commitment, Merkle path and issuer certificate. The retained packet
has no plaintext, path, blinding or serialization getter and remains device RAM.
Opening consumes the borrowed recipient on success or refusal. The decoded
packet retains its highest checked RAM clock; rollback or exclusive expiry
terminally refuses that packet, with no claim of a persisted clock floor.

The expected owner and Epoch must come from genuine current owners. This lower
transport check neither initializes an account nor proves its private opening;
the original account/circuit/prover join remains separate. Tests use maintained
HPKE, Poseidon2/Merkle and Ed25519 with fictional lower inputs, and do not claim
accepted-account or production admission. The new tests have not been executed.

# Pending account owner

The account owner captures one maintained random P-256 key and the existing
balance-purpose registered-secret commitment. It does not derive a P-256 key
from that secret, a passkey or a device signing key. Its fixed, separately framed
authenticated envelope preserves the original Engine v1/v2 wire formats.

The upper wallet keeps each preparation opaque, with one immutable operation,
sealed byte snapshot and Store base. It consumes the commit attempt before
awaiting the original Store. A public enrollment projection becomes available
only after the actual receipt binds that Store, operation and exact sealed record
hash. Cancellation and unknown outcomes retain the same encrypted intent for
reconciliation against the original authenticated winner; they never regenerate
the key or infer absence. Ordinary open accepts existing authenticated state only.
Equal passkeys supplying the same original engine binding restore the same key.

The lower internal cryptographic package's public data grants no authority. Vault
must freshly authorize original Keys Use for every production projection and drop
the wallet owner on lock. This stage adds no signing oracle, verified enrollment,
delegation, admission, accepted Frontier, proof or initialized accounting state.
Those original owner and circuit joins remain required. The added actual Store
and maintained-crypto tests are source scenarios until native execution succeeds;
Memory test storage does not establish disk durability or production admission.
