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
