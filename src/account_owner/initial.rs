//! Original opaque account capsule for an enclosing creation owner's batch.
use super::*;

/// Encrypted pending owner bound to one exact authenticated Store snapshot.
/// This contains no live key, projection, signer or admission. The enclosing
/// creation owner must commit its original batch before ordinary restoration
/// can open this record through `DurableAccountOwner::open`.
pub struct InitialAccountCheckpoint {
    sealed: SealedAccountKey,
    scope: String,
    checkpoint: [u8; 32],
    operation: [u8; 32],
}

impl DurableAccountOwner {
    /// Prepare the existing random-key capsule for an original atomic initial
    /// acknowledgment. This pure custody preparation grants no creation right;
    /// the enclosing owner must retain its genuine creation receipt and perform
    /// the actual durable CAS. Missing state during restore never calls here.
    pub fn prepare_initial<B: Backend>(
        engine: Engine,
        store: &Store<B>,
        scope: &str,
        operation: [u8; 32],
    ) -> Result<InitialAccountCheckpoint, Error> {
        let pending = Self::prepare(engine, store, scope, operation)?;
        Ok(InitialAccountCheckpoint {
            sealed: pending.sealed,
            scope: pending.scope,
            checkpoint: *blake3::hash(store.sealed_checkpoint()?).as_bytes(),
            operation,
        })
    }
}

impl InitialAccountCheckpoint {
    /// Lend only the original encrypted record for this exact batch. A different
    /// operation, changed Store or existing account refuses. Inspecting this
    /// candidate cannot manufacture a Store receipt or a public account owner.
    pub fn change_for<B: Backend>(
        &self,
        store: &Store<B>,
        operation: &[u8; 32],
    ) -> Result<Change<'_>, Error> {
        if operation != &self.operation
            || !store.is_scope(&self.scope)
            || store.read(OWNER, KEY)?.is_some()
            || blake3::hash(store.sealed_checkpoint()?).as_bytes() != &self.checkpoint
        {
            return Err(Error::Conflict);
        }
        Ok(Change::Put {
            owner: OWNER,
            key: KEY,
            value: self.sealed.as_bytes(),
        })
    }
}
