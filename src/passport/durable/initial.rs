//! Original sealed holder prepared for an enclosing owner's atomic initial batch.
use super::*;

/// Encrypted original holder record bound to one exact original Store snapshot.
/// This is data for a creation owner's batch, not durable custody or authority.
/// There is no holder, projection, signing or issuance accessor. After the outer
/// owner commits, normal restoration must use `DurableHolder::open`.
pub struct InitialCheckpoint {
    sealed: cpsd::SealedHolder,
    scope: String,
    checkpoint: [u8; 32],
    operation: [u8; 32],
}

impl DurableHolder {
    /// Prepare the original sealed format for atomic composition with initial
    /// Keys acknowledgment. The caller must retain genuine creation authority;
    /// an absent record and this encrypted candidate provide none by themselves.
    pub fn prepare_initial<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        initial: Holder,
        store: &Store<B>,
        scope: &str,
        operation: [u8; 32],
        rng: &mut R,
    ) -> Result<InitialCheckpoint> {
        if !store.is_scope(scope) || store.read(OWNER, KEY)?.is_some() {
            return Err(PersistenceError::Initialization);
        }
        if operation == [0; 32] {
            return Err(PersistenceError::Conflict);
        }
        Ok(InitialCheckpoint {
            sealed: initial.0.seal(rng)?,
            scope: scope.into(),
            checkpoint: *blake3::hash(store.sealed_checkpoint()?).as_bytes(),
            operation,
        })
    }
}

impl InitialCheckpoint {
    /// Lend only the original encrypted record for the exact enclosing batch.
    /// A changed Store, operation, scope or existing holder refuses. No receipt
    /// or initialized owner is manufactured by inspecting this candidate.
    pub fn change_for<B: Backend>(
        &self,
        store: &Store<B>,
        operation: &[u8; 32],
    ) -> Result<Change<'_>> {
        if operation != &self.operation
            || !store.is_scope(&self.scope)
            || store.read(OWNER, KEY)?.is_some()
            || blake3::hash(store.sealed_checkpoint()?).as_bytes() != &self.checkpoint
        {
            return Err(PersistenceError::Conflict);
        }
        Ok(Change::Put {
            owner: OWNER,
            key: KEY,
            value: self.sealed.as_bytes(),
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/passport_initial.rs"]
mod tests;
