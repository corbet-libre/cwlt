//! Receipt-bound private preparation, never account admission or initialization.
use super::*;
use ckmg::wallet_engine::account::{GenesisContext, PreparedGenesis};
use std::cell::Cell;

/// Opaque RAM candidate retaining the exact Engine and private opening. No
/// proof, signing, serialization, accepted-state or initialization API exists.
/// The upper owner must independently refresh current admission and policy.
pub struct AccountGenesis {
    engine: Engine,
    candidate: PreparedGenesis,
    context: GenesisContext,
    sealed: SealedAccountKey,
    failed: Cell<bool>,
}

impl DurableAccountOwner {
    /// Prepare private genesis only for the exact receipt-installed account key.
    /// The public context is data: this checks the durable local key and secret,
    /// not current enrollment authority or an issuer's acceptance.
    pub fn prepare_genesis<B: Backend>(
        &self,
        fresh_engine: Engine,
        store: &Store<B>,
        context: GenesisContext,
        now: u64,
    ) -> Result<AccountGenesis, Error> {
        let projection = self.projection(&fresh_engine, store)?;
        check_row(&self.scope, &context, &projection)?;
        let candidate = fresh_engine.prepare_genesis(context.clone())?;
        candidate.check_context(&fresh_engine, &context, now)?;
        Ok(AccountGenesis {
            engine: fresh_engine,
            candidate,
            context,
            sealed: SealedAccountKey::from_bytes(self.sealed.as_bytes())?,
            failed: Cell::new(false),
        })
    }
}

impl AccountGenesis {
    /// Terminally discard this RAM candidate after cancellation or refusal by
    /// its owning custody layer. This cannot restore or grant any authority.
    pub fn invalidate(&self) {
        self.failed.set(true);
    }

    /// Recheck the exact durable capsule and frozen public data with a fresh
    /// Keys-derived Engine. Refusal terminally fences this RAM candidate. This
    /// is local consistency only; remote current authority needs a real refresh.
    pub fn check_current<B: Backend>(
        &self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &Store<B>,
        context: &GenesisContext,
        now: u64,
    ) -> Result<(), Error> {
        if self.failed.replace(true) {
            return Err(Error::Conflict);
        }
        if self.sealed.as_bytes() != owner.sealed.as_bytes() || context != &self.context {
            return Err(Error::Conflict);
        }
        let projection = owner.projection(fresh_engine, store)?;
        check_row(&owner.scope, context, &projection)?;
        // PreparedGenesis binds its private opening to this original Arc. A
        // fresh owner authenticates the capsule above without replacing it.
        self.candidate.check_context(&self.engine, context, now)?;
        self.failed.set(false);
        Ok(())
    }
}

fn check_row(scope: &str, context: &GenesisContext, projection: &Projection) -> Result<(), Error> {
    if context.community_id != scope
        || context.enrollment.key != projection.public_key
        || context.enrollment.secret_hash != projection.registered_secret
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
