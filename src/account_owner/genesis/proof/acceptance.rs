//! Original issuer acceptance of one proven private candidate; no custody release.
use super::*;
use ckmg::wallet_engine::account::{AcceptanceBinding, AcceptedGenesisProof, IssuerAcceptance};

/// The exact proven candidate after a valid original operator signature over its
/// reconstructed public transcript. It is opaque and has no installation or
/// serialization API. The upper owner must still verify its own current
/// owner/Frontier state and win the accepted compare-and-swap before any release.
pub struct AcceptedAccountGenesis {
    engine: Engine,
    candidate: AcceptedGenesisProof,
    context: GenesisContext,
    sealed: SealedAccountKey,
    failed: Cell<bool>,
}

impl AccountGenesisProof {
    /// Verify the original operator acceptance of this retained candidate.
    ///
    /// Only the original accepted time and signature enter, with the retained
    /// request binding and pinned operator key. The signed transcript is
    /// reconstructed from this candidate; any refusal consumes it and the upper
    /// owner reopens only from its durable pending companion.
    pub fn accept<B: Backend>(
        self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &Store<B>,
        binding: &AcceptanceBinding,
        response: &IssuerAcceptance,
        mut clock: impl FnMut() -> Result<u64, ckmg::wallet_engine::Error>,
    ) -> Result<AcceptedAccountGenesis, Error> {
        let now = clock()?;
        // An acceptance cannot predate the local observation that it answers
        // or lie in the future of the trusted local clock.
        if response.accepted_at > now {
            return Err(Error::Conflict);
        }
        self.check_current(owner, fresh_engine, store, &self.context, now)?;
        let Self {
            engine,
            candidate,
            context,
            sealed,
            ..
        } = self;
        let accepted = AcceptedAccountGenesis {
            engine,
            candidate: candidate.accept(binding, response)?,
            context,
            sealed,
            failed: Cell::new(false),
        };
        accepted.check_current(owner, fresh_engine, store, clock()?)?;
        Ok(accepted)
    }
}

impl AcceptedAccountGenesis {
    /// Irreversibly fence this RAM owner after custody cancellation or refusal.
    pub fn invalidate(&self) {
        self.failed.set(true);
    }

    /// Original accepted time that the operator signed.
    pub fn accepted_at(&self) -> u64 {
        self.candidate.accepted_at()
    }

    /// Recheck this exact private candidate, account capsule and current receipt.
    /// This checks local consistency, never current remote enrollment authority.
    pub fn check_current<B: Backend>(
        &self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &Store<B>,
        now: u64,
    ) -> Result<(), Error> {
        if self.failed.replace(true) {
            return Err(Error::Conflict);
        }
        if self.sealed.as_bytes() != owner.sealed.as_bytes() {
            return Err(Error::Conflict);
        }
        let projection = owner.projection(fresh_engine, store)?;
        check_row(&owner.scope, &self.context, &projection)?;
        self.candidate
            .check_context(&self.engine, &self.context, now)?;
        self.failed.set(false);
        Ok(())
    }
}
