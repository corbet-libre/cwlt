//! Private native proof bridge; public math data is not a signed request.
use super::*;
mod acceptance;
pub use acceptance::AcceptedAccountGenesis;
mod pending;
use ckmg::wallet_engine::{
    account::{GenesisProofScope, GenesisPublic, PreparedGenesisProof},
    native_prover::NativeProver,
};
pub use pending::{ActivatedAccount, PendingActivation, ReopenedPending};

/// Original candidate and locally verified proof, without accepted custody.
/// The private opening and Engine remain owned together through cancellation.
pub struct AccountGenesisProof {
    engine: Engine,
    candidate: PreparedGenesisProof,
    context: GenesisContext,
    sealed: SealedAccountKey,
    failed: Cell<bool>,
}

/// Public mathematical data for the upper owner's original typed request codec.
/// This is neither a signed request nor permission to send or install a state.
/// Production composition retains it privately until the pending Store receipt.
pub struct GenesisRequestMaterial<'proof> {
    /// Exact projection used by the candidate's native public-input serializer.
    pub statement: GenesisPublic,
    /// Original authenticated whole circuit and verification-key group scope.
    pub scope: &'proof GenesisProofScope,
    /// Original locally verified proof; no private witness or opening is here.
    pub proof: &'proof [u8],
}

impl AccountGenesis {
    /// Consume this private candidate into the bounded original native prover.
    /// Original Keys and remote authority must be checked by the custody layer
    /// before and after this call. Successful computation grants no acceptance.
    pub fn prove<B: Backend>(
        self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &Store<B>,
        prover: &NativeProver,
        mut clock: impl FnMut() -> Result<u64, ckmg::wallet_engine::Error>,
    ) -> Result<AccountGenesisProof, Error> {
        self.check_current(owner, fresh_engine, store, &self.context, clock()?)?;
        let candidate = self.candidate.prove(&self.engine, prover, &mut clock)?;
        let proven = AccountGenesisProof {
            engine: self.engine,
            candidate,
            context: self.context,
            sealed: self.sealed,
            failed: Cell::new(false),
        };
        proven.check_current(owner, fresh_engine, store, &proven.context, clock()?)?;
        Ok(proven)
    }
}

impl AccountGenesisProof {
    /// Irreversibly fence this RAM owner after custody cancellation or refusal.
    pub fn invalidate(&self) {
        self.failed.set(true);
    }

    /// Check this exact private candidate, account capsule and current receipt.
    /// This checks local consistency, never current remote enrollment authority.
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
        self.candidate.check_context(&self.engine, context, now)?;
        self.failed.set(false);
        Ok(())
    }

    /// Borrow only verified public data after exact current local-owner checks.
    /// The upper owner independently authenticates current HTTPS origin, device,
    /// credential, policy and grant, and seals the fixed request before release.
    pub fn request_material<B: Backend>(
        &self,
        owner: &DurableAccountOwner,
        fresh_engine: &Engine,
        store: &Store<B>,
        context: &GenesisContext,
        now: u64,
    ) -> Result<GenesisRequestMaterial<'_>, Error> {
        self.check_current(owner, fresh_engine, store, context, now)?;
        Ok(GenesisRequestMaterial {
            statement: self.candidate.public_genesis(),
            scope: self.candidate.scope(),
            proof: self.candidate.proof(),
        })
    }
}
