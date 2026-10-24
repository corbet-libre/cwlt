//! Pending account-key durability; no accepted balance or proof is inferred.
use ckmg::wallet_engine::{
    Engine,
    account_key::{AccountKey, Projection, SealedAccountKey},
};
use cwst::{Change, Store, backend::Backend};

const OWNER: &str = "cwlt.account";
const KEY: &[u8] = b"owner.v1";

mod initial;
pub use initial::InitialAccountCheckpoint;
mod genesis;
pub use genesis::AccountGenesis;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use genesis::{
    AcceptedAccountGenesis, AccountGenesisProof, ActivatedAccount, GenesisRequestMaterial,
    PendingActivation, ReopenedPending,
};

/// Coarse refusal; no private key or opening is included.
#[derive(Debug)]
pub enum Error {
    /// The actual encrypted Store refused or has an uncertain outcome.
    Store(cwst::Error),
    /// Original immutable engine authentication or maintained crypto refused.
    Engine(ckmg::wallet_engine::Error),
    /// Scope, operation, exact bytes, receipt or attempt did not match.
    Conflict,
}
impl From<cwst::Error> for Error {
    fn from(e: cwst::Error) -> Self {
        Self::Store(e)
    }
}
impl From<ckmg::wallet_engine::Error> for Error {
    fn from(e: ckmg::wallet_engine::Error) -> Self {
        Self::Engine(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet account owner refused")
    }
}
impl std::error::Error for Error {}

/// Immutable attempt retained by its caller across cancellation. No projection,
/// signer, raw key, serialization or accepted-account conversion exists.
pub struct PendingAccountCreation {
    key: Option<AccountKey>,
    sealed: SealedAccountKey,
    scope: String,
    base: u64,
    operation: [u8; 32],
    attempted: bool,
}

/// Receipt-installed pending owner. Vault must authorize original Keys Use before
/// each access and drop this owner on lock. Enrollment/delegation, actual proofs
/// and issuer acceptance are independent mandatory joins; none is granted here.
pub struct DurableAccountOwner {
    key: AccountKey,
    sealed: SealedAccountKey,
    scope: String,
}

impl DurableAccountOwner {
    /// Prepare one explicit absent-record creation. Randomness is captured once
    /// before the async commit; no public enrollment data escapes this candidate.
    pub fn prepare<B: Backend>(
        engine: Engine,
        store: &Store<B>,
        scope: &str,
        operation: [u8; 32],
    ) -> Result<PendingAccountCreation, Error> {
        if !store.is_scope(scope) || store.read(OWNER, KEY)?.is_some() {
            return Err(Error::Conflict);
        }
        let base = store.version()?;
        let key = engine.prepare_account_key(scope, operation)?;
        let sealed = key.seal()?;
        Ok(PendingAccountCreation {
            key: Some(key),
            sealed,
            scope: scope.into(),
            base,
            operation,
            attempted: false,
        })
    }

    /// The committed account-key capsule. Only Keys signs with it
    /// (`Keys::sign_account_digest`); nothing here lends a signer.
    pub fn sealed(&self) -> &SealedAccountKey {
        &self.sealed
    }

    /// Read only the committed, receipt-authenticated capsule, with no engine and no
    /// restored key. Keys restores it inside its own custody when it signs.
    pub fn committed_sealed<B: Backend>(
        store: &Store<B>,
        scope: &str,
    ) -> Result<SealedAccountKey, Error> {
        if !store.is_scope(scope) {
            return Err(Error::Conflict);
        }
        let sealed = SealedAccountKey::from_bytes(store.read(OWNER, KEY)?.ok_or(Error::Conflict)?)?;
        receipt(store, &store.operation()?, &sealed)?;
        Ok(sealed)
    }

    /// Open only a real authenticated existing winner; absence never creates.
    pub fn open<B: Backend>(engine: Engine, store: &Store<B>, scope: &str) -> Result<Self, Error> {
        let sealed = Self::committed_sealed(store, scope)?;
        let key = engine.restore_account_key(&sealed, scope)?;
        Ok(Self {
            key,
            sealed,
            scope: scope.into(),
        })
    }

    /// Return the committed public cryptographic row under freshly authorized
    /// original Keys custody. It is not a verified delegation or admission.
    pub fn projection<B: Backend>(
        &self,
        fresh_engine: &Engine,
        store: &Store<B>,
    ) -> Result<Projection, Error> {
        if !store.is_scope(&self.scope) || store.read(OWNER, KEY)? != Some(self.sealed.as_bytes()) {
            return Err(Error::Conflict);
        }
        receipt(store, &store.operation()?, &self.sealed)?;
        // Authenticate the exact committed capsule under the fresh immutable
        // binding too; equal seed/context alone does not prove equal sealing key.
        let fresh = fresh_engine.restore_account_key(&self.sealed, &self.scope)?;
        if fresh.operation() != self.key.operation() {
            return Err(Error::Conflict);
        }
        Ok(fresh.projection(fresh_engine)?)
    }
}

impl PendingAccountCreation {
    /// Original immutable operation, for exact outcome reconciliation only.
    pub fn operation(&self) -> [u8; 32] {
        self.operation
    }
    /// Exact encrypted candidate digest; contains no private material.
    pub fn sealed_digest(&self) -> [u8; 32] {
        *blake3::hash(self.sealed.as_bytes()).as_bytes()
    }

    /// Attempt one actual CAS. Mark terminal before awaiting; cancellation or an
    /// uncertain result can only reconcile these same sealed bytes and operation.
    pub async fn commit<B: Backend>(
        &mut self,
        store: &mut Store<B>,
    ) -> Result<DurableAccountOwner, Error> {
        if self.attempted {
            return Err(Error::Conflict);
        }
        self.attempted = true;
        let key = self.key.take().ok_or(Error::Conflict)?;
        if !store.is_scope(&self.scope)
            || store.version()? != self.base
            || store.read(OWNER, KEY)?.is_some()
        {
            return Err(Error::Conflict);
        }
        let committed = store
            .commit_with_receipt(
                self.base,
                self.operation,
                &[Change::Put {
                    owner: OWNER,
                    key: KEY,
                    value: self.sealed.as_bytes(),
                }],
                &[],
            )
            .await?;
        if !committed.is_commit(store, &self.operation)
            || !committed.contains_record(OWNER, KEY, &self.sealed_digest())
        {
            return Err(Error::Conflict);
        }
        receipt(store, &self.operation, &self.sealed)?;
        Ok(DurableAccountOwner {
            key,
            sealed: SealedAccountKey::from_bytes(self.sealed.as_bytes())?,
            scope: self.scope.clone(),
        })
    }

    /// Consume the exact retained attempt after reopening actual Store. No retry,
    /// absence inference or newly generated owner is allowed, even on refusal.
    pub fn reconcile<B: Backend>(
        self,
        engine: Engine,
        store: &Store<B>,
    ) -> Result<DurableAccountOwner, Error> {
        if !self.attempted
            || !store.is_scope(&self.scope)
            || store.read(OWNER, KEY)? != Some(self.sealed.as_bytes())
        {
            return Err(Error::Conflict);
        }
        receipt(store, &self.operation, &self.sealed)?;
        let key = engine.restore_account_key(&self.sealed, &self.scope)?;
        if key.operation() != self.operation {
            return Err(Error::Conflict);
        }
        Ok(DurableAccountOwner {
            key,
            sealed: self.sealed,
            scope: self.scope,
        })
    }
}

fn receipt<B: Backend>(
    store: &Store<B>,
    operation: &[u8; 32],
    sealed: &SealedAccountKey,
) -> Result<(), Error> {
    let receipt = store.receipt(operation)?;
    if !receipt.is_commit(store, operation)
        || !receipt.contains_record(OWNER, KEY, blake3::hash(sealed.as_bytes()).as_bytes())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
