//! Durable record cache. The internal engine owns secrets; Store owns the CAS.
use ckmg::wallet_engine::{self, Engine, Sealed};
use cwst::{Change, Store, backend::Backend};
/// The public record types callers pass through this owner.
pub use czkp::record::{Context, Epoch, Presentation, Record};

const OWNER: &str = "cwlt.record";
const KEY: &[u8] = b"epoch.v1";

/// Coarse refusal; never contains a key, opening or proof witness.
#[derive(Debug)]
pub enum Error {
    /// The authenticated Store is locked, uncertain or unavailable.
    Store(cwst::Error),
    /// Invalid epoch, key or engine state.
    Engine(wallet_engine::Error),
    /// Exact checkpoint or nonforgeable receipt did not match.
    Conflict,
}
impl From<cwst::Error> for Error {
    fn from(e: cwst::Error) -> Self {
        Self::Store(e)
    }
}
impl From<wallet_engine::Error> for Error {
    fn from(e: wallet_engine::Error) -> Self {
        Self::Engine(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet record cache refused")
    }
}
impl std::error::Error for Error {}

/// Wallet-owned engine. Construct with the opaque engine supplied by Keys.
/// Vault drops this owner when locking; access also checks the live Store.
pub struct DurableRecord {
    engine: Engine,
    sealed: Sealed,
    scope: String,
}
impl DurableRecord {
    /// Explicit first initialization, never an implicit restore fallback.
    pub async fn create<B: Backend>(
        engine: Engine,
        store: &mut Store<B>,
        scope: &str,
        operation: [u8; 32],
    ) -> Result<Self, Error> {
        if !store.is_scope(scope) || store.read(OWNER, KEY)?.is_some() {
            return Err(Error::Conflict);
        }
        let sealed = engine.seal()?;
        persist(store, &sealed, operation).await?;
        Ok(Self {
            engine,
            sealed,
            scope: scope.into(),
        })
    }
    /// Open only existing authenticated state; missing state refuses.
    pub fn open<B: Backend>(engine: Engine, store: &Store<B>, scope: &str) -> Result<Self, Error> {
        if !store.is_scope(scope) {
            return Err(Error::Conflict);
        }
        let sealed = Sealed::from_bytes(store.read(OWNER, KEY)?.ok_or(Error::Conflict)?)?;
        let engine = engine.restored(&sealed)?;
        Ok(Self {
            engine,
            sealed,
            scope: scope.into(),
        })
    }
    fn current<B: Backend>(&self, store: &Store<B>) -> Result<(), Error> {
        if !store.is_scope(&self.scope) || store.read(OWNER, KEY)? != Some(self.sealed.as_bytes()) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Persist the fresh key before background proving; duplicate epoch calls
    /// keep the committed key. No private key or opening is exported.
    pub async fn begin_epoch<B: Backend>(
        &mut self,
        store: &mut Store<B>,
        epoch: &Epoch,
        owner: [u8; 32],
        now: u64,
        operation: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        self.current(store)?;
        let mut candidate = self.engine.restored(&self.sealed)?;
        let public = candidate.begin_record_epoch(epoch, owner, now)?;
        self.install(store, candidate, operation).await?;
        Ok(public)
    }
    /// Commit the verified prover output before making presentations available.
    /// A late job for a superseded epoch or a conflicting checkpoint refuses.
    pub async fn finish_epoch<B: Backend>(
        &mut self,
        store: &mut Store<B>,
        record: Record,
        proof: String,
        operation: [u8; 32],
    ) -> Result<(), Error> {
        self.current(store)?;
        let mut candidate = self.engine.restored(&self.sealed)?;
        candidate.cache_record_proof(record, proof)?;
        self.install(store, candidate, operation).await
    }
    async fn install<B: Backend>(
        &mut self,
        store: &mut Store<B>,
        candidate: Engine,
        operation: [u8; 32],
    ) -> Result<(), Error> {
        let sealed = candidate.seal()?;
        persist(store, &sealed, operation).await?;
        self.engine = candidate;
        self.sealed = sealed;
        Ok(())
    }
    /// Inspect readiness without generating a proof or waiting for a running job.
    pub fn ready<B: Backend>(
        &self,
        store: &Store<B>,
        epoch: &Epoch,
        now: u64,
    ) -> Result<bool, Error> {
        self.current(store)?;
        Ok(self.engine.record_ready(epoch, now))
    }
    /// Bind a relying party's challenge using only the committed epoch key/cache.
    pub fn present<B: Backend>(
        &self,
        store: &Store<B>,
        epoch: &Epoch,
        context: &Context,
        now: u64,
    ) -> Result<Presentation, Error> {
        self.current(store)?;
        Ok(self.engine.present_record(epoch, context, now)?)
    }
}
async fn persist<B: Backend>(
    store: &mut Store<B>,
    sealed: &Sealed,
    operation: [u8; 32],
) -> Result<(), Error> {
    let receipt = store
        .commit_with_receipt(
            store.version()?,
            operation,
            &[Change::Put {
                owner: OWNER,
                key: KEY,
                value: sealed.as_bytes(),
            }],
            &[],
        )
        .await?;
    if !receipt.is_commit(store, &operation)
        || !receipt.contains_record(OWNER, KEY, blake3::hash(sealed.as_bytes()).as_bytes())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
