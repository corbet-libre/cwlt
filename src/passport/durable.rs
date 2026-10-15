//! Actual Store receipt adoption for the original nonexporting CPSD engine.
use super::*;
use cwst::{Change, Output, Store, backend::Backend};

mod initial;
pub use initial::InitialCheckpoint;

const OWNER: &str = "cwlt.passport";
const KEY: &[u8] = b"holder.v1";

/// Coarse persistence failures; never includes ciphertext, keys or private state.
#[derive(Debug)]
pub enum PersistenceError {
    /// The original Store refused or could not establish a durable outcome.
    Store(cwst::Error),
    /// The original passport engine refused an operation or sealed value.
    Holder(cpsd::Error),
    /// Scope, version, current record or receipt does not match the candidate.
    Conflict,
    /// Explicit initialization found existing state, or restore found no state.
    Initialization,
}
impl From<cwst::Error> for PersistenceError {
    fn from(error: cwst::Error) -> Self {
        Self::Store(error)
    }
}
impl From<cpsd::Error> for PersistenceError {
    fn from(error: cpsd::Error) -> Self {
        Self::Holder(error)
    }
}
impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wallet passport persistence refused")
    }
}
impl std::error::Error for PersistenceError {}
type Result<T> = std::result::Result<T, PersistenceError>;

/// Wallet-owned holder paired with the exact committed sealed owner record.
/// Vault must freshly authorize access through Keys and drop this object on lock.
/// No mutable session, raw engine or uncommitted credential can be extracted.
pub struct DurableHolder {
    holder: cpsd::OpaqueHolder,
    sealed: cpsd::SealedHolder,
    scope: String,
}

/// Private candidate and its public result, released only after actual atomic CAS.
/// It has no public result, engine, serialization or success constructor.
pub struct Pending<T> {
    holder: cpsd::OpaqueHolder,
    sealed: cpsd::SealedHolder,
    previous: [u8; 32],
    base: u64,
    operation: [u8; 32],
    result: T,
}

impl DurableHolder {
    /// Explicitly initialize an absent owner record and durably seal the engine.
    /// Cancellation/unknown outcome requires reopening Store and using `open`;
    /// absence during ordinary restore never silently creates a fresh passport.
    pub async fn create<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        initial: Holder,
        store: &mut Store<B>,
        scope: &str,
        operation: [u8; 32],
        rng: &mut R,
    ) -> Result<Self> {
        if !store.is_scope(scope) || store.read(OWNER, KEY)?.is_some() {
            return Err(PersistenceError::Initialization);
        }
        let sealed = initial.0.seal(rng)?;
        let base = store.version()?;
        let receipt = store
            .commit_with_receipt(
                base,
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
            return Err(PersistenceError::Conflict);
        }
        Ok(Self {
            holder: initial.0,
            sealed,
            scope: scope.into(),
        })
    }

    /// Restore only an actual committed owner record under freshly unlocked Keys.
    /// Original CPSD authenticates key/context/identity and private codec contents.
    pub fn open<B: Backend>(initial: Holder, store: &Store<B>, scope: &str) -> Result<Self> {
        if !store.is_scope(scope) {
            return Err(PersistenceError::Conflict);
        }
        let sealed = cpsd::SealedHolder::from_bytes(
            store
                .read(OWNER, KEY)?
                .ok_or(PersistenceError::Initialization)?,
        )?;
        let holder = initial.0.restored(&sealed)?;
        Ok(Self {
            holder,
            sealed,
            scope: scope.into(),
        })
    }

    fn current<B: Backend>(&self, store: &Store<B>) -> Result<()> {
        if !store.is_scope(&self.scope) || store.read(OWNER, KEY)? != Some(self.sealed.as_bytes()) {
            return Err(PersistenceError::Conflict);
        }
        Ok(())
    }

    /// Lend read/proof operations only while the actual committed Store agrees.
    /// The shared lifetime prevents a Store mutation during this borrowed session.
    pub fn session<'a, B: Backend>(&'a self, store: &'a Store<B>) -> Result<DurableSession<'a>> {
        self.current(store)?;
        Ok(DurableSession(&self.holder))
    }

    fn prepare<B: Backend, R: rand::RngCore + rand::CryptoRng, T>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
        update: impl FnOnce(&mut cpsd::OpaqueHolder, &mut R) -> T,
    ) -> Result<Pending<T>> {
        self.current(store)?;
        if operation == [0; 32] {
            return Err(PersistenceError::Conflict);
        }
        let mut holder = self.holder.restored(&self.sealed)?;
        let result = update(&mut holder, rng);
        let sealed = holder.seal(rng)?;
        Ok(Pending {
            holder,
            sealed,
            previous: *blake3::hash(self.sealed.as_bytes()).as_bytes(),
            base: store.version()?,
            operation,
            result,
        })
    }

    /// Stage real issuance; the request cannot be obtained until its private
    /// blinding has been committed atomically with the supplied companion state.
    pub fn prepare_begin<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
        issuer: &IssuerPublicKey,
        challenge: &IssuanceChallenge,
    ) -> Result<Pending<std::result::Result<IssuanceRequest, cpsd::Error>>> {
        self.prepare(store, operation, rng, |holder, rng| {
            holder.begin_issuance(rng, issuer, challenge)
        })
    }

    /// Stage the original finish result, including consuming a rejected attempt.
    /// Even an inner error is released only after that state has committed; an
    /// invalid response cannot resurrect its consumed opening after a restart.
    pub fn prepare_finish<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
        blind: &BlindPassport,
    ) -> Result<Pending<std::result::Result<(), cpsd::Error>>> {
        self.prepare(store, operation, rng, |holder, _| {
            holder.finish_issuance(blind)
        })
    }

    /// Stage cancellation without changing the installed verified credential.
    pub fn prepare_cancel<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
    ) -> Result<Pending<()>> {
        self.prepare(store, operation, rng, |holder, _| holder.cancel_issuance())
    }
    /// Stage one stamp request; the request is released only after its private opening has
    /// committed, so the confirmation a person gives for it survives a restart.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_begin_stamp<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
        issuer: &StampPublicKey,
        challenge: &IssuanceChallenge,
        actions: &[(StampScope, StampAction)],
        now: Timestamp,
    ) -> Result<Pending<std::result::Result<StampIssuanceRequest, cpsd::Error>>> {
        self.prepare(store, operation, rng, |holder, rng| {
            holder.begin_stamp(rng, issuer, challenge, actions, now)
        })
    }

    /// Stage the stamp finish, including a refused answer that consumes the attempt.
    pub fn prepare_finish_stamp<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
        blind: &BlindStamp,
        now: Timestamp,
    ) -> Result<Pending<std::result::Result<(), cpsd::Error>>> {
        self.prepare(store, operation, rng, |holder, _| {
            holder.finish_stamp(blind, now)
        })
    }

    /// Stage dropping a pending stamp request; retained stamps stay.
    pub fn prepare_cancel_stamp<B: Backend, R: rand::RngCore + rand::CryptoRng>(
        &self,
        store: &Store<B>,
        operation: [u8; 32],
        rng: &mut R,
    ) -> Result<Pending<()>> {
        self.prepare(store, operation, rng, |holder, _| holder.cancel_stamp())
    }
}

impl<T> Pending<T> {
    /// Commit through the original compound Store CAS and check its original
    /// nonforgeable receipt before replacing the live holder or returning output.
    /// Companion owners cannot replace/delete this Wallet's own sealed namespace.
    /// On cancellation/error the original holder remains, but session checks
    /// refuse if Store is locked/uncertain or has changed; reopen to reconcile.
    pub async fn commit<B: Backend>(
        self,
        owner: &mut DurableHolder,
        store: &mut Store<B>,
        companions: &[Change<'_>],
        outputs: &[Output],
    ) -> Result<T> {
        owner.current(store)?;
        if store.version()? != self.base
            || blake3::hash(owner.sealed.as_bytes()).as_bytes() != &self.previous
        {
            return Err(PersistenceError::Conflict);
        }
        let mut changes = Vec::with_capacity(companions.len() + 1);
        for change in companions {
            changes.push(match change {
                Change::Put { owner, key, value } if *owner != OWNER => {
                    Change::Put { owner, key, value }
                }
                Change::Delete { owner, key } if *owner != OWNER => Change::Delete { owner, key },
                _ => return Err(PersistenceError::Conflict),
            });
        }
        changes.push(Change::Put {
            owner: OWNER,
            key: KEY,
            value: self.sealed.as_bytes(),
        });
        let receipt = store
            .commit_with_receipt(self.base, self.operation, &changes, outputs)
            .await?;
        if !receipt.is_commit(store, &self.operation)
            || !receipt.contains_record(OWNER, KEY, blake3::hash(self.sealed.as_bytes()).as_bytes())
        {
            return Err(PersistenceError::Conflict);
        }
        owner.holder = self.holder;
        owner.sealed = self.sealed;
        Ok(self.result)
    }
}

/// Borrowed operations on the currently committed engine, never a movable holder.
pub struct DurableSession<'a>(&'a cpsd::OpaqueHolder);
impl DurableSession<'_> {
    /// Original community pseudonym.
    pub fn pseudonym(&self, community: &CommunityId) -> Pseudonym {
        self.0.pseudonym(community)
    }
    /// Original issuer continuity tag, sent only to that issuer.
    pub fn issuer_tag(&self) -> IssuerTag {
        self.0.issuer_tag()
    }
    /// Signed public attributes of the installed credential.
    pub fn attributes(&self) -> Option<&PassportAttributes> {
        self.0.attributes()
    }
    /// Original authenticated presentation of the committed credential.
    pub fn present<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        expected: &AuthenticatedCommunity,
        signed_request: &[u8],
        now: Timestamp,
    ) -> std::result::Result<Presentation, cpsd::Error> {
        self.0.present(rng, expected, signed_request, now)
    }
    /// Whether an unexpired committed stamp approves `action` in `scope`.
    pub fn stamp_covers(&self, scope: &StampScope, action: &StampAction, now: Timestamp) -> bool {
        self.0.stamp_covers(scope, action, now)
    }
    /// Present the committed stamp for exactly `action` in `scope`.
    pub fn present_stamp<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        scope: &StampScope,
        action: &StampAction,
        now: Timestamp,
    ) -> std::result::Result<StampPresentation, cpsd::Error> {
        self.0.present_stamp(rng, scope, action, now)
    }
}

#[cfg(test)]
mod tests;
