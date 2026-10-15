//! Wallet-owned passport custody; Keys supplies a purpose-separated seed.
//! This wrapper delegates all credential and pseudonym work to Pseudonyms.

pub use cpsd::{
    ActionKind, AuthenticatedCommunity, BlindPassport, BlindStamp, CommunityFingerprint,
    CommunityId, Error, IssuanceChallenge, IssuanceRequest, IssuerPublicKey, IssuerTag,
    PassportAttributes, PayloadDigest, Presentation, Pseudonym, StampAction, StampIssuanceRequest,
    StampPresentation, StampPublicKey, StampSalt, StampScope, Timestamp, rand,
};

/// The passport and private issuance opening stay inside Wallet.
/// No Clone, Debug, serialization, seed or passport accessor is provided.
/// Keys must freshly authorize each session and drop this holder on lock.
///
/// ```compile_fail
/// let holder = cwlt::passport::Holder::from_seed(&mut [7; 32]);
/// let secret = holder.secret();
/// ```
/// ```compile_fail
/// let holder = cwlt::passport::Holder::from_seed(&mut [7; 32]);
/// let exported = format!("{holder:?}");
/// ```
pub struct Holder(cpsd::OpaqueHolder);

mod durable;
pub use durable::{DurableHolder, DurableSession, InitialCheckpoint, Pending, PersistenceError};

impl Holder {
    /// Consume the concrete freshly authorized Keys seed capability. Neither the
    /// seed nor the movable holder engine is exposed by a session or callback.
    pub fn from_holder_seed(seed: ckmg::HolderSeed<'_>) -> Result<Self, ckmg::Error> {
        seed.into_passport_holder().map(Self)
    }

    /// Consume and wipe a dedicated holder seed derived by Keys.
    /// This is not a passkey root; no KDF or alternative identity recipe lives here.
    pub fn from_seed(seed: &mut [u8; 32]) -> Self {
        Self(cpsd::OpaqueHolder::from_seed(seed))
    }

    /// Lend operations without lending the movable, owned engine.
    /// The result cannot contain the borrowed session or any of its references.
    ///
    /// ```compile_fail
    /// let mut holder = cwlt::PassportHolder::from_seed(&mut [7; 32]);
    /// let escaped = holder.with_session(|session| session);
    /// ```
    /// ```compile_fail
    /// let mut holder = cwlt::PassportHolder::from_seed(&mut [7; 32]);
    /// holder.with_session(|mut session| {
    ///     std::mem::replace(&mut session.0, &mut holder);
    /// });
    /// ```
    pub fn with_session<T>(
        &mut self,
        operation: impl for<'session> FnOnce(PassportSession<'session>) -> T,
    ) -> T {
        operation(PassportSession(&mut self.0))
    }
}

/// Freshly authorized access to a Wallet-owned passport engine.
/// Its private borrow cannot be extracted, replaced, cloned or retained by the caller.
pub struct PassportSession<'holder>(&'holder mut cpsd::OpaqueHolder);

impl PassportSession<'_> {
    /// Public community pseudonym, computed by the existing holder engine.
    pub fn pseudonym(&self, community: &CommunityId) -> Pseudonym {
        self.0.pseudonym(community)
    }

    /// Public continuity tag for the global issuer only.
    pub fn issuer_tag(&self) -> IssuerTag {
        self.0.issuer_tag()
    }

    /// Begin real blind issuance, retaining its private opening inside Wallet.
    pub fn begin_issuance<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        issuer: &IssuerPublicKey,
        challenge: &IssuanceChallenge,
    ) -> Result<IssuanceRequest, Error> {
        self.0.begin_issuance(rng, issuer, challenge)
    }

    /// Install only the existing engine's signature-verified issuer answer.
    pub fn finish_issuance(&mut self, blind: &BlindPassport) -> Result<(), Error> {
        self.0.finish_issuance(blind)
    }

    /// Abandon a pending opening while preserving the verified passport.
    pub fn cancel_issuance(&mut self) {
        self.0.cancel_issuance();
    }

    /// Signed public attributes, never the private passport.
    pub fn attributes(&self) -> Option<&PassportAttributes> {
        self.0.attributes()
    }

    /// Present only against an independently authenticated community request.
    pub fn present<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        expected: &AuthenticatedCommunity,
        signed_request: &[u8],
        now: Timestamp,
    ) -> Result<Presentation, Error> {
        self.0.present(rng, expected, signed_request, now)
    }
    /// Begin one confirmation stamp for up to [`cpsd::STAMP_SLOTS`] actions; the opening stays
    /// inside Wallet. Confirm the request with one user verification over its
    /// [`StampIssuanceRequest::confirmation_challenge`].
    pub fn begin_stamp<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
        issuer: &StampPublicKey,
        challenge: &IssuanceChallenge,
        actions: &[(StampScope, StampAction)],
        now: Timestamp,
    ) -> Result<StampIssuanceRequest, Error> {
        self.0.begin_stamp(rng, issuer, challenge, actions, now)
    }

    /// Retain only a signature-verified stamp; an invalid answer consumes the attempt.
    pub fn finish_stamp(&mut self, blind: &BlindStamp, now: Timestamp) -> Result<(), Error> {
        self.0.finish_stamp(blind, now)
    }

    /// Drop a pending stamp request; retained stamps stay.
    pub fn cancel_stamp(&mut self) {
        self.0.cancel_stamp();
    }

    /// Whether an unexpired retained stamp approves `action` in `scope`.
    pub fn stamp_covers(&self, scope: &StampScope, action: &StampAction, now: Timestamp) -> bool {
        self.0.stamp_covers(scope, action, now)
    }

    /// Present the retained stamp for exactly `action` in `scope` under this holder's pseudonym.
    pub fn present_stamp<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        scope: &StampScope,
        action: &StampAction,
        now: Timestamp,
    ) -> Result<StampPresentation, Error> {
        self.0.present_stamp(rng, scope, action, now)
    }
}
