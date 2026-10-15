//! The one Rust implementation of every member-side witness builder: genesis, reservations,
//! settlements, punishments, forced ingestion and the voucher actions, plus the statements of
//! the extension circuits. It replaces the former TypeScript builders; the golden vectors in
//! `tests/vectors/witness` pin its output to theirs.
//!
//! Every builder takes `&self` and returns a [`Candidate`] holding the next state; nothing is
//! mutated until the caller keeps `next`. The Noir relation (and the issuer) independently
//! constrain every field computed here, so a wrong witness fails to prove instead of
//! committing to something false. The integer rules live in [`crate::plan`].
use super::{
    Field, hashes,
    maps::IndexedMap,
    opening::{Opening, Standing, Voucher},
    policy::{AccountPolicy, ExtensionPolicy},
    prepared::{Enrollment, VoucherBond},
};
use crate::{Error, plan};
use std::sync::Arc;
use zeroize::Zeroizing;

mod builders;
mod contact;
mod evidence;
pub(crate) mod input;
mod roster;
mod sealed;
mod statement;
#[cfg(test)]
mod tests;

pub use builders::{Acknowledgment, Delivered, Reserve, Resolution};
pub use contact::verify_prehash;
pub use evidence::{Evidence, RecordContext, RecordPurpose, Settled, SettledOutcome, WaveContext};
pub use input::UpdateInput;
pub use roster::{Checkpoint, RosterRow};
pub use sealed::{MAX_ACCOUNT_SEALED, SealedAccount};
pub use statement::{AccountStatement, Effect, ExtensionStatement, PolicyStatement, UpdateEffect};

/// Source of the fresh blind of every new state commitment.
pub trait Entropy {
    /// A fresh uniformly random 32-byte blind.
    fn blind(&mut self) -> Result<Field, Error>;
}
/// The operating system's random source.
pub struct OsEntropy;
impl Entropy for OsEntropy {
    fn blind(&mut self) -> Result<Field, Error> {
        let mut blind = [0; 32];
        getrandom::fill(&mut blind).map_err(|_| Error::Crypto)?;
        Ok(blind)
    }
}
impl<F: FnMut() -> Field> Entropy for F {
    fn blind(&mut self) -> Result<Field, Error> {
        Ok(self())
    }
}

/// What the sponsor remembers about one bond (czkp `voucher::Entry`).
pub type BondEntry = czkp::voucher::Entry;

/// The issuer's certificate of the account's current accepted state.
#[derive(Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Operator acceptance time.
    pub accepted_at: u64,
    /// Operator signature over the acceptance.
    pub signature: [u8; 64],
}

/// One private obligation: an outgoing introduction or an incoming reception.
#[derive(Clone, PartialEq, Eq)]
pub struct Slot {
    /// 0 outgoing, 1 incoming.
    pub role: u8,
    /// The counterpart's member identifier.
    pub peer: Field,
    /// Conversation nonce.
    pub nonce: Field,
    /// Group identifier.
    pub group: Field,
    /// Contact-policy digest.
    pub contact_policy: Field,
    /// Reserved amount.
    pub amount: u32,
    /// Lifecycle phase (1 reserved, 2 active, 3 settled, 4 cancelled, 5 expired, ...).
    pub phase: u8,
    /// Settled outcome kind (0 open).
    pub outcome: u8,
    /// The conversation was answered.
    pub answered: bool,
    /// The owner punished its own contact.
    pub self_punished: bool,
    /// Common lease start.
    pub admitted_at: u64,
    /// Common lease end.
    pub expires_at: u64,
    /// The peer's enrollment leaf at reservation time.
    pub peer_authority: Field,
    /// The owner's enrollment leaf at reservation time.
    pub owner_authority: Field,
    /// The peer's enrollment row at reservation time.
    pub peer_enrollment: Enrollment,
    /// The owner's enrollment row at reservation time.
    pub owner_enrollment: Enrollment,
}

/// The delivery a punishment creates, kept to build its deposit later.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The punished slot as it was before the punishment.
    pub slot: Slot,
    /// Delivery kind (the authorization the planner granted).
    pub kind: u8,
}

/// Immutable per-account context: who, under which policy.
struct Context {
    community: Field,
    secret: Zeroizing<Field>,
    policy: AccountPolicy,
    extension: ExtensionPolicy,
    standing: czkp::standing::Params,
    policy_digest: Field,
    state_policy: Field,
    tables: plan::PolicyOut,
}

/// The member-side witness state of one account: the committed opening, the private maps
/// behind its roots, the private obligations, the sponsor's bond book and the roster the
/// membership proofs read. It carries no accessor for the secret or the opening.
#[derive(Clone)]
pub struct Account {
    cx: Arc<Context>,
    checkpoint: Arc<Checkpoint>,
    owner_index: usize,
    opening: Opening,
    outgoing: IndexedMap,
    incoming: IndexedMap,
    pairs: IndexedMap,
    bonds: IndexedMap,
    slots: Vec<(Field, Slot)>,
    bond_book: std::collections::BTreeMap<Field, (Field, BondEntry)>,
    version: u64,
    now: u64,
    commitment: Field,
    certificate: Option<Certificate>,
}

/// The result of one builder: the circuit input, the public statement and the next state.
pub struct Candidate {
    /// The private Noir input of the `update` proof.
    pub input: UpdateInput,
    /// The public statement the proof establishes.
    pub statement: AccountStatement,
    /// The inbox move and issuer-visible effect.
    pub update: UpdateEffect,
    /// The state after the update; keep it only once the issuer accepted the update.
    pub next: Account,
    /// The obligation's single-use event identifier (reservations).
    pub event: Option<Field>,
    /// The delivery a punishment created.
    pub delivery: Option<Delivery>,
    /// The sponsor's bond entry after an admission or an obligation consumption.
    pub entry: Option<BondEntry>,
    /// The obligation tag of a consumption.
    pub tag: Option<Field>,
}

/// Everything a genesis needs.
pub struct Genesis<'a> {
    /// Community digest.
    pub community: Field,
    /// Explicit account policy.
    pub policy: AccountPolicy,
    /// Extension policy (its standing digest must match `standing`).
    pub extension: ExtensionPolicy,
    /// Rulebook-signed standing and voucher parameters.
    pub standing: czkp::standing::Params,
    /// The verified roster.
    pub checkpoint: Arc<Checkpoint>,
    /// The owner's position in the roster.
    pub owner_index: usize,
    /// The owner's registered secret.
    pub owner_secret: &'a Field,
    /// Proof time.
    pub now: u64,
    /// The bond a vouchee holds with its sponsor.
    pub bond: Option<VoucherBond>,
}

pub(super) fn horizon(policy: &AccountPolicy, now: u64) -> u64 {
    let window = policy.rate_window.max(1);
    let end = (now / window + 1).saturating_mul(window);
    end.min(policy.policy_valid_until)
}

impl Account {
    /// Start an account: version zero, empty maps, the starter loan.
    pub fn genesis(g: Genesis<'_>, rng: &mut impl Entropy) -> Result<Candidate, Error> {
        let owner = g
            .checkpoint
            .entries()
            .get(g.owner_index)
            .ok_or(Error::Invalid)?
            .clone();
        if hashes::secret(&g.community, g.owner_secret)? != owner.secret_hash
            || g.policy.rate_window > 86_400
            || ExtensionPolicy::standing_digest(g.standing)? != g.extension.standing
        {
            return Err(Error::Invalid);
        }
        let (policy_digest, state_policy) = g.policy.digests(&g.community)?;
        g.extension.hash()?;
        let outgoing = IndexedMap::create()?;
        let incoming = IndexedMap::create()?;
        let pairs = IndexedMap::create()?;
        let bonds = IndexedMap::create()?;
        let horizon = horizon(&g.policy, g.now);
        let (sponsor, bond) = match &g.bond {
            Some(b) if b.secret != [0; 32] && b.sponsor != [0; 32] => {
                let domain = hashes::domain(b"cfrm.account-state.v2");
                (
                    czkp::voucher::member_tag(&domain, &g.community, &b.sponsor)
                        .map_err(|_| Error::Crypto)?,
                    czkp::voucher::bond_commit(&domain, &b.secret).map_err(|_| Error::Crypto)?,
                )
            }
            Some(_) => return Err(Error::Invalid),
            None => ([0; 32], [0; 32]),
        };
        let opening = Opening {
            reserved: 0,
            accepted: 0,
            declined: 0,
            punished: 0,
            inbox: [0; 32],
            authorization: [0; 32],
            outgoing_root: outgoing.root(),
            outgoing_count: outgoing.count(),
            incoming_root: incoming.root(),
            incoming_count: incoming.count(),
            pair_root: pairs.root(),
            pair_count: pairs.count(),
            created_at: horizon,
            standing: Standing {
                g: 0,
                a: g.standing.c0.checked_sub(1).ok_or(Error::Invalid)? << 16,
                c: 0,
                pr: 0,
                pg: 0,
                lc: 0,
                day: horizon / 86_400,
            },
            voucher: Voucher {
                proven: 0,
                away: 0,
                reserved: 0,
                lost: 0,
                bonus: 0,
                returned: 0,
                answers: 0,
                sponsor,
                bond,
                bond_root: bonds.root(),
                bond_count: bonds.count(),
            },
            blind: rng.blind()?,
        };
        let cx = Arc::new(Context {
            community: g.community,
            secret: Zeroizing::new(*g.owner_secret),
            policy: g.policy,
            extension: g.extension,
            standing: g.standing,
            policy_digest,
            state_policy,
            tables: plan::policy_out(
                &czkp::standing::Policy::derive(g.standing).map_err(|_| Error::Invalid)?,
            ),
        });
        let mut value = Account {
            cx,
            checkpoint: g.checkpoint,
            owner_index: g.owner_index,
            opening,
            outgoing,
            incoming,
            pairs,
            bonds,
            slots: Vec::new(),
            bond_book: Default::default(),
            version: 0,
            now: g.now,
            commitment: [0; 32],
            certificate: None,
        };
        value.commitment = value.commit(&value.opening, 0)?;
        let mut input = value.input(value.opening.blind, g.now)?;
        if let Some(b) = &g.bond {
            input.aux.bond_secret = b.secret;
            input.aux.sponsor = input::Hx(value.opening.voucher.sponsor);
        }
        input.genesis = true;
        input.previous_state = [0; 32];
        input.next_state = value.commitment;
        input.previous_version = 0;
        input.next_version = 0;
        Ok(Candidate {
            statement: AccountStatement::from_input(&input),
            update: statement::effect(&input),
            input,
            next: value,
            event: None,
            delivery: None,
            entry: None,
            tag: None,
        })
    }

    /// The accepted state commitment.
    pub fn state(&self) -> Field {
        self.commitment
    }
    /// The accepted version.
    pub fn version(&self) -> u64 {
        self.version
    }
    /// The time of the last proof.
    pub fn now(&self) -> u64 {
        self.now
    }
    /// The owner's enrollment row.
    pub fn owner(&self) -> &Enrollment {
        &self.checkpoint.entries()[self.owner_index]
    }
    /// Record the issuer's certificate of this accepted state (needed by the wave circuits).
    #[must_use]
    pub fn with_certificate(mut self, certificate: Certificate) -> Self {
        self.certificate = Some(certificate);
        self
    }
    /// The private obligation with this event, if any.
    pub fn slot(&self, event: &Field) -> Option<&Slot> {
        self.slots.iter().find(|(e, _)| e == event).map(|(_, s)| s)
    }
    /// The current independently admitted roster; the accepted private state is preserved.
    pub fn with_checkpoint(&self, checkpoint: Arc<Checkpoint>) -> Result<Self, Error> {
        let owner = self.owner();
        let index = checkpoint
            .entries()
            .iter()
            .position(|e| e.member == owner.member)
            .ok_or(Error::Invalid)?;
        let current = &checkpoint.entries()[index];
        if current.secret_hash != owner.secret_hash {
            return Err(Error::Invalid);
        }
        roster::verify_path(current, &self.cx.community, &checkpoint.root())?;
        let mut copy = self.clone();
        copy.checkpoint = checkpoint;
        copy.owner_index = index;
        Ok(copy)
    }
    /// Re-issue the explicit policy (tuning); the immutable state policy must not change.
    pub fn with_policy(&self, policy: AccountPolicy) -> Result<Self, Error> {
        let (digest, state) = policy.digests(&self.cx.community)?;
        if state != self.cx.state_policy {
            return Err(Error::Invalid);
        }
        let mut copy = self.clone();
        copy.cx = Arc::new(Context {
            community: self.cx.community,
            secret: self.cx.secret.clone(),
            policy,
            extension: self.cx.extension,
            standing: self.cx.standing,
            policy_digest: digest,
            state_policy: state,
            tables: self.cx.tables.clone(),
        });
        Ok(copy)
    }

    fn commit(&self, opening: &Opening, version: u64) -> Result<Field, Error> {
        opening.commitment(
            &self.cx.community,
            &self.owner().member,
            &self.cx.state_policy,
            self.owner().secret_hash,
            version,
            &self.cx.extension,
        )
    }
}
