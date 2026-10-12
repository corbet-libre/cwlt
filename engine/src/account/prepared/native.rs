//! Original typed genesis witness; private serialization stays inside this owner.
use super::*;
use crate::native_prover::{NativeProver, Proof};
use serde::{Serialize, Serializer};
use std::time::Instant;
mod acceptance;
mod accepted;
mod pending;
mod response;
pub use acceptance::{AcceptanceBinding, AcceptedGenesisProof, IssuerAcceptance};
pub use accepted::{AcceptedAccount, MAX_ACCEPTED_SEALED, SealedAcceptedAccount};
pub use pending::{MAX_PENDING_SEALED, PendingGenesisBinding, SealedPendingGenesis};
pub use response::{AcceptedResponse, AncestryResponse, Frontier, ResponseTrust};
#[cfg(test)]
mod tests;

/// Locally verified proof data. It grants no enrollment, accepted Frontier, Keys
/// authority, Store receipt or operator acceptance; those joins remain separate.
pub struct PreparedGenesisProof {
    candidate: PreparedGenesis,
    proof: Proof,
}

/// Original public genesis statement data, never a grant or accepted account.
/// All values come directly from the candidate used by the native serializer.
pub struct GenesisPublic {
    /// Original protocol for the upper owner's typed statement conversion.
    pub protocol_version: u32,
    /// Original community digest included in the proved public inputs.
    pub community: [u8; 32],
    /// Original community-scoped enrolled account owner.
    pub owner: [u8; 32],
    /// Original economic policy digest.
    pub policy_digest: [u8; 32],
    /// Original authenticated common enrollment root.
    pub enrollment_root: [u8; 32],
    /// Frozen original statement observation, never a renewed proof time.
    pub now: u64,
    /// Original exclusive proof horizon.
    pub valid_until: u64,
    /// True only for this original genesis computation.
    pub genesis: bool,
    /// Original fixed previous account version zero.
    pub previous_version: u64,
    /// Original fixed next genesis version zero.
    pub next_version: u64,
    /// Original fixed empty previous state.
    pub previous_state: [u8; 32],
    /// Commitment to the retained exact private opening.
    pub next_state: [u8; 32],
    /// Original fixed empty settlement marker.
    pub settlement_marker: [u8; 32],
}
impl PreparedGenesisProof {
    /// The explicit public context this candidate was prepared and proven under.
    pub fn context(&self) -> &GenesisContext {
        &self.candidate.context
    }
    /// Project only the original public statement that this candidate proved.
    /// No witness, opening, fresh authority or sending privilege is returned.
    pub fn public_genesis(&self) -> GenesisPublic {
        self.candidate.genesis_public()
    }
}
impl PreparedGenesis {
    fn genesis_public(&self) -> GenesisPublic {
        GenesisPublic {
            protocol_version: 2,
            community: self.community,
            owner: self.context.owner,
            policy_digest: self.policy_digest,
            enrollment_root: self.context.enrollment_root,
            now: self.context.checked_at,
            valid_until: self.opening.created_at,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: self.commitment,
            settlement_marker: [0; 32],
        }
    }
}
impl PreparedGenesisProof {
    /// Recheck the retained exact private candidate without exposing its opening.
    /// This grants no adoption or accepted account; the original candidate remains
    /// owned until a future genuine issuer-acceptance and Store-receipt join.
    pub fn check_context(
        &self,
        engine: &Engine,
        context: &GenesisContext,
        now: u64,
    ) -> Result<(), Error> {
        self.candidate.check_context(engine, context, now)
    }

    /// Exact original configured circuit and verification-key identity.
    pub fn scope(&self) -> &czkp::ProofScope {
        &self.proof.scope
    }
    /// Original ordered public field elements, with no private opening included.
    pub fn public_inputs(&self) -> &[[u8; 32]] {
        &self.proof.public_inputs
    }
    /// Locally verified proof bytes for the original operator's own verification.
    pub fn proof(&self) -> &[u8] {
        &self.proof.proof
    }
}
#[derive(Serialize)]
struct Extension {
    revision: u64,
    quorum: u32,
    change_cost: u32,
    delay: u64,
    batch: u8,
    standing: [u8; 32],
}
#[derive(Serialize)]
struct Public<'a> {
    extension: Extension,
    previous_inbox: [u8; 32],
    inbox: [u8; 32],
    consume_only: bool,
    change_binding: [u8; 32],
    community: &'a [u8; 32],
    owner: &'a [u8; 32],
    policy_digest: &'a [u8; 32],
    enrollment_root: &'a [u8; 32],
    now: u64,
    valid_until: u64,
    genesis: bool,
    previous_version: u64,
    next_version: u64,
    previous_state: [u8; 32],
    next_state: &'a [u8; 32],
    settlement_marker: [u8; 32],
    initial_credit: u32,
    maximum_available: u32,
    outgoing_reservation: u32,
    incoming_reservation: u32,
    policy_revision: u64,
    policy_valid_from: u64,
    policy_valid_until: u64,
    newcomer_period: u64,
    rate_window: u64,
    newcomer_admissions: u32,
    maximum_admissions: u32,
    refill_period: u64,
    refill_units: u32,
    abandon_after: u64,
}
struct Field<'a>(&'a [u8; 32]);
impl Serialize for Field<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", data_encoding::HEXLOWER.encode(self.0)))
    }
}
#[derive(Serialize)]
struct Row<'a> {
    #[serde(serialize_with = "bytes64")]
    key: &'a [u8; 64],
    secret_hash: &'a [u8; 32],
    start: u64,
    end: u64,
    delegation_digest: &'a [u8; 32],
    path: Vec<Field<'a>>,
    index: u32,
}
fn bytes64<S: Serializer>(bytes: &&[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    bytes.as_slice().serialize(s)
}
#[derive(Serialize)]
struct PrivateOpening<'a> {
    reserved: u128,
    accepted: u64,
    declined: u64,
    punished: u64,
    inbox: &'a [u8; 32],
    authorization: Field<'a>,
    outgoing_root: Field<'a>,
    outgoing_count: u64,
    incoming_root: Field<'a>,
    incoming_count: u64,
    pair_root: Field<'a>,
    pair_count: u64,
    created_at: u64,
    standing: StandingJson,
    blind: &'a [u8; 32],
}
#[derive(Serialize)]
struct StandingJson {
    g: u64,
    a: u64,
    c: u64,
    pr: u64,
    pg: u64,
    lc: u64,
    day: u64,
}
#[derive(Serialize)]
struct StandingPolicyJson {
    c0: u64,
    h_a: u64,
    h_g: u64,
    n_half: u64,
    n_c: u64,
    e_q: u64,
    r_max: u64,
    r_age: u64,
    c_max_q: u64,
    c_vet: u64,
    age_vet: u64,
    boost_q: u64,
    boost_days: u64,
    slope_q: u64,
    mid_q: u64,
    kappa_q: u64,
    loan_use_q: u64,
    factor: u64,
    trust: Vec<u64>,
    g_table: Vec<u64>,
    a_table: Vec<u64>,
}
#[derive(Serialize)]
struct Slot {
    role: u8,
    peer: [u8; 32],
    nonce: [u8; 32],
    group: [u8; 32],
    contact_policy: [u8; 32],
    amount: u32,
    phase: u8,
    outcome: u8,
    answered: bool,
    self_punished: bool,
    admitted_at: u64,
    expires_at: u64,
    peer_authority: u8,
    owner_authority: u8,
}
#[derive(Serialize)]
struct Map {
    leaf: [u8; 4],
    index: u32,
    path: [u8; 32],
    append_path: [u8; 32],
}
#[derive(Serialize)]
struct Resolution {
    kind: u8,
    issued_at: u64,
    history_digest: [u8; 32],
    ed25519_receipt_digest: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Serialize)]
struct Ack {
    issued_at: u64,
    signature: Vec<u8>,
}
#[derive(Serialize)]
struct Witness<'a> {
    #[serde(flatten)]
    public: &'a Public<'a>,
    owner_secret: &'a [u8; 32],
    owner_enrollment: Row<'a>,
    peer_enrollment: Row<'a>,
    receipt_owner_enrollment: Row<'a>,
    delivery_kind: u8,
    contact_signature: Vec<u8>,
    old: PrivateOpening<'a>,
    new_blind: &'a [u8; 32],
    action: u8,
    slot: Slot,
    own_map: Map,
    opposite_map: Map,
    pair_map: Map,
    pair_exists: bool,
    resolution: Resolution,
    acknowledgment: Ack,
    standing_policy: StandingPolicyJson,
}
fn standing_json(policy: &czkp::standing::Policy) -> Result<StandingPolicyJson, Error> {
    let p = &policy.params;
    Ok(StandingPolicyJson {
        c0: p.c0,
        h_a: p.h_a,
        h_g: p.h_g,
        n_half: p.n_half,
        n_c: p.n_c,
        e_q: p.e_q,
        r_max: p.r_max,
        r_age: p.r_age,
        c_max_q: p.c_max_q,
        c_vet: p.c_vet,
        age_vet: p.age_vet,
        boost_q: p.boost_q,
        boost_days: p.boost_days,
        slope_q: p.slope_q,
        mid_q: p.mid_q,
        kappa_q: p.kappa_q,
        loan_use_q: p.loan_use_q,
        factor: policy.factor,
        trust: policy.trust.to_vec(),
        g_table: policy.g_table.to_vec(),
        a_table: policy.a_table.to_vec(),
    })
}
fn row(enrollment: &Enrollment) -> Row<'_> {
    Row {
        key: &enrollment.key,
        secret_hash: &enrollment.secret_hash,
        start: enrollment.starts_at,
        end: enrollment.expires_at,
        delegation_digest: &enrollment.delegation_digest,
        path: enrollment.path.iter().map(Field).collect(),
        index: enrollment.index,
    }
}
fn empty() -> Map {
    Map {
        leaf: [0; 4],
        index: 0,
        path: [0; 32],
        append_path: [0; 32],
    }
}

impl PreparedGenesis {
    /// Consume this private candidate into the owned original native prover.
    /// Runtime supplies a real clock and freshly authorized Engine; no client
    /// JSON can select a prover path, policy, witness or timestamp. This still
    /// produces no accepted account or durable owner adoption.
    pub fn prove(
        self,
        engine: &Engine,
        prover: &NativeProver,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<PreparedGenesisProof, Error> {
        let deadline = Instant::now() + prover.timeout();
        let now = clock()?;
        self.check_context(engine, &self.context, now)?;
        let context = &self.context;
        let p = &context.policy;
        let ext = &context.extension;
        let o = &self.opening;
        let standing =
            czkp::standing::Policy::derive(context.standing).map_err(|_| Error::Invalid)?;
        let statement = self.genesis_public();
        let public = Public {
            extension: Extension {
                revision: ext.revision,
                quorum: ext.quorum,
                change_cost: ext.change_cost,
                delay: ext.delay,
                batch: ext.batch,
                standing: ext.standing,
            },
            previous_inbox: [0; 32],
            inbox: [0; 32],
            consume_only: false,
            change_binding: [0; 32],
            community: &statement.community,
            owner: &statement.owner,
            policy_digest: &statement.policy_digest,
            enrollment_root: &statement.enrollment_root,
            now: statement.now,
            valid_until: statement.valid_until,
            genesis: statement.genesis,
            previous_version: statement.previous_version,
            next_version: statement.next_version,
            previous_state: statement.previous_state,
            next_state: &statement.next_state,
            settlement_marker: statement.settlement_marker,
            initial_credit: p.initial_credit,
            maximum_available: p.maximum_available,
            outgoing_reservation: p.outgoing_reservation,
            incoming_reservation: p.incoming_reservation,
            policy_revision: p.policy_revision,
            policy_valid_from: p.policy_valid_from,
            policy_valid_until: p.policy_valid_until,
            newcomer_period: p.newcomer_period,
            rate_window: p.rate_window,
            newcomer_admissions: p.newcomer_admissions,
            maximum_admissions: p.maximum_admissions,
            refill_period: p.refill_period,
            refill_units: p.refill_units,
            abandon_after: p.abandon_after,
        };
        let public_json = serde_json::to_string(&public).map_err(|_| Error::Invalid)?;
        let expected = prover.public_inputs(&public_json)?;
        let witness = Witness {
            public: &public,
            owner_secret: &self.secret,
            owner_enrollment: row(&context.enrollment),
            peer_enrollment: row(&context.enrollment),
            receipt_owner_enrollment: row(&context.enrollment),
            delivery_kind: 0,
            contact_signature: vec![0; 64],
            old: PrivateOpening {
                reserved: o.reserved,
                accepted: o.accepted,
                declined: o.declined,
                punished: o.punished,
                inbox: &o.inbox,
                authorization: Field(&o.authorization),
                outgoing_root: Field(&o.outgoing_root),
                outgoing_count: o.outgoing_count,
                incoming_root: Field(&o.incoming_root),
                incoming_count: o.incoming_count,
                pair_root: Field(&o.pair_root),
                pair_count: o.pair_count,
                created_at: o.created_at,
                standing: StandingJson {
                    g: o.standing.g,
                    a: o.standing.a,
                    c: o.standing.c,
                    pr: o.standing.pr,
                    pg: o.standing.pg,
                    lc: o.standing.lc,
                    day: o.standing.day,
                },
                blind: &o.blind,
            },
            new_blind: &o.blind,
            action: 1,
            slot: Slot {
                role: 0,
                peer: [0; 32],
                nonce: [0; 32],
                group: [0; 32],
                contact_policy: [0; 32],
                amount: 0,
                phase: 1,
                outcome: 0,
                answered: false,
                self_punished: false,
                admitted_at: context.checked_at,
                expires_at: context.checked_at,
                peer_authority: 0,
                owner_authority: 0,
            },
            own_map: empty(),
            opposite_map: empty(),
            pair_map: empty(),
            pair_exists: false,
            resolution: Resolution {
                kind: 2,
                issued_at: context.checked_at,
                history_digest: [0; 32],
                ed25519_receipt_digest: [0; 32],
                signature: vec![0; 64],
            },
            acknowledgment: Ack {
                issued_at: context.checked_at,
                signature: vec![0; 64],
            },
            standing_policy: standing_json(&standing)?,
        };
        let input = Zeroizing::new(serde_json::to_string(&witness).map_err(|_| Error::Invalid)?);
        let proof = prover.prove(input, expected, deadline)?;
        self.check_context(engine, &self.context, clock()?)?;
        Ok(PreparedGenesisProof {
            candidate: self,
            proof,
        })
    }
}
