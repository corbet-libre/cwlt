//! Original typed genesis witness; private serialization stays inside this owner.
use super::*;
use crate::native_prover::{NativeProver, Proof};
use serde::{Serialize, Serializer};
use std::time::Instant;

/// Locally verified proof data. It grants no enrollment, accepted Frontier, Keys
/// authority, Store receipt or operator acceptance; those joins remain separate.
pub struct PreparedGenesisProof {
    candidate: PreparedGenesis,
    proof: Proof,
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
    available: u32,
    reserved: u128,
    debt: u64,
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
    frontier: u64,
    created_at: u64,
    admission_epoch: u64,
    admissions: u32,
    blind: &'a [u8; 32],
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
        let public = Public {
            extension: Extension {
                revision: ext.revision,
                quorum: ext.quorum,
                change_cost: ext.change_cost,
                delay: ext.delay,
                batch: ext.batch,
            },
            previous_inbox: [0; 32],
            inbox: [0; 32],
            consume_only: false,
            change_binding: [0; 32],
            community: &self.community,
            owner: &context.owner,
            policy_digest: &self.policy_digest,
            enrollment_root: &context.enrollment_root,
            now: context.checked_at,
            valid_until: o.frontier,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: &self.commitment,
            settlement_marker: [0; 32],
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
                available: o.available,
                reserved: o.reserved,
                debt: o.debt,
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
                frontier: o.frontier,
                created_at: o.created_at,
                admission_epoch: o.admission_epoch,
                admissions: o.admissions,
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
