//! The typed Noir input of the account `update` circuit. One owner for genesis and every later
//! transition: field order and spelling follow the circuit ABI, nothing else.
use super::{Enrollment, Field, Opening};
use crate::plan::PolicyOut;
use serde::{Serialize, Serializer};
use zeroize::Zeroize;

/// A field element the circuit declares as `Field` (spelled as 0x-hex; byte arrays stay arrays).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hx(pub(crate) Field);
impl Serialize for Hx {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(66);
        text.push_str("0x");
        for byte in self.0 {
            text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            text.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        s.serialize_str(&text)
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct ExtensionJson {
    pub(crate) revision: u64,
    pub(crate) quorum: u32,
    pub(crate) change_cost: u32,
    pub(crate) delay: u64,
    pub(crate) batch: u8,
    pub(crate) standing: Field,
}

/// The fourteen explicit policy values, spelled as the circuit names them.
#[derive(Clone, Serialize)]
pub(crate) struct PolicyWire {
    pub(crate) initial_credit: u32,
    pub(crate) maximum_available: u32,
    pub(crate) outgoing_reservation: u32,
    pub(crate) incoming_reservation: u32,
    pub(crate) policy_revision: u64,
    pub(crate) policy_valid_from: u64,
    pub(crate) policy_valid_until: u64,
    pub(crate) newcomer_period: u64,
    pub(crate) rate_window: u64,
    pub(crate) newcomer_admissions: u32,
    pub(crate) maximum_admissions: u32,
    pub(crate) refill_period: u64,
    pub(crate) refill_units: u32,
    pub(crate) abandon_after: u64,
}

#[derive(Clone, Serialize)]
pub(crate) struct RowJson {
    pub(crate) key: Vec<u8>,
    pub(crate) secret_hash: Field,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) delegation_digest: Field,
    pub(crate) path: Vec<Hx>,
    pub(crate) index: u32,
}
impl From<&Enrollment> for RowJson {
    fn from(e: &Enrollment) -> Self {
        Self {
            key: e.key.to_vec(),
            secret_hash: e.secret_hash,
            start: e.starts_at,
            end: e.expires_at,
            delegation_digest: e.delegation_digest,
            path: e.path.iter().map(|p| Hx(*p)).collect(),
            index: e.index,
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct StandingJson {
    pub(crate) g: u64,
    pub(crate) a: u64,
    pub(crate) c: u64,
    pub(crate) pr: u64,
    pub(crate) pg: u64,
    pub(crate) lc: u64,
    pub(crate) day: u64,
}

#[derive(Clone, Serialize)]
pub(crate) struct VoucherJson {
    pub(crate) proven: u64,
    pub(crate) away: u64,
    pub(crate) lost: u64,
    pub(crate) bonus: u64,
    pub(crate) returned: u64,
    pub(crate) answers: u64,
    pub(crate) sponsor: Hx,
    pub(crate) bond: Hx,
    pub(crate) bond_root: Hx,
    pub(crate) bond_count: u64,
}

/// The extended opening the circuit reads (also the one the wave circuits read).
#[derive(Clone, Serialize)]
pub(crate) struct OpeningJson {
    pub(crate) reserved: u128,
    pub(crate) outgoing_root: Hx,
    pub(crate) outgoing_count: u64,
    pub(crate) incoming_root: Hx,
    pub(crate) incoming_count: u64,
    pub(crate) pair_root: Hx,
    pub(crate) pair_count: u64,
    pub(crate) created_at: u64,
    pub(crate) standing: StandingJson,
    pub(crate) voucher: VoucherJson,
    pub(crate) blind: Field,
    pub(crate) accepted: u64,
    pub(crate) declined: u64,
    pub(crate) punished: u64,
    pub(crate) inbox: Field,
    pub(crate) authorization: Hx,
}
impl From<&Opening> for OpeningJson {
    fn from(o: &Opening) -> Self {
        Self {
            reserved: o.reserved,
            outgoing_root: Hx(o.outgoing_root),
            outgoing_count: o.outgoing_count,
            incoming_root: Hx(o.incoming_root),
            incoming_count: o.incoming_count,
            pair_root: Hx(o.pair_root),
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
            voucher: VoucherJson {
                proven: o.voucher.proven,
                away: o.voucher.away,
                lost: o.voucher.lost,
                bonus: o.voucher.bonus,
                returned: o.voucher.returned,
                answers: o.voucher.answers,
                sponsor: Hx(o.voucher.sponsor),
                bond: Hx(o.voucher.bond),
                bond_root: Hx(o.voucher.bond_root),
                bond_count: o.voucher.bond_count,
            },
            blind: o.blind,
            accepted: o.accepted,
            declined: o.declined,
            punished: o.punished,
            inbox: o.inbox,
            authorization: Hx(o.authorization),
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct SlotJson {
    pub(crate) role: u8,
    pub(crate) peer: Field,
    pub(crate) nonce: Field,
    pub(crate) group: Field,
    pub(crate) contact_policy: Field,
    pub(crate) amount: u32,
    pub(crate) phase: u8,
    pub(crate) outcome: u8,
    pub(crate) answered: bool,
    pub(crate) self_punished: bool,
    pub(crate) admitted_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) peer_authority: Hx,
    pub(crate) owner_authority: Hx,
}

/// One authenticated-map witness (`leaf`, position and the two sibling paths).
#[derive(Clone, Serialize)]
pub(crate) struct MapJson {
    pub(crate) leaf: [Hx; 4],
    pub(crate) index: u64,
    pub(crate) path: Vec<Hx>,
    pub(crate) append_path: Vec<Hx>,
}
impl MapJson {
    pub(crate) fn empty() -> Self {
        Self {
            leaf: [Hx([0; 32]); 4],
            index: 0,
            path: vec![Hx([0; 32]); 32],
            append_path: vec![Hx([0; 32]); 32],
        }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct ResolutionJson {
    pub(crate) kind: u8,
    pub(crate) issued_at: u64,
    pub(crate) history_digest: Field,
    pub(crate) ed25519_receipt_digest: Field,
    pub(crate) signature: Vec<u8>,
}
#[derive(Clone, Serialize)]
pub(crate) struct AckJson {
    pub(crate) issued_at: u64,
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, Serialize)]
pub(crate) struct EntryJson {
    pub(crate) limit: u64,
    pub(crate) done: bool,
    pub(crate) overshoot: bool,
    pub(crate) punished_seen: u64,
    pub(crate) rewards_seen: u64,
}
/// Private inputs of the voucher actions; empty for every other action.
#[derive(Clone, Serialize)]
pub(crate) struct AuxJson {
    pub(crate) bond_secret: Field,
    pub(crate) kind: u8,
    pub(crate) n: u64,
    pub(crate) entry: EntryJson,
    pub(crate) bond_map: MapJson,
    pub(crate) sponsor: Hx,
    pub(crate) count: bool,
}
impl AuxJson {
    pub(crate) fn empty() -> Self {
        Self {
            bond_secret: [0; 32],
            kind: 0,
            n: 0,
            entry: EntryJson {
                limit: 0,
                done: false,
                overshoot: false,
                punished_seen: 0,
                rewards_seen: 0,
            },
            bond_map: MapJson::empty(),
            sponsor: Hx([0; 32]),
            count: false,
        }
    }
}

/// The complete private input of one `update` proof. It carries the opening: it is never
/// logged, never leaves the device, and is wiped when dropped.
#[derive(Clone, Serialize)]
pub struct UpdateInput {
    pub(crate) extension: ExtensionJson,
    pub(crate) previous_inbox: Field,
    pub(crate) inbox: Field,
    pub(crate) consume_only: bool,
    pub(crate) change_binding: Field,
    pub(crate) community: Field,
    pub(crate) owner: Field,
    pub(crate) policy_digest: Field,
    pub(crate) enrollment_root: Field,
    pub(crate) now: u64,
    pub(crate) valid_until: u64,
    pub(crate) genesis: bool,
    pub(crate) previous_version: u64,
    pub(crate) next_version: u64,
    pub(crate) previous_state: Field,
    pub(crate) next_state: Field,
    pub(crate) settlement_marker: Field,
    #[serde(flatten)]
    pub(crate) policy: PolicyWire,
    pub(crate) role: u8,
    pub(crate) obligation: Field,
    pub(crate) owner_secret: Field,
    pub(crate) owner_enrollment: RowJson,
    pub(crate) peer_enrollment: RowJson,
    pub(crate) receipt_owner_enrollment: RowJson,
    pub(crate) delivery_kind: u8,
    pub(crate) contact_signature: Vec<u8>,
    pub(crate) old: OpeningJson,
    pub(crate) new_blind: Field,
    pub(crate) action: u8,
    pub(crate) slot: SlotJson,
    pub(crate) own_map: MapJson,
    pub(crate) opposite_map: MapJson,
    pub(crate) pair_map: MapJson,
    pub(crate) pair_exists: bool,
    pub(crate) resolution: ResolutionJson,
    pub(crate) acknowledgment: AckJson,
    pub(crate) standing_policy: PolicyOut,
    pub(crate) aux: AuxJson,
}
impl UpdateInput {
    /// The JSON the Noir host consumes; the string is wiped when dropped.
    pub fn to_json(&self) -> Result<zeroize::Zeroizing<String>, crate::Error> {
        serde_json::to_string(self)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| crate::Error::Invalid)
    }
}
impl UpdateInput {
    /// The public part of the input only: what the verifier reads, in the circuit's naming.
    pub fn public_json(&self) -> Result<String, crate::Error> {
        const PUBLIC: [&str; 33] = [
            "extension",
            "previous_inbox",
            "inbox",
            "consume_only",
            "change_binding",
            "community",
            "owner",
            "policy_digest",
            "enrollment_root",
            "now",
            "valid_until",
            "genesis",
            "previous_version",
            "next_version",
            "previous_state",
            "next_state",
            "settlement_marker",
            "initial_credit",
            "maximum_available",
            "outgoing_reservation",
            "incoming_reservation",
            "policy_revision",
            "policy_valid_from",
            "policy_valid_until",
            "newcomer_period",
            "rate_window",
            "newcomer_admissions",
            "maximum_admissions",
            "refill_period",
            "refill_units",
            "abandon_after",
            "role",
            "obligation",
        ];
        let mut value = serde_json::to_value(self).map_err(|_| crate::Error::Invalid)?;
        let object = value.as_object_mut().ok_or(crate::Error::Invalid)?;
        object.retain(|key, _| PUBLIC.contains(&key.as_str()));
        serde_json::to_string(&value).map_err(|_| crate::Error::Invalid)
    }
}
impl Drop for UpdateInput {
    fn drop(&mut self) {
        self.owner_secret.zeroize();
        self.new_blind.zeroize();
        self.old.blind.zeroize();
        self.aux.bond_secret.zeroize();
        self.contact_signature.zeroize();
    }
}
