//! Public statements of the account update proof and of the extension circuits, spelled
//! exactly as the issuer and the verifiers parse them (camelCase, byte strings as arrays).
use super::Field;
use super::input::{ExtensionJson, PolicyWire, UpdateInput};
use serde::Serialize;

/// The public policy values of an account statement.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatement {
    /// New account's initial credit.
    pub initial_credit: u32,
    /// Mature maximum.
    pub maximum_available: u32,
    /// Outgoing reservation amount.
    pub outgoing_reservation: u32,
    /// Incoming reservation amount.
    pub incoming_reservation: u32,
    /// Policy revision.
    pub policy_revision: u64,
    /// Inclusive activation.
    pub policy_valid_from: u64,
    /// Exclusive expiry.
    pub policy_valid_until: u64,
    /// Newcomer period.
    pub newcomer_period: u64,
    /// Proof window.
    pub rate_window: u64,
    /// Newcomer admissions per window.
    pub newcomer_admissions: u32,
    /// Mature admissions per window.
    pub maximum_admissions: u32,
    /// Refill period.
    pub refill_period: u64,
    /// Refill units.
    pub refill_units: u32,
    /// Waiting interval of new contacts.
    pub abandon_after: u64,
}

/// What the issuer sees of one account update.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatement {
    /// Statement version, always 2.
    pub protocol_version: u32,
    /// Community digest.
    pub community: Field,
    /// Enrolled owner.
    pub owner: Field,
    /// Digest of the explicit policy.
    pub policy_digest: Field,
    /// Common enrollment root.
    pub enrollment_root: Field,
    /// Proof time.
    pub now: u64,
    /// Exclusive proof horizon.
    pub valid_until: u64,
    /// True only for the genesis proof.
    pub genesis: bool,
    /// Version before the update.
    pub previous_version: u64,
    /// Version after the update.
    pub next_version: u64,
    /// State commitment before.
    pub previous_state: Field,
    /// State commitment after.
    pub next_state: Field,
    /// Single-use settlement marker (zero when the action settles nothing).
    pub settlement_marker: Field,
    /// The explicit policy values.
    pub policy: PolicyStatement,
}

fn policy(p: &PolicyWire) -> PolicyStatement {
    PolicyStatement {
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
    }
}

impl AccountStatement {
    pub(super) fn from_input(input: &UpdateInput) -> Self {
        Self {
            protocol_version: 2,
            community: input.community,
            owner: input.owner,
            policy_digest: input.policy_digest,
            enrollment_root: input.enrollment_root,
            now: input.now,
            valid_until: input.valid_until,
            genesis: input.genesis,
            previous_version: input.previous_version,
            next_version: input.next_version,
            previous_state: input.previous_state,
            next_state: input.next_state,
            settlement_marker: input.settlement_marker,
            policy: policy(&input.policy),
        }
    }
}

/// The inbox frontier move and the effect the issuer applies with the update.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEffect {
    /// Inbox root before.
    pub previous_inbox: InboxRoot,
    /// Inbox root after.
    pub inbox: InboxRoot,
    /// What the update does beyond moving the state.
    pub effect: Effect,
}
/// An inbox frontier root.
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct InboxRoot {
    /// The root.
    pub root: Field,
}
/// The issuer-visible effect of an update.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Effect {
    /// A plain update.
    Update,
    /// A change token bound to `binding`.
    Change {
        /// The binding the token authorizes.
        binding: Field,
    },
    /// A voucher admission by a sponsor of `role`.
    Admit {
        /// Voucher role class (member, admin, root).
        role: u8,
    },
    /// Consumption of the obligation with this tag.
    Consume {
        /// The obligation tag.
        obligation: Field,
    },
}

pub(super) fn effect(input: &UpdateInput) -> UpdateEffect {
    UpdateEffect {
        previous_inbox: InboxRoot {
            root: input.previous_inbox,
        },
        inbox: InboxRoot { root: input.inbox },
        effect: match input.action {
            9 => Effect::Change {
                binding: input.change_binding,
            },
            12 => Effect::Admit { role: input.role },
            13 => Effect::Consume {
                obligation: input.obligation,
            },
            _ => Effect::Update,
        },
    }
}

/// The extension policy as statements spell it.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionStatement {
    /// Extension revision.
    pub revision: u64,
    /// Public-record quorum.
    pub public_record_quorum: u32,
    /// Change-token cost.
    pub change_token_cost: u32,
    /// Deposit delay in seconds.
    pub deposit_delay_seconds: u64,
    /// Minimum deposit batch.
    pub minimum_deposit_batch: u8,
    /// Digest of the standing policy.
    pub standing_policy_digest: Field,
}
impl From<&ExtensionJson> for ExtensionStatement {
    fn from(e: &ExtensionJson) -> Self {
        Self {
            revision: e.revision,
            public_record_quorum: e.quorum,
            change_token_cost: e.change_cost,
            deposit_delay_seconds: e.delay,
            minimum_deposit_batch: e.batch,
            standing_policy_digest: e.standing,
        }
    }
}
