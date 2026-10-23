//! Original public account policy data and depth-bound digest framing.
use super::{Field, hashes, maps::DEPTH};
use crate::Error;

/// Explicit original account policy data; construction grants no admission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AccountPolicy {
    /// New account's initial available credit.
    pub initial_credit: u32,
    /// Mature total available plus reserved capacity.
    pub maximum_available: u32,
    /// Original outgoing reservation amount.
    pub outgoing_reservation: u32,
    /// Original incoming reservation amount.
    pub incoming_reservation: u32,
    /// Authenticated economic policy revision.
    pub policy_revision: u64,
    /// Inclusive policy activation time.
    pub policy_valid_from: u64,
    /// Exclusive policy expiry.
    pub policy_valid_until: u64,
    /// Permanent account-age maturation period.
    pub newcomer_period: u64,
    /// Original common proof/rate window.
    pub rate_window: u64,
    /// New account's rate-window admission limit.
    pub newcomer_admissions: u32,
    /// Mature account's rate-window admission limit.
    pub maximum_admissions: u32,
    /// Original refill period.
    pub refill_period: u64,
    /// Original refill units.
    pub refill_units: u32,
    /// Waiting interval for newly reserved contacts.
    pub abandon_after: u64,
}

impl AccountPolicy {
    pub(super) fn bytes(&self, community: &Field) -> Result<Vec<u8>, Error> {
        if self.maximum_available == 0
            || self.initial_credit > self.maximum_available
            || self.outgoing_reservation == 0
            || self.incoming_reservation == 0
            || self.outgoing_reservation > self.initial_credit
            || self.incoming_reservation > self.initial_credit
            || self.policy_revision == 0
            || self.policy_valid_from == 0
            || self.policy_valid_from >= self.policy_valid_until
            || self.newcomer_period == 0
            || self.rate_window == 0
            // Standing counts days: the proof window is at most one day.
            || self.rate_window > 86_400
            || self.refill_period == 0
            || self.abandon_after < self.rate_window
            || self.newcomer_admissions == 0
            || self.newcomer_admissions > self.maximum_admissions
            || self.refill_units == 0
            || self.refill_units > self.initial_credit
            || [
                self.policy_revision,
                self.policy_valid_from,
                self.policy_valid_until,
                self.newcomer_period,
                self.rate_window,
                self.refill_period,
                self.abandon_after,
            ]
            .into_iter()
            .any(|v| v > czkp::MAX_INTEGER)
        {
            return Err(Error::Invalid);
        }
        let mut bytes = b"cfrm.account-policy.v2\0".to_vec();
        bytes.extend_from_slice(community);
        for value in [
            self.initial_credit,
            self.maximum_available,
            self.outgoing_reservation,
            self.incoming_reservation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.policy_revision,
            self.policy_valid_from,
            self.policy_valid_until,
            self.newcomer_period,
            self.rate_window,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.newcomer_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.refill_period.to_be_bytes());
        bytes.extend_from_slice(&self.refill_units.to_be_bytes());
        bytes.extend_from_slice(&self.abandon_after.to_be_bytes());
        bytes.push(DEPTH as u8);
        Ok(bytes)
    }

    /// The policy fields as czkp's canonical statement encoder consumes them.
    pub(super) fn fields(&self) -> czkp::account::PolicyFields {
        czkp::account::PolicyFields {
            initial_credit: self.initial_credit,
            maximum_available: self.maximum_available,
            outgoing_reservation: self.outgoing_reservation,
            incoming_reservation: self.incoming_reservation,
            policy_revision: self.policy_revision,
            policy_valid_from: self.policy_valid_from,
            policy_valid_until: self.policy_valid_until,
            newcomer_period: self.newcomer_period,
            rate_window: self.rate_window,
            newcomer_admissions: self.newcomer_admissions,
            maximum_admissions: self.maximum_admissions,
            refill_period: self.refill_period,
            refill_units: self.refill_units,
            abandon_after: self.abandon_after,
        }
    }

    pub(super) fn digests(&self, community: &Field) -> Result<(Field, Field), Error> {
        let bytes = self.bytes(community)?;
        let mut state = b"cfrm.account-state-policy.v1\0".to_vec();
        state.extend_from_slice(community);
        state.extend_from_slice(&bytes[55..131]);
        state.push(DEPTH as u8);
        Ok((hashes::digest(&bytes)?, hashes::digest(&state)?))
    }

    pub(super) fn horizon(&self, now: u64) -> Result<u64, Error> {
        if now < self.policy_valid_from || now >= self.policy_valid_until || self.rate_window == 0 {
            return Err(Error::Invalid);
        }
        now.checked_div(self.rate_window)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(self.rate_window))
            .map(|n| n.min(self.policy_valid_until))
            .ok_or(Error::Invalid)
    }
}

/// Original extension policy fields, supplied from current authenticated data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExtensionPolicy {
    /// Original extension revision.
    pub revision: u64,
    /// Minimum public-record sample quorum.
    pub quorum: u32,
    /// Original change-token cost.
    pub change_cost: u32,
    /// Original anonymous delivery delay.
    pub delay: u64,
    /// Original minimum batch size.
    pub batch: u8,
    /// Digest of the rulebook-signed standing policy (`czkp::standing::Policy::digest`).
    pub standing: [u8; 32],
}
impl ExtensionPolicy {
    /// Digest of the rulebook-signed standing parameters under the account-state
    /// domain, as the circuit binds it; tables are derived by czkp's owner function.
    pub fn standing_digest(params: czkp::standing::Params) -> Result<[u8; 32], Error> {
        czkp::standing::Policy::derive(params)
            .map_err(|_| Error::Invalid)?
            .digest(&hashes::domain(b"cfrm.account-state.v2"))
            .map_err(|_| Error::Crypto)
    }

    pub(super) fn hash(&self) -> Result<Field, Error> {
        if self.revision == 0
            || self.revision > czkp::MAX_INTEGER
            || self.quorum == 0
            || self.change_cost == 0
            || self.delay == 0
            || self.delay > czkp::MAX_INTEGER
            || !(2..=64).contains(&self.batch)
            || self.standing == [0; 32]
        {
            return Err(Error::Invalid);
        }
        use czkp::poseidon::{integer, limbs};
        let digest = limbs(&self.standing);
        hashes::hash(
            31,
            &[
                integer(self.revision),
                integer(self.quorum.into()),
                integer(self.change_cost.into()),
                integer(self.delay),
                integer(self.batch.into()),
                digest[0],
                digest[1],
            ],
        )
    }
}
