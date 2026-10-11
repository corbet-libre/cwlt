//! Original current private Opening and exact state transcript; no proof verdict.
use super::{Field, hashes, policy::ExtensionPolicy};
use crate::Error;
use czkp::poseidon::{integer, limbs};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Opening {
    pub(super) available: u32,
    pub(super) reserved: u128,
    pub(super) debt: u64,
    pub(super) accepted: u64,
    pub(super) declined: u64,
    pub(super) punished: u64,
    pub(super) inbox: Field,
    pub(super) authorization: Field,
    pub(super) outgoing_root: Field,
    pub(super) outgoing_count: u64,
    pub(super) incoming_root: Field,
    pub(super) incoming_count: u64,
    pub(super) pair_root: Field,
    pub(super) pair_count: u64,
    pub(super) frontier: u64,
    pub(super) created_at: u64,
    pub(super) admission_epoch: u64,
    pub(super) admissions: u32,
    pub(super) blind: Field,
}

impl Opening {
    pub(super) fn commitment(
        &self,
        community: &Field,
        owner: &Field,
        state_policy: &Field,
        registered_secret: Field,
        version: u64,
        extension: &ExtensionPolicy,
    ) -> Result<Field, Error> {
        if version > czkp::MAX_INTEGER
            || [
                self.debt,
                self.accepted,
                self.declined,
                self.punished,
                self.frontier,
                self.created_at,
                self.admission_epoch,
            ]
            .into_iter()
            .any(|v| v > czkp::MAX_INTEGER)
        {
            return Err(Error::Invalid);
        }
        let mut fields = Vec::new();
        fields.extend(limbs(community));
        fields.extend(limbs(owner));
        fields.extend(limbs(state_policy));
        fields.extend([
            registered_secret,
            integer(version),
            extension.hash()?,
            integer(self.available.into()),
            hashes::integer128(self.reserved),
            integer(self.debt),
            integer(self.accepted),
            integer(self.declined),
            integer(self.punished),
        ]);
        fields.extend(limbs(&self.inbox));
        fields.extend([
            self.authorization,
            self.outgoing_root,
            integer(self.outgoing_count),
            self.incoming_root,
            integer(self.incoming_count),
            self.pair_root,
            integer(self.pair_count),
            integer(self.frontier),
            integer(self.created_at),
            integer(self.admission_epoch),
            integer(self.admissions.into()),
        ]);
        fields.extend(limbs(&self.blind));
        let result = hashes::hash(30, &fields);
        fields.zeroize();
        result
    }
}
