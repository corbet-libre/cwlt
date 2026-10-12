//! Original current private Opening and exact state transcript; no proof verdict.
use super::{Field, hashes, policy::ExtensionPolicy};
use crate::Error;
use czkp::poseidon::{integer, limbs};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The committed standing fields (czkp::standing::State without the admission day).
#[derive(Clone, Copy, Zeroize)]
pub(super) struct Standing {
    pub(super) g: u64,
    pub(super) a: u64,
    pub(super) c: u64,
    pub(super) pr: u64,
    pub(super) pg: u64,
    pub(super) lc: u64,
    pub(super) day: u64,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Opening {
    pub(super) reserved: u128,
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
    pub(super) created_at: u64,
    pub(super) standing: Standing,
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
                self.accepted,
                self.declined,
                self.punished,
                self.created_at,
                self.standing.g,
                self.standing.a,
                self.standing.c,
                self.standing.pr,
                self.standing.pg,
                self.standing.lc,
                self.standing.day,
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
            hashes::integer128(self.reserved),
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
            integer(self.created_at),
            integer(self.standing.g),
            integer(self.standing.a),
            integer(self.standing.c),
            integer(self.standing.pr),
            integer(self.standing.pg),
            integer(self.standing.lc),
            integer(self.standing.day),
        ]);
        fields.extend(limbs(&self.blind));
        let result = hashes::hash(30, &fields);
        fields.zeroize();
        result
    }
}
