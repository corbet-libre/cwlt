//! The contact transcript: both parties' consent to one exact introduction. The
//! counterpart's device signs it with its enrollment key; the update circuit verifies that
//! signature against the enrollment row before it activates a reservation.
use super::{Account, Checkpoint, Field, Reserve};
use std::sync::Arc;
use crate::{Error, account::hashes};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

const PREFIX: &[u8] = b"cblc.contact.v1\0";

impl Account {
    /// The digest both parties sign for the introduction `r` (same bytes for either role):
    /// the community, initiator, recipient, nonce, group, contact policy, both enrollment
    /// leaves and the common lease. `r.role` is THIS account's role. Nothing is reserved.
    pub fn contact_digest(&self, r: &Reserve) -> Result<Field, Error> {
        let peer = self
            .checkpoint
            .entries()
            .get(r.peer_index)
            .ok_or(Error::Invalid)?;
        let owner = self.owner();
        let (opened, expiry) = match (r.opened_at, r.expires_at) {
            (Some(o), Some(e)) => (o, e),
            _ => return Err(Error::Invalid),
        };
        let (initiator, recipient, a, b) = if r.role == 0 {
            (&owner.member, &peer.member, &owner.leaf, &peer.leaf)
        } else {
            (&peer.member, &owner.member, &peer.leaf, &owner.leaf)
        };
        let mut bytes = Vec::with_capacity(288);
        bytes.extend_from_slice(PREFIX);
        for field in [
            &self.cx.community,
            initiator,
            recipient,
            &r.nonce,
            &r.group,
            &r.contact_policy,
            a,
            b,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&opened.to_be_bytes());
        bytes.extend_from_slice(&expiry.to_be_bytes());
        hashes::digest(&bytes)
    }

    /// The current roster this account proves membership against.
    pub fn roster(&self) -> &Arc<Checkpoint> {
        &self.checkpoint
    }

    /// The event of the obligation opened for conversation `nonce`, if one exists. A wave
    /// job that restarts after a crash resumes from the slot's phase instead of reserving
    /// twice.
    pub fn event_for(&self, nonce: &Field) -> Option<Field> {
        self.slots
            .iter()
            .find(|(_, slot)| &slot.nonce == nonce)
            .map(|(event, _)| *event)
    }

    /// Check the counterpart's contact signature exactly as the update circuit does: P-256
    /// over the digest, by the key of the peer's roster row, low-S.
    pub fn verify_contact(&self, r: &Reserve, signature: &[u8; 64]) -> Result<(), Error> {
        let peer = self
            .checkpoint
            .entries()
            .get(r.peer_index)
            .ok_or(Error::Invalid)?;
        let digest = self.contact_digest(r)?;
        verify_prehash(&peer.key, &digest, signature)
    }
}

/// P-256 verification of a 32-byte digest by an uncompressed (x then y) key; high-S refused.
pub fn verify_prehash(key: &[u8; 64], digest: &Field, signature: &[u8; 64]) -> Result<(), Error> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(key);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::Invalid)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Invalid)?;
    if signature.normalize_s() != signature {
        return Err(Error::Invalid);
    }
    key.verify_prehash(digest, &signature)
        .map_err(|_| Error::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountPolicy, ExtensionPolicy, hashes};
    use crate::account::witness::{Genesis, RosterRow};
    use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }
    fn public(k: &SigningKey) -> [u8; 64] {
        let point = k.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(point.x().unwrap());
        out[32..].copy_from_slice(point.y().unwrap());
        out
    }
    fn sign(k: &SigningKey, digest: &Field) -> [u8; 64] {
        let sig: Signature = k.sign_prehash(digest).unwrap();
        let sig = sig.normalize_s();
        sig.to_bytes().into()
    }

    /// Two enrolled members, each with a genesis account over the shared roster.
    fn pair() -> (Account, Account, SigningKey, SigningKey) {
        let community = [9u8; 32];
        let params = czkp::reference::params();
        let policy = AccountPolicy {
            initial_credit: 3,
            maximum_available: 3,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 3_000_000,
            newcomer_period: 100,
            rate_window: 10,
            newcomer_admissions: 8,
            maximum_admissions: 8,
            refill_period: 10,
            refill_units: 1,
            abandon_after: 100,
        };
        let extension = ExtensionPolicy {
            revision: 1,
            quorum: 2,
            change_cost: 1,
            delay: 10,
            batch: 2,
            standing: ExtensionPolicy::standing_digest(params).unwrap(),
        };
        let keys = [key(3), key(4)];
        let secrets = [[20u8; 32], [21u8; 32]];
        let rows: Vec<RosterRow> = (0..2)
            .map(|i| RosterRow {
                member: [10 + i as u8; 32],
                key: public(&keys[i]),
                secret_hash: hashes::secret(&community, &secrets[i]).unwrap(),
                issued_at: 1,
                expires_at: 3_000_000,
                delegation_digest: [30 + i as u8; 32],
            })
            .collect();
        let roster = Arc::new(Checkpoint::from_verified(&community, &rows).unwrap());
        let build = |i: usize| {
            Account::genesis(
                Genesis {
                    community,
                    policy,
                    extension,
                    standing: params,
                    checkpoint: roster.clone(),
                    owner_index: i,
                    owner_secret: &secrets[i],
                    now: 50,
                    bond: None,
                },
                &mut || [40 + i as u8; 32],
            )
            .unwrap()
            .next
        };
        let [k0, k1] = keys;
        (build(0), build(1), k0, k1)
    }

    fn request(role: u8, peer_index: usize) -> Reserve {
        Reserve {
            peer_index,
            role,
            nonce: [7; 32],
            group: [8; 32],
            contact_policy: [5; 32],
            opened_at: Some(50),
            expires_at: Some(150),
        }
    }

    #[test]
    fn both_roles_sign_the_same_transcript_and_the_circuit_rule_is_enforced() {
        let (sender, recipient, sender_key, recipient_key) = pair();
        let from_sender = sender.contact_digest(&request(0, 1)).unwrap();
        let from_recipient = recipient.contact_digest(&request(1, 0)).unwrap();
        assert_eq!(from_sender, from_recipient);
        // The digest is the SHA-256 of the framed transcript.
        let mut other = request(0, 1);
        other.nonce = [6; 32];
        assert_ne!(sender.contact_digest(&other).unwrap(), from_sender);
        // A countersignature verifies for the counterpart only.
        let signature = sign(&recipient_key, &from_recipient);
        sender.verify_contact(&request(0, 1), &signature).unwrap();
        assert!(recipient.verify_contact(&request(1, 0), &signature).is_err());
        let own = sign(&sender_key, &from_sender);
        recipient.verify_contact(&request(1, 0), &own).unwrap();
        // Any changed term, a flipped bit and a high-S twin are refused.
        assert!(sender.verify_contact(&other, &signature).is_err());
        let mut flipped = signature;
        flipped[5] ^= 1;
        assert!(sender.verify_contact(&request(0, 1), &flipped).is_err());
        let parsed = Signature::from_slice(&signature).unwrap();
        let (r, s) = parsed.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        assert!(sender
            .verify_contact(&request(0, 1), &high.to_bytes().into())
            .is_err());
        // The lease must be named for either role.
        let mut open = request(0, 1);
        open.opened_at = None;
        assert!(sender.contact_digest(&open).is_err());
    }
}
