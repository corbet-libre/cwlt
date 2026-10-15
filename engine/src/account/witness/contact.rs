//! The contact transcript: both parties' consent to one exact introduction. The
//! counterpart's device signs it with its enrollment key; the update circuit verifies that
//! signature against the enrollment row before it activates a reservation.
use super::{Account, Acknowledgment, Checkpoint, Field, Reserve, Resolution};
use crate::account::Enrollment;
use crate::{Error, account::hashes};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::sync::Arc;

const PREFIX: &[u8] = b"cblc.contact.v1\0";
const RECEIPT: &[u8] = b"cmsg.accounting-receipt.v1\0";
const RECEIPT_DIGEST: &[u8] = b"cmsg.accounting-receipt-digest.v1\0";
const ACK: &[u8] = b"cmsg.accounting-ack.v1\0";

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

    /// The roster rows of (initiator, recipient) of the introduction `r`, from this
    /// account's point of view. The slot need not exist yet.
    fn parties(&self, r: &Reserve) -> Result<(Enrollment, Enrollment), Error> {
        let peer = self
            .checkpoint
            .entries()
            .get(r.peer_index)
            .ok_or(Error::Invalid)?
            .clone();
        let owner = self.owner().clone();
        Ok(if r.role == 0 {
            (owner, peer)
        } else {
            (peer, owner)
        })
    }

    /// The signed bytes of the recipient's receipt (the circuit's `receipt_bytes`).
    fn receipt_message(&self, r: &Reserve, receipt: &Resolution) -> Result<Vec<u8>, Error> {
        let (initiator, recipient) = self.parties(r)?;
        let mut bytes = Vec::with_capacity(357);
        bytes.extend_from_slice(RECEIPT);
        for field in [
            &self.cx.community,
            &recipient.member,
            &initiator.member,
            &initiator.member,
            &r.nonce,
            &r.group,
            &recipient.delegation_digest,
            &r.contact_policy,
            &receipt.history_digest,
            &receipt.ed25519_receipt_digest,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.push(receipt.kind);
        bytes.push(1);
        bytes.extend_from_slice(&receipt.issued_at.to_be_bytes());
        debug_assert_eq!(bytes.len(), 357);
        Ok(bytes)
    }

    /// The digest the recipient's account key signs to settle the introduction `r`
    /// (Answer or Close). `r.role` is THIS account's role.
    pub fn resolution_digest(&self, r: &Reserve, receipt: &Resolution) -> Result<Field, Error> {
        if !matches!(receipt.kind, 1 | 2) {
            return Err(Error::Invalid);
        }
        hashes::digest(&self.receipt_message(r, receipt)?)
    }

    /// Check the recipient's receipt signature against the recipient's roster key.
    pub fn verify_resolution(&self, r: &Reserve, receipt: &Resolution) -> Result<(), Error> {
        let (_, recipient) = self.parties(r)?;
        let digest = self.resolution_digest(r, receipt)?;
        verify_prehash(&recipient.key, &digest, &receipt.signature)
    }

    /// The digest the sender's account key signs to acknowledge the Answer `receipt` at
    /// `issued_at`.
    pub fn acknowledgment_digest(
        &self,
        r: &Reserve,
        receipt: &Resolution,
        issued_at: u64,
    ) -> Result<Field, Error> {
        if receipt.kind != 1 {
            return Err(Error::Invalid);
        }
        let (initiator, recipient) = self.parties(r)?;
        let mut answer = Vec::with_capacity(455);
        answer.extend_from_slice(RECEIPT_DIGEST);
        answer.append(&mut self.receipt_message(r, receipt)?);
        answer.extend_from_slice(&receipt.signature);
        let answer_digest = hashes::digest(&answer)?;
        let mut bytes = Vec::with_capacity(255);
        bytes.extend_from_slice(ACK);
        for field in [
            &self.cx.community,
            &initiator.member,
            &recipient.member,
            &r.nonce,
            &r.group,
            &answer_digest,
            &initiator.delegation_digest,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&issued_at.to_be_bytes());
        debug_assert_eq!(bytes.len(), 255);
        hashes::digest(&bytes)
    }

    /// Check the sender's acknowledgment signature against the sender's roster key.
    pub fn verify_acknowledgment(
        &self,
        r: &Reserve,
        receipt: &Resolution,
        ack: &Acknowledgment,
    ) -> Result<(), Error> {
        let (initiator, _) = self.parties(r)?;
        let digest = self.acknowledgment_digest(r, receipt, ack.issued_at)?;
        verify_prehash(&initiator.key, &digest, &ack.signature)
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
    use crate::account::witness::{Genesis, RosterRow};
    use crate::account::{AccountPolicy, ExtensionPolicy, hashes};
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
        assert!(
            recipient
                .verify_contact(&request(1, 0), &signature)
                .is_err()
        );
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
        assert!(
            sender
                .verify_contact(&request(0, 1), &high.to_bytes().into())
                .is_err()
        );
        // The lease must be named for either role.
        let mut open = request(0, 1);
        open.opened_at = None;
        assert!(sender.contact_digest(&open).is_err());
    }
    #[test]
    fn receipt_and_acknowledgment_digests_agree_on_both_sides() {
        let (sender, recipient, sender_key, recipient_key) = pair();
        let mut rng = || [77u8; 32];
        let sender = sender.reserve(request(0, 1), 50, &mut rng).unwrap().next;
        let recipient = recipient.reserve(request(1, 0), 50, &mut rng).unwrap().next;
        let (s_event, r_event) = (request(0, 1), request(1, 0));
        let mut receipt = Resolution {
            kind: 1,
            issued_at: 60,
            history_digest: [3; 32],
            ed25519_receipt_digest: [4; 32],
            signature: [0; 64],
        };
        let digest = recipient.resolution_digest(&r_event, &receipt).unwrap();
        assert_eq!(
            digest,
            sender.resolution_digest(&s_event, &receipt).unwrap()
        );
        receipt.signature = sign(&recipient_key, &digest);
        sender.verify_resolution(&s_event, &receipt).unwrap();
        recipient.verify_resolution(&r_event, &receipt).unwrap();
        let mut forged = receipt.clone();
        forged.history_digest = [9; 32];
        assert!(sender.verify_resolution(&s_event, &forged).is_err());
        let ack_digest = sender
            .acknowledgment_digest(&s_event, &receipt, 61)
            .unwrap();
        assert_eq!(
            ack_digest,
            recipient
                .acknowledgment_digest(&r_event, &receipt, 61)
                .unwrap()
        );
        let ack = Acknowledgment {
            issued_at: 61,
            signature: sign(&sender_key, &ack_digest),
        };
        recipient
            .verify_acknowledgment(&r_event, &receipt, &ack)
            .unwrap();
        let late = Acknowledgment {
            issued_at: 62,
            ..ack.clone()
        };
        assert!(
            recipient
                .verify_acknowledgment(&r_event, &receipt, &late)
                .is_err()
        );
        // A Close has no acknowledgment.
        let mut close = receipt.clone();
        close.kind = 2;
        assert!(sender.acknowledgment_digest(&s_event, &close, 61).is_err());
    }
    /// The recipient's whole settlement as the wave wallet runs it: reserve, activate under
    /// the sender's contact signature, settle under the signed receipt (and the sender's
    /// acknowledgment of an Answer), then the `outcome` evidence.
    #[test]
    fn signed_receipts_settle_the_recipient_slot_and_yield_the_outcome_evidence() {
        for answer in [true, false] {
            let (sender, recipient, sender_key, recipient_key) = pair();
            let mut rng = || [77u8; 32];
            let sender = sender.reserve(request(0, 1), 50, &mut rng).unwrap().next;
            let (s_req, r_req) = (request(0, 1), request(1, 0));
            let contact = sender.contact_digest(&s_req).unwrap();
            let reserved = recipient.reserve(request(1, 0), 50, &mut rng).unwrap();
            let event = reserved.event.unwrap();
            let sender_signature = sign(&sender_key, &contact);
            recipient.verify_contact(&r_req, &sender_signature).unwrap();
            let active = reserved
                .next
                .activate(&event, 60, sender_signature, &mut rng)
                .unwrap()
                .next;
            let mut receipt = Resolution {
                kind: if answer { 1 } else { 2 },
                issued_at: 50,
                history_digest: [3; 32],
                ed25519_receipt_digest: [4; 32],
                signature: [0; 64],
            };
            receipt.signature = sign(
                &recipient_key,
                &active.resolution_digest(&r_req, &receipt).unwrap(),
            );
            let ack = answer.then(|| {
                let digest = sender.acknowledgment_digest(&s_req, &receipt, 50).unwrap();
                Acknowledgment {
                    issued_at: 50,
                    signature: sign(&sender_key, &digest),
                }
            });
            if let Some(ack) = &ack {
                active.verify_acknowledgment(&r_req, &receipt, ack).unwrap();
            }
            let settled = active
                .settle(&event, &receipt, ack.as_ref(), 70, None, None, &mut rng)
                .unwrap()
                .next
                .with_certificate(crate::account::witness::Certificate {
                    accepted_at: 70,
                    signature: [1; 64],
                });
            let evidence = settled
                .wave_evidence(
                    &event,
                    &crate::account::witness::WaveContext {
                        history: [3; 32],
                        challenge: [9; 32],
                    },
                    &[2; 32],
                    &[6; 64],
                    Some(&crate::account::witness::Settled {
                        outcome: if answer {
                            crate::account::witness::SettledOutcome::Answer
                        } else {
                            crate::account::witness::SettledOutcome::Close
                        },
                        resolution: Some(receipt),
                        acknowledgment: ack,
                    }),
                )
                .unwrap();
            assert!(evidence.statement_json().unwrap().contains("\"outcome\""));
        }
    }
}
