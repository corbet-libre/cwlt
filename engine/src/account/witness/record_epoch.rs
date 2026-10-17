//! The per-epoch record (R2) witness: the received common-root packet matched against the
//! accepted account state. Generated once per epoch in the background; the cached proof is
//! then bound to each relying party's challenge by the epoch presentation key (`record.rs`).
//! Pure member-side construction: no network, no storage, no proving.
use super::input::{ExtensionJson, Hx, OpeningJson};
use super::{Account, Field};
use crate::{Error, ReceivedRecord};
use czkp::record::{Epoch, Leaf, Record};
use serde::Serialize;
use zeroize::Zeroize;

/// The Noir input of `record_epoch`, field for field in the circuit's parameter order.
#[derive(Serialize)]
struct Input {
    extension: ExtensionJson,
    record_issuer_key: Field,
    record_certificate: Vec<u8>,
    scope: Field,
    verification_scope: Field,
    community: Field,
    owner: Field,
    epoch: u64,
    epoch_start: u64,
    epoch_end: u64,
    epoch_root: Field,
    leaf_count: u32,
    blinded_leaf: Field,
    presentation_key: [Hx; 2],
    present: bool,
    shares: [u16; 3],
    version: u64,
    state: Field,
    required_inbox: Field,
    role: u8,
    blinding: Field,
    state_policy: Field,
    registered_secret: Hx,
    opening: OpeningJson,
}

/// One epoch's public record with the private input that proves it.
pub struct RecordEpochEvidence {
    record: Record,
    input: Input,
}
impl RecordEpochEvidence {
    /// The public record every relying party verifies; it carries no private state.
    pub fn record(&self) -> &Record {
        &self.record
    }
    /// The private circuit input as JSON; the string is wiped when dropped.
    pub fn input_json(&self) -> Result<zeroize::Zeroizing<String>, Error> {
        serde_json::to_string(&self.input)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| Error::Invalid)
    }
}
impl Drop for RecordEpochEvidence {
    fn drop(&mut self) {
        self.input.blinding.zeroize();
        self.input.opening.blind.zeroize();
    }
}

impl Account {
    /// The record-epoch evidence of this accepted state for one received packet, bound to the
    /// epoch's public presentation key. Refuses a packet whose leaf is not exactly this state
    /// (owner, version, commitment, required inbox) or whose descriptor fails at `now`.
    pub fn record_epoch(
        &self,
        received: &ReceivedRecord,
        presentation_key: [u8; 32],
        now: u64,
    ) -> Result<RecordEpochEvidence, Error> {
        received.check(received.epoch(), self.owner().member, now)?;
        self.record_epoch_leaf(
            received.epoch(),
            received.leaf(),
            received.certificate(),
            presentation_key,
        )
    }

    /// The same evidence from an epoch, a leaf of this state and the issuer's certificate
    /// over the leaf's blinded commitment (checked here; R2 proves no tree path).
    fn record_epoch_leaf(
        &self,
        epoch: &Epoch,
        leaf: &Leaf,
        certificate: &[u8; 64],
        presentation_key: [u8; 32],
    ) -> Result<RecordEpochEvidence, Error> {
        let owner = self.owner().member;
        let o = &self.opening;
        if epoch.community != self.cx.community
            || leaf.owner != owner
            || leaf.version != self.version
            || leaf.state != self.commitment
            || leaf.required_inbox != o.inbox
            || presentation_key == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let blinded_leaf = leaf
            .commitment(&epoch.community, epoch.epoch)
            .map_err(|_| Error::Invalid)?;
        czkp::record::verify_certificate(
            &epoch.issuer_key,
            &epoch.community,
            epoch.epoch,
            &blinded_leaf,
            certificate,
        )
        .map_err(|_| Error::Invalid)?;
        let total = u128::from(o.accepted) + u128::from(o.declined) + u128::from(o.punished);
        let shares = if total >= u128::from(self.cx.extension.quorum) {
            if total == 0 {
                return Err(Error::Invalid);
            }
            let accepted = (u128::from(o.accepted) * 10_000 / total) as u16;
            let declined = (u128::from(o.declined) * 10_000 / total) as u16;
            Some([accepted, declined, 10_000 - accepted - declined])
        } else {
            None
        };
        let certificate = certificate.to_vec();
        let record = Record {
            epoch: epoch.clone(),
            owner,
            presentation_key: czkp::record::presentation_key(&presentation_key),
            blinded_leaf,
            certificate: certificate.clone(),
            shares,
        };
        record.validate().map_err(|_| Error::Invalid)?;
        let limb = |half: &[u8]| {
            let mut field = [0; 32];
            field[16..].copy_from_slice(half);
            Hx(field)
        };
        let input = Input {
            extension: super::evidence::ext(self),
            record_issuer_key: epoch.issuer_key,
            record_certificate: certificate,
            scope: epoch.proof_scope.circuit_digest,
            verification_scope: epoch.proof_scope.verifying_key_digest,
            community: epoch.community,
            owner,
            epoch: epoch.epoch,
            epoch_start: epoch.starts_at,
            epoch_end: epoch.expires_at,
            epoch_root: epoch.root,
            leaf_count: epoch.leaf_count,
            blinded_leaf,
            presentation_key: [
                limb(&record.presentation_key[..16]),
                limb(&record.presentation_key[16..]),
            ],
            present: shares.is_some(),
            shares: shares.unwrap_or([0; 3]),
            version: leaf.version,
            state: leaf.state,
            required_inbox: leaf.required_inbox,
            role: leaf.role,
            blinding: leaf.blinding,
            state_policy: self.cx.state_policy,
            registered_secret: Hx(self.owner().secret_hash),
            opening: OpeningJson::from(o),
        };
        Ok(RecordEpochEvidence { record, input })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::witness::{Checkpoint, Genesis, RosterRow};
    use crate::account::{AccountPolicy, ExtensionPolicy, hashes};
    use czkp::{ProofScope, record::Purpose};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Arc;

    const COMMUNITY: [u8; 32] = [9; 32];

    fn account() -> Account {
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
        let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let mut public = [0u8; 64];
        public[..32].copy_from_slice(point.x().unwrap());
        public[32..].copy_from_slice(point.y().unwrap());
        let secret = [20u8; 32];
        let row = RosterRow {
            member: [10; 32],
            key: public,
            secret_hash: hashes::secret(&COMMUNITY, &secret).unwrap(),
            issued_at: 1,
            expires_at: 3_000_000,
            delegation_digest: [30; 32],
        };
        let roster = Arc::new(Checkpoint::from_verified(&COMMUNITY, &[row]).unwrap());
        Account::genesis(
            Genesis {
                community: COMMUNITY,
                policy,
                extension,
                standing: params,
                checkpoint: roster,
                owner_index: 0,
                owner_secret: &secret,
                now: 50,
                bond: None,
            },
            &mut || [40; 32],
        )
        .unwrap()
        .next
    }

    fn epoch(issuer: &SigningKey) -> Epoch {
        Epoch {
            purpose: Purpose::RecordEpochV3,
            community: COMMUNITY,
            policy_epoch: 1,
            epoch: 2,
            starts_at: 200,
            expires_at: 300,
            root: [5; 32],
            issuer_key: issuer.verifying_key().to_bytes(),
            proof_scope: ProofScope {
                circuit_digest: [7; 32],
                verifying_key_digest: [8; 32],
            },
            leaf_count: 1,
            download_digest: [1; 32],
            download_bytes: 1,
        }
    }

    fn leaf(account: &Account) -> Leaf {
        Leaf {
            owner: account.owner().member,
            version: account.version,
            state: account.commitment,
            required_inbox: account.opening.inbox,
            role: 0,
            blinding: [44; 32],
        }
    }

    fn certify(issuer: &SigningKey, epoch: &Epoch, leaf: &Leaf) -> [u8; 64] {
        let blinded = leaf.commitment(&epoch.community, epoch.epoch).unwrap();
        issuer
            .sign(
                &czkp::record::certificate_bytes(&epoch.community, epoch.epoch, &blinded).unwrap(),
            )
            .to_bytes()
    }

    #[test]
    fn the_leaf_of_this_state_yields_the_r2_record_and_circuit_input() {
        let account = account();
        let issuer = SigningKey::from_bytes(&[19; 32]);
        let epoch = epoch(&issuer);
        let leaf = leaf(&account);
        let certificate = certify(&issuer, &epoch, &leaf);
        let mut key = [0; 32];
        key[..16].copy_from_slice(&[0xaa; 16]);
        key[16..].copy_from_slice(&[0xbb; 16]);
        let evidence = account
            .record_epoch_leaf(&epoch, &leaf, &certificate, key)
            .unwrap();
        let record = evidence.record();
        assert_eq!(record.epoch, epoch);
        assert_eq!(record.owner, [10; 32]);
        assert_eq!(record.presentation_key, key);
        assert_eq!(record.certificate, certificate.to_vec());
        // Genesis has no settled contacts: below the quorum, no shares are shown.
        assert_eq!(record.shares, None);
        record.validate().unwrap();
        let input: serde_json::Value =
            serde_json::from_str(&evidence.input_json().unwrap()).unwrap();
        let limb = |byte: &str| format!("0x{}{}", "00".repeat(16), byte.repeat(16));
        assert_eq!(input["presentation_key"][0], limb("aa"));
        assert_eq!(input["presentation_key"][1], limb("bb"));
        assert_eq!(input["present"], false);
        assert_eq!(input["shares"], serde_json::json!([0, 0, 0]));
        assert_eq!(input["epoch"], 2);
        assert_eq!(input["epoch_start"], 200);
        assert_eq!(input["epoch_end"], 300);
        assert_eq!(input["leaf_count"], 1);
        assert_eq!(input["role"], 0);
        assert_eq!(input["record_certificate"].as_array().unwrap().len(), 64);
        let blinded: Vec<u8> = serde_json::from_value(input["blinded_leaf"].clone()).unwrap();
        assert_eq!(blinded, record.blinded_leaf.to_vec());
    }

    #[test]
    fn a_leaf_of_another_state_or_a_foreign_certificate_refuses() {
        let account = account();
        let issuer = SigningKey::from_bytes(&[19; 32]);
        let epoch = epoch(&issuer);
        let good = leaf(&account);
        let mut cases = Vec::new();
        for change in 0..4 {
            let mut other = good.clone();
            match change {
                0 => other.version += 1,
                1 => other.state[31] ^= 1,
                2 => other.required_inbox[0] ^= 1,
                _ => other.owner[0] ^= 1,
            }
            let certificate = certify(&issuer, &epoch, &other);
            cases.push((epoch.clone(), other, certificate, [1; 32]));
        }
        let mut foreign = epoch.clone();
        foreign.community = [8; 32];
        let certificate = certify(&issuer, &foreign, &good);
        cases.push((foreign, good.clone(), certificate, [1; 32]));
        let stranger = SigningKey::from_bytes(&[20; 32]);
        cases.push((
            epoch.clone(),
            good.clone(),
            certify(&stranger, &epoch, &good),
            [1; 32],
        ));
        cases.push((
            epoch.clone(),
            good.clone(),
            certify(&issuer, &epoch, &good),
            [0; 32],
        ));
        for (epoch, leaf, certificate, key) in cases {
            assert!(matches!(
                account.record_epoch_leaf(&epoch, &leaf, &certificate, key),
                Err(Error::Invalid)
            ));
        }
    }
}
