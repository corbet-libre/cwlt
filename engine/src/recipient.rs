//! Opaque custody for the original common record-witness HPKE object.
//!
//! This transport opening is not an initialized account, a private account
//! opening, proof authority, or evidence that the descriptor is current.
use super::Error;
use czkp::record::{Epoch, EpochTree, Leaf};
use hpke::{Deserializable, Kem as _, Serializable};
use std::{cell::Cell, marker::PhantomData};
use zeroize::{Zeroize, Zeroizing};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;
const PREFIX: &[u8] = b"cblc.record-witnesses.v2\0";
const INFO: &[u8] = b"cblc.record-witness.v2\0";
const ENCAP: usize = 32;
const TAG: usize = 16;
const LEAF: usize = 141;
const CERTIFICATE: usize = 64;

/// Borrowed, nonexporting recipient initialized inside freshly authorized Keys.
/// No private key, seed, plaintext callback, Clone or serialization is available.
/// The lifetime prevents the capability escaping Keys' synchronous callback.
pub struct RecordRecipient<'key> {
    seed: Zeroizing<[u8; 32]>,
    community: [u8; 32],
    checked_at: u64,
    lifetime: PhantomData<&'key mut [u8; 32]>,
}

impl<'key> RecordRecipient<'key> {
    /// Consume the dedicated purpose input; wipe the caller buffer on all paths.
    /// Constructing this lower owner does not authenticate membership or epoch.
    pub fn from_seed(
        seed: &'key mut [u8; 32],
        community: [u8; 32],
        checked_at: u64,
    ) -> Result<Self, Error> {
        let owned = Zeroizing::new(*seed);
        seed.zeroize();
        if community == [0; 32] || checked_at > czkp::MAX_INTEGER {
            return Err(Error::Invalid);
        }
        Ok(Self {
            seed: owned,
            community,
            checked_at,
            lifetime: PhantomData,
        })
    }

    /// Public coordinate for the original admitted-account recipient registration.
    pub fn public_key(&self) -> [u8; 32] {
        Kem::derive_keypair(self.seed.as_ref()).1.to_bytes().into()
    }

    /// Open exactly one packet from the complete original shuffled object.
    /// The caller supplies the actual authenticated descriptor, Rulebook period
    /// and admitted owner. Transports must bound allocation before this call.
    /// Invoke after the download await through a fresh Keys/Charter observation;
    /// neither these public arguments nor the result grant current authority.
    /// This consumes the capability on success or refusal; another attempt needs
    /// another freshly authorized Keys callback.
    pub fn receive(
        self,
        epoch: &Epoch,
        period_seconds: u64,
        owner: [u8; 32],
        object: &[u8],
        now: u64,
    ) -> Result<ReceivedRecord, Error> {
        epoch
            .validate(&self.community, period_seconds)
            .map_err(|_| Error::Invalid)?;
        epoch.check_time(now).map_err(|_| Error::Invalid)?;
        epoch.check_object(object).map_err(|_| Error::Invalid)?;
        if owner == [0; 32] || epoch.policy_epoch == 0 || now < self.checked_at {
            return Err(Error::Invalid);
        }
        let header = PREFIX.len() + 8;
        let packet_size = ENCAP + TAG + LEAF + 32 * epoch.depth() as usize + CERTIFICATE;
        let expected = packet_size
            .checked_mul(epoch.leaf_count as usize)
            .and_then(|packets| header.checked_add(packets))
            .ok_or(Error::Invalid)?;
        if object.len() != expected
            || !object.starts_with(PREFIX)
            || u32::from_be_bytes(
                object[PREFIX.len()..PREFIX.len() + 4]
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            ) != epoch.leaf_count
            || u32::from_be_bytes(
                object[PREFIX.len() + 4..header]
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            ) as usize
                != packet_size
        {
            return Err(Error::Invalid);
        }
        let aad = packet_aad(epoch)?;
        let private = Kem::derive_keypair(self.seed.as_ref()).0;
        let mut opened = None;
        for packet in object[header..].chunks_exact(packet_size) {
            let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&packet[..ENCAP])
                .map_err(|_| Error::Crypto)?;
            if let Ok(bytes) = hpke::single_shot_open::<Aead, Kdf, Kem>(
                &hpke::OpModeR::Base,
                &private,
                &enc,
                INFO,
                &packet[ENCAP..],
                &aad,
            ) {
                let plaintext = Zeroizing::new(bytes);
                if opened.is_some() {
                    return Err(Error::Invalid);
                }
                opened = Some(decode(epoch, period_seconds, owner, now, &plaintext)?);
            }
        }
        let received = opened.ok_or(Error::Crypto)?;
        received.check(epoch, owner, now)?;
        Ok(received)
    }
}

/// One opaque verified transport packet, retained in device RAM only.
/// It has no leaf, path, blinding, private state or serialization accessor.
/// A future holder must match its genuine retained account opening before proof.
pub struct ReceivedRecord {
    epoch: Epoch,
    period_seconds: u64,
    leaf: Leaf,
    index: u32,
    path: Vec<[u8; 32]>,
    certificate: [u8; CERTIFICATE],
    checked_at: Cell<u64>,
    failed: Cell<bool>,
}

impl ReceivedRecord {
    /// Original public descriptor; this does not establish newest currentness.
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    /// The private leaf, for the crate's own record-epoch witness builder only.
    pub(crate) fn leaf(&self) -> &Leaf {
        &self.leaf
    }

    /// The issuer's certificate over this leaf's blinded commitment.
    pub(crate) fn certificate(&self) -> &[u8; CERTIFICATE] {
        &self.certificate
    }

    /// Recheck the exact independently authenticated descriptor/owner and time.
    /// Successful transport validation alone never proves private account state.
    pub fn check(&self, expected: &Epoch, owner: [u8; 32], now: u64) -> Result<(), Error> {
        if self.failed.get() {
            return Err(Error::Invalid);
        }
        if now < self.checked_at.get() {
            self.failed.set(true);
            return Err(Error::Invalid);
        }
        self.checked_at.set(now);
        if expected != &self.epoch || owner != self.leaf.owner || owner == [0; 32] {
            return Err(Error::Invalid);
        }
        expected
            .validate(&expected.community, self.period_seconds)
            .map_err(|_| Error::Invalid)?;
        if expected.check_time(now).is_err() {
            self.failed.set(true);
            return Err(Error::Invalid);
        }
        if self.index >= expected.leaf_count || self.path.len() != expected.depth() as usize {
            return Err(Error::Invalid);
        }
        let leaf = self
            .leaf
            .commitment(&expected.community, expected.epoch)
            .map_err(|_| Error::Invalid)?;
        let proof = rs_merkle::MerkleProof::<EpochTree>::new(self.path.clone());
        if !proof.verify(
            expected.root,
            &[self.index as usize],
            &[leaf],
            (expected.leaf_count as usize).max(2).next_power_of_two(),
        ) {
            return Err(Error::Invalid);
        }
        czkp::record::verify_certificate(
            &expected.issuer_key,
            &expected.community,
            expected.epoch,
            &leaf,
            &self.certificate,
        )
        .map_err(|_| Error::Invalid)
    }
}

impl Drop for ReceivedRecord {
    fn drop(&mut self) {
        self.leaf.state.zeroize();
        self.leaf.required_inbox.zeroize();
        self.leaf.blinding.zeroize();
        self.path.zeroize();
    }
}

fn packet_aad(epoch: &Epoch) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        "cblc.record-packet.v2",
        epoch.community,
        epoch.policy_epoch,
        epoch.epoch,
        epoch.starts_at,
        epoch.expires_at,
        epoch.root,
        epoch.issuer_key,
        epoch.proof_scope,
        epoch.leaf_count,
        epoch.download_bytes,
    ]))
    .map_err(|_| Error::Invalid)
}

fn decode(
    epoch: &Epoch,
    period_seconds: u64,
    owner: [u8; 32],
    now: u64,
    bytes: &[u8],
) -> Result<ReceivedRecord, Error> {
    let expected = LEAF + 32 * epoch.depth() as usize + CERTIFICATE;
    if bytes.len() != expected {
        return Err(Error::Invalid);
    }
    let leaf = Leaf {
        owner: bytes[..32].try_into().map_err(|_| Error::Invalid)?,
        version: u64::from_be_bytes(bytes[32..40].try_into().map_err(|_| Error::Invalid)?),
        state: bytes[40..72].try_into().map_err(|_| Error::Invalid)?,
        required_inbox: bytes[72..104].try_into().map_err(|_| Error::Invalid)?,
        blinding: bytes[104..136].try_into().map_err(|_| Error::Invalid)?,
        role: bytes[136],
    };
    let received = ReceivedRecord {
        epoch: epoch.clone(),
        period_seconds,
        leaf,
        index: u32::from_be_bytes(bytes[137..141].try_into().map_err(|_| Error::Invalid)?),
        path: bytes[LEAF..expected - CERTIFICATE]
            .as_chunks::<32>()
            .0
            .to_vec(),
        certificate: bytes[expected - CERTIFICATE..]
            .try_into()
            .map_err(|_| Error::Invalid)?,
        checked_at: Cell::new(now),
        failed: Cell::new(false),
    };
    if received.leaf.owner != owner {
        return Err(Error::Invalid);
    }
    Ok(received)
}

#[cfg(test)]
#[path = "recipient/tests.rs"]
mod tests;
