//! Epoch-local presentation custody. Keys never cross the Wallet boundary.
use super::{Engine, Error};
use czkp::record::{Context, Epoch, Presentation, Record, presentation_key_commitment};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    epoch: Epoch,
    owner: [u8; 32],
    key: [u8; 32],
    cached: Option<(Record, String)>,
}
impl Drop for State {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl State {
    fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.key).verifying_key().to_bytes()
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        let record = Record {
            epoch: self.epoch.clone(),
            owner: self.owner,
            presentation_key_commitment: presentation_key_commitment(&self.public_key()),
            shares: None,
        };
        record.validate().map_err(|_| Error::Invalid)?;
        if let Some((record, proof)) = &self.cached {
            self.check_cache(record, proof)?;
        }
        Ok(())
    }
    fn check_cache(&self, record: &Record, proof: &str) -> Result<(), Error> {
        record.validate().map_err(|_| Error::Invalid)?;
        if record.epoch != self.epoch
            || record.owner != self.owner
            || record.presentation_key_commitment != presentation_key_commitment(&self.public_key())
            || proof.is_empty()
            || proof.len() > 8 * 1024 * 1024
            || proof.len() % 2 != 0
            || !proof.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

impl Engine {
    /// Prepare after authenticating and opening the newest common download.
    /// Persist through Wallet before starting background work. Same-epoch retry
    /// retains the same key and cache; an epoch cannot be replaced or rolled back.
    /// Only the public Ed25519 key is released to the existing witness builder.
    pub fn begin_record_epoch(
        &mut self,
        epoch: &Epoch,
        owner: [u8; 32],
        now: u64,
    ) -> Result<[u8; 32], Error> {
        epoch.check_time(now).map_err(|_| Error::Invalid)?;
        let period = epoch
            .expires_at
            .checked_sub(epoch.starts_at)
            .ok_or(Error::Invalid)?;
        epoch
            .validate(&epoch.community, period)
            .map_err(|_| Error::Invalid)?;
        if let Some(state) = &self.record {
            epoch
                .check_successor(&state.epoch, period)
                .map_err(|_| Error::Invalid)?;
            if owner != state.owner {
                return Err(Error::Invalid);
            }
            if epoch == &state.epoch {
                return Ok(state.public_key());
            }
        }
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| Error::Crypto)?;
        let candidate = State {
            epoch: epoch.clone(),
            owner,
            key,
            cached: None,
        };
        key.zeroize();
        candidate.validate()?;
        let public_key = candidate.public_key();
        self.record = Some(candidate);
        Ok(public_key)
    }

    /// Cache the original prover's public output after its own verification.
    /// This stores bytes, never grants proof authority. Every relying party must
    /// independently verify the relation; no caller-supplied verdict is accepted.
    pub fn cache_record_proof(&mut self, record: Record, proof: String) -> Result<(), Error> {
        let state = self.record.as_mut().ok_or(Error::Invalid)?;
        state.check_cache(&record, &proof)?;
        if let Some(cached) = &state.cached {
            return if cached == &(record, proof) {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
        }
        state.cached = Some((record, proof));
        Ok(())
    }

    /// A ready cache for this exact authenticated epoch; no proving on contact.
    pub fn record_ready(&self, epoch: &Epoch, now: u64) -> bool {
        epoch.check_time(now).is_ok()
            && self
                .record
                .as_ref()
                .is_some_and(|s| &s.epoch == epoch && s.cached.is_some())
    }

    /// Millisecond Ed25519 binding only. Refuse an absent proof or stale epoch.
    /// Wallet lends this operation only against its current committed Store.
    pub fn present_record(
        &self,
        epoch: &Epoch,
        context: &Context,
        now: u64,
    ) -> Result<Presentation, Error> {
        if !self.record_ready(epoch, now) || now >= context.expires_at {
            return Err(Error::Invalid);
        }
        let state = self.record.as_ref().ok_or(Error::Invalid)?;
        let (record, proof) = state.cached.as_ref().ok_or(Error::Invalid)?;
        let message = record
            .presentation_bytes(context)
            .map_err(|_| Error::Invalid)?;
        let key = SigningKey::from_bytes(&state.key);
        Ok(Presentation {
            record: record.clone(),
            context: context.clone(),
            public_key: key.verifying_key().to_bytes(),
            signature: key.sign(&message).to_bytes().to_vec(),
            proof: proof.clone(),
        })
    }
}
