//! Peer release evidence types for the actual extension account relation.
//! The counterpart verifier over the native worker is not ported yet: the
//! v01 process verifier has no equivalent in czkp main, so no Verified value can
//! be constructed from this crate until that port exists.
#![allow(missing_docs)]
use czkp::{Error, ProofScope};
use serde::{Deserialize, Serialize};

/// Mandatory platform policy; no implicit quorum or economic defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPolicy {
    pub revision: u64,
    pub public_record_quorum: u32,
    pub change_token_cost: u32,
    pub deposit_delay_seconds: u64,
    pub minimum_deposit_batch: u8,
}
impl ExtensionPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.revision == 0
            || self.revision > czkp::MAX_INTEGER
            || self.public_record_quorum == 0
            || self.change_token_cost == 0
            || self.deposit_delay_seconds == 0
            || self.deposit_delay_seconds > czkp::MAX_INTEGER
            || !(2..=64).contains(&self.minimum_deposit_batch)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Independently authenticated common verifier parameters. Construct these from
/// the installed Balance publication, never from a peer's presentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WavePolicy {
    pub community: [u8; 32],
    pub extension: ExtensionPolicy,
    pub proof_scope: ProofScope,
    pub certificate_key: Vec<u8>,
    pub manifest_sha256: [u8; 32],
    pub state_policy: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
}
impl WavePolicy {
    pub fn validate(&self) -> Result<(), Error> {
        self.extension.validate()?;
        if self.certificate_key.len() != 64
            || self.manifest_sha256 == [0; 32]
            || self.proof_scope.circuit_digest == [0; 32]
            || self.proof_scope.verifying_key_digest == [0; 32]
            || self.valid_from == 0
            || self.valid_from >= self.valid_until
            || self.valid_until > czkp::MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Exact independently expected contact transcript, with the original common
/// lease and one-use challenge. All fields are bound in the proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaveContext {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub peer: [u8; 32],
    pub role: u8,
    pub nonce: [u8; 32],
    pub group: [u8; 32],
    pub contact_policy: [u8; 32],
    pub history: [u8; 32],
    pub challenge: [u8; 32],
    pub opened_at: u64,
    pub expires_at: u64,
    pub owner_authority: [u8; 32],
    pub peer_authority: [u8; 32],
}
/// Public evidence with the issuer certificate verified natively. The private
/// opening stays in the proof witness. The relation permits active phase two only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaveStatement {
    pub context: WaveContext,
    pub state_policy: [u8; 32],
    pub version: u64,
    pub state: [u8; 32],
    pub accepted_at: u64,
    pub binding: [u8; 32],
    pub certificate: Vec<u8>,
}
/// Original settled extension outcomes. Silence is only the sender's fixed-date
/// refund; it never attests that the recipient sent an Answer or Close.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum WaveOutcome {
    Answer,
    Close,
    Silence,
}
/// Public proof of a settled slot plus the original signed transcript receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(utoipa::ToSchema, schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaveOutcomeStatement {
    pub evidence: WaveStatement,
    pub outcome: WaveOutcome,
    pub receipt_digest: [u8; 32],
}
/// Concrete verified outcome. No deserializer or caller constructor exists.
pub struct VerifiedWaveOutcome {
    context: WaveContext,
    outcome: WaveOutcome,
    receipt_digest: [u8; 32],
}
impl VerifiedWaveOutcome {
    pub fn context(&self) -> &WaveContext {
        &self.context
    }
    pub fn outcome(&self) -> WaveOutcome {
        self.outcome
    }
    pub fn receipt_digest(&self) -> &[u8; 32] {
        &self.receipt_digest
    }
}

/// Successfully checked counterpart evidence. It is deliberately neither
/// deserializable nor caller-constructible. Durable one-use consumption and the
/// second party's evidence are still required before releasing message content.
pub struct VerifiedWaveReservation {
    context: WaveContext,
}
impl VerifiedWaveReservation {
    pub fn context(&self) -> &WaveContext {
        &self.context
    }
}
