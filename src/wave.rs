//! Peer release evidence for the actual extension account relation.
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
    /// Project the canonical portable descriptor from original authenticated
    /// Beacon bytes. Older material without this descriptor cannot authorize Waves.
    #[cfg(feature = "beacon")]
    pub fn from_balance(balance: &cbcn::balance::Balance, now: u64) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Material {
            community: String,
            wave_verifier: WavePolicy,
        }
        if now >= balance.valid_until() {
            return Err(Error::Expired);
        }
        let material: Material =
            serde_json::from_slice(balance.payload()).map_err(|_| Error::InvalidInput)?;
        material.wave_verifier.validate()?;
        if material.wave_verifier.community
            != czkp::decode::<32>(&czkp::digest(material.community.as_bytes()))?
        {
            return Err(Error::PolicyMismatch);
        }
        if now < material.wave_verifier.valid_from || now >= material.wave_verifier.valid_until {
            return Err(Error::Expired);
        }
        Ok(material.wave_verifier)
    }
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
/// Public evidence only. The issuer certificate and private opening stay in the
/// proof witness. The relation permits active phase two only.
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
impl WaveOutcome {
    #[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
    fn code(self) -> u8 {
        match self {
            Self::Answer => 1,
            Self::Close => 2,
            Self::Silence => 3,
        }
    }
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

#[cfg(any(test, feature = "native-verifier", target_arch = "wasm32"))]
fn validate_context(
    policy: &WavePolicy,
    statement: &WaveStatement,
    expected: &WaveContext,
    now: u64,
    outcome: Option<WaveOutcome>,
) -> Result<(), Error> {
    let c = &statement.context;
    if c != expected
        || c.community != policy.community
        || statement.state_policy != policy.state_policy
    {
        return Err(Error::PolicyMismatch);
    }
    if c.owner == c.peer
        || c.role > 1
        || c.nonce == [0; 32]
        || c.challenge == [0; 32]
        || c.opened_at == 0
        || c.expires_at <= c.opened_at
        || statement.version == 0
        || statement.version > czkp::MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    if now < policy.valid_from
        || now >= policy.valid_until
        || now < c.opened_at
        || (outcome.is_none() && now >= c.expires_at)
        || c.expires_at >= policy.valid_until
        || statement.accepted_at < c.opened_at
        || statement.accepted_at > now
    {
        return Err(Error::Expired);
    }
    if let Some(outcome) = outcome {
        let valid = match outcome {
            WaveOutcome::Answer => statement.accepted_at < c.expires_at,
            WaveOutcome::Close => c.role == 1,
            WaveOutcome::Silence => c.role == 0 && statement.accepted_at >= c.expires_at,
        };
        if !valid {
            return Err(Error::InvalidInput);
        }
    }
    for field in [
        &c.owner_authority,
        &c.peer_authority,
        &statement.state,
        &statement.binding,
    ] {
        czkp::field(field, true)?;
    }
    Ok(())
}

/// Concrete native verifier using the shared maintained proof worker. The script
/// must be the shipped neutral czkp suite verifier and its artifacts independently pinned.
#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
pub struct WaveVerifier {
    policy: WavePolicy,
    observed_at: u64,
    authority_until: u64,
    verifier: czkp::process::ProcessVerifier,
}

/// Per-call Wave refusal, with no request contents or worker output retained.
#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaveVerificationFailure {
    /// An original policy, expected-context or clock check refused the request.
    Context(Error),
    /// The original maintained proof worker refused or could not complete.
    Process(czkp::process::ProcessVerificationFailure),
}
#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl WaveVerificationFailure {
    /// Recover the original Wave verifier error without weakening acceptance.
    pub fn error(self) -> Error {
        match self {
            Self::Context(error) => error,
            Self::Process(failure) => failure.error(),
        }
    }

    /// Fixed label for this attempt; never derived from request values.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Context(_) => "wave_context",
            Self::Process(failure) => failure.category(),
        }
    }
}
#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl From<Error> for WaveVerificationFailure {
    fn from(error: Error) -> Self {
        Self::Context(error)
    }
}
#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl From<czkp::process::ProcessVerificationFailure> for WaveVerificationFailure {
    fn from(failure: czkp::process::ProcessVerificationFailure) -> Self {
        Self::Process(failure)
    }
}

#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl WaveVerifier {
    pub fn from_balance(
        balance: &cbcn::balance::Balance,
        config: czkp::process::ProcessVerifierConfig,
        now: u64,
    ) -> Result<Self, Error> {
        let policy = WavePolicy::from_balance(balance, now)?;
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(&config.artifact_config)
            .map_err(|_| Error::CryptoProvider)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::CryptoProvider)?;
        if bytes.len() > 65536 {
            return Err(Error::InvalidInput);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Manifest {
            manifest_sha256: String,
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
        if manifest.manifest_sha256 != data_encoding::HEXLOWER.encode(&policy.manifest_sha256) {
            return Err(Error::PolicyMismatch);
        }
        if config.scope != policy.proof_scope {
            return Err(Error::PolicyMismatch);
        }
        Ok(Self {
            policy,
            observed_at: now,
            authority_until: balance.valid_until(),
            verifier: czkp::process::ProcessVerifier::new(config)?,
        })
    }
    pub fn verify(
        &self,
        statement: &WaveStatement,
        proof: &[u8],
        expected: &WaveContext,
        now: u64,
    ) -> Result<VerifiedWaveReservation, Error> {
        self.verify_detailed(statement, proof, expected, now)
            .map_err(WaveVerificationFailure::error)
    }
    /// The same reservation verification, retaining a value-free failure cause.
    pub fn verify_detailed(
        &self,
        statement: &WaveStatement,
        proof: &[u8],
        expected: &WaveContext,
        now: u64,
    ) -> Result<VerifiedWaveReservation, WaveVerificationFailure> {
        if now < self.observed_at {
            return Err(Error::ClockRollback.into());
        }
        if now >= self.authority_until {
            return Err(Error::Expired.into());
        }
        validate_context(&self.policy, statement, expected, now, None)?;
        let input = self.public_input(statement);
        self.verifier.verify_detailed(&input, proof)?;
        Ok(VerifiedWaveReservation {
            context: expected.clone(),
        })
    }
    /// Verify a settled outcome and its independently expected original receipt.
    /// Answer proves the recipient signature and sender acknowledgment; Close
    /// proves the recipient signature; Silence proves the accepted fixed refund.
    pub fn verify_outcome(
        &self,
        statement: &WaveOutcomeStatement,
        proof: &[u8],
        expected: &WaveContext,
        expected_outcome: WaveOutcome,
        expected_receipt_digest: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedWaveOutcome, Error> {
        self.verify_outcome_detailed(
            statement,
            proof,
            expected,
            expected_outcome,
            expected_receipt_digest,
            now,
        )
        .map_err(WaveVerificationFailure::error)
    }
    /// The same outcome verification, retaining a value-free failure cause.
    pub fn verify_outcome_detailed(
        &self,
        statement: &WaveOutcomeStatement,
        proof: &[u8],
        expected: &WaveContext,
        expected_outcome: WaveOutcome,
        expected_receipt_digest: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedWaveOutcome, WaveVerificationFailure> {
        if now < self.observed_at {
            return Err(Error::ClockRollback.into());
        }
        if now >= self.authority_until {
            return Err(Error::Expired.into());
        }
        if statement.outcome != expected_outcome
            || &statement.receipt_digest != expected_receipt_digest
            || (statement.outcome == WaveOutcome::Silence && statement.receipt_digest != [0; 32])
        {
            return Err(Error::PolicyMismatch.into());
        }
        validate_context(
            &self.policy,
            &statement.evidence,
            expected,
            now,
            Some(statement.outcome),
        )?;
        let mut input = self.public_input(&statement.evidence);
        input["circuit"] = serde_json::json!("outcome");
        input["input"]["outcome"] = serde_json::json!(statement.outcome.code());
        input["input"]["receipt_digest"] = serde_json::json!(statement.receipt_digest);
        self.verifier.verify_detailed(&input, proof)?;
        Ok(VerifiedWaveOutcome {
            context: expected.clone(),
            outcome: statement.outcome,
            receipt_digest: statement.receipt_digest,
        })
    }
    fn public_input(&self, statement: &WaveStatement) -> serde_json::Value {
        let p = &self.policy.extension;
        let c = &statement.context;
        serde_json::json!({"circuit":"wave","input":{
            "extension":{"revision":p.revision,"quorum":p.public_record_quorum,"change_cost":p.change_token_cost,"delay":p.deposit_delay_seconds,"batch":p.minimum_deposit_batch},
            "issuer_key":self.policy.certificate_key,"scope":self.policy.proof_scope.circuit_digest,
            "community":c.community,"owner":c.owner,"peer":c.peer,"role":c.role,"nonce":c.nonce,"group":c.group,"contact_policy":c.contact_policy,
            "history":c.history,"challenge":c.challenge,"opened_at":c.opened_at,"expires_at":c.expires_at,"owner_authority":c.owner_authority,"peer_authority":c.peer_authority,
            "state_policy":statement.state_policy,"version":statement.version,"state":statement.state,"accepted_at":statement.accepted_at,"binding":statement.binding,
        }})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (WavePolicy, WaveStatement) {
        let policy = WavePolicy {
            community: [1; 32],
            extension: ExtensionPolicy {
                revision: 1,
                public_record_quorum: 2,
                change_token_cost: 1,
                deposit_delay_seconds: 10,
                minimum_deposit_batch: 2,
            },
            proof_scope: ProofScope {
                circuit_digest: [2; 32],
                verifying_key_digest: [3; 32],
            },
            certificate_key: vec![4; 64],
            manifest_sha256: [17; 32],
            state_policy: [5; 32],
            valid_from: 1,
            valid_until: 200,
        };
        let statement = WaveStatement {
            context: WaveContext {
                community: [1; 32],
                owner: [6; 32],
                peer: [7; 32],
                role: 0,
                nonce: [8; 32],
                group: [9; 32],
                contact_policy: [10; 32],
                history: [11; 32],
                challenge: [12; 32],
                opened_at: 20,
                expires_at: 100,
                owner_authority: [13; 32],
                peer_authority: [14; 32],
            },
            state_policy: [5; 32],
            version: 2,
            state: [15; 32],
            accepted_at: 21,
            binding: [16; 32],
        };
        (policy, statement)
    }
    #[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
    #[test]
    fn detailed_refusal_preserves_original_context_checks_and_error_mapping() {
        use czkp::process::{ProcessVerificationFailure, ProcessVerifier, ProcessVerifierConfig};
        let (policy, statement) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let verifier = WaveVerifier {
            observed_at: 20,
            authority_until: 150,
            verifier: ProcessVerifier::new(ProcessVerifierConfig {
                // There is no accepting stub: a context that reaches the real
                // process boundary must fail to start this absent executable.
                node: dir.path().join("absent-node"),
                script: dir.path().join("worker.mjs"),
                artifact_config: dir.path().join("config.json"),
                scope: policy.proof_scope.clone(),
                timeout: std::time::Duration::from_secs(1),
                maximum_parallel: 1,
                max_proof_bytes: 100,
                node_heap_megabytes: 64,
            })
            .unwrap(),
            policy,
        };
        let mut wrong_context = statement.context.clone();
        wrong_context.challenge[0] ^= 1;
        for (expected, now, failure) in [
            (
                &statement.context,
                19,
                WaveVerificationFailure::Context(Error::ClockRollback),
            ),
            (
                &statement.context,
                150,
                WaveVerificationFailure::Context(Error::Expired),
            ),
            (
                &wrong_context,
                22,
                WaveVerificationFailure::Context(Error::PolicyMismatch),
            ),
            (
                &statement.context,
                22,
                WaveVerificationFailure::Process(ProcessVerificationFailure::Spawn),
            ),
        ] {
            assert_eq!(
                verifier
                    .verify_detailed(&statement, &[1], expected, now)
                    .err(),
                Some(failure.clone())
            );
            assert_eq!(
                verifier.verify(&statement, &[1], expected, now).err(),
                Some(failure.error())
            );
        }
        let outcome = WaveOutcomeStatement {
            evidence: statement,
            outcome: WaveOutcome::Answer,
            receipt_digest: [23; 32],
        };
        for (expected_outcome, digest, now, failure) in [
            (
                WaveOutcome::Answer,
                [23; 32],
                19,
                WaveVerificationFailure::Context(Error::ClockRollback),
            ),
            (
                WaveOutcome::Answer,
                [23; 32],
                150,
                WaveVerificationFailure::Context(Error::Expired),
            ),
            (
                WaveOutcome::Close,
                [23; 32],
                22,
                WaveVerificationFailure::Context(Error::PolicyMismatch),
            ),
            (
                WaveOutcome::Answer,
                [24; 32],
                22,
                WaveVerificationFailure::Context(Error::PolicyMismatch),
            ),
            (
                WaveOutcome::Answer,
                [23; 32],
                22,
                WaveVerificationFailure::Process(ProcessVerificationFailure::Spawn),
            ),
        ] {
            assert_eq!(
                verifier
                    .verify_outcome_detailed(
                        &outcome,
                        &[1],
                        &outcome.evidence.context,
                        expected_outcome,
                        &digest,
                        now,
                    )
                    .err(),
                Some(failure.clone())
            );
            assert_eq!(
                verifier
                    .verify_outcome(
                        &outcome,
                        &[1],
                        &outcome.evidence.context,
                        expected_outcome,
                        &digest,
                        now,
                    )
                    .err(),
                Some(failure.error())
            );
        }
    }
    // Shape/time checks are not evidence: only the real verifier can construct a
    // VerifiedWaveReservation. Real proof success and tampering run in cblc CI.
    #[test]
    fn refuse_untrusted_context_before_proof_work() {
        let (policy, statement) = fixture();
        assert_eq!(policy.validate(), Ok(()));
        assert_eq!(
            validate_context(&policy, &statement, &statement.context, 22, None),
            Ok(())
        );
        for field in 0..23 {
            let mut bad = statement.clone();
            let mut expected = statement.context.clone();
            let mut now = 22;
            match field {
                0 => expected.group[0] ^= 1,
                1 => bad.context.community[0] ^= 1,
                2 => bad.state_policy[0] ^= 1,
                3 => bad.context.peer = bad.context.owner,
                4 => bad.context.role = 2,
                5 => bad.context.nonce = [0; 32],
                6 => bad.context.challenge = [0; 32],
                7 => bad.context.opened_at = 0,
                8 => bad.context.expires_at = bad.context.opened_at,
                9 => bad.version = 0,
                10 => bad.version = czkp::MAX_INTEGER + 1,
                11 => now = 0,
                12 => now = policy.valid_until,
                13 => now = 19,
                14 => now = 100,
                15 => bad.context.expires_at = policy.valid_until,
                16 => bad.accepted_at = 19,
                17 => bad.accepted_at = 23,
                18 => bad.context.owner_authority = [0; 32],
                19 => bad.context.peer_authority = [255; 32],
                20 => bad.state = [0; 32],
                21 => bad.binding = [255; 32],
                _ => bad.context.owner_authority = [255; 32],
            }
            if field != 0 {
                expected = bad.context.clone();
            }
            assert!(
                validate_context(&policy, &bad, &expected, now, None).is_err(),
                "field {field}"
            );
        }
        for field in 0..7 {
            let mut bad = policy.clone();
            match field {
                0 => bad.certificate_key.pop().map(|_| ()).unwrap(),
                1 => bad.proof_scope.circuit_digest = [0; 32],
                2 => bad.proof_scope.verifying_key_digest = [0; 32],
                3 => bad.valid_from = 0,
                4 => bad.valid_from = bad.valid_until,
                5 => bad.valid_until = czkp::MAX_INTEGER + 1,
                _ => bad.extension.revision = 0,
            }
            assert!(bad.validate().is_err());
        }
        for field in 0..8 {
            let mut bad = policy.extension.clone();
            match field {
                0 => bad.revision = 0,
                1 => bad.revision = czkp::MAX_INTEGER + 1,
                2 => bad.public_record_quorum = 0,
                3 => bad.change_token_cost = 0,
                4 => bad.deposit_delay_seconds = 0,
                5 => bad.deposit_delay_seconds = czkp::MAX_INTEGER + 1,
                6 => bad.minimum_deposit_batch = 1,
                _ => bad.minimum_deposit_batch = 65,
            }
            assert_eq!(bad.validate(), Err(Error::InvalidInput));
        }
    }
}
