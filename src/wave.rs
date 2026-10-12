//! Peer release evidence for the actual extension account relation. With the
//! `native-verifier` feature the counterpart check runs the wave and outcome
//! relations through the bounded native worker (`cvfy`).
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
    /// Digest of the rulebook-signed standing policy.
    pub standing_policy_digest: [u8; 32],
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
            || self.standing_policy_digest == [0; 32]
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
        || statement.certificate.len() != 64
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

/// Public field elements, as in the Noir public ABI: every byte is one field.
pub type PublicField = [u8; 32];
fn scalar(value: u64) -> PublicField {
    let mut field = [0; 32];
    field[24..].copy_from_slice(&value.to_be_bytes());
    field
}
fn push_bytes(fields: &mut Vec<PublicField>, value: &[u8]) {
    fields.extend(value.iter().map(|byte| scalar(u64::from(*byte))));
}

/// One proof check of the counterpart relations over the ordered public
/// fields. The host supplies the backend (native worker or browser prover
/// library) built from authenticated artifacts; every context, policy, lease
/// and issuer-certificate check stays in [`WaveVerifier`], never in a backend.
pub trait ProofCheck {
    /// `Ok` only for a valid proof of exactly these public fields.
    fn check(
        &self,
        fields: &[PublicField],
        proof: &[u8],
    ) -> impl std::future::Future<Output = Result<(), Error>>;
}

#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl ProofCheck for cvfy::NativeVerifier {
    async fn check(&self, fields: &[PublicField], proof: &[u8]) -> Result<(), Error> {
        self.verify(fields, proof)
    }
}

/// Browser backend: one asynchronous JavaScript function
/// `(fields: Uint8Array, proof: Uint8Array) => Promise<boolean>` that runs the
/// pinned prover library's verifier (bb.js, `@corbet-labs/czkp/verify`
/// primitives) under the authenticated key. `fields` is the concatenation of
/// the 32-byte big-endian public fields. Anything but a resolved `true` is a
/// refusal.
#[cfg(target_arch = "wasm32")]
pub struct BrowserCheck(js_sys::Function);

#[cfg(target_arch = "wasm32")]
impl BrowserCheck {
    /// Wrap the host's verifier function.
    pub fn new(verify: js_sys::Function) -> Self {
        Self(verify)
    }
}

#[cfg(target_arch = "wasm32")]
impl ProofCheck for BrowserCheck {
    async fn check(&self, fields: &[PublicField], proof: &[u8]) -> Result<(), Error> {
        use wasm_bindgen::JsCast;
        let flat: Vec<u8> = fields.iter().flatten().copied().collect();
        let promise = self
            .0
            .call2(
                &wasm_bindgen::JsValue::NULL,
                &js_sys::Uint8Array::from(flat.as_slice()),
                &js_sys::Uint8Array::from(proof),
            )
            .map_err(|_| Error::CryptoProvider)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| Error::CryptoProvider)?;
        match wasm_bindgen_futures::JsFuture::from(promise).await {
            Ok(verdict) if verdict.as_bool() == Some(true) => Ok(()),
            _ => Err(Error::CryptoProvider),
        }
    }
}

/// JavaScript face of the browser verifier (a local safety check; the server's
/// `cvfy` verification is authoritative): the same [`WaveVerifier`], with the
/// host's bb.js functions as the two proof checks. JSON in, JSON out; a refusal
/// rejects the promise with the Rust error name.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub struct BrowserWaveVerifier(WaveVerifier<BrowserCheck>);

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl BrowserWaveVerifier {
    /// `policy` is the authenticated [`WavePolicy`] as JSON.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        policy: &str,
        now: u64,
        authority_until: u64,
        wave: js_sys::Function,
        outcome: js_sys::Function,
    ) -> Result<BrowserWaveVerifier, String> {
        let policy: WavePolicy = serde_json::from_str(policy).map_err(|_| "InvalidInput")?;
        WaveVerifier::new(
            policy,
            now,
            authority_until,
            BrowserCheck::new(wave),
            BrowserCheck::new(outcome),
        )
        .map(Self)
        .map_err(|error| error.to_string())
    }

    /// Verify a reservation; resolves to the verified context as JSON.
    pub async fn verify(
        &self,
        statement: &str,
        proof: &[u8],
        expected: &str,
        now: u64,
    ) -> Result<String, String> {
        let statement: WaveStatement =
            serde_json::from_str(statement).map_err(|_| "InvalidInput")?;
        let expected: WaveContext = serde_json::from_str(expected).map_err(|_| "InvalidInput")?;
        let verified = self
            .0
            .verify(&statement, proof, &expected, now)
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_string(verified.context()).map_err(|_| "InvalidInput".into())
    }

    /// Verify an outcome (`answer`, `close` or `silence`); resolves to the
    /// verified context as JSON.
    pub async fn verify_outcome(
        &self,
        statement: &str,
        proof: &[u8],
        expected: &str,
        expected_outcome: &str,
        expected_receipt_digest: &[u8],
        now: u64,
    ) -> Result<String, String> {
        let statement: WaveOutcomeStatement =
            serde_json::from_str(statement).map_err(|_| "InvalidInput")?;
        let expected: WaveContext = serde_json::from_str(expected).map_err(|_| "InvalidInput")?;
        let outcome: WaveOutcome =
            serde_json::from_value(expected_outcome.into()).map_err(|_| "InvalidInput")?;
        let digest: [u8; 32] = expected_receipt_digest
            .try_into()
            .map_err(|_| "InvalidInput")?;
        let verified = self
            .0
            .verify_outcome(&statement, proof, &expected, outcome, &digest, now)
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_string(verified.context()).map_err(|_| "InvalidInput".into())
    }
}

/// The device-side check is a local safety check; the server's `cvfy`
/// verification is the authoritative one.
/// Counterpart verifier. The host builds both checks from authenticated
/// artifacts; nothing here reads a file, trusts a proof-supplied key or caches
/// a verdict. Native and browser share this one implementation.
pub struct WaveVerifier<C: ProofCheck> {
    policy: WavePolicy,
    observed_at: u64,
    authority_until: u64,
    wave: C,
    outcome: C,
}

#[cfg(all(feature = "native-verifier", not(target_arch = "wasm32")))]
impl WaveVerifier<cvfy::NativeVerifier> {
    /// Native worker backend from authenticated configurations.
    pub fn native(
        policy: WavePolicy,
        now: u64,
        authority_until: u64,
        wave: cvfy::NativeVerifierConfig,
        outcome: cvfy::NativeVerifierConfig,
    ) -> Result<Self, Error> {
        Self::new(
            policy,
            now,
            authority_until,
            cvfy::NativeVerifier::new(wave)?,
            cvfy::NativeVerifier::new(outcome)?,
        )
    }
}

impl<C: ProofCheck> WaveVerifier<C> {
    /// `authority_until` is the exclusive end of the authenticated policy lease.
    pub fn new(
        policy: WavePolicy,
        now: u64,
        authority_until: u64,
        wave: C,
        outcome: C,
    ) -> Result<Self, Error> {
        policy.validate()?;
        if now < policy.valid_from || now >= policy.valid_until || now >= authority_until {
            return Err(Error::Expired);
        }
        Ok(Self {
            policy,
            observed_at: now,
            authority_until,
            wave,
            outcome,
        })
    }

    /// Verify the counterpart's reservation proof for the independently expected context.
    pub async fn verify(
        &self,
        statement: &WaveStatement,
        proof: &[u8],
        expected: &WaveContext,
        now: u64,
    ) -> Result<VerifiedWaveReservation, Error> {
        self.check_time(now)?;
        validate_context(&self.policy, statement, expected, now, None)?;
        check_certificate(&self.policy, statement)?;
        self.wave
            .check(&public_fields(&self.policy, statement, None)?, proof)
            .await?;
        Ok(VerifiedWaveReservation {
            context: expected.clone(),
        })
    }

    /// Verify a settled outcome and its independently expected original receipt.
    /// Answer proves the recipient signature and sender acknowledgment; Close the
    /// recipient signature; Silence only the sender's refund after the fixed lease.
    pub async fn verify_outcome(
        &self,
        statement: &WaveOutcomeStatement,
        proof: &[u8],
        expected: &WaveContext,
        expected_outcome: WaveOutcome,
        expected_receipt_digest: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedWaveOutcome, Error> {
        self.check_time(now)?;
        if statement.outcome != expected_outcome
            || &statement.receipt_digest != expected_receipt_digest
            || (statement.outcome == WaveOutcome::Silence && statement.receipt_digest != [0; 32])
        {
            return Err(Error::PolicyMismatch);
        }
        validate_context(
            &self.policy,
            &statement.evidence,
            expected,
            now,
            Some(statement.outcome),
        )?;
        check_certificate(&self.policy, &statement.evidence)?;
        let fields = public_fields(&self.policy, &statement.evidence, Some(statement))?;
        self.outcome.check(&fields, proof).await?;
        Ok(VerifiedWaveOutcome {
            context: expected.clone(),
            outcome: statement.outcome,
            receipt_digest: statement.receipt_digest,
        })
    }

    fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.observed_at {
            return Err(Error::ClockRollback);
        }
        if now >= self.authority_until {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// The issuer's accepted-state certificate is checked explicitly: the circuit
/// only requires the bytes to be non-zero.
fn check_certificate(policy: &WavePolicy, statement: &WaveStatement) -> Result<(), Error> {
    let key: [u8; 64] = policy
        .certificate_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidInput)?;
    let signature: [u8; 64] = statement
        .certificate
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidInput)?;
    czkp::certificate::AcceptedState {
        community: statement.context.community,
        owner: statement.context.owner,
        state: statement.state,
        scope: policy.proof_scope.circuit_digest,
        version: statement.version,
        accepted_at: statement.accepted_at,
    }
    .verify(&key, &signature)
}

/// Ordered exactly as the public parameters of the Noir `wave` and `outcome`
/// relations; `outcome` adds the outcome code and receipt digest before the
/// certificate.
fn public_fields(
    policy: &WavePolicy,
    statement: &WaveStatement,
    outcome: Option<&WaveOutcomeStatement>,
) -> Result<Vec<PublicField>, Error> {
    let p = &policy.extension;
    let c = &statement.context;
    let mut fields: Vec<PublicField> = [
        p.revision,
        u64::from(p.public_record_quorum),
        u64::from(p.change_token_cost),
        p.deposit_delay_seconds,
        u64::from(p.minimum_deposit_batch),
    ]
    .map(scalar)
    .to_vec();
    push_bytes(&mut fields, &p.standing_policy_digest);
    push_bytes(&mut fields, &policy.certificate_key);
    push_bytes(&mut fields, &policy.proof_scope.circuit_digest);
    for value in [&c.community, &c.owner, &c.peer] {
        push_bytes(&mut fields, value);
    }
    fields.push(scalar(u64::from(c.role)));
    for value in [
        &c.nonce,
        &c.group,
        &c.contact_policy,
        &c.history,
        &c.challenge,
    ] {
        push_bytes(&mut fields, value);
    }
    fields.push(scalar(c.opened_at));
    fields.push(scalar(c.expires_at));
    for value in [
        &c.owner_authority,
        &c.peer_authority,
        &statement.state_policy,
    ] {
        push_bytes(&mut fields, value);
    }
    fields.push(scalar(statement.version));
    push_bytes(&mut fields, &statement.state);
    fields.push(scalar(statement.accepted_at));
    push_bytes(&mut fields, &statement.binding);
    if let Some(outcome) = outcome {
        fields.push(scalar(match outcome.outcome {
            WaveOutcome::Answer => 1,
            WaveOutcome::Close => 2,
            WaveOutcome::Silence => 3,
        }));
        push_bytes(&mut fields, &outcome.receipt_digest);
    }
    push_bytes(&mut fields, &statement.certificate);
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use czkp::ProofScope;

    fn policy() -> WavePolicy {
        WavePolicy {
            community: [1; 32],
            extension: ExtensionPolicy {
                revision: 1,
                public_record_quorum: 5,
                change_token_cost: 1,
                deposit_delay_seconds: 60,
                minimum_deposit_batch: 2,
                standing_policy_digest: [7; 32],
            },
            proof_scope: ProofScope {
                circuit_digest: [2; 32],
                verifying_key_digest: [3; 32],
            },
            certificate_key: vec![4; 64],
            manifest_sha256: [5; 32],
            state_policy: [6; 32],
            valid_from: 1,
            valid_until: 10_000,
        }
    }
    fn statement() -> WaveStatement {
        WaveStatement {
            context: WaveContext {
                community: [1; 32],
                owner: [7; 32],
                peer: [8; 32],
                role: 0,
                nonce: [9; 32],
                group: [10; 32],
                contact_policy: [11; 32],
                history: [12; 32],
                challenge: [13; 32],
                opened_at: 100,
                expires_at: 500,
                owner_authority: [14; 32],
                peer_authority: [15; 32],
            },
            state_policy: [6; 32],
            version: 3,
            state: [16; 32],
            accepted_at: 120,
            binding: [17; 32],
            certificate: vec![18; 64],
        }
    }

    #[test]
    fn public_fields_follow_the_noir_abi_widths() {
        let s = statement();
        let wave = public_fields(&policy(), &s, None).unwrap();
        assert_eq!(wave.len(), 618);
        let outcome = WaveOutcomeStatement {
            evidence: s.clone(),
            outcome: WaveOutcome::Close,
            receipt_digest: [19; 32],
        };
        let fields = public_fields(&policy(), &s, Some(&outcome)).unwrap();
        assert_eq!(fields.len(), 651);
        // Outcome code and receipt precede the trailing 64 certificate fields.
        assert_eq!(fields[554], scalar(2));
        assert_eq!(fields[555], scalar(19));
        assert_eq!(&fields[..554], &wave[..554]);
        assert_eq!(fields[650], scalar(18));
    }

    #[test]
    fn an_unsigned_certificate_is_refused_before_any_proof_is_trusted() {
        assert_eq!(
            check_certificate(&policy(), &statement()),
            Err(Error::Signature)
        );
        let mut short = statement();
        short.certificate = vec![1; 63];
        assert_eq!(
            check_certificate(&policy(), &short),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn context_must_match_the_independent_expectation_and_the_lease() {
        let s = statement();
        let expected = s.context.clone();
        assert_eq!(
            validate_context(&policy(), &s, &expected, 130, None),
            Ok(())
        );
        let mut other = expected.clone();
        other.nonce = [99; 32];
        assert_eq!(
            validate_context(&policy(), &s, &other, 130, None),
            Err(Error::PolicyMismatch)
        );
        // A reservation after its deadline is expired; an outcome may arrive later.
        assert_eq!(
            validate_context(&policy(), &s, &expected, 500, None),
            Err(Error::Expired)
        );
        let mut late = s.clone();
        late.accepted_at = 120;
        assert_eq!(
            validate_context(&policy(), &late, &expected, 500, Some(WaveOutcome::Close)),
            Err(Error::InvalidInput)
        );
    }

    use std::cell::Cell;

    /// Counts calls; never a substitute for proof soundness, which the retained
    /// real-proof round trips establish.
    struct Backend {
        calls: Cell<usize>,
        verdict: Result<(), Error>,
    }
    impl ProofCheck for Backend {
        async fn check(&self, fields: &[PublicField], _proof: &[u8]) -> Result<(), Error> {
            self.calls.set(self.calls.get() + 1);
            assert!(!fields.is_empty());
            self.verdict.clone()
        }
    }
    fn backend(verdict: Result<(), Error>) -> Backend {
        Backend {
            calls: Cell::new(0),
            verdict,
        }
    }
    fn signed() -> (WavePolicy, WaveStatement) {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        let key = SigningKey::from_bytes(&[7; 32].into()).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let mut policy = policy();
        policy.certificate_key = point.as_bytes()[1..].to_vec();
        let mut statement = statement();
        let signature: Signature = key.sign(
            &czkp::certificate::AcceptedState {
                community: statement.context.community,
                owner: statement.context.owner,
                state: statement.state,
                scope: policy.proof_scope.circuit_digest,
                version: statement.version,
                accepted_at: statement.accepted_at,
            }
            .bytes(),
        );
        statement.certificate = signature.to_bytes().to_vec();
        (policy, statement)
    }

    #[test]
    fn the_shared_verifier_asks_the_backend_only_after_every_rust_check() {
        use futures::executor::block_on;
        let (policy, s) = signed();
        let expected = s.context.clone();
        let verifier = |verdict: Result<(), Error>| {
            WaveVerifier::new(
                policy.clone(),
                100,
                1_000,
                backend(verdict.clone()),
                backend(verdict),
            )
            .unwrap()
        };
        let ok = verifier(Ok(()));
        let verified = block_on(ok.verify(&s, b"proof", &expected, 130)).unwrap();
        assert_eq!(verified.context(), &expected);
        assert_eq!((ok.wave.calls.get(), ok.outcome.calls.get()), (1, 0));
        // A backend refusal is the verdict.
        let bad = verifier(Err(Error::CryptoProvider));
        assert!(matches!(
            block_on(bad.verify(&s, b"proof", &expected, 130)),
            Err(Error::CryptoProvider)
        ));
        // Context, lease, clock and certificate failures never reach the backend.
        let mut other = expected.clone();
        other.nonce = [99; 32];
        assert!(block_on(ok.verify(&s, b"proof", &other, 130)).is_err());
        assert!(block_on(ok.verify(&s, b"proof", &expected, 1_000)).is_err());
        assert!(block_on(ok.verify(&s, b"proof", &expected, 99)).is_err());
        let mut forged = s.clone();
        forged.certificate[0] ^= 1;
        assert!(block_on(ok.verify(&forged, b"proof", &expected, 130)).is_err());
        assert_eq!(ok.wave.calls.get(), 1);
        // Outcome: the expected outcome and receipt are checked before the backend.
        let outcome = WaveOutcomeStatement {
            evidence: s.clone(),
            outcome: WaveOutcome::Answer,
            receipt_digest: [21; 32],
        };
        assert!(
            block_on(ok.verify_outcome(
                &outcome,
                b"p",
                &expected,
                WaveOutcome::Close,
                &[21; 32],
                130
            ))
            .is_err()
        );
        assert!(
            block_on(ok.verify_outcome(
                &outcome,
                b"p",
                &expected,
                WaveOutcome::Answer,
                &[22; 32],
                130
            ))
            .is_err()
        );
        assert_eq!(ok.outcome.calls.get(), 0);
        let done = block_on(ok.verify_outcome(
            &outcome,
            b"p",
            &expected,
            WaveOutcome::Answer,
            &[21; 32],
            130,
        ))
        .unwrap();
        assert_eq!(done.outcome(), WaveOutcome::Answer);
        assert_eq!(ok.outcome.calls.get(), 1);
    }
}
