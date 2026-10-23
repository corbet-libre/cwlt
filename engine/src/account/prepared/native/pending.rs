//! Durable pending companion of one proven genesis candidate, in two states.
//!
//! State A ("sent") is written before the signed request leaves the device and
//! carries the exact outbox and request digest only. State B additionally binds
//! the DISTINCT extended acceptance digest and is written only after the actual
//! response was verified. The state tag is part of the AAD, so a state-A
//! ciphertext can never authenticate as state B or the reverse. A advances to B
//! only through `advance_pending`; there is no downgrade and no skip.
//!
//! This reuses the engine's existing XChaCha20-Poly1305 sealing key and context
//! binding with its own purpose-separated magic and AAD, so it can never be
//! confused with the key capsule or other sealed records. Reopening restores the
//! exact stored blind, proof, scope and public context: nothing is reproved,
//! reblinded, rerooted or given a later expiry. It is not an accepted account.
use super::*;
use crate::account::{Field, policy::AccountPolicy, policy::ExtensionPolicy};
use chacha20poly1305::{
    XNonce,
    aead::{Aead, Payload},
};
use czkp::ProofScope;

const MAGIC: &[u8] = b"cwlt.account-pending-genesis.v1\0";
const NONCE: usize = 24;
const SENT: u8 = 1;
const ACCEPTED: u8 = 2;
const VERSION: u8 = 1;
/// Original single-value Store limit; the whole sealed companion stays below it.
pub const MAX_PENDING_SEALED: usize = 1024 * 1024;
const MAX_UPPER: usize = 640 * 1024;
const MAX_INPUTS: usize = 1024;
const MAX_PROOF: usize = 256 * 1024;

/// Retained upper-owner binding sealed together with the candidate. The engine
/// treats `upper` as opaque authenticated bytes (origin, Lineage/device/credential
/// binding and the exact signed ApplyExtended outbox) and returns them unchanged;
/// the upper owner must compare them with its freshly authenticated state.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingGenesisBinding {
    /// Original request identity, signed request digest and pinned operator key.
    pub acceptance: AcceptanceBinding,
    /// DISTINCT digest of the original extended acceptance of the same request.
    /// `None` is state A (sent); `Some` is state B and is never zero or equal to
    /// the request digest.
    pub extended_acceptance_digest: Option<[u8; 32]>,
    /// The fully verified operator response, sealed in state B so activation
    /// never needs a re-send. `Some` exactly when the digest is `Some`.
    pub response: Option<AcceptedResponse>,
    /// Opaque authenticated upper binding and exact signed outbox bytes.
    pub upper: Vec<u8>,
}

/// Bounded ciphertext of one pending genesis companion.
pub struct SealedPendingGenesis(Vec<u8>);
impl SealedPendingGenesis {
    /// Check the exact envelope before authenticated restore by the same engine.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= MAGIC.len() + 1 + NONCE + 16
            || bytes.len() > MAX_PENDING_SEALED
            || !bytes.starts_with(MAGIC)
            || ![SENT, ACCEPTED].contains(&bytes[MAGIC.len()])
        {
            return Err(Error::Invalid);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Encrypted bytes safe to retain inside the original atomic Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(super) use crate::account::codec::{Reader, Writer};

pub(super) fn write_context(w: &mut Writer, c: &GenesisContext) -> Result<(), Error> {
    w.var(c.community_id.as_bytes())?;
    w.bytes(&c.owner);
    let p = &c.policy;
    for v in [
        p.initial_credit,
        p.maximum_available,
        p.outgoing_reservation,
        p.incoming_reservation,
    ] {
        w.u32(v);
    }
    for v in [
        p.policy_revision,
        p.policy_valid_from,
        p.policy_valid_until,
        p.newcomer_period,
        p.rate_window,
    ] {
        w.u64(v);
    }
    w.u32(p.newcomer_admissions);
    w.u32(p.maximum_admissions);
    w.u64(p.refill_period);
    w.u32(p.refill_units);
    w.u64(p.abandon_after);
    let e = &c.extension;
    w.u64(e.revision);
    w.u32(e.quorum);
    w.u32(e.change_cost);
    w.u64(e.delay);
    w.bytes(&[e.batch]);
    w.bytes(&e.standing);
    let sp = &c.standing;
    for v in [
        sp.c0,
        sp.h_a,
        sp.h_g,
        sp.n_half,
        sp.n_c,
        sp.e_q,
        sp.r_max,
        sp.r_age,
        sp.c_max_q,
        sp.c_vet,
        sp.age_vet,
        sp.boost_q,
        sp.boost_days,
        sp.slope_q,
        sp.mid_q,
        sp.kappa_q,
        sp.loan_use_q,
    ] {
        w.u64(v);
    }
    let vp = &sp.voucher;
    for v in vp.slope_q.iter().chain(&vp.min).chain(&vp.max).chain(&[
        vp.days,
        vp.k,
        vp.max_punished,
        vp.brake_cap,
        vp.reward_cap,
    ]) {
        w.u64(*v);
    }
    let r = &c.enrollment;
    w.bytes(&r.member);
    w.bytes(&r.key);
    w.bytes(&r.secret_hash);
    w.u64(r.starts_at);
    w.u64(r.expires_at);
    w.bytes(&r.delegation_digest);
    w.bytes(&r.leaf);
    w.u32(r.index);
    for sibling in &r.path {
        w.bytes(sibling);
    }
    w.bytes(&c.enrollment_root);
    w.u64(c.checked_at);
    match &c.bond {
        Some(b) => {
            w.bytes(&[1]);
            w.bytes(&b.sponsor);
            w.bytes(&b.secret);
        }
        None => w.bytes(&[0]),
    }
    Ok(())
}

pub(super) fn read_context(r: &mut Reader<'_>) -> Result<GenesisContext, Error> {
    let community_id = String::from_utf8(r.var(256)?.to_vec()).map_err(|_| Error::Crypto)?;
    let owner = r.array()?;
    let policy = AccountPolicy {
        initial_credit: r.u32()?,
        maximum_available: r.u32()?,
        outgoing_reservation: r.u32()?,
        incoming_reservation: r.u32()?,
        policy_revision: r.u64()?,
        policy_valid_from: r.u64()?,
        policy_valid_until: r.u64()?,
        newcomer_period: r.u64()?,
        rate_window: r.u64()?,
        newcomer_admissions: r.u32()?,
        maximum_admissions: r.u32()?,
        refill_period: r.u64()?,
        refill_units: r.u32()?,
        abandon_after: r.u64()?,
    };
    let extension = ExtensionPolicy {
        revision: r.u64()?,
        quorum: r.u32()?,
        change_cost: r.u32()?,
        delay: r.u64()?,
        batch: r.array::<1>()?[0],
        standing: r.array()?,
    };
    let standing = czkp::standing::Params {
        c0: r.u64()?,
        h_a: r.u64()?,
        h_g: r.u64()?,
        n_half: r.u64()?,
        n_c: r.u64()?,
        e_q: r.u64()?,
        r_max: r.u64()?,
        r_age: r.u64()?,
        c_max_q: r.u64()?,
        c_vet: r.u64()?,
        age_vet: r.u64()?,
        boost_q: r.u64()?,
        boost_days: r.u64()?,
        slope_q: r.u64()?,
        mid_q: r.u64()?,
        kappa_q: r.u64()?,
        loan_use_q: r.u64()?,
        voucher: {
            let mut take3 = || -> Result<[u64; 3], Error> { Ok([r.u64()?, r.u64()?, r.u64()?]) };
            let (slope_q, min, max) = (take3()?, take3()?, take3()?);
            czkp::standing::VoucherParams {
                slope_q,
                min,
                max,
                days: r.u64()?,
                k: r.u64()?,
                max_punished: r.u64()?,
                brake_cap: r.u64()?,
                reward_cap: r.u64()?,
            }
        },
    };
    let mut enrollment = Enrollment {
        member: r.array()?,
        key: r.array()?,
        secret_hash: r.array()?,
        starts_at: r.u64()?,
        expires_at: r.u64()?,
        delegation_digest: r.array()?,
        leaf: r.array()?,
        index: r.u32()?,
        path: [[0; 32]; 32],
    };
    for sibling in &mut enrollment.path {
        *sibling = r.array()?;
    }
    let enrollment_root = r.array()?;
    let checked_at = r.u64()?;
    let bond = match r.array::<1>()?[0] {
        0 => None,
        1 => Some(crate::account::VoucherBond {
            sponsor: r.array()?,
            secret: r.array()?,
        }),
        _ => return Err(Error::Crypto),
    };
    Ok(GenesisContext {
        community_id,
        owner,
        policy,
        extension,
        standing,
        bond,
        enrollment,
        enrollment_root,
        checked_at,
    })
}

fn check_binding(binding: &PendingGenesisBinding) -> Result<(), Error> {
    let a = &binding.acceptance;
    if a.request_id == [0; 32]
        || a.request_digest == [0; 32]
        || a.operator_key == [0; 32]
        || binding
            .extended_acceptance_digest
            .is_some_and(|digest| digest == [0; 32] || digest == a.request_digest)
        || binding.extended_acceptance_digest.is_some() != binding.response.is_some()
        || binding.upper.is_empty()
        || binding.upper.len() > MAX_UPPER
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

impl PreparedGenesisProof {
    /// Seal this exact proven candidate as state A (sent) with the upper binding
    /// for durable reopen. The binding must carry no acceptance digest: state B
    /// exists only through `Engine::advance_pending`. Only the same engine that
    /// produced the candidate can seal it. The result is a pending companion,
    /// never an accepted account or a custody release.
    pub fn seal_pending(
        &self,
        engine: &Engine,
        binding: &PendingGenesisBinding,
    ) -> Result<SealedPendingGenesis, Error> {
        if binding.extended_acceptance_digest.is_some() {
            return Err(Error::Invalid);
        }
        self.seal_state(engine, binding)
    }

    fn seal_state(
        &self,
        engine: &Engine,
        binding: &PendingGenesisBinding,
    ) -> Result<SealedPendingGenesis, Error> {
        check_binding(binding)?;
        let state = if binding.extended_acceptance_digest.is_some() {
            ACCEPTED
        } else {
            SENT
        };
        let candidate = &self.candidate;
        if !Arc::ptr_eq(&candidate.binding, &engine.sealing)
            || candidate.secret.as_ref() != engine.seed.as_ref()
        {
            return Err(Error::Invalid);
        }
        let public = candidate.genesis_public();
        if self.proof.public_inputs.len() > MAX_INPUTS || self.proof.proof.len() > MAX_PROOF {
            return Err(Error::Invalid);
        }
        // One allocation, so no reallocated copy of the private blind is left behind.
        let mut w = Writer(Zeroizing::new(Vec::with_capacity(MAX_PENDING_SEALED)));
        w.bytes(&[VERSION]);
        w.bytes(engine.seed.as_ref());
        w.bytes(&candidate.opening.blind);
        w.bytes(&public.next_state);
        write_context(&mut w, &candidate.context)?;
        w.bytes(&self.proof.scope.circuit_digest);
        w.bytes(&self.proof.scope.verifying_key_digest);
        w.u32(u32::try_from(self.proof.public_inputs.len()).map_err(|_| Error::Invalid)?);
        for input in &self.proof.public_inputs {
            w.bytes(input);
        }
        w.var(&self.proof.proof)?;
        w.bytes(&binding.acceptance.request_id);
        w.bytes(&binding.acceptance.request_digest);
        w.bytes(&binding.acceptance.operator_key);
        w.bytes(&binding.extended_acceptance_digest.unwrap_or_default());
        if let Some(response) = &binding.response {
            response.write(&mut w)?;
        }
        w.var(&binding.upper)?;
        if w.0.len() + MAGIC.len() + 1 + NONCE + 16 > MAX_PENDING_SEALED {
            return Err(Error::Invalid);
        }
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, &[state], engine.sealing.context.as_slice()].concat();
        let encrypted = engine
            .sealing
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: w.0.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(SealedPendingGenesis(
            [MAGIC, &[state], &nonce, &encrypted].concat(),
        ))
    }
}

impl Engine {
    /// Reopen one pending companion for this engine at the trusted local `now`.
    /// The exact stored blind, proof and public context are restored; a changed
    /// commitment, root, scope or an expired horizon refuses. Nothing is reproved.
    pub fn restore_pending_genesis(
        &self,
        sealed: &SealedPendingGenesis,
        now: u64,
    ) -> Result<(PreparedGenesisProof, PendingGenesisBinding), Error> {
        let (proof, binding) = self.open_pending(sealed)?;
        proof
            .candidate
            .check_context(self, &proof.candidate.context, now)?;
        Ok((proof, binding))
    }

    /// Authenticate and decode one pending companion of this engine without any
    /// time check: the exact stored blind must reproduce the proven commitment.
    fn open_pending(
        &self,
        sealed: &SealedPendingGenesis,
    ) -> Result<(PreparedGenesisProof, PendingGenesisBinding), Error> {
        let state = sealed.0[MAGIC.len()];
        let offset = MAGIC.len() + 1;
        let nonce: [u8; NONCE] = sealed.0[offset..offset + NONCE]
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let aad = [MAGIC, &[state], self.sealing.context.as_slice()].concat();
        let plaintext = Zeroizing::new(
            self.sealing
                .cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &sealed.0[offset + NONCE..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        let mut r = Reader(&plaintext);
        let version = r.array::<1>()?[0];
        let seed: Field = r.array()?;
        let mut blind: Field = r.array()?;
        let next_state: Field = r.array()?;
        if version != VERSION || seed != *self.seed {
            return Err(Error::Crypto);
        }
        let context = read_context(&mut r)?;
        let scope = ProofScope {
            circuit_digest: r.array()?,
            verifying_key_digest: r.array()?,
        };
        let count = usize::try_from(r.u32()?).map_err(|_| Error::Crypto)?;
        if count > MAX_INPUTS {
            return Err(Error::Crypto);
        }
        let mut public_inputs = Vec::with_capacity(count);
        for _ in 0..count {
            public_inputs.push(r.array()?);
        }
        let proof = r.var(MAX_PROOF)?.to_vec();
        let acceptance = AcceptanceBinding {
            request_id: r.array()?,
            request_digest: r.array()?,
            operator_key: r.array()?,
        };
        let digest: Field = r.array()?;
        let extended_acceptance_digest = match state {
            SENT if digest == [0; 32] => None,
            ACCEPTED => Some(digest),
            _ => return Err(Error::Crypto),
        };
        let response = match state {
            ACCEPTED => Some(AcceptedResponse::read(&mut r)?),
            _ => None,
        };
        let binding = PendingGenesisBinding {
            acceptance,
            extended_acceptance_digest,
            response,
            upper: r.var(MAX_UPPER)?.to_vec(),
        };
        if !r.0.is_empty() {
            return Err(Error::Crypto);
        }
        check_binding(&binding)?;
        let candidate = self.genesis_with_blind(context.clone(), blind);
        zeroize::Zeroize::zeroize(&mut blind);
        let candidate = candidate?;
        // The stored blind must reproduce the exact proven commitment.
        if candidate.genesis_public().next_state != next_state {
            return Err(Error::Crypto);
        }
        Ok((
            PreparedGenesisProof {
                candidate,
                proof: crate::native_prover::Proof {
                    scope,
                    public_inputs,
                    proof,
                },
            },
            binding,
        ))
    }
}

impl Engine {
    /// Advance state A to state B after the actual response arrived. The engine
    /// itself verifies the full response (operator acceptance, state certificate,
    /// ancestry rule) against the CURRENT trust, derives the acceptance digest, and
    /// seals the verified response in B. The candidate, outbox binding and request
    /// digest are carried over unchanged. B, or any failed check, never advances.
    pub fn advance_pending(
        &self,
        sealed: &SealedPendingGenesis,
        response: &AcceptedResponse,
        trust: &ResponseTrust,
        now: u64,
    ) -> Result<SealedPendingGenesis, Error> {
        let (proof, mut binding) = self.restore_pending_genesis(sealed, now)?;
        if binding.extended_acceptance_digest.is_some() {
            return Err(Error::Invalid);
        }
        binding.extended_acceptance_digest =
            Some(proof.verify_response(&binding.acceptance, response, trust)?);
        binding.response = Some(response.clone());
        proof.seal_state(self, &binding)
    }

    /// Reopen only a state-B companion for activation. State A (no verified
    /// response) never activates.
    pub fn restore_accepted_pending(
        &self,
        sealed: &SealedPendingGenesis,
        now: u64,
    ) -> Result<(PreparedGenesisProof, PendingGenesisBinding), Error> {
        let (proof, binding) = self.restore_pending_genesis(sealed, now)?;
        if binding.extended_acceptance_digest.is_none() {
            return Err(Error::Invalid);
        }
        Ok((proof, binding))
    }
}

impl Engine {
    /// Reopen state B before the horizon and re-verify the stored response offline
    /// under the CURRENT trust (frontier/epoch included). Success yields the opaque
    /// accepted candidate; the upper owner then rechecks admission, Keys and binding
    /// around the accepted commit. Any failure releases nothing.
    pub fn activate_pending(
        &self,
        sealed: &SealedPendingGenesis,
        trust: &ResponseTrust,
        now: u64,
    ) -> Result<AcceptedGenesisProof, Error> {
        let (proof, binding) = self.restore_accepted_pending(sealed, now)?;
        let response = binding.response.ok_or(Error::Invalid)?;
        let digest = proof.verify_response(&binding.acceptance, &response, trust)?;
        if binding.extended_acceptance_digest != Some(digest) {
            return Err(Error::Crypto);
        }
        Ok(AcceptedGenesisProof {
            accepted_at: response.issuer.accepted_at,
            candidate: proof,
            response: Some(response),
            binding: binding.acceptance,
            extended_acceptance_digest: digest,
        })
    }
}

/// Margin after a genesis request's `expires_at` before an operator status may
/// prove that the request was never accepted. The ledger takes its commit
/// decision strictly before `expires_at` (cblc `CommitDeadline`), but a decided
/// transaction becomes visible to a later status read only once it is durable:
/// the single libSQL writer persists it in milliseconds, behind a queue under
/// load within a few seconds. 15 s is several times that and costs an overrun
/// device one wait of at most 15 s before it re-prepares. Both compared times are
/// the operator's own signed times; the device clock never takes part.
pub const GENESIS_DISCARD_COMMIT_MARGIN_SECONDS: u64 = 15;

const STATUS_REQUEST: &[u8] = b"cfrm.account.status.v1\0";
const STATUS_RESPONSE: &[u8] = b"cfrm.account.status-response.v1\0";

/// One operator-signed Balance status answer to an owner lookup (no request id)
/// that reports no acceptance. The engine rebuilds both signed messages (the
/// Balance `account_status_bytes` and `account_status_response_bytes` formats)
/// from these raw values; nothing here is a caller verdict.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerAbsence {
    /// Community digest the status request named.
    pub community: [u8; 32],
    /// Account owner the status request named.
    pub owner: [u8; 32],
    /// Fresh non-zero request challenge.
    pub challenge: [u8; 32],
    /// Device key that signed the status request.
    pub chat_public_key: [u8; 32],
    /// Status request window start.
    pub issued_at: u64,
    /// Status request window end.
    pub expires_at: u64,
    /// Device signature of the status request.
    pub request_signature: [u8; 64],
    /// The operator's own signed observation time.
    pub observed_at: u64,
    /// Operator signature of the status response.
    pub signature: [u8; 64],
}

impl OwnerAbsence {
    /// Strict Ed25519 verification of the response under `operator_key`, bound to
    /// the exact request digest (SHA-256 of message then signature).
    pub fn verify(&self, operator_key: &[u8; 32]) -> Result<(), Error> {
        if self.challenge == [0; 32]
            || self.issued_at == 0
            || self.issued_at >= self.expires_at
            || self.observed_at < self.issued_at
            || self.observed_at >= self.expires_at
        {
            return Err(Error::Invalid);
        }
        let mut request = STATUS_REQUEST.to_vec();
        request.extend_from_slice(&self.community);
        request.extend_from_slice(&self.owner);
        request.push(0);
        request.extend_from_slice(&[0; 32]);
        request.extend_from_slice(&self.challenge);
        request.extend_from_slice(&self.chat_public_key);
        request.extend_from_slice(&self.issued_at.to_be_bytes());
        request.extend_from_slice(&self.expires_at.to_be_bytes());
        // The same SHA-256(message || signature) construction as an acceptance digest.
        let digest = czkp::account::acceptance_digest(&request, &self.request_signature);
        let mut response = STATUS_RESPONSE.to_vec();
        response.extend_from_slice(&digest);
        response.extend_from_slice(&self.observed_at.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&[0; 32]);
        czkp::account::verify_acceptance(&response, operator_key, &self.signature)
            .map_err(|_| Error::Crypto)
    }
}

impl Engine {
    /// Authorize the discard of one state-A companion whose request can no longer
    /// be accepted: an operator status signed under the SEALED operator key shows
    /// no account for the sealed owner and community at an observation time at
    /// least `GENESIS_DISCARD_COMMIT_MARGIN_SECONDS` after the request's
    /// `expires_at` (read by the upper owner from the receipt-bound outbox, and
    /// bounded here by the sealed statement). State B never qualifies. No local
    /// time is read. Returns the authenticated companion; nothing is written.
    pub fn check_elapsed_pending(
        &self,
        sealed: &SealedPendingGenesis,
        request_expires_at: u64,
        absence: &OwnerAbsence,
    ) -> Result<(PreparedGenesisProof, PendingGenesisBinding), Error> {
        let (proof, binding) = self.open_pending(sealed)?;
        let public = proof.candidate.genesis_public();
        if binding.extended_acceptance_digest.is_some()
            || absence.owner != public.owner
            || absence.community != public.community
            || request_expires_at <= public.now
            || request_expires_at > public.valid_until
            || absence.observed_at
                < request_expires_at.saturating_add(GENESIS_DISCARD_COMMIT_MARGIN_SECONDS)
        {
            return Err(Error::Invalid);
        }
        absence.verify(&binding.acceptance.operator_key)?;
        Ok((proof, binding))
    }
}

#[cfg(test)]
#[path = "pending/tests.rs"]
mod tests;
