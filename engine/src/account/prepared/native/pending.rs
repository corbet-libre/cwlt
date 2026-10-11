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

pub(super) struct Writer(pub(super) Zeroizing<Vec<u8>>);
impl Writer {
    pub(super) fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    pub(super) fn var(&mut self, value: &[u8]) -> Result<(), Error> {
        self.u32(u32::try_from(value.len()).map_err(|_| Error::Invalid)?);
        self.bytes(value);
        Ok(())
    }
}

pub(super) struct Reader<'a>(pub(super) &'a [u8]);
impl<'a> Reader<'a> {
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Crypto);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Crypto)
    }
    pub(super) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn var(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.u32()?).map_err(|_| Error::Crypto)?;
        if n > max {
            return Err(Error::Crypto);
        }
        self.take(n)
    }
}

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
    Ok(GenesisContext {
        community_id,
        owner,
        policy,
        extension,
        enrollment,
        enrollment_root: r.array()?,
        checked_at: r.u64()?,
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
        candidate.check_context(self, &context, now)?;
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

#[cfg(test)]
#[path = "pending/tests.rs"]
mod tests;
