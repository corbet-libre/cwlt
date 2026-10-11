//! Verification of the original fixed issuer acceptance of one retained candidate.
//!
//! The signed message is reconstructed from lower-owned retained fields only.
//! The upper owner supplies nothing but the original acceptance time and operator
//! signature, plus the retained request binding and pinned issuer key. A verified
//! acceptance releases no custody: the upper current-owner/Frontier verification
//! and the accepted compare-and-swap remain mandatory and separate.
use super::response::verify_issuer_material;
use super::*;
use crate::account::policy::AccountPolicy;

/// Retained original request identity and pinned authenticated Balance issuer.
/// These are data from the pending companion, never a caller verdict.
#[derive(Clone, PartialEq, Eq)]
pub struct AcceptanceBinding {
    /// Original non-zero request identifier of the signed account request.
    pub request_id: [u8; 32],
    /// Original plain digest of the signed account request, signature included.
    pub request_digest: [u8; 32],
    /// Pinned Ed25519 verification key of the authenticated Balance operator.
    pub operator_key: [u8; 32],
}

/// The only values that enter from the original operator's response.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerAcceptance {
    /// Original accepted time that the operator signed.
    pub accepted_at: u64,
    /// Original Ed25519 operator signature over the fixed acceptance message.
    pub signature: [u8; 64],
}

/// Candidate whose exact public acceptance transcript carries a valid original
/// operator signature. It is opaque: no installation, serialization or custody
/// release exists here, and it asserts nothing about the current Frontier.
pub struct AcceptedGenesisProof {
    pub(super) candidate: PreparedGenesisProof,
    pub(super) accepted_at: u64,
    /// The full verified response; `None` only for the signature-only `accept`.
    pub(super) response: Option<AcceptedResponse>,
    pub(super) binding: AcceptanceBinding,
    pub(super) extended_acceptance_digest: [u8; 32],
}

impl AcceptedGenesisProof {
    /// Original accepted time that the operator signed.
    pub fn accepted_at(&self) -> u64 {
        self.accepted_at
    }

    /// Public statement data of the accepted candidate.
    pub fn public_genesis(&self) -> GenesisPublic {
        self.candidate.public_genesis()
    }

    /// Recheck the retained private candidate; see `PreparedGenesisProof`.
    pub fn check_context(
        &self,
        engine: &Engine,
        context: &GenesisContext,
        now: u64,
    ) -> Result<(), Error> {
        self.candidate.check_context(engine, context, now)
    }
}

/// The retained genesis statement as czkp's canonical encoder consumes it, after the
/// holder-side checks that it is a plain genesis within the policy horizon.
fn statement_fields(
    public: &GenesisPublic,
    policy: &AccountPolicy,
) -> Result<czkp::account::StatementFields, Error> {
    if public.protocol_version != 2
        || !public.genesis
        || public.previous_version != 0
        || public.next_version != 0
        || public.previous_state != [0; 32]
        || public.settlement_marker != [0; 32]
        || public.now < policy.policy_valid_from
        || public.now >= policy.policy_valid_until
        || public.valid_until != policy.horizon(public.now)?
    {
        return Err(Error::Invalid);
    }
    Ok(czkp::account::StatementFields {
        protocol_version: public.protocol_version,
        community: public.community,
        owner: public.owner,
        policy_digest: public.policy_digest,
        enrollment_root: public.enrollment_root,
        now: public.now,
        valid_until: public.valid_until,
        genesis: public.genesis,
        previous_version: public.previous_version,
        next_version: public.next_version,
        previous_state: public.previous_state,
        next_state: public.next_state,
        settlement_marker: public.settlement_marker,
        policy: policy.fields(),
    })
}

/// Original operator acceptance message for the retained statement and scope.
pub(super) fn acceptance_message(
    public: &GenesisPublic,
    policy: &AccountPolicy,
    scope: &czkp::ProofScope,
    binding: &AcceptanceBinding,
    accepted_at: u64,
) -> Result<Vec<u8>, Error> {
    if binding.request_id == [0; 32]
        || accepted_at < public.now
        || accepted_at >= public.valid_until
    {
        return Err(Error::Invalid);
    }
    Ok(czkp::account::acceptance_bytes(
        &binding.request_id,
        &binding.request_digest,
        scope,
        accepted_at,
        &statement_fields(public, policy)?,
    ))
}

/// Maintained strict Ed25519 verification of the pinned operator signature.
fn verify(message: &[u8], key: &[u8; 32], signature: &[u8; 64]) -> Result<(), Error> {
    czkp::account::verify_acceptance(message, key, signature).map_err(|_| Error::Crypto)
}

impl PreparedGenesisProof {
    /// Verify the original operator signature over the fixed public acceptance
    /// transcript reconstructed from this retained candidate. Maintained strict
    /// Ed25519 verification is used. Any refusal consumes this RAM candidate; the
    /// durable pending companion remains the only reopen path. Success releases no
    /// custody and replaces neither the Frontier nor accepted-state checks.
    pub fn accept(
        self,
        binding: &AcceptanceBinding,
        response: &IssuerAcceptance,
    ) -> Result<AcceptedGenesisProof, Error> {
        let accepted_at = response.accepted_at;
        let message = acceptance_message(
            &self.candidate.genesis_public(),
            &self.candidate.context.policy,
            &self.proof.scope,
            binding,
            accepted_at,
        )?;
        verify(&message, &binding.operator_key, &response.signature)?;
        Ok(AcceptedGenesisProof {
            extended_acceptance_digest: acceptance_digest(&message, &response.signature)?,
            candidate: self,
            accepted_at,
            response: None,
            binding: binding.clone(),
        })
    }

    /// Verify the operator's FULL response without consuming the candidate: the
    /// acceptance signature over the reconstructed transcript, the issuer's state
    /// certificate, and the ancestry rule under the current trust. Returns the
    /// DISTINCT acceptance digest (SHA-256 of the acceptance message and signature).
    pub(super) fn verify_response(
        &self,
        binding: &AcceptanceBinding,
        response: &AcceptedResponse,
        trust: &ResponseTrust,
    ) -> Result<[u8; 32], Error> {
        let public = self.candidate.genesis_public();
        let message = acceptance_message(
            &public,
            &self.candidate.context.policy,
            &self.proof.scope,
            binding,
            response.issuer.accepted_at,
        )?;
        verify(&message, &binding.operator_key, &response.issuer.signature)?;
        verify_issuer_material(&public, &self.proof.scope, response, trust)?;
        acceptance_digest(&message, &response.issuer.signature)
    }
}

/// SHA-256 of the signed acceptance (message then signature): the same value
/// the Balance status response uses for an embedded acceptance.
fn acceptance_digest(message: &[u8], signature: &[u8; 64]) -> Result<[u8; 32], Error> {
    Ok(czkp::account::acceptance_digest(message, signature))
}

#[cfg(test)]
#[path = "acceptance/tests.rs"]
mod tests;
