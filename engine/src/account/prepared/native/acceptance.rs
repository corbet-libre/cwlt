//! Verification of the original fixed issuer acceptance of one retained candidate.
//!
//! The signed message is reconstructed from lower-owned retained fields only.
//! The upper owner supplies nothing but the original acceptance time and operator
//! signature, plus the retained request binding and pinned issuer key. A verified
//! acceptance releases no custody: the upper current-owner/Frontier verification
//! and the accepted compare-and-swap remain mandatory and separate.
use super::*;
use crate::account::{hashes, policy::AccountPolicy};
use ed25519_dalek::{Signature, VerifyingKey};

const ACCEPTANCE_DOMAIN: &[u8] = b"cfrm.account.acceptance.v1\0";
const STATEMENT_DOMAIN: &[u8] = b"cfrm.account.statement.v2\0";

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
    candidate: PreparedGenesisProof,
    accepted_at: u64,
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

fn append_policy(bytes: &mut Vec<u8>, policy: &AccountPolicy) {
    for value in [
        policy.initial_credit,
        policy.maximum_available,
        policy.outgoing_reservation,
        policy.incoming_reservation,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        policy.policy_revision,
        policy.policy_valid_from,
        policy.policy_valid_until,
        policy.newcomer_period,
        policy.rate_window,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&policy.newcomer_admissions.to_be_bytes());
    bytes.extend_from_slice(&policy.maximum_admissions.to_be_bytes());
    bytes.extend_from_slice(&policy.refill_period.to_be_bytes());
    bytes.extend_from_slice(&policy.refill_units.to_be_bytes());
    bytes.extend_from_slice(&policy.abandon_after.to_be_bytes());
}

/// Exact original fixed statement transcript of a genesis account relation.
fn statement_bytes(public: &GenesisPublic, policy: &AccountPolicy) -> Result<Vec<u8>, Error> {
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
    let mut bytes = STATEMENT_DOMAIN.to_vec();
    bytes.extend_from_slice(&public.protocol_version.to_be_bytes());
    for digest in [
        public.community,
        public.owner,
        public.policy_digest,
        public.enrollment_root,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&public.now.to_be_bytes());
    bytes.extend_from_slice(&public.valid_until.to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&public.previous_version.to_be_bytes());
    bytes.extend_from_slice(&public.next_version.to_be_bytes());
    for digest in [
        public.previous_state,
        public.next_state,
        public.settlement_marker,
    ] {
        bytes.extend_from_slice(&digest);
    }
    append_policy(&mut bytes, policy);
    Ok(bytes)
}

/// Original operator acceptance message for the retained statement and scope.
fn acceptance_message(
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
    let mut bytes = ACCEPTANCE_DOMAIN.to_vec();
    bytes.extend_from_slice(&binding.request_id);
    bytes.extend_from_slice(&binding.request_digest);
    bytes.extend_from_slice(&scope.circuit_digest);
    bytes.extend_from_slice(&scope.verifying_key_digest);
    bytes.extend_from_slice(&accepted_at.to_be_bytes());
    bytes.extend_from_slice(&hashes::digest(&statement_bytes(public, policy)?)?);
    Ok(bytes)
}

/// Maintained strict Ed25519 verification of the pinned operator signature.
fn verify(message: &[u8], key: &[u8; 32], signature: &[u8; 64]) -> Result<(), Error> {
    VerifyingKey::from_bytes(key)
        .map_err(|_| Error::Crypto)?
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::Crypto)
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
            candidate: self,
            accepted_at,
        })
    }
}

#[cfg(test)]
#[path = "acceptance/tests.rs"]
mod tests;
