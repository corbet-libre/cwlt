//! Acceptance transcript conformance. The golden digest below is also asserted by
//! the Messenger host tests against the original Balance verifier, so both
//! owners pin one independently computed message for the same public fields.
use super::*;
use crate::{account::hashes, native_prover::NativeProver};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

/// SHA-256 of the original acceptance message for `golden_inputs`.
const GOLDEN_MESSAGE_DIGEST: &str =
    "a9189a36a90839b5a224f459ea8ca880194d26f4f439b2ace7b70e912bf8bc3a";

fn policy() -> AccountPolicy {
    AccountPolicy {
        initial_credit: 20,
        maximum_available: 100,
        outgoing_reservation: 5,
        incoming_reservation: 5,
        policy_revision: 1,
        policy_valid_from: 1,
        policy_valid_until: 10_000,
        newcomer_period: 100,
        rate_window: 100,
        newcomer_admissions: 2,
        maximum_admissions: 10,
        refill_period: 100,
        refill_units: 2,
        abandon_after: 200,
    }
}

fn golden_inputs() -> (
    GenesisPublic,
    AccountPolicy,
    czkp::ProofScope,
    AcceptanceBinding,
) {
    let community = hashes::digest(b"community").unwrap();
    let policy = policy();
    let policy_digest = hashes::digest(&policy.bytes(&community).unwrap()).unwrap();
    let mut root = [0; 32];
    root[31] = 7;
    let mut next = [0; 32];
    next[31] = 9;
    (
        GenesisPublic {
            protocol_version: 2,
            community,
            owner: [2; 32],
            policy_digest,
            enrollment_root: root,
            now: 101,
            valid_until: 200,
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: [0; 32],
            next_state: next,
            settlement_marker: [0; 32],
        },
        policy,
        czkp::ProofScope {
            circuit_digest: [0xC3; 32],
            verifying_key_digest: [0xD4; 32],
        },
        AcceptanceBinding {
            request_id: [0xA1; 32],
            request_digest: [0xB2; 32],
            operator_key: SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
        },
    )
}

#[test]
fn reconstructed_message_matches_the_independent_golden_digest() {
    let (public, policy, scope, binding) = golden_inputs();
    let message = acceptance_message(&public, &policy, &scope, &binding, 150).unwrap();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&Sha256::digest(message)),
        GOLDEN_MESSAGE_DIGEST
    );
}

/// Deterministic operator signature for the golden message, computed outside
/// this crate with the pinned test key; the Messenger tests verify the same
/// vector with the original Balance verifier.
const GOLDEN_SIGNATURE: &str = "1f722ba31f953dc655a6f1247d616798bd8d227427c3cf1358bf780082a3012db4ea429443439188e9c14ff78fa56f7a2dd38bce7e7d04273d016022f2562f08";
const GOLDEN_OPERATOR: &str = "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1";

#[test]
fn golden_operator_signature_verifies_only_for_the_exact_message() {
    let (public, policy, scope, binding) = golden_inputs();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&binding.operator_key),
        GOLDEN_OPERATOR
    );
    let signature: [u8; 64] = data_encoding::HEXLOWER
        .decode(GOLDEN_SIGNATURE.as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let message = acceptance_message(&public, &policy, &scope, &binding, 150).unwrap();
    verify(&message, &binding.operator_key, &signature).unwrap();
    let other = acceptance_message(&public, &policy, &scope, &binding, 151).unwrap();
    assert!(verify(&other, &binding.operator_key, &signature).is_err());
    let mut wrong = signature;
    wrong[63] ^= 1;
    assert!(verify(&message, &binding.operator_key, &wrong).is_err());
}

#[test]
fn reconstruction_refuses_every_noncanonical_transcript_input() {
    let (public, policy, scope, binding) = golden_inputs();
    let message = |p: &GenesisPublic, b: &AcceptanceBinding, at: u64| {
        acceptance_message(p, &policy, &scope, b, at)
    };
    assert!(message(&public, &binding, 150).is_ok());
    // Acceptance time is bounded by the original statement observation/horizon.
    assert!(message(&public, &binding, 100).is_err());
    assert!(message(&public, &binding, 101).is_ok());
    assert!(message(&public, &binding, 199).is_ok());
    assert!(message(&public, &binding, 200).is_err());
    let mut zero = binding.clone();
    zero.request_id = [0; 32];
    assert!(message(&public, &zero, 150).is_err());
    for mutate in [
        (|p: &mut GenesisPublic| p.protocol_version = 1) as fn(&mut GenesisPublic),
        |p| p.genesis = false,
        |p| p.previous_version = 1,
        |p| p.next_version = 1,
        |p| p.previous_state[0] = 1,
        |p| p.settlement_marker[0] = 1,
        |p| p.now = 0,
        |p| p.now = 10_000,
        |p| p.valid_until = 201,
    ] {
        let (mut changed, ..) = golden_inputs();
        mutate(&mut changed);
        assert!(message(&changed, &binding, 150).is_err());
    }
}

#[test]
fn bound_fields_change_the_signed_message() {
    let (public, policy, scope, binding) = golden_inputs();
    let base = acceptance_message(&public, &policy, &scope, &binding, 150).unwrap();
    let mut other = binding.clone();
    other.request_digest[0] ^= 1;
    assert_ne!(
        base,
        acceptance_message(&public, &policy, &scope, &other, 150).unwrap()
    );
    let mut other = binding.clone();
    other.request_id[0] ^= 1;
    assert_ne!(
        base,
        acceptance_message(&public, &policy, &scope, &other, 150).unwrap()
    );
    let mut group = scope.clone();
    group.verifying_key_digest[0] ^= 1;
    assert_ne!(
        base,
        acceptance_message(&public, &policy, &group, &binding, 150).unwrap()
    );
    assert_ne!(
        base,
        acceptance_message(&public, &policy, &scope, &binding, 151).unwrap()
    );
    let (mut state, ..) = golden_inputs();
    state.next_state[0] ^= 1;
    assert_ne!(
        base,
        acceptance_message(&state, &policy, &scope, &binding, 150).unwrap()
    );
}

#[test]
fn actual_proof_accepts_only_the_exact_operator_signature_over_its_transcript() {
    let (engine, context) = super::super::tests::fixture();
    let prover = NativeProver::new(crate::native_prover::tests::config()).unwrap();
    let operator = SigningKey::from_bytes(&[5; 32]);
    let binding = AcceptanceBinding {
        request_id: [0xA1; 32],
        request_digest: [0xB2; 32],
        operator_key: operator.verifying_key().to_bytes(),
    };
    let prove = || {
        engine
            .prepare_genesis(context.clone())
            .unwrap()
            .prove(&engine, &prover, || Ok(101))
            .unwrap()
    };
    let proof = prove();
    let accepted_at = 150;
    let message = acceptance_message(
        &proof.public_genesis(),
        &context.policy,
        proof.scope(),
        &binding,
        accepted_at,
    )
    .unwrap();
    let signature = operator.sign(&message).to_bytes();
    let response = IssuerAcceptance {
        accepted_at,
        signature,
    };
    let accepted = proof.accept(&binding, &response).unwrap();
    assert_eq!(accepted.accepted_at(), accepted_at);
    assert!(accepted.public_genesis().genesis);
    accepted.check_context(&engine, &context, 102).unwrap();

    // Wrong time, request digest, key and corrupt signatures all refuse.
    let mut other_digest = binding.clone();
    other_digest.request_digest[0] ^= 1;
    let mut other_key = binding.clone();
    other_key.operator_key = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let mut corrupt = signature;
    corrupt[0] ^= 1;
    for (candidate, at, sig) in [
        (&binding, accepted_at + 1, signature),
        (&other_digest, accepted_at, signature),
        (&other_key, accepted_at, signature),
        (&binding, accepted_at, corrupt),
        (&binding, accepted_at, [0; 64]),
    ] {
        let response = IssuerAcceptance {
            accepted_at: at,
            signature: sig,
        };
        assert!(prove().accept(candidate, &response).is_err());
    }
}
