//! Pending companion conformance without a prover: the engine never verifies the
//! proof bytes it stores, so fabricated bytes exercise the sealing exactly.
use super::super::acceptance::acceptance_message;
use super::*;
use crate::native_prover::Proof;

fn proven(engine: &Engine, context: &GenesisContext) -> PreparedGenesisProof {
    PreparedGenesisProof {
        candidate: engine.prepare_genesis(context.clone()).unwrap(),
        proof: Proof {
            scope: ProofScope {
                circuit_digest: [0xC3; 32],
                verifying_key_digest: [0xD4; 32],
            },
            public_inputs: vec![[1; 32]; 345],
            proof: vec![9; 14_000],
        },
    }
}

fn binding() -> PendingGenesisBinding {
    PendingGenesisBinding {
        acceptance: AcceptanceBinding {
            request_id: [0xA1; 32],
            request_digest: [0xB2; 32],
            operator_key: [0x77; 32],
        },
        extended_acceptance_digest: [0xE5; 32],
        upper: vec![4; 20_000],
    }
}

#[test]
fn reopen_restores_the_exact_candidate_proof_and_binding_without_reproving() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let before = proof.public_genesis();
    let sealed = proof.seal_pending(&engine, &binding()).unwrap();
    assert!(sealed.as_bytes().len() < MAX_PENDING_SEALED);
    let wire = SealedPendingGenesis::from_bytes(sealed.as_bytes()).unwrap();
    let (reopened, restored) = engine.restore_pending_genesis(&wire, 102).unwrap();
    assert!(restored == binding());
    let after = reopened.public_genesis();
    // Same blind: identical commitment, root, horizon and original observation.
    assert_eq!(after.next_state, before.next_state);
    assert_eq!(after.enrollment_root, before.enrollment_root);
    assert_eq!(after.now, before.now);
    assert_eq!(after.valid_until, before.valid_until);
    assert_eq!(reopened.proof(), proof.proof());
    assert_eq!(reopened.public_inputs(), proof.public_inputs());
    assert_eq!(reopened.scope(), proof.scope());
    // A fresh preparation reblinds; the pending reopen must not.
    let fresh = engine.prepare_genesis(context.clone()).unwrap();
    assert_ne!(fresh.genesis_public().next_state, before.next_state);
    // Two seals of one candidate are different ciphertexts that both reopen.
    let again = proof.seal_pending(&engine, &binding()).unwrap();
    assert_ne!(again.as_bytes(), sealed.as_bytes());
    engine.restore_pending_genesis(&again, 102).unwrap();
}

#[test]
fn reopen_never_extends_the_original_expiry_or_rewinds_the_clock() {
    let (engine, context) = super::super::tests::fixture();
    let sealed = proven(&engine, &context)
        .seal_pending(&engine, &binding())
        .unwrap();
    // Horizon is 200 and the original observation 101.
    assert!(engine.restore_pending_genesis(&sealed, 199).is_ok());
    assert!(engine.restore_pending_genesis(&sealed, 200).is_err());
    assert!(engine.restore_pending_genesis(&sealed, 100).is_err());
    assert!(engine.restore_pending_genesis(&sealed, u64::MAX).is_err());
}

#[test]
fn foreign_engines_tampering_and_other_sealed_kinds_never_reopen() {
    let (engine, context) = super::super::tests::fixture();
    let sealed = proven(&engine, &context)
        .seal_pending(&engine, &binding())
        .unwrap();
    let other =
        Engine::from_seed_and_sealing_key(&mut [6; 32], &mut [8; 32], b"community").unwrap();
    assert!(other.restore_pending_genesis(&sealed, 102).is_err());
    let other =
        Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [6; 32], b"community").unwrap();
    assert!(other.restore_pending_genesis(&sealed, 102).is_err());
    let other = Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"other").unwrap();
    assert!(other.restore_pending_genesis(&sealed, 102).is_err());
    for index in [
        MAGIC.len(),
        MAGIC.len() + NONCE + 3,
        sealed.as_bytes().len() - 1,
    ] {
        let mut bytes = sealed.as_bytes().to_vec();
        bytes[index] ^= 1;
        let wire = SealedPendingGenesis::from_bytes(&bytes).unwrap();
        assert!(engine.restore_pending_genesis(&wire, 102).is_err());
    }
    // Purpose separation: key capsule and engine seals are not pending companions.
    let key = engine.prepare_account_key("community", [1; 32]).unwrap();
    assert!(SealedPendingGenesis::from_bytes(key.seal().unwrap().as_bytes()).is_err());
    assert!(SealedPendingGenesis::from_bytes(engine.seal().unwrap().as_bytes()).is_err());
    // A pending envelope is not another kind either.
    assert!(crate::Sealed::from_bytes(sealed.as_bytes()).is_err());
    assert!(SealedPendingGenesis::from_bytes(&[]).is_err());
    assert!(SealedPendingGenesis::from_bytes(&sealed.as_bytes()[..MAGIC.len()]).is_err());
    let mut huge = sealed.as_bytes().to_vec();
    huge.resize(MAX_PENDING_SEALED + 1, 0);
    assert!(SealedPendingGenesis::from_bytes(&huge).is_err());
}

#[test]
fn binding_must_be_complete_distinct_and_bounded() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let mutations: [fn(&mut PendingGenesisBinding); 7] = [
        |b| b.acceptance.request_id = [0; 32],
        |b| b.acceptance.request_digest = [0; 32],
        |b| b.acceptance.operator_key = [0; 32],
        |b| b.extended_acceptance_digest = [0; 32],
        // The signed request and the extended acceptance digests must differ.
        |b| b.extended_acceptance_digest = b.acceptance.request_digest,
        |b| b.upper.clear(),
        |b| b.upper = vec![0; MAX_UPPER + 1],
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed = binding();
        mutate(&mut changed);
        let result = proof.seal_pending(&engine, &changed);
        assert!(result.is_err(), "mutation {index}");
    }
}

#[test]
fn only_the_producing_engine_can_seal_a_candidate() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let other =
        Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"community").unwrap();
    assert!(proof.seal_pending(&other, &binding()).is_err());
}

#[test]
fn restored_candidate_still_requires_the_exact_operator_acceptance() {
    use ed25519_dalek::{Signer, SigningKey};
    let (engine, context) = super::super::tests::fixture();
    let operator = SigningKey::from_bytes(&[5; 32]);
    let mut pending = binding();
    pending.acceptance.operator_key = operator.verifying_key().to_bytes();
    let sealed = proven(&engine, &context)
        .seal_pending(&engine, &pending)
        .unwrap();
    let (reopened, restored) = engine.restore_pending_genesis(&sealed, 102).unwrap();
    let message = acceptance_message(
        &reopened.public_genesis(),
        &context.policy,
        reopened.scope(),
        &restored.acceptance,
        150,
    )
    .unwrap();
    let response = IssuerAcceptance {
        accepted_at: 150,
        signature: operator.sign(&message).to_bytes(),
    };
    let accepted = reopened.accept(&restored.acceptance, &response).unwrap();
    assert_eq!(accepted.accepted_at(), 150);
}
