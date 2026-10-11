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
        extended_acceptance_digest: None,
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
        MAGIC.len() + 1,
        MAGIC.len() + 1 + NONCE + 3,
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
    let mutations: [fn(&mut PendingGenesisBinding); 5] = [
        |b| b.acceptance.request_id = [0; 32],
        |b| b.acceptance.request_digest = [0; 32],
        |b| b.acceptance.operator_key = [0; 32],
        |b| b.upper.clear(),
        |b| b.upper = vec![0; MAX_UPPER + 1],
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed = binding();
        mutate(&mut changed);
        let result = proof.seal_pending(&engine, &changed);
        assert!(result.is_err(), "mutation {index}");
    }
    // State B never seals directly, and its digest is never zero or the request digest.
    let mut direct = binding();
    direct.extended_acceptance_digest = Some([0xE5; 32]);
    assert!(proof.seal_pending(&engine, &direct).is_err());
    assert!(proof.seal_state(&engine, &direct).is_ok());
    direct.extended_acceptance_digest = Some([0; 32]);
    assert!(proof.seal_state(&engine, &direct).is_err());
    direct.extended_acceptance_digest = Some(direct.acceptance.request_digest);
    assert!(proof.seal_state(&engine, &direct).is_err());
}

#[test]
fn state_advances_only_from_sent_to_accepted_and_only_accepted_activates() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &binding()).unwrap();
    // State A reopens (exact outbox) but never activates.
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    assert!(a.extended_acceptance_digest.is_none());
    assert!(engine.restore_accepted_pending(&sent, 102).is_err());
    // Bad digests never advance.
    assert!(engine.advance_pending(&sent, [0; 32], 102).is_err());
    assert!(
        engine
            .advance_pending(&sent, a.acceptance.request_digest, 102)
            .is_err()
    );
    let accepted = engine.advance_pending(&sent, [0xE5; 32], 102).unwrap();
    let (reopened, b) = engine.restore_accepted_pending(&accepted, 103).unwrap();
    // Everything but the added digest is carried over unchanged.
    assert!(b.acceptance == a.acceptance && b.upper == a.upper);
    assert_eq!(b.extended_acceptance_digest, Some([0xE5; 32]));
    assert_eq!(reopened.proof(), proof.proof());
    assert_eq!(
        reopened.public_genesis().next_state,
        proof.public_genesis().next_state
    );
    // No skip, no re-advance, no downgrade: B cannot advance and has no path back to A.
    assert!(engine.advance_pending(&accepted, [0xE6; 32], 103).is_err());
    // The state tag is authenticated: swapping it makes either ciphertext refuse.
    for (wire, tag) in [(&sent, 2u8), (&accepted, 1u8)] {
        let mut bytes = wire.as_bytes().to_vec();
        bytes[MAGIC.len()] = tag;
        let swapped = SealedPendingGenesis::from_bytes(&bytes).unwrap();
        assert!(engine.restore_pending_genesis(&swapped, 103).is_err());
    }
    // State A expires at the original horizon exactly like before.
    assert!(engine.advance_pending(&sent, [0xE5; 32], 200).is_err());
    assert!(engine.restore_accepted_pending(&accepted, 200).is_err());
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
