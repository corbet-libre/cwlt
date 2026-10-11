//! Pending companion conformance without a prover: the engine never verifies the
//! proof bytes it stores, so fabricated bytes exercise the sealing exactly.
use super::super::acceptance::acceptance_message;
use super::*;
use crate::account::hashes;
use crate::native_prover::Proof;
use ed25519_dalek::{Signer as _, SigningKey as OperatorKey};
use p256::ecdsa::{SigningKey as IssuerKey, signature::Signer as _};

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
        response: None,
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
    // A digest without a verified response (or the reverse) never seals.
    let mut direct = binding();
    direct.extended_acceptance_digest = Some([0xE5; 32]);
    assert!(proof.seal_pending(&engine, &direct).is_err());
    assert!(proof.seal_state(&engine, &direct).is_err());
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

fn issuer() -> IssuerKey {
    IssuerKey::from_slice(&[11; 32]).unwrap()
}

fn issuer_public(key: &IssuerKey) -> [u8; 64] {
    key.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap()
}

fn operator() -> OperatorKey {
    OperatorKey::from_bytes(&[5; 32])
}

fn real_binding() -> PendingGenesisBinding {
    let mut value = binding();
    value.acceptance.operator_key = operator().verifying_key().to_bytes();
    value
}

fn trust(frontier: Option<Frontier>) -> ResponseTrust {
    ResponseTrust {
        certificate_key: issuer_public(&issuer()),
        frontier,
    }
}

fn frontier() -> Frontier {
    Frontier {
        epoch: 3,
        root: [5; 32],
    }
}

/// A genuine issuer response for the candidate, signed with test keys.
fn response(
    proof: &PreparedGenesisProof,
    binding: &AcceptanceBinding,
    at: u64,
    with_frontier: bool,
) -> AcceptedResponse {
    let public = proof.public_genesis();
    let message =
        acceptance_message(&public, &proof.context().policy, proof.scope(), binding, at).unwrap();
    // The issuer signs the bytes czkp encodes, exactly as the real issuer does.
    let certificate: p256::ecdsa::Signature =
        issuer().sign(&super::super::response::accepted_state(&public, proof.scope(), at).bytes());
    let ancestry = with_frontier.then(|| {
        let mut ancestry = AncestryResponse {
            epoch: 3,
            root: [5; 32],
            frozen_leaf: [6; 32],
            signature: [0; 64],
            record: vec![1, 2, 3],
        };
        let bytes = super::super::response::ancestry_body(&public, proof.scope(), &ancestry, at)
            .bytes()
            .unwrap();
        let signature: p256::ecdsa::Signature = issuer().sign(&bytes);
        ancestry.signature = signature.to_bytes().into();
        ancestry
    });
    AcceptedResponse {
        issuer: IssuerAcceptance {
            accepted_at: at,
            signature: operator().sign(&message).to_bytes(),
        },
        certificate: certificate.to_bytes().into(),
        ancestry,
    }
}

#[test]
fn full_response_advances_sent_to_accepted_and_activates_offline() {
    for with_frontier in [false, true] {
        let (engine, context) = super::super::tests::fixture();
        let proof = proven(&engine, &context);
        let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
        let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
        assert!(a.extended_acceptance_digest.is_none() && a.response.is_none());
        // State A never activates.
        let live = trust(with_frontier.then(frontier));
        assert!(engine.activate_pending(&sent, &live, 102).is_err());
        let good = response(&proof, &a.acceptance, 150, with_frontier);
        let accepted = engine.advance_pending(&sent, &good, &live, 102).unwrap();
        let (reopened, b) = engine.restore_accepted_pending(&accepted, 103).unwrap();
        // Everything but the verified response and its derived digest is unchanged.
        assert!(b.acceptance == a.acceptance && b.upper == a.upper);
        assert!(b.response.as_ref() == Some(&good));
        assert_eq!(reopened.proof(), proof.proof());
        // The digest is derived by the engine: SHA-256(acceptance message || signature).
        let message = acceptance_message(
            &proof.public_genesis(),
            &context.policy,
            proof.scope(),
            &a.acceptance,
            150,
        )
        .unwrap();
        assert_eq!(
            b.extended_acceptance_digest,
            Some(hashes::digest(&[message, good.issuer.signature.to_vec()].concat()).unwrap())
        );
        // Activation re-verifies the stored response offline, with no re-send.
        let activated = engine.activate_pending(&accepted, &live, 104).unwrap();
        assert_eq!(activated.accepted_at(), 150);
        // No second advance, and the horizon still bounds both states.
        assert!(
            engine
                .advance_pending(&accepted, &good, &live, 103)
                .is_err()
        );
        assert!(engine.activate_pending(&accepted, &live, 200).is_err());
        assert!(engine.advance_pending(&sent, &good, &live, 200).is_err());
    }
}

#[test]
fn a_response_that_fails_any_check_never_advances_or_activates() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust(Some(frontier()));
    assert!(engine.advance_pending(&sent, &good, &live, 102).is_ok());
    let advance = |response: &AcceptedResponse, trust: &ResponseTrust| {
        engine.advance_pending(&sent, response, trust, 102)
    };
    // Operator signature, time, certificate and ancestry tampering.
    let mut bad = good.clone();
    bad.issuer.signature[0] ^= 1;
    assert!(advance(&bad, &live).is_err());
    let mut bad = good.clone();
    bad.issuer.accepted_at = 151;
    assert!(advance(&bad, &live).is_err());
    let mut bad = good.clone();
    bad.certificate[0] ^= 1;
    assert!(advance(&bad, &live).is_err());
    let mut bad = good.clone();
    bad.ancestry.as_mut().unwrap().signature[0] ^= 1;
    assert!(advance(&bad, &live).is_err());
    let mut bad = good.clone();
    bad.ancestry.as_mut().unwrap().frozen_leaf[0] ^= 1;
    assert!(advance(&bad, &live).is_err());
    // The ancestry rule: mandatory with a frontier, forbidden without one.
    let mut bad = good.clone();
    bad.ancestry = None;
    assert!(advance(&bad, &live).is_err());
    assert!(advance(&good, &trust(None)).is_err());
    // Wrong frontier epoch or root, wrong issuer key.
    for changed in [
        Frontier {
            epoch: 4,
            root: [5; 32],
        },
        Frontier {
            epoch: 3,
            root: [6; 32],
        },
    ] {
        assert!(advance(&good, &trust(Some(changed))).is_err());
    }
    let mut wrong_key = live.clone();
    wrong_key.certificate_key[0] ^= 1;
    assert!(advance(&good, &wrong_key).is_err());
    // Activation uses the CURRENT trust: a changed frontier refuses the stored response.
    let accepted = engine.advance_pending(&sent, &good, &live, 102).unwrap();
    assert!(
        engine
            .activate_pending(&accepted, &trust(None), 103)
            .is_err()
    );
    let moved = Frontier {
        epoch: 3,
        root: [9; 32],
    };
    assert!(
        engine
            .activate_pending(&accepted, &trust(Some(moved)), 103)
            .is_err()
    );
    assert!(engine.activate_pending(&accepted, &live, 103).is_ok());
}

#[test]
fn accepted_record_is_engine_written_distinct_and_restores_the_accepted_commitment() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust(Some(frontier()));
    let accepted = engine.advance_pending(&sent, &good, &live, 102).unwrap();
    let activated = engine.activate_pending(&accepted, &live, 103).unwrap();
    let sealed = activated.seal_account(&engine).unwrap();
    let wire = SealedAcceptedAccount::from_bytes(sealed.as_bytes()).unwrap();
    let account = engine.restore_accepted_account(&wire).unwrap();
    assert_eq!(account.state(), proof.public_genesis().next_state);
    assert_eq!(account.version(), 0);
    assert_eq!(account.accepted_at(), 150);
    assert!(account.response() == &good);
    assert_eq!(
        account.extended_acceptance_digest(),
        activated.extended_acceptance_digest()
    );
    // Kinds are purpose-separated: neither pending state nor the key capsule is an
    // accepted record, and the accepted record is neither pending state.
    assert!(SealedAcceptedAccount::from_bytes(sent.as_bytes()).is_err());
    assert!(SealedAcceptedAccount::from_bytes(accepted.as_bytes()).is_err());
    assert!(SealedPendingGenesis::from_bytes(sealed.as_bytes()).is_err());
    let key = engine.prepare_account_key("community", [1; 32]).unwrap();
    assert!(SealedAcceptedAccount::from_bytes(key.seal().unwrap().as_bytes()).is_err());
    // Foreign engines and tampering never restore it.
    let other =
        Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [6; 32], b"community").unwrap();
    assert!(other.restore_accepted_account(&wire).is_err());
    for index in [MAGIC_LEN, MAGIC_LEN + 30, sealed.as_bytes().len() - 1] {
        let mut bytes = sealed.as_bytes().to_vec();
        bytes[index] ^= 1;
        let tampered = SealedAcceptedAccount::from_bytes(&bytes).unwrap();
        assert!(engine.restore_accepted_account(&tampered).is_err());
    }
    // Only a candidate carrying the full verified response can be sealed: the
    // signature-only path has no response, and there is no public constructor.
    let signature_only = {
        let message = acceptance_message(
            &proof.public_genesis(),
            &context.policy,
            proof.scope(),
            &a.acceptance,
            150,
        )
        .unwrap();
        let response = IssuerAcceptance {
            accepted_at: 150,
            signature: operator().sign(&message).to_bytes(),
        };
        let (fresh, _) = engine.restore_pending_genesis(&sent, 102).unwrap();
        fresh.accept(&a.acceptance, &response).unwrap()
    };
    assert!(signature_only.seal_account(&engine).is_err());
}

const MAGIC_LEN: usize = b"cwlt.account-accepted.v1\0".len();
