//! Pending companion conformance without a prover: the engine never verifies the
//! proof bytes it stores, so fabricated bytes exercise the sealing exactly.
use super::super::acceptance::acceptance_message;
use super::*;
use crate::account::hashes;
use crate::proof::Proof;
use ed25519_dalek::{Signer as _, SigningKey as OperatorKey};
use p256::ecdsa::SigningKey as IssuerKey;

fn proven(engine: &Engine, context: &GenesisContext) -> PreparedGenesisProof {
    PreparedGenesisProof {
        candidate: engine.prepare_genesis(context.clone()).unwrap(),
        proof: Proof {
            scope: ProofScope {
                circuit_digest: [0xC3; 32],
                verifying_key_digest: [0xD4; 32],
            },
            public_inputs: vec![[1; 32]; 410],
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

const IDENTITY: [u8; 32] = [12; 32];

fn issuer() -> IssuerKey {
    IssuerKey::from_slice(&[11; 32]).unwrap()
}

fn issuer_public(key: &IssuerKey) -> [u8; 64] {
    key.verifying_key().to_sec1_point(false).as_bytes()[1..]
        .try_into()
        .unwrap()
}

/// The issuer emits canonical low-S signatures only; normalise like it does.
fn low_s(signature: p256::ecdsa::Signature) -> [u8; 64] {
    signature.normalize_s().to_bytes().into()
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
    trust_both(frontier, None)
}

/// The same trust, plus the join descriptor the operator's signed publication
/// named for a first genesis accepted after the record freeze.
fn trust_both(frontier: Option<Frontier>, join: Option<JoinEpoch>) -> ResponseTrust {
    ResponseTrust {
        certificate_keys: vec![czkp::issuer_keys::CertificateKeyPeriod {
            public_key: issuer_public(&issuer()).to_vec(),
            valid_from: 1,
            valid_until: None,
        }],
        community_identity: IDENTITY,
        frontier,
        join,
    }
}

/// The published epoch descriptor of the join publication: the same epoch/root
/// the ancestry certificate carries, with the record-issuer key.
fn join_epoch(epoch: u64, root: [u8; 32]) -> JoinEpoch {
    JoinEpoch {
        epoch,
        root,
        issuer_key: record_issuer_key(),
    }
}

fn frontier() -> Frontier {
    Frontier {
        epoch: 3,
        root: [5; 32],
        issuer_key: record_issuer_key(),
    }
}

fn record_issuer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[19; 32])
}

fn record_issuer_key() -> [u8; 32] {
    record_issuer().verifying_key().to_bytes()
}

/// The join-time record leaf the ledger signs for an accepted genesis: the exact
/// genesis state under a fresh blinding, certified with the epoch record-issuer key.
fn join_leaf(public: &GenesisPublic) -> czkp::record::Leaf {
    czkp::record::Leaf {
        owner: public.owner,
        version: public.next_version,
        state: public.next_state,
        required_inbox: [7; 32],
        role: 0,
        blinding: [8; 32],
    }
}

fn join_record_of(public: &GenesisPublic, leaf: czkp::record::Leaf) -> ([u8; 32], Vec<u8>) {
    let commitment = leaf.commitment(&public.community, 3).unwrap();
    let signature = record_issuer()
        .sign(&czkp::record::certificate_bytes(&public.community, 3, &commitment).unwrap())
        .to_bytes()
        .to_vec();
    let signed = czkp::record::SignedLeaf { leaf, signature };
    (commitment, serde_json::to_vec(&signed).unwrap())
}

fn join_record(public: &GenesisPublic) -> ([u8; 32], Vec<u8>) {
    join_record_of(public, join_leaf(public))
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
    let certificate: p256::ecdsa::Signature = issuer().sign(
        &super::super::response::accepted_state(&public, proof.scope(), &IDENTITY, at).bytes(),
    );
    let ancestry = with_frontier.then(|| {
        let (frozen_leaf, record) = join_record(&public);
        let mut ancestry = AncestryResponse {
            epoch: 3,
            root: [5; 32],
            frozen_leaf,
            signature: [0; 64],
            record,
        };
        let bytes = super::super::response::ancestry_body(&public, proof.scope(), &ancestry, at)
            .bytes()
            .unwrap();
        let signature: p256::ecdsa::Signature = issuer().sign(&bytes);
        ancestry.signature = low_s(signature);
        ancestry
    });
    AcceptedResponse {
        issuer: IssuerAcceptance {
            accepted_at: at,
            signature: operator().sign(&message).to_bytes(),
        },
        certificate: low_s(certificate),
        ancestry,
        join: None,
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
    // The ancestry rule: a present one must match the frontier and is forbidden
    // without one. A genesis that started after the freeze has no frozen leaf:
    // under a frontier its response carries no ancestry and still advances.
    let mut fresh = good.clone();
    fresh.ancestry = None;
    assert!(advance(&fresh, &live).is_ok());
    assert!(advance(&good, &trust(None)).is_err());
    // Wrong frontier epoch or root, wrong issuer key.
    for changed in [
        Frontier {
            epoch: 4,
            root: [5; 32],
            issuer_key: record_issuer_key(),
        },
        Frontier {
            epoch: 3,
            root: [6; 32],
            issuer_key: record_issuer_key(),
        },
    ] {
        assert!(advance(&good, &trust(Some(changed))).is_err());
    }
    let mut wrong_key = live.clone();
    wrong_key.certificate_keys[0].public_key =
        issuer_public(&IssuerKey::from_slice(&[13; 32]).unwrap()).to_vec();
    assert!(advance(&good, &wrong_key).is_err());
    // A certificate bound to another community identity fails.
    let mut other_identity = live.clone();
    other_identity.community_identity = [14; 32];
    assert!(advance(&good, &other_identity).is_err());
    // The signing key verifies only inside its own period: retired before the
    // acceptance (150) it fails, retired after it the old certificate still verifies.
    let rotated = |until: u64| {
        let mut ring = live.clone();
        ring.certificate_keys[0].valid_until = Some(until);
        ring.certificate_keys
            .push(czkp::issuer_keys::CertificateKeyPeriod {
                public_key: issuer_public(&IssuerKey::from_slice(&[13; 32]).unwrap()).to_vec(),
                valid_from: until,
                valid_until: None,
            });
        ring
    };
    assert!(advance(&good, &rotated(150)).is_err());
    assert!(advance(&good, &rotated(151)).is_ok());
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
        issuer_key: record_issuer_key(),
    };
    assert!(
        engine
            .activate_pending(&accepted, &trust(Some(moved)), 103)
            .is_err()
    );
    assert!(engine.activate_pending(&accepted, &live, 103).is_ok());
}

/// Row 16: a newcomer's genesis accepted after an epoch freeze. The operator
/// certifies ancestry only for owners frozen in the epoch, so the response
/// carries none; it advances and activates under the current frontier, also
/// one that moved or ended meanwhile.
#[test]
fn a_genesis_after_the_freeze_carries_no_ancestry_and_activates_under_the_current_frontier() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let fresh = response(&proof, &a.acceptance, 150, false);
    let live = trust(Some(frontier()));
    let accepted = engine.advance_pending(&sent, &fresh, &live, 102).unwrap();
    let moved = Frontier {
        epoch: 4,
        root: [9; 32],
        issuer_key: record_issuer_key(),
    };
    for current in [live.clone(), trust(Some(moved)), trust(None)] {
        assert_eq!(
            engine
                .activate_pending(&accepted, &current, 103)
                .unwrap()
                .accepted_at(),
            150
        );
    }
}

/// The join-time record leaf rides the genesis acceptance. Even with a valid issuer
/// signature over the ancestry, the leaf must be exactly the accepted genesis state
/// and its blinded commitment must be the certified `frozen_leaf`.
#[test]
fn a_join_record_must_be_exactly_the_accepted_genesis_state() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust(Some(frontier()));
    let public = proof.public_genesis();
    let at = 150;
    let advance = |response: &AcceptedResponse| engine.advance_pending(&sent, response, &live, 102);
    assert!(advance(&good).is_ok());
    // Re-issue the ancestry with a valid signature over whatever the test changed.
    let reissue = |frozen_leaf: [u8; 32], record: Vec<u8>| {
        let mut ancestry = AncestryResponse {
            epoch: 3,
            root: [5; 32],
            frozen_leaf,
            signature: [0; 64],
            record,
        };
        let bytes = super::super::response::ancestry_body(&public, proof.scope(), &ancestry, at)
            .bytes()
            .unwrap();
        let signature: p256::ecdsa::Signature = issuer().sign(&bytes);
        ancestry.signature = low_s(signature);
        let mut response = good.clone();
        response.ancestry = Some(ancestry);
        response
    };
    // Another owner, another version, another state: never the accepted genesis.
    let mut leaves = Vec::new();
    for change in 0..3 {
        let mut leaf = join_leaf(&public);
        match change {
            0 => leaf.owner[0] ^= 1,
            1 => leaf.version += 1,
            _ => leaf.state[0] ^= 1,
        }
        leaves.push(leaf);
    }
    for leaf in leaves {
        let (frozen_leaf, record) = join_record_of(&public, leaf);
        assert!(advance(&reissue(frozen_leaf, record)).is_err());
    }
    // A certified commitment that is not this leaf's, and a packet that is no leaf.
    let (_, record) = join_record(&public);
    assert!(advance(&reissue([6; 32], record)).is_err());
    assert!(advance(&reissue(join_record(&public).0, vec![1, 2, 3])).is_err());
}

/// The join leaf's Ed25519 certificate is verified at acceptance, against the
/// epoch issuer key: a tampered signature, or a leaf signed under another key,
/// is refused even with a valid ancestry signature over the certified commitment.
#[test]
fn a_join_record_with_a_tampered_signature_is_refused_at_acceptance() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust(Some(frontier()));
    let public = proof.public_genesis();
    let at = 150;
    let advance = |response: &AcceptedResponse| engine.advance_pending(&sent, response, &live, 102);
    assert!(advance(&good).is_ok());
    let reissue = |frozen_leaf: [u8; 32], record: Vec<u8>| {
        let mut ancestry = AncestryResponse {
            epoch: 3,
            root: [5; 32],
            frozen_leaf,
            signature: [0; 64],
            record,
        };
        let bytes = super::super::response::ancestry_body(&public, proof.scope(), &ancestry, at)
            .bytes()
            .unwrap();
        let signature: p256::ecdsa::Signature = issuer().sign(&bytes);
        ancestry.signature = low_s(signature);
        let mut response = good.clone();
        response.ancestry = Some(ancestry);
        response
    };
    let (frozen_leaf, record) = join_record(&public);
    let mut signed: czkp::record::SignedLeaf = serde_json::from_slice(&record).unwrap();
    // A tampered Ed25519 signature over the same leaf and commitment.
    signed.signature[0] ^= 1;
    assert!(advance(&reissue(frozen_leaf, serde_json::to_vec(&signed).unwrap())).is_err());
    // A leaf signed under another record-issuer key.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[20; 32]);
    let leaf = join_leaf(&public);
    let commitment = leaf.commitment(&public.community, 3).unwrap();
    let stranger_sig = stranger
        .sign(&czkp::record::certificate_bytes(&public.community, 3, &commitment).unwrap())
        .to_bytes()
        .to_vec();
    let stranger_record = serde_json::to_vec(&czkp::record::SignedLeaf {
        leaf,
        signature: stranger_sig,
    })
    .unwrap();
    assert!(advance(&reissue(commitment, stranger_record)).is_err());
    // A wrong epoch issuer key in the trust refuses the genuine leaf.
    let mut wrong_trust = live.clone();
    wrong_trust.frontier.as_mut().unwrap().issuer_key = [9; 32];
    assert!(
        engine
            .advance_pending(&sent, &good, &wrong_trust, 102)
            .is_err()
    );
}

/// The delivered join record is offered for exactly its epoch; an acceptance
/// without a record (an account with no join record) offers none.
#[test]
fn the_accepted_account_offers_its_join_record_for_exactly_its_epoch() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let live = trust(Some(frontier()));
    let with = response(&proof, &a.acceptance, 150, true);
    let accepted = engine.advance_pending(&sent, &with, &live, 102).unwrap();
    let activated = engine.activate_pending(&accepted, &live, 103).unwrap();
    let sealed = activated.seal_account(&engine).unwrap();
    let accepted = engine.restore_accepted_account(&sealed).unwrap();
    let leaf = accepted.delivered_record_leaf(3).unwrap();
    assert_eq!(leaf.leaf.owner, accepted.owner());
    assert_eq!(leaf.leaf.version, accepted.version());
    assert_eq!(leaf.leaf.state, accepted.state());
    // The next epoch takes the common download.
    assert!(accepted.delivered_record_leaf(4).is_none());
    let without = response(&proof, &a.acceptance, 150, false);
    let accepted = engine.advance_pending(&sent, &without, &live, 102).unwrap();
    let activated = engine.activate_pending(&accepted, &live, 103).unwrap();
    let sealed = activated.seal_account(&engine).unwrap();
    let accepted = engine.restore_accepted_account(&sealed).unwrap();
    assert!(accepted.delivered_record_leaf(3).is_none());
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
    // The witness seam rebuilds the same committed opening from the sealed blind.
    {
        let roster = std::sync::Arc::new(
            crate::account::witness::Checkpoint::from_rows(
                context.enrollment_root,
                vec![context.enrollment.clone()],
            )
            .unwrap(),
        );
        let witness = account.witness(roster).unwrap();
        assert_eq!(witness.state(), account.state());
        assert_eq!(witness.version(), 0);
    }
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

/// An operator-signed owner-lookup status that reports no account, built from the
/// Balance wire formats independently of the engine's own encoder.
fn absence(
    community: [u8; 32],
    owner: [u8; 32],
    observed_at: u64,
    key: &OperatorKey,
) -> OwnerAbsence {
    use sha2::{Digest as _, Sha256};
    let device = OperatorKey::from_bytes(&[9; 32]);
    let (issued_at, expires_at) = (observed_at - 10, observed_at + 90);
    let mut request = b"cfrm.account.status.v1\0".to_vec();
    request.extend_from_slice(&community);
    request.extend_from_slice(&owner);
    request.push(0);
    request.extend_from_slice(&[0; 32]);
    request.extend_from_slice(&[3; 32]);
    request.extend_from_slice(&device.verifying_key().to_bytes());
    request.extend_from_slice(&issued_at.to_be_bytes());
    request.extend_from_slice(&expires_at.to_be_bytes());
    let request_signature = device.sign(&request).to_bytes();
    let digest: [u8; 32] = Sha256::digest([request, request_signature.to_vec()].concat()).into();
    let mut response = b"cfrm.account.status-response.v1\0".to_vec();
    response.extend_from_slice(&digest);
    response.extend_from_slice(&observed_at.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&[0; 32]);
    OwnerAbsence {
        community,
        owner,
        challenge: [3; 32],
        chat_public_key: device.verifying_key().to_bytes(),
        issued_at,
        expires_at,
        request_signature,
        observed_at,
        signature: key.sign(&response).to_bytes(),
    }
}

#[test]
fn an_elapsed_state_a_is_discardable_only_on_the_operators_own_late_no_account_status() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let public = proof.public_genesis();
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    // Statement time 101, horizon 200; the request expired at 150.
    let expires = 150;
    let due = expires + GENESIS_DISCARD_COMMIT_MARGIN_SECONDS;
    let good = absence(public.community, public.owner, due, &operator());
    let (_, binding) = engine.check_elapsed_pending(&sent, expires, &good).unwrap();
    assert!(binding == real_binding());
    // Only operator times decide: one second before the margin refuses. No local
    // clock exists in this check, so a device clock far ahead cannot help; the
    // ordinary reopen at that far-ahead time refuses on the horizon instead.
    let early = absence(public.community, public.owner, due - 1, &operator());
    assert!(
        engine
            .check_elapsed_pending(&sent, expires, &early)
            .is_err()
    );
    assert!(engine.restore_pending_genesis(&sent, u64::MAX).is_err());
    assert!(engine.check_elapsed_pending(&sent, expires, &good).is_ok());
    // The observation must be about this owner and community.
    let other = absence(public.community, [0xEE; 32], due, &operator());
    assert!(
        engine
            .check_elapsed_pending(&sent, expires, &other)
            .is_err()
    );
    let other = absence([0xEE; 32], public.owner, due, &operator());
    assert!(
        engine
            .check_elapsed_pending(&sent, expires, &other)
            .is_err()
    );
    // Signed under the sealed operator key only, over the exact values.
    let foreign = absence(
        public.community,
        public.owner,
        due,
        &OperatorKey::from_bytes(&[6; 32]),
    );
    assert!(
        engine
            .check_elapsed_pending(&sent, expires, &foreign)
            .is_err()
    );
    for tamper in [
        |a: &mut OwnerAbsence| a.observed_at += 1,
        |a: &mut OwnerAbsence| a.challenge = [4; 32],
        |a: &mut OwnerAbsence| a.issued_at -= 1,
        |a: &mut OwnerAbsence| a.request_signature[0] ^= 1,
    ] {
        let mut bad = good.clone();
        tamper(&mut bad);
        assert!(engine.check_elapsed_pending(&sent, expires, &bad).is_err());
    }
    // The stored expiry is bounded by the sealed statement and horizon.
    for bad in [public.now, public.valid_until + 1] {
        let late = absence(
            public.community,
            public.owner,
            bad + GENESIS_DISCARD_COMMIT_MARGIN_SECONDS,
            &operator(),
        );
        assert!(engine.check_elapsed_pending(&sent, bad, &late).is_err());
    }
    // State B (a verified acceptance) is never discardable.
    let live = trust(None);
    let accepted_response = response(&proof, &real_binding().acceptance, 120, false);
    let accepted = engine
        .advance_pending(&sent, &accepted_response, &live, 102)
        .unwrap();
    assert!(
        engine
            .check_elapsed_pending(&accepted, expires, &good)
            .is_err()
    );
    // Another engine cannot open the row at all.
    let foreign_engine =
        Engine::from_seed_and_sealing_key(&mut [6; 32], &mut [8; 32], b"community").unwrap();
    assert!(
        foreign_engine
            .check_elapsed_pending(&sent, expires, &good)
            .is_err()
    );
}

/// Row 16, the fixed case: a newcomer whose first genesis is accepted after the
/// record freeze. The community may certify the join-time record leaf only under
/// its published epoch; its own signed material on the response names that epoch
/// (`ResponseTrust.join`), and the acceptance advances and activates under it
/// even though the newcomer has no frozen frontier.
#[test]
fn a_first_genesis_after_the_freeze_advances_under_the_published_join_descriptor() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust_both(None, Some(join_epoch(3, [5; 32])));
    let accepted = engine
        .advance_pending(&sent, &good, &live, 102)
        .expect("a join ancestry under the published descriptor advances");
    // Activation re-verifies the stored response under the same trust.
    assert_eq!(
        engine
            .activate_pending(&accepted, &live, 103)
            .unwrap()
            .accepted_at(),
        150
    );
    // The stored response still refreshes the join record for its epoch.
    let sealed = engine
        .activate_pending(&accepted, &live, 103)
        .unwrap()
        .seal_account(&engine)
        .unwrap();
    let account = engine.restore_accepted_account(&sealed).unwrap();
    assert_eq!(
        account.delivered_record_leaf(3).unwrap().leaf.owner,
        account.owner()
    );
}

/// A tampered ancestry signature, or a tampered join-record signature, is refused
/// for a join ancestry exactly as under a frozen frontier.
#[test]
fn a_join_ancestry_with_a_tampered_signature_is_invalid() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let live = trust_both(None, Some(join_epoch(3, [5; 32])));
    let advance = |response: &AcceptedResponse| engine.advance_pending(&sent, response, &live, 102);
    assert!(advance(&good).is_ok());
    // The issuer's P-256 signature over the ancestry transcript.
    let mut bad = good.clone();
    bad.ancestry.as_mut().unwrap().signature[0] ^= 1;
    assert!(advance(&bad).is_err());
    // The record issuer's Ed25519 signature over the join leaf.
    let mut bad = good.clone();
    let mut signed: czkp::record::SignedLeaf =
        serde_json::from_slice(&bad.ancestry.as_ref().unwrap().record).unwrap();
    signed.signature[0] ^= 1;
    bad.ancestry.as_mut().unwrap().record = serde_json::to_vec(&signed).unwrap();
    assert!(advance(&bad).is_err());
    // A join leaf signed under another epoch issuer key than the descriptor's.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[20; 32]);
    let leaf = join_leaf(&proof.public_genesis());
    let commitment = leaf
        .commitment(&proof.public_genesis().community, 3)
        .unwrap();
    let stranger_signature = stranger
        .sign(
            &czkp::record::certificate_bytes(&proof.public_genesis().community, 3, &commitment)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let mut bad = good.clone();
    bad.ancestry.as_mut().unwrap().record = serde_json::to_vec(&czkp::record::SignedLeaf {
        leaf,
        signature: stranger_signature,
    })
    .unwrap();
    assert!(advance(&bad).is_err());
}

/// The join ancestry must sit under exactly the descriptor the community
/// publication named: another epoch, another root, or another issuer key is refused.
#[test]
fn a_join_ancestry_not_under_the_published_descriptor_is_invalid() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    for join in [
        join_epoch(4, [5; 32]),
        join_epoch(3, [6; 32]),
        JoinEpoch {
            epoch: 3,
            root: [5; 32],
            issuer_key: [9; 32],
        },
        JoinEpoch {
            epoch: 0,
            root: [5; 32],
            issuer_key: record_issuer_key(),
        },
    ] {
        assert!(
            engine
                .advance_pending(&sent, &good, &trust_both(None, Some(join)), 102)
                .is_err()
        );
    }
}

/// Without a published descriptor no join ancestry may come: the arm stays
/// Invalid, and no frozen frontier stands in for it.
#[test]
fn a_join_ancestry_without_a_published_descriptor_is_invalid() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    assert!(
        engine
            .advance_pending(&sent, &good, &trust_both(None, None), 102)
            .is_err()
    );
}

/// The pre-freeze case is unchanged: a first genesis with no ancestry advances and
/// activates with no frontier and no join descriptor, and a join descriptor alone
/// binds nothing (no ancestry, nothing to check).
#[test]
fn a_first_genesis_before_the_freeze_is_unchanged() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let fresh = response(&proof, &a.acceptance, 150, false);
    for live in [
        trust_both(None, None),
        trust_both(None, Some(join_epoch(3, [5; 32]))),
        trust(Some(frontier())),
    ] {
        let accepted = engine
            .advance_pending(&sent, &fresh, &live, 102)
            .expect("a genesis before the freeze carries no ancestry and advances");
        assert_eq!(
            engine
                .activate_pending(&accepted, &live, 103)
                .unwrap()
                .accepted_at(),
            150
        );
    }
}

/// Review M4: a stored join is the descriptor this acceptance was ADMITTED under.
/// When the device's material later gains a frozen frontier of another epoch, the
/// activation still re-checks the stored response under that stored descriptor
/// (its epoch is the ancestry's), not under the newer frontier, which it can never
/// match.
#[test]
fn a_stored_join_activates_after_the_frontier_moved_to_another_epoch() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let accepted = engine
        .advance_pending(
            &sent,
            &good,
            &trust_both(None, Some(join_epoch(3, [5; 32]))),
            102,
        )
        .unwrap();
    let moved = Frontier {
        epoch: 4,
        root: [6; 32],
        issuer_key: record_issuer_key(),
    };
    for live in [
        trust_both(Some(moved.clone()), Some(join_epoch(3, [5; 32]))),
        // The stored descriptor is read from the sealed row, not from the trust.
        trust_both(Some(moved.clone()), None),
    ] {
        assert_eq!(
            engine
                .activate_pending(&accepted, &live, 103)
                .expect("the stored join decides for its own epoch")
                .accepted_at(),
            150
        );
    }
}

/// A frontier of the SAME epoch that disagrees with the stored join is a fork of
/// that epoch's descriptor: the activation refuses it instead of choosing one.
#[test]
fn a_stored_join_that_a_frontier_of_its_epoch_contradicts_is_invalid() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let good = response(&proof, &a.acceptance, 150, true);
    let accepted = engine
        .advance_pending(
            &sent,
            &good,
            &trust_both(None, Some(join_epoch(3, [5; 32]))),
            102,
        )
        .unwrap();
    for fork in [
        Frontier {
            epoch: 3,
            root: [6; 32],
            issuer_key: record_issuer_key(),
        },
        Frontier {
            epoch: 3,
            root: [5; 32],
            issuer_key: [9; 32],
        },
    ] {
        assert!(
            engine
                .activate_pending(&accepted, &trust(Some(fork)), 103)
                .is_err()
        );
    }
}

/// Only a sealed row carries a stored join: an advance never takes one from the
/// response it is handed, so a caller cannot smuggle a descriptor past the
/// publication the upper owner verified.
#[test]
fn an_advance_never_takes_a_join_from_the_response() {
    let (engine, context) = super::super::tests::fixture();
    let proof = proven(&engine, &context);
    let sent = proof.seal_pending(&engine, &real_binding()).unwrap();
    let (_, a) = engine.restore_pending_genesis(&sent, 102).unwrap();
    let mut smuggled = response(&proof, &a.acceptance, 150, true);
    smuggled.join = Some(join_epoch(3, [5; 32]));
    for live in [
        trust_both(None, None),
        trust_both(None, Some(join_epoch(3, [5; 32]))),
    ] {
        assert!(
            engine
                .advance_pending(&sent, &smuggled, &live, 102)
                .is_err()
        );
    }
}
