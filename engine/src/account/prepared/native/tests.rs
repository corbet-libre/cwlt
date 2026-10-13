//! Actual original Noir/BB proof conformance over fictional cryptographic inputs.
//! This does not authenticate a grant, certificate, accepted account or receipt.
use super::*;
use crate::account::hashes;
use czkp::poseidon::{integer, limbs};

/// Fictional but original-relation-consistent engine and public context.
pub(super) fn fixture() -> (Engine, GenesisContext) {
    let engine =
        Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"community").unwrap();
    let key = engine.prepare_account_key("community", [1; 32]).unwrap();
    let projection = key.projection(&engine).unwrap();
    let community = hashes::digest(b"community").unwrap();
    let mut context = GenesisContext {
        community_id: "community".into(),
        owner: [3; 32],
        policy: AccountPolicy {
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
        },
        extension: ExtensionPolicy {
            revision: 1,
            quorum: 2,
            change_cost: 1,
            delay: 100,
            batch: 2,
            standing: ExtensionPolicy::standing_digest(czkp::standing::Params::default()).unwrap(),
        },
        standing: czkp::standing::Params::default(),
        bond: None,
        enrollment: Enrollment {
            member: [3; 32],
            key: projection.public_key,
            secret_hash: projection.registered_secret,
            starts_at: 1,
            expires_at: 9000,
            delegation_digest: [4; 32],
            leaf: [0; 32],
            index: 3,
            path: [[0; 32]; 32],
        },
        enrollment_root: [0; 32],
        checked_at: 101,
    };
    // Original maintained hash/path relation. The fictional root is public data,
    // not a fabricated issuer verdict or current enrollment source.
    let row = &mut context.enrollment;
    let x = row.key[..32].try_into().unwrap();
    let y = row.key[32..].try_into().unwrap();
    let mut fields = [limbs(&community), limbs(&row.member), limbs(&x), limbs(&y)].concat();
    fields.extend([
        row.secret_hash,
        integer(row.starts_at),
        integer(row.expires_at),
    ]);
    fields.extend(limbs(&row.delegation_digest));
    row.leaf = hashes::hash(1, &fields).unwrap();
    let mut root = row.leaf;
    let mut index = row.index;
    for sibling in row.path {
        root = if index & 1 == 0 {
            hashes::enrollment_node(root, sibling)
        } else {
            hashes::enrollment_node(sibling, root)
        }
        .unwrap();
        index >>= 1;
    }
    context.enrollment_root = root;
    (engine, context)
}

#[test]
fn original_update_proves_genesis_and_retains_same_private_candidate_without_adoption() {
    let (engine, context) = fixture();
    let candidate = engine.prepare_genesis(context.clone()).unwrap();
    let opening = zeroize::Zeroizing::new(candidate.opening.blind);
    let prover = NativeProver::new(crate::native_prover::tests::config()).unwrap();
    let proof = candidate.prove(&engine, &prover, || Ok(101)).unwrap();
    assert_eq!(proof.public_inputs().len(), 410);
    assert!(!proof.proof().is_empty());
    assert_eq!(
        proof.scope().circuit_digest.to_vec(),
        data_encoding::HEXLOWER
            .decode(b"89609daca158496d5fc7b028b89d33f6b72d7804ccc199125c7f8bb2b6259938")
            .unwrap()
    );
    assert!(
        proof.candidate.opening.blind == *opening,
        "same private candidate retained"
    );
    assert!(engine.record.is_none());
    proof.check_context(&engine, &context, 102).unwrap();
    assert!(proof.check_context(&engine, &context, 101).is_err());
    assert!(proof.check_context(&engine, &context, 102).is_err());
}
