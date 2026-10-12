//! Real private constructor/hash/path preparation; no accepted grant or proof.
use super::*;
use czkp::poseidon::{integer, limbs};

fn engine(context: &[u8]) -> Engine {
    Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], context).unwrap()
}
fn context(engine: &Engine) -> GenesisContext {
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
        enrollment: Enrollment {
            member: [3; 32],
            key: [5; 64],
            secret_hash: hashes::secret(&community, &engine.seed).unwrap(),
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
    // This is explicitly public lower input, not a certificate or accepted owner.
    let row = &mut context.enrollment;
    let mut fields = [
        limbs(&community),
        limbs(&row.member),
        limbs(&[5; 32]),
        limbs(&[5; 32]),
    ]
    .concat();
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
    context
}

#[test]
fn original_genesis_is_a_private_candidate_and_engine_sealed_format_stays_uninitialized() {
    let engine = engine(b"community");
    let context = context(&engine);
    let sealed_before = engine.seal().unwrap();
    let prepared = engine.prepare_genesis(context.clone()).unwrap();
    prepared.check_context(&engine, &context, 101).unwrap();
    assert_eq!(prepared.opening.reserved, 0);
    assert_eq!(prepared.opening.standing.a, 2 << 16);
    assert_eq!(prepared.opening.standing.day, 0);
    assert_eq!(prepared.opening.created_at, 200);
    assert_eq!(prepared.opening.outgoing_count, 1);
    assert_eq!(prepared.opening.inbox, [0; 32]);
    assert_ne!(prepared.commitment, [0; 32]);
    assert!(engine.record.is_none());
    assert!(engine.restored(&sealed_before).unwrap().record.is_none());
    // Preparing did not add candidate bytes or an accepted-state tag to Engine.
    assert_eq!(
        sealed_before.as_bytes().len(),
        engine.seal().unwrap().as_bytes().len()
    );
}

#[test]
fn wrong_scope_owner_registered_secret_root_path_index_and_policy_refuse() {
    let engine = engine(b"community");
    let original = context(&engine);
    let mut changed = original.clone();
    changed.community_id = "other".into();
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.owner[0] ^= 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.enrollment.secret_hash[0] ^= 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.enrollment_root[0] ^= 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.enrollment.path[0][0] ^= 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.enrollment.index ^= 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.policy.rate_window = 0;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.extension.batch = 1;
    assert!(engine.prepare_genesis(changed).is_err());
    // Standing parameters must hash to the rulebook-signed digest.
    let mut changed = original.clone();
    changed.standing.n_half += 1;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.policy.rate_window = 86_401;
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.enrollment.path[0] = [0xff; 32];
    assert!(engine.prepare_genesis(changed).is_err());
    let mut changed = original.clone();
    changed.checked_at = changed.policy.policy_valid_until;
    assert!(engine.prepare_genesis(changed).is_err());
}

#[test]
fn private_candidate_fences_foreign_engine_context_clock_rollback_and_exact_deadline() {
    let engine = engine(b"community");
    let context = context(&engine);
    let prepared = engine.prepare_genesis(context.clone()).unwrap();
    let foreign =
        Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"community").unwrap();
    assert!(prepared.check_context(&foreign, &context, 101).is_err());
    let mut changed = context.clone();
    changed.extension.quorum += 1;
    assert!(prepared.check_context(&engine, &changed, 101).is_err());
    prepared.check_context(&engine, &context, 102).unwrap();
    assert!(prepared.check_context(&engine, &context, 101).is_err());
    assert!(prepared.check_context(&engine, &context, 102).is_err());
    let prepared = engine.prepare_genesis(context.clone()).unwrap();
    assert!(prepared.check_context(&engine, &context, 200).is_err());
    assert!(prepared.check_context(&engine, &context, 199).is_err());
}
