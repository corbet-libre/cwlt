//! Real receipt-installed key consistency; these public rows grant no admission.
use super::*;
use ckmg::wallet_engine::account::{AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext};
use czkp::poseidon::{hash, integer, limbs};

fn tagged(domain: &[u8], tag: u64, fields: &[[u8; 32]]) -> [u8; 32] {
    let mut prefix = [0; 32];
    prefix[32 - domain.len()..].copy_from_slice(domain);
    let mut input = vec![prefix, integer(tag)];
    input.extend_from_slice(fields);
    hash(&input).unwrap()
}
fn context(owner: &DurableAccountOwner, store: &Store<Controlled>) -> GenesisContext {
    let projection = owner.projection(&engine(), store).unwrap();
    let community = czkp::decode(&czkp::digest(SCOPE.as_bytes())).unwrap();
    let mut row = Enrollment {
        member: [3; 32],
        key: projection.public_key,
        secret_hash: projection.registered_secret,
        starts_at: 1,
        expires_at: 9000,
        delegation_digest: [4; 32],
        leaf: [0; 32],
        index: 0,
        path: [[0; 32]; 32],
    };
    let x: [u8; 32] = row.key[..32].try_into().unwrap();
    let y: [u8; 32] = row.key[32..].try_into().unwrap();
    let mut fields = [limbs(&community), limbs(&row.member), limbs(&x), limbs(&y)].concat();
    fields.extend([
        row.secret_hash,
        integer(row.starts_at),
        integer(row.expires_at),
    ]);
    fields.extend(limbs(&row.delegation_digest));
    row.leaf = tagged(b"cfrm.account-state.v2", 1, &fields);
    let mut root = row.leaf;
    for sibling in row.path {
        root = tagged(b"cfrm.accounting.poseidon2.v1", 6, &[root, sibling]);
    }
    GenesisContext {
        community_id: SCOPE.into(),
        owner: row.member,
        enrollment: row,
        enrollment_root: root,
        checked_at: 101,
        policy: AccountPolicy {
            initial_credit: 20,
            maximum_available: 100,
            outgoing_reservation: 5,
            incoming_reservation: 5,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 10000,
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
        },
    }
}

#[test]
fn exact_durable_key_prepares_without_write_and_keeps_original_engine_binding() {
    block_on(async {
        let backend = Controlled::new();
        let mut store = Store::create(backend.clone(), &cipher(), SCOPE)
            .await
            .unwrap();
        let owner = begin(&store, [31; 32]).commit(&mut store).await.unwrap();
        let context = context(&owner, &store);
        let before = backend.actual.read().await.unwrap();
        let candidate = owner
            .prepare_genesis(engine(), &store, context.clone(), 101)
            .unwrap();
        candidate
            .check_current(&owner, &engine(), &store, &context, 101)
            .unwrap();
        assert_eq!(backend.actual.read().await.unwrap(), before);
        // An unrelated genuine Store mutation preserves the same capsule/receipt.
        store
            .commit_with_receipt(
                store.version().unwrap(),
                [32; 32],
                &[Change::Put {
                    owner: "fixture",
                    key: b"unrelated",
                    value: b"data",
                }],
                &[],
            )
            .await
            .unwrap();
        candidate
            .check_current(&owner, &engine(), &store, &context, 102)
            .unwrap();
        assert!(
            candidate
                .check_current(&owner, &engine(), &store, &context, 101)
                .is_err()
        );
        assert!(
            candidate
                .check_current(&owner, &engine(), &store, &context, 103)
                .is_err()
        );
    });
}

#[test]
fn foreign_scope_key_secret_and_expiry_refuse_without_mutation() {
    block_on(async {
        let backend = Controlled::new();
        let mut store = Store::create(backend.clone(), &cipher(), SCOPE)
            .await
            .unwrap();
        let owner = begin(&store, [33; 32]).commit(&mut store).await.unwrap();
        let original = context(&owner, &store);
        let before = backend.actual.read().await.unwrap();
        for field in 0..3 {
            let mut changed = original.clone();
            match field {
                0 => changed.community_id = "foreign".into(),
                1 => changed.enrollment.key[0] ^= 1,
                _ => changed.enrollment.secret_hash[0] ^= 1,
            }
            assert!(
                owner
                    .prepare_genesis(engine(), &store, changed, 101)
                    .is_err()
            );
        }
        assert!(
            owner
                .prepare_genesis(engine(), &store, original.clone(), 200)
                .is_err()
        );
        let candidate = owner
            .prepare_genesis(engine(), &store, original.clone(), 101)
            .unwrap();
        let foreign =
            Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [9; 32], SCOPE.as_bytes())
                .unwrap();
        assert!(
            candidate
                .check_current(&owner, &foreign, &store, &original, 101)
                .is_err()
        );
        assert!(
            candidate
                .check_current(&owner, &engine(), &store, &original, 102)
                .is_err()
        );
        assert_eq!(backend.actual.read().await.unwrap(), before);
    });
}

#[test]
fn actual_capsule_replacement_fences_the_candidate_permanently() {
    block_on(async {
        let backend = Controlled::new();
        let mut store = Store::create(backend, &cipher(), SCOPE).await.unwrap();
        let owner = begin(&store, [34; 32]).commit(&mut store).await.unwrap();
        let context = context(&owner, &store);
        let original = store
            .read("cwlt.account", b"owner.v1")
            .unwrap()
            .unwrap()
            .to_vec();
        let candidate = owner
            .prepare_genesis(engine(), &store, context.clone(), 101)
            .unwrap();
        store
            .commit_with_receipt(
                store.version().unwrap(),
                [35; 32],
                &[Change::Put {
                    owner: "cwlt.account",
                    key: b"owner.v1",
                    value: b"foreign capsule",
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(
            candidate
                .check_current(&owner, &engine(), &store, &context, 102)
                .is_err()
        );
        store
            .commit_with_receipt(
                store.version().unwrap(),
                [36; 32],
                &[Change::Put {
                    owner: "cwlt.account",
                    key: b"owner.v1",
                    value: &original,
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(
            candidate
                .check_current(&owner, &engine(), &store, &context, 103)
                .is_err()
        );
    });
}
