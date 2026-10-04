#![cfg(feature = "record")]
use cwlt::record::DurableRecord;
use cwlt_engine::Engine;
use cwst::{Store, backend::Memory};
use czkp::record::{Context, Epoch, Purpose, Record, Use, presentation_key_commitment};

fn engine() -> Engine {
    Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"record-store-fixture").unwrap()
}
fn epoch() -> Epoch {
    Epoch {
        purpose: Purpose::RecordEpochV1,
        community: [1; 32],
        policy_epoch: 1,
        epoch: 2,
        starts_at: 200,
        expires_at: 300,
        root: [2; 32],
        proof_scope: czkp::ProofScope {
            circuit_digest: [3; 32],
            verifying_key_digest: [4; 32],
        },
        leaf_count: 2,
        download_digest: [5; 32],
        download_bytes: 1000,
    }
}
#[test]
fn committed_cache_reopens_and_conflicting_or_locked_store_refuses() {
    futures::executor::block_on(async {
        let scope = "record-store-fixture";
        let cipher = ckmg::passkey::store_cipher(
            &ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap(),
            scope,
        )
        .unwrap();
        let backend = Memory::new();
        let mut store = Store::create(backend.clone(), &cipher, scope)
            .await
            .unwrap();
        assert!(DurableRecord::open(engine(), &store, scope).is_err());
        let mut wallet = DurableRecord::create(engine(), &mut store, scope, [1; 32])
            .await
            .unwrap();
        let epoch = epoch();
        let context = Context {
            purpose: Use::ForumListing,
            challenge: [10; 32],
            expires_at: 250,
        };
        assert!(wallet.present(&store, &epoch, &context, 210).is_err());
        let public = wallet
            .begin_epoch(&mut store, &epoch, [6; 32], 210, [2; 32])
            .await
            .unwrap();
        let record = Record {
            epoch: epoch.clone(),
            owner: [6; 32],
            presentation_key_commitment: presentation_key_commitment(&public),
            shares: None,
        };
        let stale = DurableRecord::open(engine(), &store, scope).unwrap();
        // Storage fixture bytes grant no proof authority. The real-proof suite
        // separately checks original issuer proof verification and replay.
        wallet
            .finish_epoch(&mut store, record, "aabb".into(), [3; 32])
            .await
            .unwrap();
        assert!(wallet.ready(&store, &epoch, 211).unwrap());
        assert!(stale.present(&store, &epoch, &context, 211).is_err());
        let original = wallet.present(&store, &epoch, &context, 211).unwrap();
        drop(wallet);
        drop(store);
        let mut store = Store::open(backend, &cipher, scope).await.unwrap();
        let wallet = DurableRecord::open(engine(), &store, scope).unwrap();
        assert!(DurableRecord::open(engine(), &store, "other").is_err());
        let restored = wallet.present(&store, &epoch, &context, 212).unwrap();
        assert_eq!(original.proof, restored.proof);
        assert_eq!(original.public_key, restored.public_key);
        restored
            .check_binding(&context, &epoch, &[6; 32], 212)
            .unwrap();
        assert!(wallet.present(&store, &epoch, &context, 300).is_err());
        store.lock_in_place();
        assert!(wallet.present(&store, &epoch, &context, 213).is_err());
    });
}
