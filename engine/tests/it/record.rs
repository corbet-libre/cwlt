//! Record presentation validation and engine custody scenarios.

use cwlt_engine::{Engine, Sealed};
use czkp::record::{Context, Epoch, Purpose, Record, Use, presentation_key};
fn engine() -> Engine {
    Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"record-fixture").unwrap()
}
fn epoch() -> Epoch {
    Epoch {
        purpose: Purpose::RecordEpochV3,
        community: [1; 32],
        policy_epoch: 1,
        epoch: 2,
        starts_at: 200,
        expires_at: 300,
        root: [2; 32],
        issuer_key: ed25519_dalek::SigningKey::from_bytes(&[19; 32])
            .verifying_key()
            .to_bytes(),
        proof_scope: czkp::ProofScope {
            circuit_digest: [3; 32],
            verifying_key_digest: [4; 32],
        },
        leaf_count: 2,
        download_digest: [5; 32],
        download_bytes: 1000,
    }
}
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn epoch_key_cache_is_sealed_and_restored_without_proving() {
    let epoch = epoch();
    let context = Context {
        purpose: Use::ForumListing,
        challenge: [9; 32],
        expires_at: 250,
    };
    let mut holder = engine();
    assert!(holder.present_record(&epoch, &context, 210).is_err());
    let public = holder.begin_record_epoch(&epoch, [6; 32], 210).unwrap();
    assert!(!holder.record_ready(&epoch, 210));
    assert!(holder.present_record(&epoch, &context, 210).is_err());
    let sealed = holder.seal().unwrap();
    let mut holder = engine()
        .restored(&Sealed::from_bytes(sealed.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(
        public,
        holder.begin_record_epoch(&epoch, [6; 32], 211).unwrap()
    );
    let record = Record {
        epoch: epoch.clone(),
        owner: [6; 32],
        presentation_key: presentation_key(&public),
        blinded_leaf: [1; 32],
        certificate: ed25519_dalek::Signer::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[19; 32]),
            &czkp::record::certificate_bytes(&[1; 32], 2, &[1; 32]).unwrap(),
        )
        .to_bytes()
        .to_vec(),
        shares: None,
    };
    assert!(
        holder
            .cache_record_proof(record.clone(), String::new())
            .is_err()
    );
    // This tests storage and signing only; these bytes are not a valid ZK proof.
    holder
        .cache_record_proof(record.clone(), "aabb".into())
        .unwrap();
    assert!(
        holder
            .cache_record_proof(record.clone(), "aacc".into())
            .is_err()
    );
    let sealed = holder.seal().unwrap();
    let restored = engine().restored(&sealed).unwrap();
    assert!(restored.record_ready(&epoch, 212));
    let presentation = restored.present_record(&epoch, &context, 212).unwrap();
    presentation
        .check_binding(&context, &epoch, &[6; 32], 212)
        .unwrap();
    let mut next_context = context.clone();
    next_context.challenge[0] ^= 1;
    let second = restored.present_record(&epoch, &next_context, 213).unwrap();
    assert_eq!(presentation.proof, second.proof);
    assert_ne!(presentation.signature, second.signature);
    assert!(
        presentation
            .check_binding(&next_context, &epoch, &[6; 32], 213)
            .is_err()
    );
    assert!(restored.present_record(&epoch, &context, 300).is_err());
    let mut changed = epoch.clone();
    changed.root[0] ^= 1;
    assert!(holder.begin_record_epoch(&changed, [6; 32], 213).is_err());
    let mut next = epoch.clone();
    next.epoch += 1;
    next.starts_at += 100;
    next.expires_at += 100;
    let newer = holder.begin_record_epoch(&next, [6; 32], 310).unwrap();
    assert_ne!(public, newer);
    assert!(!holder.record_ready(&next, 310));
    assert!(holder.cache_record_proof(record, "aabb".into()).is_err());
    assert!(holder.begin_record_epoch(&epoch, [6; 32], 210).is_err());
    for offset in [0, sealed.as_bytes().len() / 2, sealed.as_bytes().len() - 1] {
        let mut bytes = sealed.as_bytes().to_vec();
        bytes[offset] ^= 1;
        if let Ok(bad) = Sealed::from_bytes(&bytes) {
            assert!(engine().restored(&bad).is_err());
        }
    }
}
