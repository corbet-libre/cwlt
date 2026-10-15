use super::*;
use cpsd::rand::{SeedableRng, rngs::StdRng};

fn initial() -> Holder {
    // Known test inputs use the same original CPSD constructor that Keys calls
    // internally. No successful cipher, proof or Store implementation is mocked.
    Holder(
        cpsd::OpaqueHolder::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], b"wallet-test")
            .unwrap(),
    )
}
fn cipher() -> ckmg::passkey::StoreCipher {
    ckmg::passkey::store_cipher(
        &ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap(),
        "wallet-test",
    )
    .unwrap()
}

async fn round_trip<B: Backend + Clone>(backend: B) {
    let mut rng = StdRng::seed_from_u64(803);
    let cipher = cipher();
    let mut store = Store::create(backend.clone(), &cipher, "wallet-test")
        .await
        .unwrap();
    assert!(DurableHolder::open(initial(), &store, "wallet-test").is_err());
    let mut holder = DurableHolder::create(initial(), &mut store, "wallet-test", [1; 32], &mut rng)
        .await
        .unwrap();
    assert!(
        DurableHolder::create(initial(), &mut store, "wallet-test", [2; 32], &mut rng)
            .await
            .is_err()
    );
    assert!(holder.session(&store).unwrap().attributes().is_none());
    let issuer =
        cpsd::IssuerKey::generate(&mut rng, cpsd::KeyId::new("issuer").unwrap(), vec![]).unwrap();
    let challenge = IssuanceChallenge::generate(&mut rng);
    let candidate = holder
        .prepare_begin(&store, [3; 32], &mut rng, issuer.public_key(), &challenge)
        .unwrap();
    assert!(holder.session(&store).unwrap().attributes().is_none());
    let request = candidate
        .commit(
            &mut holder,
            &mut store,
            &[Change::Put {
                owner: "cvlt",
                key: b"lifecycle",
                value: b"issuance-pending",
            }],
            &[],
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.read("cvlt", b"lifecycle").unwrap(),
        Some(b"issuance-pending".as_slice())
    );
    drop(holder);
    drop(store);
    let mut store = Store::open(backend.clone(), &cipher, "wallet-test")
        .await
        .unwrap();
    let mut holder = DurableHolder::open(initial(), &store, "wallet-test").unwrap();
    let attributes = PassportAttributes::new(2000, 7);
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, &attributes)
        .unwrap();
    let pending = holder
        .prepare_finish(&store, [4; 32], &mut rng, &blind)
        .unwrap();
    assert!(holder.session(&store).unwrap().attributes().is_none());
    pending
        .commit(&mut holder, &mut store, &[], &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        holder.session(&store).unwrap().attributes(),
        Some(&attributes)
    );
    let nym = holder
        .session(&store)
        .unwrap()
        .pseudonym(&CommunityId::new(b"community").unwrap());

    // A competing real compound commit invalidates a staged candidate's base.
    let stale = holder.prepare_cancel(&store, [5; 32], &mut rng).unwrap();
    let base = store.version().unwrap();
    store
        .commit(
            base,
            [6; 32],
            &[Change::Put {
                owner: "cthr",
                key: b"thread",
                value: b"committed",
            }],
            &[],
        )
        .await
        .unwrap();
    assert!(
        stale
            .commit(&mut holder, &mut store, &[], &[])
            .await
            .is_err()
    );
    assert_eq!(
        holder.session(&store).unwrap().attributes(),
        Some(&attributes)
    );

    // Companion state cannot replace the private Wallet-owned namespace.
    let candidate = holder.prepare_cancel(&store, [7; 32], &mut rng).unwrap();
    assert!(
        candidate
            .commit(
                &mut holder,
                &mut store,
                &[Change::Delete {
                    owner: OWNER,
                    key: KEY,
                }],
                &[]
            )
            .await
            .is_err()
    );
    assert!(holder.prepare_cancel(&store, [0; 32], &mut rng).is_err());
    assert!(DurableHolder::open(initial(), &store, "other").is_err());

    store.lock_in_place();
    assert!(holder.session(&store).is_err());
    drop(holder);
    drop(store);
    let store = Store::open(backend, &cipher, "wallet-test").await.unwrap();
    let holder = DurableHolder::open(initial(), &store, "wallet-test").unwrap();
    assert_eq!(
        holder
            .session(&store)
            .unwrap()
            .pseudonym(&CommunityId::new(b"community").unwrap()),
        nym
    );
    assert_eq!(
        holder.session(&store).unwrap().attributes(),
        Some(&attributes)
    );
    // Execute the original authenticated proof after a genuine encrypted reopen.
    let mut signer = csgn::Signer::new(
        "community",
        csgn::SecretKey::from_seed(&mut [4; 32]),
        0,
        cpsd::TIME_LIMIT,
    )
    .unwrap();
    let community = CommunityId::new(b"community").unwrap();
    let request =
        cpsd::PresentationRequest::for_epoch(&mut rng, community.clone(), 7, [], 1000, 2000)
            .unwrap();
    let signed = signer
        .sign(csgn::Kind::Credential, &request.to_bytes(), 0, 1001)
        .unwrap();
    let expected =
        AuthenticatedCommunity::from_authenticated_origin(community, signer.key_ring().clone());
    let proof = holder
        .session(&store)
        .unwrap()
        .present(&mut rng, &expected, &signed, 1000)
        .unwrap();
    assert_eq!(
        cpsd::verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
        nym
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_memory_store_receipt_and_real_passport_round_trip() {
    futures::executor::block_on(round_trip(cwst::backend::Memory::new()));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn original_file_store_reopens_pending_and_installed_passport() {
    let directory = tempfile::tempdir().unwrap();
    futures::executor::block_on(round_trip(cwst::native::FileBackend::new(directory.path())));
}

#[derive(Clone)]
struct FaultAfterWrite {
    inner: cwst::backend::Memory,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
}
impl Backend for FaultAfterWrite {
    async fn read(&self) -> std::result::Result<Option<Vec<u8>>, cwst::Error> {
        self.inner.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> std::result::Result<(), cwst::Error> {
        // Real CAS happens first. Inject only lost reply/cancellation afterward;
        // no successful Store operation or encrypted checkpoint is fabricated.
        self.inner.compare_exchange(expected, next).await?;
        match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
            1 => Err(cwst::Error::Uncertain),
            2 => std::future::pending().await,
            _ => Ok(()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_and_cancelled_actual_writes_require_original_store_reopen() {
    futures::executor::block_on(async {
        for mode in [1, 2] {
            let mut rng = StdRng::seed_from_u64(804);
            let backend = FaultAfterWrite {
                inner: cwst::backend::Memory::new(),
                mode: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            };
            let cipher = cipher();
            let mut store = Store::create(backend.clone(), &cipher, "wallet-test")
                .await
                .unwrap();
            let mut holder =
                DurableHolder::create(initial(), &mut store, "wallet-test", [1; 32], &mut rng)
                    .await
                    .unwrap();
            let pending = holder.prepare_cancel(&store, [2; 32], &mut rng).unwrap();
            backend
                .mode
                .store(mode, std::sync::atomic::Ordering::SeqCst);
            if mode == 1 {
                assert!(
                    pending
                        .commit(&mut holder, &mut store, &[], &[])
                        .await
                        .is_err()
                );
            } else {
                let mut future = Box::pin(pending.commit(&mut holder, &mut store, &[], &[]));
                assert!(futures::poll!(future.as_mut()).is_pending());
                drop(future);
            }
            assert!(holder.session(&store).is_err());
            drop(store);
            backend.mode.store(0, std::sync::atomic::Ordering::SeqCst);
            let reopened = Store::open(backend, &cipher, "wallet-test").await.unwrap();
            assert_eq!(reopened.operation().unwrap(), [2; 32]);
            assert!(holder.session(&reopened).is_err());
            let restored = DurableHolder::open(initial(), &reopened, "wallet-test").unwrap();
            assert_eq!(
                restored.session(&reopened).unwrap().issuer_tag(),
                initial().0.issuer_tag()
            );
        }
    });
}

/// Human time: a stamp request the person is confirming survives a restart, and the stamp the
/// wallet answers with is presented after another reopen.
async fn stamp_round_trip<B: Backend + Clone>(backend: B) {
    const NOW: Timestamp = 3_600_200;
    let mut rng = StdRng::seed_from_u64(804);
    let cipher = cipher();
    let mut store = Store::create(backend.clone(), &cipher, "wallet-test")
        .await
        .unwrap();
    let mut holder = DurableHolder::create(initial(), &mut store, "wallet-test", [1; 32], &mut rng)
        .await
        .unwrap();
    let params = cpsd::StampParams::new(86_400).unwrap();
    let issuer =
        cpsd::StampIssuerKey::generate(&mut rng, cpsd::KeyId::new("stamp").unwrap(), &params)
            .unwrap();
    let challenge = IssuanceChallenge::generate(&mut rng);
    let scope = StampScope::new(
        CommunityId::new(b"community").unwrap(),
        CommunityFingerprint::from_bytes([3; 32]),
    );
    let action = StampAction::new(
        ActionKind::new("device_join").unwrap(),
        PayloadDigest::from_bytes([4; 32]),
        StampSalt::from_bytes([5; 32]),
    );
    let request = holder
        .prepare_begin_stamp(
            &store,
            [2; 32],
            &mut rng,
            issuer.public_key(),
            &challenge,
            &[(scope.clone(), action.clone())],
            NOW,
        )
        .unwrap()
        .commit(&mut holder, &mut store, &[], &[])
        .await
        .unwrap()
        .unwrap();
    // A second request waits until the pending one finishes or is cancelled.
    assert!(
        holder
            .prepare_begin_stamp(
                &store,
                [3; 32],
                &mut rng,
                issuer.public_key(),
                &challenge,
                &[(scope.clone(), action.clone())],
                NOW,
            )
            .unwrap()
            .commit(&mut holder, &mut store, &[], &[])
            .await
            .unwrap()
            .is_err()
    );
    drop(holder);
    drop(store);
    let mut store = Store::open(backend.clone(), &cipher, "wallet-test")
        .await
        .unwrap();
    let mut holder = DurableHolder::open(initial(), &store, "wallet-test").unwrap();
    assert!(
        !holder
            .session(&store)
            .unwrap()
            .stamp_covers(&scope, &action, NOW)
    );
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, 9, NOW)
        .unwrap();
    holder
        .prepare_finish_stamp(&store, [4; 32], &mut rng, &blind, NOW)
        .unwrap()
        .commit(&mut holder, &mut store, &[], &[])
        .await
        .unwrap()
        .unwrap();
    drop(holder);
    drop(store);
    let mut store = Store::open(backend, &cipher, "wallet-test").await.unwrap();
    let mut holder = DurableHolder::open(initial(), &store, "wallet-test").unwrap();
    let session = holder.session(&store).unwrap();
    assert!(session.stamp_covers(&scope, &action, NOW));
    let presentation = session
        .present_stamp(&mut rng, &scope, &action, NOW)
        .unwrap();
    let verified = cpsd::verify_stamp(
        &[issuer.public_key().clone()],
        &params,
        &scope,
        9,
        &action,
        &presentation,
        NOW,
    )
    .unwrap();
    let _ = verified;
    // Cancelling with nothing pending keeps the retained stamp.
    holder
        .prepare_cancel_stamp(&store, [5; 32], &mut rng)
        .unwrap()
        .commit(&mut holder, &mut store, &[], &[])
        .await
        .unwrap();
    assert!(
        holder
            .session(&store)
            .unwrap()
            .stamp_covers(&scope, &action, NOW)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_pending_stamp_and_its_stamp_survive_reopen() {
    futures::executor::block_on(stamp_round_trip(cwst::backend::Memory::new()));
}
