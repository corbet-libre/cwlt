//! Actual initial batch, cancellation and competing-clone receipt boundaries.
use super::*;

#[test]
fn initial_account_batch_restores_only_exact_durable_winner() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        let mut clone = Store::open(backend.clone(), &cipher, SCOPE).await.unwrap();
        let operation = [41; 32];
        let first =
            DurableAccountOwner::prepare_initial(engine(), &store, SCOPE, operation).unwrap();
        let second =
            DurableAccountOwner::prepare_initial(engine(), &clone, SCOPE, operation).unwrap();
        assert!(first.change_for(&store, &[42; 32]).is_err());
        assert!(DurableAccountOwner::open(engine(), &store, SCOPE).is_err());
        let change = first.change_for(&store, &operation).unwrap();
        let digest = match &change {
            Change::Put { value, .. } => *blake3::hash(value).as_bytes(),
            _ => unreachable!(),
        };
        let receipt = store
            .commit_with_receipt(
                0,
                operation,
                &[
                    change,
                    Change::Put {
                        owner: "fixture",
                        key: b"ack",
                        value: b"same original batch",
                    },
                ],
                &[],
            )
            .await
            .unwrap();
        assert!(receipt.is_commit(&store, &operation));
        assert!(receipt.contains_record("cwlt.account", b"owner.v1", &digest));
        let winner = DurableAccountOwner::open(engine(), &store, SCOPE)
            .unwrap()
            .projection(&engine(), &store)
            .unwrap();
        let loser = second.change_for(&clone, &operation).unwrap();
        assert!(matches!(
            clone.commit_with_receipt(0, operation, &[loser], &[]).await,
            Err(cwst::Error::Conflict)
        ));
        assert!(DurableAccountOwner::open(engine(), &clone, SCOPE).is_err());
        assert!(first.change_for(&store, &operation).is_err());
        assert!(DurableAccountOwner::prepare_initial(engine(), &store, SCOPE, [42; 32]).is_err());
        drop(store);
        let reopened = Store::open(backend, &cipher, SCOPE).await.unwrap();
        assert_eq!(
            reopened.read("fixture", b"ack").unwrap(),
            Some(b"same original batch".as_slice())
        );
        assert_eq!(
            DurableAccountOwner::open(engine(), &reopened, SCOPE)
                .unwrap()
                .projection(&engine(), &reopened)
                .unwrap(),
            winner
        );
        assert!(second.change_for(&reopened, &operation).is_err());
        let wrong =
            Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [11; 32], SCOPE.as_bytes())
                .unwrap();
        assert!(DurableAccountOwner::open(wrong, &reopened, SCOPE).is_err());
    });
}

#[test]
fn interrupted_initial_batch_preserves_actual_commit_and_never_returns_an_owner() {
    block_on(async {
        for mode in [1, 2, 3] {
            let backend = Controlled::new();
            let cipher = cipher();
            let mut store = Store::create(backend.clone(), &cipher, SCOPE)
                .await
                .unwrap();
            let before = backend.actual.read().await.unwrap();
            let operation = [43; 32];
            let candidate =
                DurableAccountOwner::prepare_initial(engine(), &store, SCOPE, operation).unwrap();
            let changes = [candidate.change_for(&store, &operation).unwrap()];
            backend.mode.set(mode);
            let mut commit = Box::pin(store.commit_with_receipt(0, operation, &changes, &[]));
            match commit
                .as_mut()
                .poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref()))
            {
                Poll::Pending => assert!(mode == 1 || mode == 2),
                Poll::Ready(result) => {
                    assert_eq!(mode, 3);
                    assert!(matches!(result, Err(cwst::Error::Uncertain)));
                }
            }
            drop(commit);
            assert!(DurableAccountOwner::open(engine(), &store, SCOPE).is_err());
            drop(store);
            backend.mode.set(0);
            let reopened = Store::open(backend.clone(), &cipher, SCOPE).await.unwrap();
            if mode == 1 {
                assert_eq!(backend.actual.read().await.unwrap(), before);
                assert!(DurableAccountOwner::open(engine(), &reopened, SCOPE).is_err());
            } else {
                assert!(candidate.change_for(&reopened, &operation).is_err());
                let receipt = reopened.receipt(&operation).unwrap();
                let bytes = reopened.read("cwlt.account", b"owner.v1").unwrap().unwrap();
                assert!(receipt.is_commit(&reopened, &operation));
                assert!(receipt.contains_record(
                    "cwlt.account",
                    b"owner.v1",
                    blake3::hash(bytes).as_bytes()
                ));
                let owner = DurableAccountOwner::open(engine(), &reopened, SCOPE).unwrap();
                assert_ne!(
                    owner.projection(&engine(), &reopened).unwrap().public_key,
                    [0; 64]
                );
            }
        }
    });
}
