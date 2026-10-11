//! Original encrypted holder record composition; no enrollment authority fixture.
#![cfg(feature = "passport")]
use crate::passport::{
    CommunityId, DurableHolder, Holder,
    rand::{SeedableRng, rngs::StdRng},
};
use cwst::{
    Change, Store,
    backend::{Backend, Memory},
};
use std::{cell::Cell, rc::Rc};

fn holder() -> Holder {
    Holder(
        cpsd::OpaqueHolder::from_seed_and_sealing_key(&mut [31; 32], &mut [32; 32], b"wallet")
            .unwrap(),
    )
}
fn cipher() -> ckmg::passkey::StoreCipher {
    ckmg::passkey::store_cipher(
        &ckmg::passkey::PrfOutput::from_bytes(&[32; 32]).unwrap(),
        "wallet",
    )
    .unwrap()
}

#[test]
fn initial_record_binds_exact_scope_snapshot_operation_and_actual_receipt() {
    futures::executor::block_on(async {
        let cipher = cipher();
        let backend = Memory::new();
        let mut store = Store::create(backend.clone(), &cipher, "wallet")
            .await
            .unwrap();
        let mut rng = StdRng::seed_from_u64(31);
        assert!(
            DurableHolder::prepare_initial(holder(), &store, "other", [1; 32], &mut rng).is_err()
        );
        assert!(
            DurableHolder::prepare_initial(holder(), &store, "wallet", [0; 32], &mut rng).is_err()
        );
        let candidate =
            DurableHolder::prepare_initial(holder(), &store, "wallet", [1; 32], &mut rng).unwrap();
        assert!(candidate.change_for(&store, &[2; 32]).is_err());
        assert!(DurableHolder::open(holder(), &store, "wallet").is_err());
        let change = candidate.change_for(&store, &[1; 32]).unwrap();
        let (owner, key, digest) = match &change {
            Change::Put { owner, key, value } => (*owner, *key, *blake3::hash(value).as_bytes()),
            _ => unreachable!(),
        };
        let receipt = store
            .commit_with_receipt(
                0,
                [1; 32],
                &[
                    change,
                    Change::Put {
                        owner: "fixture-companion",
                        key: b"same-batch",
                        value: b"original-public-data",
                    },
                ],
                &[],
            )
            .await
            .unwrap();
        assert!(receipt.is_commit(&store, &[1; 32]));
        assert!(receipt.contains_record(owner, key, &digest));
        assert!(candidate.change_for(&store, &[1; 32]).is_err());
        assert!(
            DurableHolder::prepare_initial(holder(), &store, "wallet", [3; 32], &mut rng).is_err()
        );
        let nym = DurableHolder::open(holder(), &store, "wallet")
            .unwrap()
            .session(&store)
            .unwrap()
            .pseudonym(&CommunityId::new(b"alpha").unwrap());
        drop(store);
        let reopened = Store::open(backend, &cipher, "wallet").await.unwrap();
        assert_eq!(
            reopened.read("fixture-companion", b"same-batch").unwrap(),
            Some(b"original-public-data".as_slice())
        );
        assert_eq!(
            DurableHolder::open(holder(), &reopened, "wallet")
                .unwrap()
                .session(&reopened)
                .unwrap()
                .pseudonym(&CommunityId::new(b"alpha").unwrap()),
            nym
        );
        assert!(
            DurableHolder::open(
                Holder(
                    cpsd::OpaqueHolder::from_seed_and_sealing_key(
                        &mut [31; 32],
                        &mut [33; 32],
                        b"wallet"
                    )
                    .unwrap()
                ),
                &reopened,
                "wallet"
            )
            .is_err()
        );
    });
}

#[derive(Clone)]
struct Interrupted {
    backend: Memory,
    mode: Rc<Cell<u8>>,
}
impl Backend for Interrupted {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.backend.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        if self.mode.get() == 1 {
            futures::future::pending::<()>().await;
        }
        self.backend.compare_exchange(expected, next).await?;
        if self.mode.get() == 2 {
            futures::future::pending::<()>().await;
        }
        if self.mode.get() == 3 {
            return Err(cwst::Error::Uncertain);
        }
        Ok(())
    }
}

#[test]
fn canceled_or_unknown_initial_batch_reopens_only_actual_committed_holder() {
    use futures::FutureExt as _;
    futures::executor::block_on(async {
        for mode in [1, 2, 3] {
            let cipher = cipher();
            let backend = Interrupted {
                backend: Memory::new(),
                mode: Rc::new(Cell::new(0)),
            };
            let mut store = Store::create(backend.clone(), &cipher, "wallet")
                .await
                .unwrap();
            let mut rng = StdRng::seed_from_u64(34);
            let candidate =
                DurableHolder::prepare_initial(holder(), &store, "wallet", [1; 32], &mut rng)
                    .unwrap();
            let changes = [candidate.change_for(&store, &[1; 32]).unwrap()];
            backend.mode.set(mode);
            let result = store
                .commit_with_receipt(0, [1; 32], &changes, &[])
                .now_or_never();
            if mode == 3 {
                assert!(matches!(result, Some(Err(cwst::Error::Uncertain))));
            } else {
                assert!(result.is_none());
            }
            assert!(candidate.change_for(&store, &[1; 32]).is_err());
            backend.mode.set(0);
            let reopened = Store::open(backend, &cipher, "wallet").await.unwrap();
            assert_eq!(
                DurableHolder::open(holder(), &reopened, "wallet").is_ok(),
                mode != 1
            );
            assert_eq!(reopened.version().unwrap(), u64::from(mode != 1));
        }
    });
}
