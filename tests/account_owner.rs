//! Actual encrypted Store receipt barriers for pending account-owner custody.
//! Memory supplies ephemeral storage evidence, never disk durability or admission.
#![cfg(feature = "account")]
use ckmg::wallet_engine::Engine;
use cwlt::account_owner::{DurableAccountOwner, PendingAccountCreation};
use cwst::{
    Change, Store,
    backend::{Backend, Memory},
};
use futures::{FutureExt, executor::block_on};
use std::{
    cell::Cell,
    rc::Rc,
    task::{Context, Poll},
};

const SCOPE: &str = "account-owner-fixture";
#[cfg(feature = "record")]
#[path = "account_owner/genesis.rs"]
mod genesis;
#[path = "account_owner/initial.rs"]
mod initial;
fn engine() -> Engine {
    Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [8; 32], SCOPE.as_bytes()).unwrap()
}
fn cipher() -> ckmg::passkey::StoreCipher {
    ckmg::passkey::store_cipher(
        &ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap(),
        SCOPE,
    )
    .unwrap()
}

#[derive(Clone)]
struct Controlled {
    actual: Memory,
    mode: Rc<Cell<u8>>,
}
impl Controlled {
    fn new() -> Self {
        Self {
            actual: Memory::new(),
            mode: Rc::new(Cell::new(0)),
        }
    }
}
impl Backend for Controlled {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.actual.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        let mode = self.mode.get();
        if mode == 1 {
            futures::future::pending::<()>().await;
        }
        self.actual.compare_exchange(expected, next).await?;
        if mode == 2 {
            futures::future::pending::<()>().await;
        }
        if mode == 3 {
            return Err(cwst::Error::Uncertain);
        }
        Ok(())
    }
}
fn begin(store: &Store<Controlled>, operation: [u8; 32]) -> PendingAccountCreation {
    DurableAccountOwner::prepare(engine(), store, SCOPE, operation).unwrap()
}

#[test]
fn original_receipt_installs_once_and_equal_key_reopens_same_public_owner() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        assert!(DurableAccountOwner::open(engine(), &store, SCOPE).is_err());
        assert!(DurableAccountOwner::prepare(engine(), &store, SCOPE, [0; 32]).is_err());
        let mut pending = begin(&store, [1; 32]);
        let hash = pending.sealed_digest();
        let owner = pending.commit(&mut store).await.unwrap();
        assert!(pending.commit(&mut store).await.is_err());
        let receipt = store.receipt(&[1; 32]).unwrap();
        assert!(receipt.is_commit(&store, &[1; 32]));
        assert!(receipt.contains_record("cwlt.account", b"owner.v1", &hash));
        let public = owner.projection(&engine(), &store).unwrap();
        assert_eq!(public.public_key.len(), 64);
        assert_ne!(public.registered_secret, [0; 32]);
        assert!(DurableAccountOwner::prepare(engine(), &store, SCOPE, [2; 32]).is_err());
        drop(owner);
        drop(store);
        let mut reopened = Store::open(backend, &cipher, SCOPE).await.unwrap();
        let restored = DurableAccountOwner::open(engine(), &reopened, SCOPE).unwrap();
        assert_eq!(restored.projection(&engine(), &reopened).unwrap(), public);
        reopened.lock_in_place();
        assert!(restored.projection(&engine(), &reopened).is_err());
    });
}

#[test]
fn cancellation_before_cas_has_no_projection_and_cannot_regenerate_or_retry() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        let before = backend.actual.read().await.unwrap();
        let mut pending = begin(&store, [3; 32]);
        let original_hash = pending.sealed_digest();
        backend.mode.set(1);
        let mut future = Box::pin(pending.commit(&mut store));
        assert!(matches!(
            future
                .as_mut()
                .poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())),
            Poll::Pending
        ));
        drop(future);
        assert_eq!(pending.operation(), [3; 32]);
        assert_eq!(pending.sealed_digest(), original_hash);
        assert!(pending.commit(&mut store).await.is_err());
        assert_eq!(backend.actual.read().await.unwrap(), before);
        drop(store);
        backend.mode.set(0);
        let reopened = Store::open(backend, &cipher, SCOPE).await.unwrap();
        assert!(pending.reconcile(engine(), &reopened).is_err());
        assert!(DurableAccountOwner::open(engine(), &reopened, SCOPE).is_err());
    });
}

#[test]
fn cancellation_after_actual_cas_reconciles_only_same_operation_and_ciphertext() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        let mut pending = begin(&store, [4; 32]);
        let hash = pending.sealed_digest();
        backend.mode.set(2);
        let mut future = Box::pin(pending.commit(&mut store));
        assert!(matches!(
            future
                .as_mut()
                .poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())),
            Poll::Pending
        ));
        drop(future);
        assert!(store.read("cwlt.account", b"owner.v1").is_err());
        drop(store);
        backend.mode.set(0);
        let reopened = Store::open(backend, &cipher, SCOPE).await.unwrap();
        assert!(reopened.receipt(&[4; 32]).unwrap().contains_record(
            "cwlt.account",
            b"owner.v1",
            &hash
        ));
        let owner = pending.reconcile(engine(), &reopened).unwrap();
        let public = owner.projection(&engine(), &reopened).unwrap();
        assert_eq!(
            DurableAccountOwner::open(engine(), &reopened, SCOPE)
                .unwrap()
                .projection(&engine(), &reopened)
                .unwrap(),
            public
        );
    });
}

#[test]
fn unknown_after_real_commit_reopens_original_winner_without_another_cas() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        let mut pending = begin(&store, [5; 32]);
        backend.mode.set(3);
        assert!(pending.commit(&mut store).await.is_err());
        let committed_wire = backend.actual.read().await.unwrap();
        assert!(pending.commit(&mut store).await.is_err());
        drop(store);
        backend.mode.set(0);
        let reopened = Store::open(backend.clone(), &cipher, SCOPE).await.unwrap();
        let owner = pending.reconcile(engine(), &reopened).unwrap();
        owner.projection(&engine(), &reopened).unwrap();
        assert_eq!(backend.actual.read().await.unwrap(), committed_wire);
    });
}

#[test]
fn competing_actual_cas_and_wrong_operation_receipt_never_install_candidate() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut first = Store::create(backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        let mut second = Store::open(backend.clone(), &cipher, SCOPE).await.unwrap();
        let mut a = begin(&first, [6; 32]);
        let mut b = begin(&second, [7; 32]);
        let winner = a.commit(&mut first).await.unwrap();
        let public = winner.projection(&engine(), &first).unwrap();
        assert!(b.commit(&mut second).await.is_err());
        let mut reopened = Store::open(backend.clone(), &cipher, SCOPE).await.unwrap();
        assert!(b.reconcile(engine(), &reopened).is_err());
        assert_eq!(
            DurableAccountOwner::open(engine(), &reopened, SCOPE)
                .unwrap()
                .projection(&engine(), &reopened)
                .unwrap(),
            public
        );
        // A genuine later receipt for another operation is not the lost attempt's
        // receipt, even when it leaves those same encrypted owner bytes intact.
        let base = reopened.version().unwrap();
        reopened
            .commit_with_receipt(
                base,
                [8; 32],
                &[Change::Put {
                    owner: "other",
                    key: b"key",
                    value: b"public",
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(a.reconcile(engine(), &reopened).is_err());
        assert_eq!(winner.projection(&engine(), &reopened).unwrap(), public);
        assert_eq!(
            DurableAccountOwner::open(engine(), &reopened, SCOPE)
                .unwrap()
                .projection(&engine(), &reopened)
                .unwrap(),
            public
        );
    });
}

#[test]
fn original_root_scope_corrupt_owner_and_authentication_fail_closed() {
    block_on(async {
        let backend = Controlled::new();
        let cipher = cipher();
        let mut store = Store::create(backend, &cipher, SCOPE).await.unwrap();
        let mut pending = begin(&store, [9; 32]);
        let owner = pending.commit(&mut store).await.unwrap();
        let foreign_root =
            Engine::from_seed_and_sealing_key(&mut [6; 32], &mut [8; 32], SCOPE.as_bytes())
                .unwrap();
        let foreign_key =
            Engine::from_seed_and_sealing_key(&mut [7; 32], &mut [6; 32], SCOPE.as_bytes())
                .unwrap();
        assert!(owner.projection(&foreign_root, &store).is_err());
        assert!(owner.projection(&foreign_key, &store).is_err());
        assert!(DurableAccountOwner::open(foreign_root, &store, SCOPE).is_err());
        assert!(DurableAccountOwner::open(foreign_key, &store, SCOPE).is_err());
        assert!(DurableAccountOwner::open(engine(), &store, "other").is_err());
        let mut corrupt = store
            .read("cwlt.account", b"owner.v1")
            .unwrap()
            .unwrap()
            .to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let base = store.version().unwrap();
        store
            .commit_with_receipt(
                base,
                [10; 32],
                &[Change::Put {
                    owner: "cwlt.account",
                    key: b"owner.v1",
                    value: &corrupt,
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(DurableAccountOwner::open(engine(), &store, SCOPE).is_err());
        assert!(owner.projection(&engine(), &store).is_err());
    });
}
