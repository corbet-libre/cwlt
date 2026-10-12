//! Real-prover durability of the pending companion and the accepted record. The
//! prover is the genuine original worker; the operator and issuer keys are test
//! keys that sign exactly the transcripts the engine reconstructs.
use super::genesis::context;
use super::*;
use ckmg::wallet_engine::{
    account::{
        AcceptanceBinding, AcceptedResponse, GenesisProofScope, GenesisPublic, IssuerAcceptance,
        PendingGenesisBinding, ResponseTrust,
    },
    native_prover::{NativeProver, NativeProverConfig},
};
use cwlt::account_owner::AccountGenesisProof;
use ed25519_dalek::{Signer as _, SigningKey as OperatorKey};
use p256::ecdsa::SigningKey as IssuerKey;
use std::{path::PathBuf, time::Duration};

const REQUEST: [u8; 32] = [0xA1; 32];

fn sha(bytes: &[u8]) -> [u8; 32] {
    czkp::decode(&czkp::digest(bytes)).unwrap()
}

fn prover() -> NativeProver {
    let directory = PathBuf::from(
        std::env::var_os("CWLT_NATIVE_PROVER_FIXTURE")
            .expect("genuine original retained extension artifact prerequisite"),
    );
    let read = |name: &str| std::fs::read(directory.join(name)).unwrap();
    let (circuit, keys, g1, g2) = (
        read("circuits.json"),
        read("keys.json"),
        read("setup/g1.dat"),
        read("setup/g2.dat"),
    );
    let executable = PathBuf::from(
        std::env::var_os("CWLT_NATIVE_PROVER_WORKER")
            .expect("actual owned native worker prerequisite"),
    );
    NativeProver::new(NativeProverConfig {
        executable_digest: sha(&std::fs::read(&executable).unwrap()),
        executable,
        scope: GenesisProofScope {
            circuit_digest: sha(&circuit),
            verifying_key_digest: sha(&keys),
        },
        circuit,
        verification_key: keys,
        srs_g1_digest: sha(&g1),
        srs_g1: g1,
        num_points: 2_621_440,
        srs_g2_digest: sha(&g2),
        srs_g2: g2.try_into().unwrap(),
        timeout: Duration::from_secs(300),
        maximum_parallel: 1,
        threads: 2,
        memory_megabytes: 4096,
    })
    .unwrap()
}

fn operator() -> OperatorKey {
    OperatorKey::from_bytes(&[5; 32])
}
fn issuer() -> IssuerKey {
    IssuerKey::from_slice(&[11; 32]).unwrap()
}
fn trust() -> ResponseTrust {
    ResponseTrust {
        certificate_key: issuer().verifying_key().to_sec1_point(false).as_bytes()[1..]
            .try_into()
            .unwrap(),
        frontier: None,
    }
}

/// A genuine response for the proven statement, signed with the test keys.
fn response(
    public: &GenesisPublic,
    policy: &ckmg::wallet_engine::account::AccountPolicy,
    scope: &GenesisProofScope,
    binding: &AcceptanceBinding,
    at: u64,
) -> AcceptedResponse {
    let fields = czkp::account::StatementFields {
        protocol_version: public.protocol_version,
        community: public.community,
        owner: public.owner,
        policy_digest: public.policy_digest,
        enrollment_root: public.enrollment_root,
        now: public.now,
        valid_until: public.valid_until,
        genesis: public.genesis,
        previous_version: public.previous_version,
        next_version: public.next_version,
        previous_state: public.previous_state,
        next_state: public.next_state,
        settlement_marker: public.settlement_marker,
        policy: czkp::account::PolicyFields {
            initial_credit: policy.initial_credit,
            maximum_available: policy.maximum_available,
            outgoing_reservation: policy.outgoing_reservation,
            incoming_reservation: policy.incoming_reservation,
            policy_revision: policy.policy_revision,
            policy_valid_from: policy.policy_valid_from,
            policy_valid_until: policy.policy_valid_until,
            newcomer_period: policy.newcomer_period,
            rate_window: policy.rate_window,
            newcomer_admissions: policy.newcomer_admissions,
            maximum_admissions: policy.maximum_admissions,
            refill_period: policy.refill_period,
            refill_units: policy.refill_units,
            abandon_after: policy.abandon_after,
        },
    };
    let message = czkp::account::acceptance_bytes(
        &binding.request_id,
        &binding.request_digest,
        scope,
        at,
        &fields,
    );
    let state = czkp::certificate::AcceptedState {
        community: public.community,
        owner: public.owner,
        state: public.next_state,
        scope: scope.circuit_digest,
        version: public.next_version,
        accepted_at: at,
    };
    let certificate: p256::ecdsa::Signature = issuer().sign(&state.bytes());
    AcceptedResponse {
        issuer: IssuerAcceptance {
            accepted_at: at,
            signature: operator().sign(&message).to_bytes(),
        },
        certificate: certificate.normalize_s().to_bytes().into(),
        ancestry: None,
    }
}

/// Backend that can refuse one chosen write before anything is stored.
#[derive(Clone)]
struct Flaky {
    actual: Memory,
    writes: Rc<Cell<u32>>,
    fail_at: Rc<Cell<u32>>,
}
impl Flaky {
    fn new() -> Self {
        Self {
            actual: Memory::new(),
            writes: Rc::new(Cell::new(0)),
            fail_at: Rc::new(Cell::new(0)),
        }
    }
}
impl Backend for Flaky {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.actual.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        if self.writes.get() == self.fail_at.get() {
            return Err(cwst::Error::Uncertain);
        }
        self.actual.compare_exchange(expected, next).await
    }
}

fn binding(operator_key: [u8; 32]) -> PendingGenesisBinding {
    PendingGenesisBinding {
        acceptance: AcceptanceBinding {
            request_id: REQUEST,
            request_digest: [0xB2; 32],
            operator_key,
        },
        extended_acceptance_digest: None,
        response: None,
        upper: vec![4; 300],
    }
}

struct Staged {
    backend: Flaky,
    store: Store<Flaky>,
    owner: DurableAccountOwner,
    proof: AccountGenesisProof,
    outbox: Vec<u8>,
    response: AcceptedResponse,
}

/// Prove one genuine candidate; nothing is staged yet.
async fn proven() -> Staged {
    let backend = Flaky::new();
    let mut store = Store::create(backend.clone(), &cipher(), SCOPE)
        .await
        .unwrap();
    let owner = DurableAccountOwner::prepare(engine(), &store, SCOPE, [31; 32])
        .unwrap()
        .commit(&mut store)
        .await
        .unwrap();
    let context = context(&owner, &store);
    let candidate = owner
        .prepare_genesis(engine(), &store, context.clone(), 101)
        .unwrap();
    let proof = candidate
        .prove(&owner, &engine(), &store, &prover(), || Ok(101))
        .unwrap();
    let binding = binding(operator().verifying_key().to_bytes());
    let response = {
        let material = proof
            .request_material(&owner, &engine(), &store, &context, 101)
            .unwrap();
        response(
            &material.statement,
            &context.policy,
            material.scope,
            &binding.acceptance,
            150,
        )
    };
    Staged {
        backend,
        store,
        owner,
        proof,
        outbox: b"{\"signed\":\"apply-extended\"}".to_vec(),
        response,
    }
}

impl Staged {
    async fn stage(&mut self) {
        let binding = binding(operator().verifying_key().to_bytes());
        self.proof
            .stage_pending(
                &self.owner,
                &engine(),
                &mut self.store,
                &binding,
                self.outbox.clone(),
                [40; 32],
                101,
            )
            .await
            .unwrap();
    }

    /// Everything in RAM is gone: only the backend bytes remain.
    async fn crash(self) -> (Flaky, Store<Flaky>, DurableAccountOwner) {
        let Self {
            backend,
            store,
            owner,
            proof,
            ..
        } = self;
        drop((store, owner, proof));
        let store = Store::open(backend.clone(), &cipher(), SCOPE)
            .await
            .unwrap();
        let owner = DurableAccountOwner::open(engine(), &store, SCOPE).unwrap();
        (backend, store, owner)
    }
}

#[test]
fn state_a_and_the_outbox_share_one_commit_and_reopen_byte_identical_after_a_crash() {
    block_on(async {
        let mut staged = proven().await;
        // Refusals leave the Store untouched and the proof reusable.
        let before = staged.backend.actual.read().await.unwrap();
        let good = binding(operator().verifying_key().to_bytes());
        let mut with_digest = binding(operator().verifying_key().to_bytes());
        with_digest.extended_acceptance_digest = Some([9; 32]);
        let mut with_response = binding(operator().verifying_key().to_bytes());
        with_response.response = Some(staged.response.clone());
        let mut zero_request = binding(operator().verifying_key().to_bytes());
        zero_request.acceptance.request_id = [0; 32];
        for (binding, outbox, operation) in [
            (&good, staged.outbox.clone(), [0; 32]),
            (&good, Vec::new(), [40; 32]),
            (&with_digest, staged.outbox.clone(), [40; 32]),
            (&with_response, staged.outbox.clone(), [40; 32]),
            (&zero_request, staged.outbox.clone(), [40; 32]),
        ] {
            assert!(
                staged
                    .proof
                    .stage_pending(
                        &staged.owner,
                        &engine(),
                        &mut staged.store,
                        binding,
                        outbox,
                        operation,
                        101,
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(staged.backend.actual.read().await.unwrap(), before);
        assert!(
            staged
                .owner
                .reopen_pending(&engine(), &staged.store, 102)
                .is_err()
        );

        staged.stage().await;
        let receipt = staged.store.receipt(&[40; 32]).unwrap();
        assert!(receipt.is_commit(&staged.store, &[40; 32]));
        assert!(receipt.contains_output(&REQUEST, blake3::hash(&staged.outbox).as_bytes()));
        // A second staging, even with another operation, never replaces state A.
        assert!(
            staged
                .proof
                .stage_pending(
                    &staged.owner,
                    &engine(),
                    &mut staged.store,
                    &good,
                    staged.outbox.clone(),
                    [41; 32],
                    101,
                )
                .await
                .is_err()
        );
        let outbox = staged.outbox.clone();
        let (_, mut store, owner) = staged.crash().await;
        for _ in 0..2 {
            let reopened = owner.reopen_pending(&engine(), &store, 102).unwrap();
            assert!(!reopened.accepted());
            assert_eq!(
                reopened.outbox, outbox,
                "the exact stored bytes are re-sent"
            );
            assert_eq!(reopened.binding.upper, vec![4; 300]);
            assert_eq!(reopened.binding.acceptance.request_id, REQUEST);
        }
        // Never past the original horizon or before the original observation.
        assert!(owner.reopen_pending(&engine(), &store, 200).is_err());
        assert!(owner.reopen_pending(&engine(), &store, 100).is_err());
        // State A never activates, and an outbox tamper cannot hide: acking the
        // output removes it and the companion no longer reopens.
        assert!(
            owner
                .begin_activation(&engine(), &store, &trust(), 102)
                .is_err()
        );
        store
            .ack_output(store.version().unwrap(), [42; 32], REQUEST)
            .await
            .unwrap();
        assert!(owner.reopen_pending(&engine(), &store, 102).is_err());
    });
}

#[test]
fn a_failed_acknowledgement_leaves_an_accepted_account_that_settles_exactly_once() {
    block_on(async {
        let mut staged = proven().await;
        staged.stage().await;
        let (backend, mut store, owner) = {
            let response = staged.response.clone();
            let (backend, mut store, owner) = staged.crash().await;
            // A to B only through the verified response, in one commit.
            owner
                .advance_pending(&engine(), &mut store, &response, &trust(), [43; 32], 151)
                .await
                .unwrap();
            let reopened = owner.reopen_pending(&engine(), &store, 152).unwrap();
            assert!(reopened.accepted());
            assert!(reopened.binding.response.as_ref() == Some(&response));
            assert_eq!(reopened.outbox, b"{\"signed\":\"apply-extended\"}".to_vec());
            // B never moves again, and a changed trust key never advances.
            assert!(
                owner
                    .advance_pending(&engine(), &mut store, &response, &trust(), [44; 32], 151)
                    .await
                    .is_err()
            );
            (backend, store, owner)
        };
        let mut wrong = trust();
        wrong.certificate_key[0] ^= 1;
        assert!(
            owner
                .begin_activation(&engine(), &store, &wrong, 152)
                .is_err()
        );
        assert!(
            owner
                .begin_activation(&engine(), &store, &trust(), 200)
                .is_err()
        );
        let activation = owner
            .begin_activation(&engine(), &store, &trust(), 152)
            .unwrap();
        assert_eq!(activation.accepted_at(), 150);
        // The accepted commit is the first write, the acknowledgement the second.
        backend.fail_at.set(backend.writes.get() + 2);
        let activated = activation
            .commit(&owner, &mut store, [45; 32], [46; 32])
            .await
            .unwrap();
        assert_eq!(activated.version, 0);
        assert_eq!(activated.accepted_at, 150);
        assert!(
            !activated.outbox_settled,
            "the ack failed, the account stands"
        );
        drop((store, owner));

        // Reopen from the backend bytes only: accepted, outbox still owed.
        let mut store = Store::open(backend.clone(), &cipher(), SCOPE)
            .await
            .unwrap();
        let owner = DurableAccountOwner::open(engine(), &store, SCOPE).unwrap();
        assert!(owner.reopen_pending(&engine(), &store, 152).is_err());
        let accepted = owner.restore_accepted(&engine(), &store).unwrap();
        assert_eq!(accepted.state(), activated.state);
        assert_eq!(
            accepted.extended_acceptance_digest(),
            activated.extended_acceptance_digest
        );
        assert!(
            store
                .load_pending()
                .unwrap()
                .iter()
                .any(|o| o.id == REQUEST)
        );

        let writes = backend.writes.get();
        assert!(owner.settle_outbox(&mut store, [47; 32]).await.unwrap());
        assert_eq!(
            backend.writes.get(),
            writes + 1,
            "acknowledged exactly once"
        );
        assert!(
            store
                .load_pending()
                .unwrap()
                .iter()
                .all(|o| o.id != REQUEST)
        );
        // Repeating is idempotent and writes nothing.
        assert!(owner.settle_outbox(&mut store, [48; 32]).await.unwrap());
        assert_eq!(backend.writes.get(), writes + 1);
        // A zero operation is refused and the accepted record stays restorable.
        assert!(owner.settle_outbox(&mut store, [0; 32]).await.is_err());
        owner.restore_accepted(&engine(), &store).unwrap();
    });
}

#[test]
fn activation_commits_once_and_a_stale_pending_row_is_refused() {
    block_on(async {
        let mut staged = proven().await;
        staged.stage().await;
        let response = staged.response.clone();
        let (backend, mut store, owner) = staged.crash().await;
        assert!(
            owner
                .settle_outbox(&mut store, [49; 32])
                .await
                .is_ok_and(|done| !done)
        );
        owner
            .advance_pending(&engine(), &mut store, &response, &trust(), [43; 32], 151)
            .await
            .unwrap();
        let first = owner
            .begin_activation(&engine(), &store, &trust(), 152)
            .unwrap();
        let second = owner
            .begin_activation(&engine(), &store, &trust(), 152)
            .unwrap();
        // The zero and equal operation ids are refused before any write.
        let writes = backend.writes.get();
        assert!(
            owner
                .begin_activation(&engine(), &store, &trust(), 152)
                .unwrap()
                .commit(&owner, &mut store, [45; 32], [45; 32])
                .await
                .is_err()
        );
        assert_eq!(backend.writes.get(), writes);
        let activated = first
            .commit(&owner, &mut store, [45; 32], [46; 32])
            .await
            .unwrap();
        assert!(activated.outbox_settled);
        // The same verified candidate cannot commit again: the pending row is gone.
        assert!(
            second
                .commit(&owner, &mut store, [50; 32], [51; 32])
                .await
                .is_err()
        );
        assert!(owner.settle_outbox(&mut store, [52; 32]).await.unwrap());
        assert!(store.load_pending().unwrap().is_empty());
    });
}
