//! Real-prover durability of the pending companion and the accepted record. The
//! prover is the genuine original worker; the operator and issuer keys are test
//! keys that sign exactly the transcripts the engine reconstructs.
use super::genesis::context;
use super::*;
use ckmg::wallet_engine::{
    account::{
        AcceptanceBinding, AcceptedResponse, GENESIS_DISCARD_COMMIT_MARGIN_SECONDS,
        GenesisProofScope, GenesisPublic, IssuerAcceptance, OwnerAbsence, PendingGenesisBinding,
        ResponseTrust,
    },
    native_prover::{NativeProver, NativeProverConfig, Program},
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
        program: Program::Update,
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
const IDENTITY: [u8; 32] = [12; 32];
fn trust() -> ResponseTrust {
    ResponseTrust {
        certificate_keys: vec![czkp::issuer_keys::CertificateKeyPeriod {
            public_key: issuer().verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec(),
            valid_from: 1,
            valid_until: None,
        }],
        community_identity: IDENTITY,
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
        identity: IDENTITY,
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
        wrong.community_identity = [13; 32];
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

/// An operator-signed owner-lookup status reporting no account at `observed_at`,
/// in the Balance wire formats.
fn absence(public: &GenesisPublic, observed_at: u64, key: &OperatorKey) -> OwnerAbsence {
    let device = OperatorKey::from_bytes(&[9; 32]);
    let (issued_at, expires_at) = (observed_at - 10, observed_at + 90);
    let mut request = b"cfrm.account.status.v1\0".to_vec();
    request.extend_from_slice(&public.community);
    request.extend_from_slice(&public.owner);
    request.push(0);
    request.extend_from_slice(&[0; 32]);
    request.extend_from_slice(&[3; 32]);
    request.extend_from_slice(&device.verifying_key().to_bytes());
    request.extend_from_slice(&issued_at.to_be_bytes());
    request.extend_from_slice(&expires_at.to_be_bytes());
    let request_signature = device.sign(&request).to_bytes();
    let mut response = b"cfrm.account.status-response.v1\0".to_vec();
    response.extend_from_slice(&czkp::account::acceptance_digest(&request, &request_signature));
    response.extend_from_slice(&observed_at.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&[0; 32]);
    OwnerAbsence {
        community: public.community,
        owner: public.owner,
        challenge: [3; 32],
        chat_public_key: device.verifying_key().to_bytes(),
        issued_at,
        expires_at,
        request_signature,
        observed_at,
        signature: key.sign(&response).to_bytes(),
    }
}

#[test]
fn an_elapsed_state_a_is_discarded_in_one_commit_that_keeps_its_request_digest() {
    block_on(async {
        let mut staged = proven().await;
        staged.stage().await;
        let context = context(&staged.owner, &staged.store);
        let public = staged
            .proof
            .request_material(&staged.owner, &engine(), &staged.store, &context, 101)
            .unwrap()
            .statement;
        // The request expired at 150; only operator times decide.
        let expires = 150;
        let due = expires + GENESIS_DISCARD_COMMIT_MARGIN_SECONDS;
        let good = absence(&public, due, &operator());
        let early = absence(&public, due - 1, &operator());
        let foreign = absence(&public, due, &OperatorKey::from_bytes(&[6; 32]));
        let writes = staged.backend.writes.get();
        for (absence, operation, acknowledgement) in [
            (&early, [60; 32], [61; 32]),
            (&foreign, [60; 32], [61; 32]),
            (&good, [0; 32], [61; 32]),
            (&good, [60; 32], [60; 32]),
        ] {
            assert!(
                staged
                    .owner
                    .discard_elapsed_pending(
                        &engine(),
                        &mut staged.store,
                        expires,
                        absence,
                        operation,
                        acknowledgement,
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(staged.backend.writes.get(), writes, "refusals write nothing");
        assert!(staged.owner.discarded_genesis(&staged.store).unwrap().is_empty());
        let digest = staged
            .owner
            .discard_elapsed_pending(&engine(), &mut staged.store, expires, &good, [60; 32], [61; 32])
            .await
            .unwrap();
        assert_eq!(digest, [0xB2; 32]);
        // Exactly the pending row went; the digest stays, the outbox is acknowledged.
        assert!(staged.owner.reopen_pending(&engine(), &staged.store, 102).is_err());
        assert_eq!(
            staged.owner.discarded_genesis(&staged.store).unwrap(),
            vec![[0xB2; 32]]
        );
        assert!(staged.store.load_pending().unwrap().is_empty());
        let (_, mut store, owner) = staged.crash().await;
        assert_eq!(owner.discarded_genesis(&store).unwrap(), vec![[0xB2; 32]]);
        // Nothing is left to discard, and settling again is a no-op.
        assert!(
            owner
                .discard_elapsed_pending(&engine(), &mut store, expires, &good, [62; 32], [63; 32])
                .await
                .is_err()
        );
        owner.settle_discarded(&mut store, [64; 32]).await.unwrap();
    });
}

#[test]
fn an_accepted_state_is_never_discarded_and_a_fresh_request_stages_after_a_discard() {
    block_on(async {
        let mut staged = proven().await;
        staged.stage().await;
        let context = context(&staged.owner, &staged.store);
        let public = staged
            .proof
            .request_material(&staged.owner, &engine(), &staged.store, &context, 101)
            .unwrap()
            .statement;
        let good = absence(&public, 150 + GENESIS_DISCARD_COMMIT_MARGIN_SECONDS, &operator());
        // A lost response: the operator accepted, the device adopts (state B) and
        // the late no-account status cannot discard it.
        let response = staged.response.clone();
        staged
            .owner
            .advance_pending(&engine(), &mut staged.store, &response, &trust(), [43; 32], 151)
            .await
            .unwrap();
        assert!(
            staged
                .owner
                .discard_elapsed_pending(&engine(), &mut staged.store, 150, &good, [60; 32], [61; 32])
                .await
                .is_err()
        );
        assert!(staged.owner.reopen_pending(&engine(), &staged.store, 152).unwrap().accepted());

        // A second store: discard state A, then a fresh request stages normally.
        let mut fresh = proven().await;
        fresh.stage().await;
        fresh
            .owner
            .discard_elapsed_pending(&engine(), &mut fresh.store, 150, &good, [60; 32], [61; 32])
            .await
            .unwrap();
        let mut next = binding(operator().verifying_key().to_bytes());
        next.acceptance.request_id = [0xA2; 32];
        next.acceptance.request_digest = [0xB3; 32];
        fresh
            .proof
            .stage_pending(
                &fresh.owner,
                &engine(),
                &mut fresh.store,
                &next,
                fresh.outbox.clone(),
                [65; 32],
                102,
            )
            .await
            .unwrap();
        let reopened = fresh.owner.reopen_pending(&engine(), &fresh.store, 103).unwrap();
        assert_eq!(reopened.binding.acceptance.request_id, [0xA2; 32]);
        assert_eq!(fresh.owner.discarded_genesis(&fresh.store).unwrap(), vec![[0xB2; 32]]);
    });
}
