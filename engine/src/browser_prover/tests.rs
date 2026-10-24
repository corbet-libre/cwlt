//! The browser prover's engine side against the retained original artifacts and a worker port
//! that is a fake (replies) or the native prover (a real proof through the same path).
use super::*;
use crate::prover_shared::sha;
use std::{
    path::PathBuf,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::yield_now();
    }
}

fn read(name: &str) -> Vec<u8> {
    let directory = PathBuf::from(
        std::env::var_os("CWLT_NATIVE_PROVER_FIXTURE")
            .expect("genuine original retained extension artifact prerequisite"),
    );
    assert!(directory.is_absolute());
    std::fs::read(directory.join(name)).expect("original retained prover fixture")
}

fn config() -> BrowserProverConfig {
    let circuit = read("circuits.json");
    let verification_key = read("keys.json");
    BrowserProverConfig {
        scope: ProofScope {
            circuit_digest: sha(&circuit).unwrap(),
            verifying_key_digest: sha(&verification_key).unwrap(),
        },
        program: Program::Update,
        circuit,
        verification_key,
        srs: SrsLocation {
            g1_path: "/prover/srs/g1-1048576.dat".into(),
            g2_path: "/prover/srs/g2.dat".into(),
            points: 1 << 20,
        },
        timeout: Duration::from_secs(240),
        max_threads: 8,
    }
}

/// A worker that answers with a fixed reply and records what it was handed.
struct Fake {
    reply: Mutex<Result<String, Error>>,
    cancelled: AtomicBool,
    seen: Mutex<Vec<(String, String)>>,
}
impl Fake {
    fn new(reply: Result<String, Error>) -> Arc<Self> {
        Arc::new(Self {
            reply: Mutex::new(reply),
            cancelled: AtomicBool::new(false),
            seen: Mutex::new(Vec::new()),
        })
    }
}
impl ProofWorker for Fake {
    fn prove<'a>(
        &'a self,
        setup: &'a str,
        input: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>> + 'a>> {
        self.seen
            .lock()
            .unwrap()
            .push((setup.to_owned(), input.to_owned()));
        let reply = self.reply.lock().unwrap().clone();
        Box::pin(async move { reply })
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

fn publics() -> Vec<[u8; 32]> {
    (0..410u32)
        .map(|i| {
            let mut field = [0u8; 32];
            field[28..].copy_from_slice(&(i + 1).to_be_bytes());
            field
        })
        .collect()
}
fn reply(verified: bool, public: &[[u8; 32]], proof: &[u8]) -> String {
    serde_json::json!({
        "verified": verified,
        "public_inputs": public.iter().map(|f| hex(f)).collect::<Vec<_>>(),
        "proof": hex(proof),
    })
    .to_string()
}
fn input() -> Zeroizing<String> {
    Zeroizing::new("{\"private\":\"witness\"}".into())
}

#[test]
fn only_the_pinned_setup_sizes_the_origin_paths_and_the_bounds_are_accepted() {
    let worker = Fake::new(Err(Error::Crypto));
    assert!(BrowserProver::new(config(), worker.clone()).is_ok());
    let mut c = config();
    c.srs.points = 1 << 18;
    assert!(BrowserProver::new(c, worker.clone()).is_err());
    for bad in [
        "https://crs.aztec-cdn.foundation/g1.dat",
        "//evil.example/g1.dat",
        "g1.dat",
        "/a/../g1.dat",
        "/a/./g1.dat",
        "/g1.dat?x=1",
        "/g1 .dat",
    ] {
        let mut c = config();
        c.srs.g1_path = bad.into();
        assert!(BrowserProver::new(c, worker.clone()).is_err(), "{bad}");
    }
    let mut c = config();
    c.srs.g2_path = c.srs.g1_path.clone();
    assert!(BrowserProver::new(c, worker.clone()).is_err());
    for timeout in [0, 600_001] {
        let mut c = config();
        c.timeout = Duration::from_millis(timeout);
        assert!(BrowserProver::new(c, worker.clone()).is_err());
    }
    for threads in [0, 17] {
        let mut c = config();
        c.max_threads = threads;
        assert!(BrowserProver::new(c, worker.clone()).is_err());
    }
}

#[test]
fn the_pin_table_is_dyadic_and_names_distinct_digests() {
    for pin in SRS_PINS {
        assert!(pin.points.is_power_of_two());
        assert_ne!(pin.compressed_sha256, pin.expanded_sha256);
    }
    assert_ne!(SRS_PINS[0], SRS_PINS[1]);
    assert_eq!(srs_pin(1 << 20), Some(&SRS_PINS[1]));
    assert_eq!(srs_pin(1 << 21), None);
    // The pins are those of the authenticated setup prefix the fixture carries.
    if let Some(directory) = std::env::var_os("CWLT_NATIVE_PROVER_FIXTURE") {
        let g1 = std::fs::read(PathBuf::from(&directory).join("setup/g1.dat")).unwrap();
        for pin in SRS_PINS {
            let prefix = &g1[..pin.points as usize * 32];
            assert_eq!(sha(prefix).unwrap(), pin.compressed_sha256);
        }
        let g2 = std::fs::read(PathBuf::from(&directory).join("setup/g2.dat")).unwrap();
        assert_eq!(sha(&g2).unwrap(), SRS_G2_SHA256);
    }
}

#[test]
fn the_identity_of_the_groups_is_checked_like_the_native_prover_does() {
    let worker = Fake::new(Err(Error::Crypto));
    let mut c = config();
    c.scope.circuit_digest[0] ^= 1;
    assert!(BrowserProver::new(c, worker.clone()).is_err());
    let mut c = config();
    c.scope.verifying_key_digest[0] ^= 1;
    assert!(BrowserProver::new(c, worker.clone()).is_err());
    // A change to another member of the group changes the whole-group digest.
    let mut c = config();
    let mut group: serde_json::Value = serde_json::from_slice(&c.circuit).unwrap();
    group["record"]["noir_version"] = serde_json::json!("foreign");
    c.circuit = serde_json::to_vec(&group).unwrap();
    assert!(BrowserProver::new(c, worker.clone()).is_err());
    // Even with a matching digest, a foreign Noir version of the member is refused.
    let mut c = config();
    let mut group: serde_json::Value = serde_json::from_slice(&c.circuit).unwrap();
    group["update"]["noir_version"] = serde_json::json!("1.0.0-beta.27");
    c.circuit = serde_json::to_vec(&group).unwrap();
    c.scope.circuit_digest = sha(&c.circuit).unwrap();
    assert!(BrowserProver::new(c, worker).is_err());
}

#[test]
fn the_setup_names_public_data_only_and_the_pins_from_the_table() {
    let prover = BrowserProver::new(config(), Fake::new(Err(Error::Crypto))).unwrap();
    let setup: serde_json::Value = serde_json::from_str(prover.setup_json()).unwrap();
    let circuit = setup["circuit"].as_object().unwrap();
    assert_eq!(
        circuit.keys().map(String::as_str).collect::<Vec<_>>(),
        ["abi", "bytecode"]
    );
    assert_eq!(setup["program"], "update");
    assert_eq!(setup["srs"]["points"], 1 << 20);
    assert_eq!(
        setup["srs"]["g1_sha256"],
        hex(&SRS_PINS[1].compressed_sha256)
    );
    assert_eq!(
        setup["srs"]["g1_expanded_sha256"],
        hex(&SRS_PINS[1].expanded_sha256)
    );
    assert_eq!(setup["srs"]["g2_sha256"], hex(&SRS_G2_SHA256));
    assert_eq!(setup["timeout_ms"], 240_000);
    assert!(setup.get("input").is_none());
}

#[test]
fn the_circuit_id_names_the_circuit_version_and_nothing_else() {
    let prover = BrowserProver::new(config(), Fake::new(Err(Error::Crypto))).unwrap();
    let setup: serde_json::Value = serde_json::from_str(prover.setup_json()).unwrap();
    // The setup carries the id the device keeps its calibration under.
    assert_eq!(setup["circuit_id"], prover.circuit_id());
    assert_eq!(prover.circuit_id().len(), 64);
    assert!(
        prover
            .circuit_id()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    // Timeout and threads are not part of the circuit version; the setup size is.
    let mut other = config();
    other.timeout = Duration::from_secs(60);
    other.max_threads = 2;
    let same = BrowserProver::new(other, Fake::new(Err(Error::Crypto))).unwrap();
    assert_eq!(same.circuit_id(), prover.circuit_id());
    let mut smaller = config();
    smaller.srs.points = 1 << 19;
    let smaller = BrowserProver::new(smaller, Fake::new(Err(Error::Crypto))).unwrap();
    assert_ne!(smaller.circuit_id(), prover.circuit_id());
}

#[test]
fn a_matching_verified_reply_becomes_the_proof_and_the_worker_got_exactly_the_input() {
    let public = publics();
    let worker = Fake::new(Ok(reply(true, &public, &[7; 64])));
    let prover = BrowserProver::new(config(), worker.clone()).unwrap();
    let proof = block_on(prover.prove(input(), public.clone())).unwrap();
    assert_eq!(proof.public_inputs, public);
    assert_eq!(proof.proof, vec![7; 64]);
    assert_eq!(proof.scope, prover.config.scope);
    let seen = worker.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, prover.setup_json());
    assert_eq!(seen[0].1, "{\"private\":\"witness\"}");
    assert!(!seen[0].0.contains("witness"));
}

#[test]
fn every_reply_that_does_not_match_what_the_engine_expects_is_refused() {
    let public = publics();
    let mut changed = public.clone();
    changed[409][31] ^= 1;
    let mut reordered = public.clone();
    reordered.swap(0, 1);
    let mut short = public.clone();
    short.pop();
    let mut unreduced = public.clone();
    unreduced[3] = [0xff; 32];
    let mut with_unreduced_expected = public.clone();
    with_unreduced_expected[3] = [0xff; 32];
    let cases: Vec<(&str, String, Vec<[u8; 32]>)> = vec![
        (
            "not verified",
            reply(false, &public, &[7; 64]),
            public.clone(),
        ),
        (
            "changed public input",
            reply(true, &changed, &[7; 64]),
            public.clone(),
        ),
        (
            "reordered public inputs",
            reply(true, &reordered, &[7; 64]),
            public.clone(),
        ),
        (
            "too few public inputs",
            reply(true, &short, &[7; 64]),
            public.clone(),
        ),
        ("empty proof", reply(true, &public, &[]), public.clone()),
        (
            "proof not in whole fields",
            reply(true, &public, &[7; 65]),
            public.clone(),
        ),
        (
            "proof over the bound",
            reply(true, &public, &vec![7; MAX_PROOF + 32]),
            public.clone(),
        ),
        (
            "public input outside the field",
            reply(true, &unreduced, &[7; 64]),
            with_unreduced_expected,
        ),
        ("not json", "verified".into(), public.clone()),
        (
            "an unknown field",
            reply(true, &public, &[7; 64]).replace("\"verified\"", "\"extra\":1,\"verified\""),
            public.clone(),
        ),
        (
            "odd hex",
            reply(true, &public, &[7; 64]).replace("0707", "07g7"),
            public.clone(),
        ),
    ];
    for (label, answer, expected) in cases {
        let prover = BrowserProver::new(config(), Fake::new(Ok(answer))).unwrap();
        assert!(
            matches!(
                block_on(prover.prove(input(), expected)),
                Err(Error::Crypto)
            ),
            "{label}"
        );
    }
    // A worker that fails surfaces only the coarse error.
    let prover = BrowserProver::new(config(), Fake::new(Err(Error::Crypto))).unwrap();
    assert!(matches!(
        block_on(prover.prove(input(), public.clone())),
        Err(Error::Crypto)
    ));
    // An expected set of the wrong length never reaches the worker.
    let worker = Fake::new(Ok(reply(true, &public, &[7; 64])));
    let prover = BrowserProver::new(config(), worker.clone()).unwrap();
    assert!(matches!(
        block_on(prover.prove(input(), public[..409].to_vec())),
        Err(Error::Invalid)
    ));
    assert!(worker.seen.lock().unwrap().is_empty());
}

struct Hang;
impl Future for Hang {
    type Output = Result<String, Error>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
struct Slow(Arc<Fake>);
impl ProofWorker for Slow {
    fn prove<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>> + 'a>> {
        Box::pin(Hang)
    }
    fn cancel(&self) {
        self.0.cancel();
    }
}

#[test]
fn one_proof_at_a_time_and_cancellation_ends_the_worker_and_refuses_later_work() {
    let public = publics();
    let fake = Fake::new(Ok(reply(true, &public, &[7; 64])));
    let prover = BrowserProver::new(config(), Arc::new(Slow(fake.clone()))).unwrap();
    // The first proof is in flight (polled once, never finished).
    let mut first = Box::pin(prover.prove(input(), public.clone()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    // A second one is refused while the first holds the only slot.
    assert!(matches!(
        block_on(prover.prove(input(), public.clone())),
        Err(Error::Crypto)
    ));
    // Dropping the first frees the slot.
    drop(first);
    assert_eq!(prover.active.load(Ordering::Acquire), 0);
    let cancellation = prover.cancellation();
    assert!(!fake.cancelled.load(Ordering::Acquire));
    cancellation.cancel();
    assert!(fake.cancelled.load(Ordering::Acquire));
    assert!(matches!(
        block_on(prover.prove(input(), public)),
        Err(Error::Crypto)
    ));
}

/// A worker that is the native prover: the same input, the same expected public inputs and a
/// real, natively verified proof come back through the browser path.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod real {
    use super::*;
    use crate::{
        account::{
            AccountPolicy, ActivationRequest, ExtensionPolicy, prove_activation,
            prove_activation_browser,
        },
        native_prover::NativeProver,
    };

    struct Native {
        prover: NativeProver,
        abi: Abi,
        calls: AtomicUsize,
    }
    impl ProofWorker for Native {
        fn prove<'a>(
            &'a self,
            setup: &'a str,
            input: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<String, Error>> + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::AcqRel);
                // The Worker is handed only the setup and the input: it derives nothing the
                // engine would trust, so the expected set is recomputed from the input here.
                let setup_text = setup;
                let setup: serde_json::Value =
                    serde_json::from_str(setup).map_err(|_| Error::Invalid)?;
                assert!(setup["circuit"].get("debug_symbols").is_none());
                let expected = abi::public_inputs(Program::Update, &self.abi, input)?;
                // The browser tests (cmsg/prover) take a real setup, a real input of a throw-away
                // genesis and the public inputs the native engine expects from this directory.
                if let Some(out) = std::env::var_os("CWLT_BROWSER_FIXTURE_OUT") {
                    let out = PathBuf::from(out);
                    std::fs::create_dir_all(&out).unwrap();
                    std::fs::write(out.join("setup.json"), setup_text).unwrap();
                    std::fs::write(out.join("input.json"), input).unwrap();
                    let fields: Vec<String> = expected.iter().map(|field| hex(field)).collect();
                    std::fs::write(
                        out.join("expected.json"),
                        serde_json::to_vec(&fields).unwrap(),
                    )
                    .unwrap();
                }
                let proof = self.prover.prove(
                    Zeroizing::new(input.to_owned()),
                    expected,
                    std::time::Instant::now() + Duration::from_secs(300),
                )?;
                Ok(reply(true, &proof.public_inputs, &proof.proof))
            })
        }
        fn cancel(&self) {}
    }

    fn request(community: &str) -> ActivationRequest {
        ActivationRequest {
            community_id: community.into(),
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
                standing: ExtensionPolicy::standing_digest(czkp::reference::params()).unwrap(),
            },
            standing: czkp::reference::params(),
            checked_at: 101,
            owner: czkp::activation_owner(community, &[7; 32]),
        }
    }

    #[test]
    fn a_genesis_proves_through_the_browser_path_to_the_same_statement_the_native_path_proves() {
        let native = NativeProver::new(crate::native_prover::tests::config()).unwrap();
        let checked = check_groups(
            Program::Update,
            &config().scope,
            &config().circuit,
            &config().verification_key,
        )
        .unwrap();
        let worker = Arc::new(Native {
            prover: native.clone(),
            abi: checked.abi,
            calls: AtomicUsize::new(0),
        });
        let browser = BrowserProver::new(config(), worker.clone()).unwrap();
        let through_browser = block_on(prove_activation_browser(
            &browser,
            request("firstcommunity"),
        ))
        .unwrap();
        assert_eq!(worker.calls.load(Ordering::Acquire), 1);
        let direct = prove_activation(&native, request("firstcommunity")).unwrap();
        // Same community, same fixed relation, same shape; the secrets differ per call.
        assert!(through_browser.public.genesis && direct.public.genesis);
        assert_eq!(through_browser.public.community, direct.public.community);
        assert_eq!(through_browser.public.owner, direct.public.owner);
        assert_eq!(
            through_browser.public.policy_digest,
            direct.public.policy_digest
        );
        assert_eq!(through_browser.public.now, direct.public.now);
        assert_eq!(through_browser.proof.len(), direct.proof.len());
        assert!(!through_browser.proof.is_empty());
        // A standing digest the parameters do not name is refused on this path as well.
        let mut wrong = request("firstcommunity");
        wrong.extension.standing = [9; 32];
        assert!(block_on(prove_activation_browser(&browser, wrong)).is_err());
    }
}
