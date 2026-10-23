//! The engine side of the browser prover. All logic stays here: the identity checks of the
//! circuit and key groups, the pinned setup sizes, the public inputs expected from the public
//! statement, and the refusal of every reply that does not match them. A Web Worker behind the
//! [`ProofWorker`] port only runs the witness execution and the proof system; it is handed the
//! private input and returns a proof, nothing else. Configuration is trusted runtime data.
pub use crate::prover_shared::Program;
use crate::prover_shared::{MAX_PROOF, abi, check_groups};
use crate::{Error, proof::Proof};
use czkp::ProofScope;
use noirc_abi::Abi;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
pub mod calibration;
#[cfg(test)]
mod tests;

/// One pinned setup size: the SHA-256 of the first `points` compressed G1 points as the
/// wallet origin serves them (32 bytes each), and of the same points expanded by the proof
/// system (64 bytes each), which is the form the Worker caches in IndexedDB. Both digests
/// are code constants: neither the caller nor the origin can choose them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrsPin {
    /// The dyadic number of points (a power of two).
    pub points: u32,
    /// SHA-256 of the served compressed prefix.
    pub compressed_sha256: [u8; 32],
    /// SHA-256 of the proof system's expanded form of that prefix.
    pub expanded_sha256: [u8; 32],
}

const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lowercase hexadecimal digit"),
    }
}

/// The pinned prefixes of the authenticated extension setup (`g1.dat`, whose complete digest
/// the extension manifest authenticates): 2^19 and 2^20 points. A circuit needs the dyadic
/// size of its gate count; a size outside this table is refused.
pub const SRS_PINS: [SrsPin; 2] = [
    SrsPin {
        points: 1 << 19,
        compressed_sha256: hex32(
            "1d03ebeb73e1a6d426e44a2ccc88b04125ca185ab9d1679817380502a723fa80",
        ),
        expanded_sha256: hex32("ea7b37bb4e1840b5632675fb2d79873ac0a1598374d3087344ba0e980736b8ac"),
    },
    SrsPin {
        points: 1 << 20,
        compressed_sha256: hex32(
            "f767d001dd244d42bb3863f0edc7644356ba33c662fe4fe6fb98793f8b918bd4",
        ),
        expanded_sha256: hex32("5d0ff516149e0c6644ab16567b914c9d02bf41f872c1129af8436b41d4d82c62"),
    },
];
/// SHA-256 of the authenticated G2 setup (128 bytes).
pub const SRS_G2_SHA256: [u8; 32] =
    hex32("01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f");

/// The pin of a setup size, or `None` when the size is not pinned.
pub fn srs_pin(points: u32) -> Option<&'static SrsPin> {
    SRS_PINS.iter().find(|pin| pin.points == points)
}

/// Where the Worker fetches the setup: absolute paths on the wallet origin, never URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SrsLocation {
    /// Path of the compressed G1 prefix (exactly `points * 32` bytes).
    pub g1_path: String,
    /// Path of the 128-byte G2 setup.
    pub g2_path: String,
    /// The dyadic number of points the circuit needs; must be pinned in [`SRS_PINS`].
    pub points: u32,
}

/// Explicit immutable policy material and resource bounds. The host authenticates it from
/// current owners; callers cannot choose it through request JSON.
pub struct BrowserProverConfig {
    /// Original authenticated circuit and verification-key identities.
    pub scope: ProofScope,
    /// Which member of the circuit group this prover runs.
    pub program: Program,
    /// Exact original whole circuit-group JSON; only the program's member is used.
    pub circuit: Vec<u8>,
    /// Exact original whole verification-key group JSON; only the program's key is used.
    pub verification_key: Vec<u8>,
    /// Where the Worker finds the pinned setup on the wallet origin.
    pub srs: SrsLocation,
    /// Whole timeout of one proof, including setup load and worker start (1 s to 600 s).
    pub timeout: Duration,
    /// Most threads the Worker may start; it starts more than one only when the page is
    /// cross-origin isolated (1 to 16).
    pub max_threads: u8,
}

/// The port a Web Worker answers behind. Strings carry JSON: the first is the public setup
/// (circuit member, key, setup plan, limits), the second is the private witness input. The
/// answer is the reply JSON. An implementation must start an isolated worker per proof, hand
/// it the input once, end it when the proof is done, and surface nothing but fixed errors.
pub trait ProofWorker: Send + Sync {
    /// Prove in an isolated worker. `Err` carries no diagnostic text by construction.
    fn prove<'a>(
        &'a self,
        setup: &'a str,
        input: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Error>> + 'a>>;
    /// Withdraw: end the running worker at once; later proofs are refused by the caller.
    fn cancel(&self);
}

/// One-way withdrawal; never renews a source, changes material or grants success.
#[derive(Clone)]
pub struct BrowserProverCancellation {
    flag: Arc<AtomicBool>,
    worker: Arc<dyn ProofWorker>,
}
impl BrowserProverCancellation {
    /// End the running worker and refuse all later work.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.worker.cancel();
    }
}

/// Verified material with an owned worker port and capacity of one proof at a time (a proof
/// holds about 0.9 GiB of memory). No admission, current Charter, Keys Use or accepted-account
/// capability.
#[derive(Clone)]
pub struct BrowserProver {
    config: Arc<Config>,
    abi: Arc<Abi>,
    setup: Arc<String>,
    circuit_id: Arc<String>,
    worker: Arc<dyn ProofWorker>,
    active: Arc<AtomicUsize>,
    cancelled: Arc<AtomicBool>,
}
struct Config {
    scope: ProofScope,
    program: Program,
}

#[derive(Serialize)]
struct SetupWire<'a> {
    version: u8,
    program: &'a str,
    /// Names this circuit version (program, circuit, key, setup size): the key under which a
    /// device keeps its calibration, so a changed circuit is calibrated again.
    circuit_id: &'a str,
    /// The program's member of the circuit group: bytecode and ABI, without debug symbols.
    circuit: serde_json::Value,
    verification_key: String,
    srs: SrsWire<'a>,
    timeout_ms: u32,
    max_threads: u8,
}
#[derive(Serialize)]
struct SrsWire<'a> {
    g1_path: &'a str,
    g2_path: &'a str,
    points: u32,
    g1_sha256: String,
    g1_expanded_sha256: String,
    g2_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    verified: bool,
    public_inputs: Vec<String>,
    proof: String,
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}
// An absolute path on the wallet origin: no scheme, no authority, no dot segments.
fn same_origin_path(path: &str) -> bool {
    path.len() <= 256
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._".contains(&b))
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

impl BrowserProver {
    /// Validate exact data identities, the original ABI, the pinned setup size and the bounds.
    pub fn new(config: BrowserProverConfig, worker: Arc<dyn ProofWorker>) -> Result<Self, Error> {
        let pin = srs_pin(config.srs.points).ok_or(Error::Invalid)?;
        if config.timeout < Duration::from_secs(1)
            || config.timeout > Duration::from_secs(600)
            || !(1..=16).contains(&config.max_threads)
            || !same_origin_path(&config.srs.g1_path)
            || !same_origin_path(&config.srs.g2_path)
            || config.srs.g1_path == config.srs.g2_path
        {
            return Err(Error::Invalid);
        }
        let checked = check_groups(
            config.program,
            &config.scope,
            &config.circuit,
            &config.verification_key,
        )?;
        let member = checked.member;
        let circuit = serde_json::json!({
            "bytecode": member.get("bytecode").ok_or(Error::Invalid)?,
            "abi": member.get("abi").ok_or(Error::Invalid)?,
        });
        let circuit_id = {
            let mut identity = Vec::with_capacity(96);
            identity.extend_from_slice(config.program.key().as_bytes());
            identity.extend_from_slice(&config.scope.circuit_digest);
            identity.extend_from_slice(&config.scope.verifying_key_digest);
            identity.extend_from_slice(&pin.points.to_be_bytes());
            hex(&crate::prover_shared::sha(&identity)?)
        };
        let wire = SetupWire {
            version: 1,
            program: config.program.key(),
            circuit_id: &circuit_id,
            circuit,
            verification_key: hex(&checked.key),
            srs: SrsWire {
                g1_path: &config.srs.g1_path,
                g2_path: &config.srs.g2_path,
                points: pin.points,
                g1_sha256: hex(&pin.compressed_sha256),
                g1_expanded_sha256: hex(&pin.expanded_sha256),
                g2_sha256: hex(&SRS_G2_SHA256),
            },
            timeout_ms: u32::try_from(config.timeout.as_millis()).map_err(|_| Error::Invalid)?,
            max_threads: config.max_threads,
        };
        let setup = serde_json::to_string(&wire).map_err(|_| Error::Invalid)?;
        Ok(Self {
            config: Arc::new(Config {
                scope: config.scope,
                program: config.program,
            }),
            abi: Arc::new(checked.abi),
            setup: Arc::new(setup),
            circuit_id: Arc::new(circuit_id),
            worker,
            active: Arc::new(AtomicUsize::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Retain this withdrawal handle with the actual Vault/source lifetime.
    pub fn cancellation(&self) -> BrowserProverCancellation {
        BrowserProverCancellation {
            flag: self.cancelled.clone(),
            worker: self.worker.clone(),
        }
    }

    /// The public setup the Worker receives; it holds no private input.
    pub fn setup_json(&self) -> &str {
        &self.setup
    }

    /// Names this circuit version; a device's calibration is kept under it (lowercase hex).
    pub fn circuit_id(&self) -> &str {
        &self.circuit_id
    }

    /// Prove one input through the same checks as an account proof, for the wasm probe: the
    /// engine derives the public inputs from `public_json` itself and accepts only a reply that
    /// matches them. It exists so the browser build can show, in a real browser, that the
    /// public-input derivation and the reply checks run on wasm32; the account paths use
    /// [`BrowserProver::prove`] through the prepared proof.
    #[cfg(feature = "browser-prover-probe")]
    pub async fn probe_prove(
        &self,
        public_json: &str,
        input: Zeroizing<String>,
    ) -> Result<Proof, Error> {
        let expected = self.public_inputs(public_json)?;
        self.prove(input, expected).await
    }

    pub(crate) fn public_inputs(&self, input: &str) -> Result<Vec<[u8; 32]>, Error> {
        abi::public_only(self.config.program, &self.abi, input)
    }

    fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error::Crypto)
        } else {
            Ok(())
        }
    }

    /// Prove one input in the Worker and accept only a proof that matches `public`.
    pub(crate) async fn prove(
        &self,
        input: Zeroizing<String>,
        public: Vec<[u8; 32]>,
    ) -> Result<Proof, Error> {
        self.check()?;
        if public.len() != self.config.program.publics() {
            return Err(Error::Invalid);
        }
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 1).then_some(n + 1)
            })
            .map_err(|_| Error::Crypto)?;
        struct Permit(Arc<AtomicUsize>);
        impl Drop for Permit {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _permit = Permit(self.active.clone());
        let reply = self.worker.prove(&self.setup, &input).await?;
        drop(input);
        self.check()?;
        let reply: ReplyWire = serde_json::from_str(&reply).map_err(|_| Error::Crypto)?;
        let public_inputs = reply
            .public_inputs
            .iter()
            .map(|field| {
                data_encoding::HEXLOWER
                    .decode(field.as_bytes())
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or(Error::Crypto)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = data_encoding::HEXLOWER
            .decode(reply.proof.as_bytes())
            .map_err(|_| Error::Crypto)?;
        if !reply.verified
            || public_inputs != public
            || proof.is_empty()
            || proof.len() > MAX_PROOF
            || !proof.len().is_multiple_of(32)
        {
            return Err(Error::Crypto);
        }
        for field in &public_inputs {
            czkp::field(field, false).map_err(|_| Error::Crypto)?;
        }
        Ok(Proof {
            scope: self.config.scope.clone(),
            public_inputs,
            proof,
        })
    }
}
