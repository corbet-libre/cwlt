//! Native member-side proving. Configuration is trusted runtime data, not a grant.
//! Private inputs have no public constructor, serializer or callback boundary.
use crate::{Error, proof::Proof};
use czkp::ProofScope;
use noirc_abi::Abi;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod abi;
mod compression;
#[cfg(test)]
pub(crate) mod tests;
mod transport;
mod worker;

pub(crate) const MAX_CIRCUIT: usize = 64 * 1024 * 1024;
pub(crate) const MAX_SETUP: usize = 128 * 1024 * 1024;
// Original extension artifact contract bounds the complete shared setup at 128 MiB.
pub(crate) const MAX_POINTS: u32 = (MAX_SETUP / 32) as u32;
pub(crate) const MAX_FRAME: usize = (MAX_CIRCUIT + MAX_SETUP) * 4 + 2 * 1024 * 1024;
pub(crate) const MAX_PROOF: usize = 1024 * 1024;

/// The circuit of a group this prover proves. The authenticated circuit digest
/// already binds the group; the program only selects which member is run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Program {
    /// The account update (and genesis) relation.
    Update,
    /// The peer-release reservation evidence.
    Wave,
    /// The peer-release settled outcome evidence.
    Outcome,
    /// The per-epoch record (R2), proven once per epoch and cached.
    RecordEpoch,
}
impl Program {
    /// The member name inside the circuit and key group JSON.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Wave => "wave",
            Self::Outcome => "outcome",
            Self::RecordEpoch => "record_epoch",
        }
    }
    /// Exact count of public fields of the compiled program.
    pub const fn publics(self) -> usize {
        match self {
            Self::Update => 410,
            Self::Wave => 618,
            Self::Outcome => 651,
            Self::RecordEpoch => 335,
        }
    }
}

/// Explicit immutable original policy material and resource bounds. The host
/// authenticates it from current owners; callers cannot choose it via request JSON.
pub struct NativeProverConfig {
    /// Absolute trusted owned worker executable. It must not fork descendants.
    pub executable: PathBuf,
    /// Actual compiled worker SHA-256 checked before each process launch.
    pub executable_digest: [u8; 32],
    /// Original authenticated circuit and verification-key identities.
    pub scope: ProofScope,
    /// Which member of the circuit group this prover runs.
    pub program: Program,
    /// Exact original whole circuit-group JSON; only its fixed update is used.
    pub circuit: Vec<u8>,
    /// Exact original whole verification-key group JSON; only update is decoded.
    pub verification_key: Vec<u8>,
    /// Full authenticated compressed G1 setup required by the original circuit.
    pub srs_g1: Vec<u8>,
    /// Independently authenticated full G1 setup digest.
    pub srs_g1_digest: [u8; 32],
    /// Exact setup point count, each compressed G1 point occupies 32 bytes.
    pub num_points: u32,
    /// Original authenticated G2 setup, also checked by maintained BB.
    pub srs_g2: [u8; 128],
    /// Independently authenticated G2 setup digest.
    pub srs_g2_digest: [u8; 32],
    /// Whole monotonic call timeout, including preparation and startup.
    pub timeout: Duration,
    /// Shared concurrent proving capacity across clones.
    pub maximum_parallel: usize,
    /// Explicit maintained worker thread count.
    pub threads: usize,
    /// Finite child address-space limit applied before parsing private input.
    pub memory_megabytes: usize,
}

/// One-way withdrawal; never renews a source, changes material or grants success.
#[derive(Clone, Default)]
pub struct NativeProverCancellation(Arc<AtomicBool>);
impl NativeProverCancellation {
    /// Stop active work at its next bounded poll and refuse all later work.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<(), Error> {
        if self.0.load(Ordering::Acquire) {
            Err(Error::Crypto)
        } else {
            Ok(())
        }
    }
}

/// Immutable material with owned process and capacity. This is no admission,
/// current Charter, Keys Use, accepted account or issuer-acceptance capability.
#[derive(Clone)]
pub struct NativeProver {
    config: Arc<NativeProverConfig>,
    abi: Arc<Abi>,
    active: Arc<AtomicUsize>,
    cancellation: NativeProverCancellation,
}
impl NativeProver {
    /// Validate exact data identities, the original ABI and bounded resources.
    /// Full G1 material is required; a verifier's first chunk is insufficient.
    pub fn new(config: NativeProverConfig) -> Result<Self, Error> {
        if !config.executable.is_absolute()
            || config.executable_digest == [0; 32]
            || config.scope.circuit_digest == [0; 32]
            || config.circuit.is_empty()
            || config.circuit.len() > MAX_CIRCUIT
            || sha(&config.circuit)? != config.scope.circuit_digest
            || config.verification_key.is_empty()
            || config.verification_key.len() > MAX_PROOF
            || sha(&config.verification_key)? != config.scope.verifying_key_digest
            || config.num_points == 0
            || config.num_points > MAX_POINTS
            || config.srs_g1.len() > MAX_SETUP
            || !config.srs_g1.len().is_multiple_of(4 * 1024 * 1024)
            || config.srs_g1.len() != config.num_points as usize * 32
            || sha(&config.srs_g1)? != config.srs_g1_digest
            || sha(&config.srs_g2)? != config.srs_g2_digest
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(300)
            || !(1..=64).contains(&config.maximum_parallel)
            || !(1..=64).contains(&config.threads)
            || !(256..=65_536).contains(&config.memory_megabytes)
        {
            return Err(Error::Invalid);
        }
        #[derive(Deserialize)]
        struct Header {
            noir_version: String,
            abi: Abi,
        }
        let mut group: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&config.circuit).map_err(|_| Error::Invalid)?;
        let header: Header =
            serde_json::from_value(group.remove(config.program.key()).ok_or(Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        program_key(&config.verification_key, config.program.key())?;
        if header.noir_version != "1.0.0-beta.26"
            && !header.noir_version.starts_with("1.0.0-beta.26+")
        {
            return Err(Error::Invalid);
        }
        abi::check(config.program, &header.abi)?;
        Ok(Self {
            config: Arc::new(config),
            abi: Arc::new(header.abi),
            active: Arc::new(AtomicUsize::new(0)),
            cancellation: NativeProverCancellation::default(),
        })
    }
    /// Retain this withdrawal handle with the actual Vault/source lifetime.
    pub fn cancellation(&self) -> NativeProverCancellation {
        self.cancellation.clone()
    }

    pub(crate) fn public_inputs(&self, input: &str) -> Result<Vec<[u8; 32]>, Error> {
        abi::public_only(self.config.program, &self.abi, input)
    }
    pub(crate) fn timeout(&self) -> Duration {
        self.config.timeout
    }

    pub(crate) fn prove(
        &self,
        input: Zeroizing<String>,
        public: Vec<[u8; 32]>,
        deadline: Instant,
    ) -> Result<Proof, Error> {
        self.cancellation.check()?;
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.config.maximum_parallel).then_some(n + 1)
            })
            .map_err(|_| Error::Crypto)?;
        struct Permit(Arc<AtomicUsize>);
        impl Drop for Permit {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _permit = Permit(self.active.clone());
        let deadline = deadline.min(Instant::now() + self.config.timeout);
        let result = transport::prove(&self.config, input, &public, deadline, &self.cancellation)?;
        if result.scope != self.config.scope
            || result.public_inputs != public
            || result.proof.is_empty()
            || result.proof.len() > MAX_PROOF
            || !result.proof.len().is_multiple_of(32)
        {
            return Err(Error::Crypto);
        }
        self.cancellation.check()?;
        if Instant::now() >= deadline {
            return Err(Error::Crypto);
        }
        Ok(result)
    }
}

impl NativeProver {
    /// Prove one epoch's record and return the proof string a presentation carries: the
    /// lower-hex JSON bundle `{"version":1,"proofs":[{"proof":"<hex>"}]}` relying parties
    /// decode. Blocking; run it on a background worker. The record proves nothing until a
    /// relying party verifies it against its own authenticated epoch descriptor.
    pub fn prove_record_epoch(
        &self,
        evidence: &crate::account::RecordEpochEvidence,
    ) -> Result<String, Error> {
        if self.config.program != Program::RecordEpoch
            || evidence.record().epoch.proof_scope != self.config.scope
        {
            return Err(Error::Invalid);
        }
        let input = evidence.input_json()?;
        let public = abi::public_inputs(self.config.program, &self.abi, &input)?;
        let proof = self.prove(input, public, Instant::now() + self.config.timeout)?;
        let hex = data_encoding::HEXLOWER.encode(&proof.proof);
        let bundle = serde_json::json!({"version": 1, "proofs": [{"proof": hex}]});
        let bytes = serde_json::to_vec(&bundle).map_err(|_| Error::Invalid)?;
        Ok(data_encoding::HEXLOWER.encode(&bytes))
    }

    /// Prepare the proof of one account update built from the witness (`Account::reserve`,
    /// `activate`, `settle`, ...). Only a prover of the `update` member accepts it. The
    /// returned job owns its private input (wiped on drop) and runs blocking, off the
    /// caller's task, with [`PreparedProof::run`].
    pub fn prepare_update(
        &self,
        input: &crate::account::UpdateInput,
    ) -> Result<PreparedProof, Error> {
        if self.config.program != Program::Update {
            return Err(Error::Invalid);
        }
        let json = input.to_json()?;
        let public = abi::public_inputs(self.config.program, &self.abi, &json)?;
        Ok(PreparedProof {
            prover: self.clone(),
            input: json,
            public,
        })
    }

    /// Prepare the proof of one `wave` (reservation) or `outcome` (settled slot)
    /// evidence; the counterpart checks it with its `WaveVerifier`. The prover's member
    /// must match the evidence: `wave` for a reservation, `outcome` for a settled slot.
    pub fn prepare_wave_evidence(
        &self,
        evidence: &crate::account::Evidence,
    ) -> Result<PreparedProof, Error> {
        let expected = if evidence.is_outcome() {
            Program::Outcome
        } else {
            Program::Wave
        };
        if self.config.program != expected {
            return Err(Error::Invalid);
        }
        let json = evidence.input_json()?;
        let public = abi::public_inputs(self.config.program, &self.abi, &json)?;
        Ok(PreparedProof {
            prover: self.clone(),
            input: json,
            public,
        })
    }

    /// The circuit member this prover runs.
    pub fn program(&self) -> Program {
        self.config.program
    }
}

/// One prepared proof: the private circuit input (wiped when dropped) and its public
/// fields, bound to the prover that checked them. It owns everything it needs, so the
/// blocking [`run`](Self::run) can move to a worker thread.
pub struct PreparedProof {
    prover: NativeProver,
    input: Zeroizing<String>,
    public: Vec<[u8; 32]>,
}
impl PreparedProof {
    /// Prove (blocking) and return the raw proof bytes.
    pub fn run(self) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now() + self.prover.timeout();
        Ok(self.prover.prove(self.input, self.public, deadline)?.proof)
    }
}

#[cfg(test)]
pub(crate) fn update_key(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    program_key(bytes, Program::Update.key())
}
pub(crate) fn program_key(bytes: &[u8], name: &str) -> Result<Vec<u8>, Error> {
    let mut group: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let key = data_encoding::HEXLOWER
        .decode(group.remove(name).ok_or(Error::Invalid)?.as_bytes())
        .map_err(|_| Error::Invalid)?;
    if key.is_empty() || key.len() > MAX_PROOF {
        return Err(Error::Invalid);
    }
    Ok(key)
}

pub(crate) fn sha(bytes: &[u8]) -> Result<[u8; 32], Error> {
    czkp::decode(&czkp::digest(bytes)).map_err(|_| Error::Crypto)
}

/// Fixed nonsecret failure stage of the dedicated owned worker. It contains no
/// witness, library error, diagnostic text or private input.
pub struct WorkerFailure {
    code: u8,
}
impl WorkerFailure {
    /// Reserved process exit code identifying only a fixed execution stage.
    /// These codes are diagnostics, never proof or owner acceptance.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.code)
    }
}

/// Execute only the owned worker entry point with finite memory/core limits.
/// It emits a locally verified public proof or a fixed nonsecret failure stage.
/// The parent prover continues to expose only its coarse authentication error.
pub fn run_worker() -> Result<(), WorkerFailure> {
    worker::run()
}
