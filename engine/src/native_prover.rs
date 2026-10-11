//! Native member-side proving. Configuration is trusted runtime data, not a grant.
//! Private inputs have no public constructor, serializer or callback boundary.
use crate::Error;
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

/// Explicit immutable original policy material and resource bounds. The host
/// authenticates it from current owners; callers cannot choose it via request JSON.
pub struct NativeProverConfig {
    /// Absolute trusted owned worker executable. It must not fork descendants.
    pub executable: PathBuf,
    /// Actual compiled worker SHA-256 checked before each process launch.
    pub executable_digest: [u8; 32],
    /// Original authenticated circuit and verification-key identities.
    pub scope: ProofScope,
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
        #[derive(Deserialize)]
        struct Group {
            update: Header,
        }
        let Group { update: header } =
            serde_json::from_slice(&config.circuit).map_err(|_| Error::Invalid)?;
        update_key(&config.verification_key)?;
        if header.noir_version != "1.0.0-beta.26"
            && !header.noir_version.starts_with("1.0.0-beta.26+")
        {
            return Err(Error::Invalid);
        }
        abi::check(&header.abi)?;
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
        abi::public_only(&self.abi, input)
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub scope: ProofScope,
    pub public_inputs: Vec<[u8; 32]>,
    pub proof: Vec<u8>,
}
pub(crate) fn update_key(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(Deserialize)]
    struct Group {
        update: String,
    }
    let group: Group = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let key = data_encoding::HEXLOWER
        .decode(group.update.as_bytes())
        .map_err(|_| Error::Invalid)?;
    if key.is_empty() || key.len() > MAX_PROOF {
        return Err(Error::Invalid);
    }
    Ok(key)
}

pub(crate) fn sha(bytes: &[u8]) -> Result<[u8; 32], Error> {
    czkp::decode(&czkp::digest(bytes)).map_err(|_| Error::Crypto)
}

/// Execute only the owned worker entry point. It imposes finite memory/core limits
/// and emits a locally verified public proof or exits with a coarse refusal.
pub fn run_worker() -> Result<(), Error> {
    worker::run()
}
