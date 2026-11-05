//! Internal Wallet package: nonexporting root custody and original witness engine.
//!
//! Keys initializes the immutable purpose-key binding. The parent Wallet owns
//! Store transactions; constructing this engine does not establish accepted state.
#![forbid(unsafe_code)]

pub mod account;
/// Internal cryptographic state; the upper wallet owns every durable receipt.
/// Its public data is not enrollment, admission or accepted-account authority.
pub mod account_key;
/// The engine side of the browser prover: material checks, expected public inputs and the
/// `ProofWorker` port a Web Worker answers behind.
#[cfg(feature = "browser-prover")]
pub mod browser_prover;
/// Native private witness execution over the maintained original Noir/BB owners.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod native_prover;
/// Checked integer planning of every account transition (shared by native and wasm holders).
pub mod plan;
mod proof;
#[cfg(feature = "prover-core")]
mod prover_shared;
mod recipient;
mod record;
mod sealing;

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Coarse error with no holder secrets, openings, or ciphertext included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid constructor or bounded sealed input.
    Invalid,
    /// Authentication or maintained cryptographic operation failed.
    Crypto,
    /// An original indexed-map constraint was violated.
    Map,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid wallet engine input",
            Self::Crypto => "wallet engine authentication failed",
            Self::Map => "invalid wallet map transition",
        })
    }
}
impl std::error::Error for Error {}

/// Keys-initialized holder. No raw key, root, witness, or rekey accessor exists.
///
/// The current constructor creates an **uninitialized** accounting engine. It
/// grants neither accepted balance nor a Wave reservation. Signed genesis and
/// actual proof/adoption operations are implemented separately before integration.
///
/// ```compile_fail
/// # let mut seed = [7;32]; let mut key = [8;32];
/// # let holder = cwlt_engine::Engine::from_seed_and_sealing_key(&mut seed,&mut key,b"scope").unwrap();
/// holder.rekey(&mut [0;32]);
/// ```
/// ```compile_fail
/// # let mut seed = [7;32]; let mut key = [8;32];
/// # let holder = cwlt_engine::Engine::from_seed_and_sealing_key(&mut seed,&mut key,b"scope").unwrap();
/// let root = holder.seed;
/// ```
pub struct Engine {
    seed: Zeroizing<[u8; 32]>,
    // Seals every private state format (engine, pending, accepted, account witness).
    sealing: Arc<sealing::Binding>,
    // Opening only, newest first: predecessor state keys. They never seal.
    opening: Arc<[sealing::Binding]>,
    // Seals the account-key capsule only.
    account_sealing: Arc<sealing::Binding>,
    record: Option<record::State>,
}

impl Engine {
    /// Bind the original purpose seed and ONE sealing key, for the private state and
    /// the account-key capsule alike, exactly once; nothing older opens.
    /// Both caller buffers are wiped on every return, including invalid context.
    /// Legitimate member seeds/keys are supplied inside Keys, never by Wallet.
    pub fn from_seed_and_sealing_key(
        seed: &mut [u8; 32],
        key: &mut [u8; 32],
        wallet_context: &[u8],
    ) -> Result<Self, Error> {
        let mut account = Zeroizing::new(*key);
        Self::from_seed_and_sealing_keys(seed, key, &mut [], &mut account, wallet_context)
    }

    /// Bind the original purpose seed and two distinct sealing keys exactly once.
    /// `state` seals every private state format; Keys derives it from the member's
    /// current epoch root, so a device removal rotates it. `opening` holds the
    /// predecessor state keys, newest first: they only open, and a reopened state
    /// seals under `state` again, out of a removed device's reach. `account` seals the
    /// account-key capsule, which guards a stable scalar and so never rotates.
    /// Every caller buffer is wiped on every return, including invalid context.
    pub fn from_seed_and_sealing_keys(
        seed: &mut [u8; 32],
        state: &mut [u8; 32],
        opening: &mut [[u8; 32]],
        account: &mut [u8; 32],
        wallet_context: &[u8],
    ) -> Result<Self, Error> {
        let owned_seed = Zeroizing::new(*seed);
        let owned_state = Zeroizing::new(*state);
        let owned_opening = Zeroizing::new(opening.to_vec());
        let owned_account = Zeroizing::new(*account);
        seed.zeroize();
        state.zeroize();
        opening.iter_mut().for_each(Zeroize::zeroize);
        account.zeroize();
        let sealing = sealing::Binding::new(&owned_state, wallet_context)?;
        let opening = owned_opening
            .iter()
            .map(|key| sealing::Binding::new(key, wallet_context))
            .collect::<Result<Vec<_>, _>>()?;
        let account_sealing = sealing::Binding::new(&owned_account, wallet_context)?;
        Ok(Self {
            seed: owned_seed,
            sealing: Arc::new(sealing),
            opening: opening.into(),
            account_sealing: Arc::new(account_sealing),
            record: None,
        })
    }
}

pub use account::PreparedGenesisProof;
pub use account::{
    AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext, PreparedGenesis, VoucherBond,
};
pub use recipient::{ReceivedRecord, RecordRecipient};
pub use sealing::Sealed;

// Private account preparation computes an uninitialized candidate only. Original
// cross-runtime vectors, the native prover and signed state adoption still need
// their own conformance and owner integration before an accepted account exists.
