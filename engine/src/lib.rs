//! Internal Wallet package: nonexporting root custody and original witness engine.
//!
//! Keys initializes the immutable purpose-key binding. The parent Wallet owns
//! Store transactions; constructing this engine does not establish accepted state.
#![forbid(unsafe_code)]

pub mod account;
/// Internal cryptographic state; the upper wallet owns every durable receipt.
/// Its public data is not enrollment, admission or accepted-account authority.
pub mod account_key;
/// Native private witness execution over the maintained original Noir/BB owners.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod native_prover;
/// Checked integer planning of every account transition (shared by native and wasm holders).
pub mod plan;
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
    sealing: Arc<sealing::Binding>,
    record: Option<record::State>,
}

impl Engine {
    /// Bind the original purpose seed and distinct sealing key exactly once.
    /// Both caller buffers are wiped on every return, including invalid context.
    /// Legitimate member seeds/keys are supplied inside Keys, never by Wallet.
    pub fn from_seed_and_sealing_key(
        seed: &mut [u8; 32],
        key: &mut [u8; 32],
        wallet_context: &[u8],
    ) -> Result<Self, Error> {
        let owned_seed = Zeroizing::new(*seed);
        let owned_key = Zeroizing::new(*key);
        seed.zeroize();
        key.zeroize();
        let sealing = sealing::Binding::new(&owned_key, wallet_context)?;
        Ok(Self {
            seed: owned_seed,
            sealing: Arc::new(sealing),
            record: None,
        })
    }
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use account::PreparedGenesisProof;
pub use account::{
    AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext, PreparedGenesis, VoucherBond,
};
pub use recipient::{ReceivedRecord, RecordRecipient};
pub use sealing::Sealed;

// Private account preparation computes an uninitialized candidate only. Original
// cross-runtime vectors, the native prover and signed state adoption still need
// their own conformance and owner integration before an accepted account exists.
