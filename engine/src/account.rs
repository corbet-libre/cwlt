//! Private original account preparation. Public input objects are data only.
//! No accepted account is installed or serialized by this behavioral stage.
mod activation;
mod codec;
mod hashes;
mod maps;
mod opening;
mod policy;
mod prepared;
mod witness;
#[cfg(feature = "driver")]
pub use witness::driver;

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use activation::prove_activation;
#[cfg(feature = "browser-prover")]
pub use activation::prove_activation_browser;
pub use activation::{ActivationProof, ActivationRequest};
pub use czkp::ProofScope as GenesisProofScope;
pub use policy::{AccountPolicy, ExtensionPolicy};
pub use prepared::{
    AcceptanceBinding, AcceptedAccount, AcceptedGenesisProof, AcceptedResponse, AncestryResponse,
    Frontier, GENESIS_DISCARD_COMMIT_MARGIN_SECONDS, GenesisPublic, IssuerAcceptance,
    MAX_ACCEPTED_SEALED, MAX_PENDING_SEALED, OwnerAbsence, PendingGenesisBinding,
    PreparedGenesisProof, ResponseTrust, SealedAcceptedAccount, SealedPendingGenesis,
};
pub use prepared::{Enrollment, GenesisContext, PreparedGenesis, VoucherBond};
pub use witness::{
    Account, AccountStatement, Acknowledgment, BondEntry, Candidate, Certificate, Checkpoint,
    Delivered, Delivery, Effect, Entropy, Evidence, ExtensionStatement, Genesis,
    MAX_ACCOUNT_SEALED, OsEntropy, PolicyStatement, RecordContext, RecordEpochEvidence,
    RecordPurpose, Reserve, Resolution, RosterRow, SealedAccount, Settled, SettledOutcome, Slot,
    UpdateEffect, UpdateInput, WaveContext, verify_prehash,
};

type Field = [u8; 32];

pub(crate) fn registered_secret(scope: &str, seed: &Field) -> Result<Field, crate::Error> {
    hashes::secret(&hashes::digest(scope.as_bytes())?, seed)
}
