//! Private original account preparation. Public input objects are data only.
//! No accepted account is installed or serialized by this behavioral stage.
mod hashes;
mod maps;
mod opening;
mod policy;
mod prepared;

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use czkp::ProofScope as GenesisProofScope;
pub use policy::{AccountPolicy, ExtensionPolicy};
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use prepared::{
    AcceptanceBinding, AcceptedGenesisProof, GenesisPublic, IssuerAcceptance, PreparedGenesisProof,
};
pub use prepared::{Enrollment, GenesisContext, PreparedGenesis};

type Field = [u8; 32];

pub(crate) fn registered_secret(scope: &str, seed: &Field) -> Result<Field, crate::Error> {
    hashes::secret(&hashes::digest(scope.as_bytes())?, seed)
}
