//! Private original account preparation. Public input objects are data only.
//! No accepted account is installed or serialized by this behavioral stage.
mod hashes;
mod maps;
mod opening;
mod policy;
mod prepared;

pub use policy::{AccountPolicy, ExtensionPolicy};
pub use prepared::{Enrollment, GenesisContext, PreparedGenesis};

type Field = [u8; 32];
