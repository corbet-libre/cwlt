//! The proof record the account engine retains. It is plain data: any prover (the native
//! one or a browser one) fills it, and the engine only reads it back.
use czkp::ProofScope;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub scope: ProofScope,
    pub public_inputs: Vec<[u8; 32]>,
    pub proof: Vec<u8>,
}
