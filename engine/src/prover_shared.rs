//! What the native and the browser prover share: the exact ABI, the program table, the
//! identity checks of the circuit and key groups, and the size bounds. Nothing here runs a
//! prover; it holds no private input and is compiled for every target (wasm32 included).
use crate::Error;
use czkp::ProofScope;
use noirc_abi::Abi;
use serde::{Deserialize, Serialize};
pub(crate) mod abi;

pub(crate) const MAX_CIRCUIT: usize = 64 * 1024 * 1024;
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

/// The authenticated circuit and key groups of one program, checked once: both groups hash to
/// the scope's digests, the program's member exists, its Noir version is the maintained one
/// and its ABI is exactly the original one. The ABI is what both provers derive the expected
/// public inputs from.
pub(crate) struct Checked {
    pub abi: Abi,
    /// The program's own member of the circuit group, exactly as published.
    pub member: serde_json::Value,
    /// The program's verification key (raw bytes).
    pub key: Vec<u8>,
}
pub(crate) fn check_groups(
    program: Program,
    scope: &ProofScope,
    circuit: &[u8],
    verification_key: &[u8],
) -> Result<Checked, Error> {
    if scope.circuit_digest == [0; 32]
        || circuit.is_empty()
        || circuit.len() > MAX_CIRCUIT
        || sha(circuit)? != scope.circuit_digest
        || verification_key.is_empty()
        || verification_key.len() > MAX_PROOF
        || sha(verification_key)? != scope.verifying_key_digest
    {
        return Err(Error::Invalid);
    }
    #[derive(Deserialize)]
    struct Header {
        noir_version: String,
        abi: Abi,
    }
    let mut group: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(circuit).map_err(|_| Error::Invalid)?;
    let member = group.remove(program.key()).ok_or(Error::Invalid)?;
    let header: Header = serde_json::from_value(member.clone()).map_err(|_| Error::Invalid)?;
    let key = program_key(verification_key, program.key())?;
    if header.noir_version != "1.0.0-beta.26" && !header.noir_version.starts_with("1.0.0-beta.26+")
    {
        return Err(Error::Invalid);
    }
    abi::check(program, &header.abi)?;
    Ok(Checked {
        abi: header.abi,
        member,
        key,
    })
}
