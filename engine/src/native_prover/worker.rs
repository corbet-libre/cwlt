//! Original maintained ABI, ACVM and BB execution in one disposable process.
use super::{
    Error, MAX_CIRCUIT, MAX_FRAME, MAX_POINTS, MAX_PROOF, MAX_SETUP, Proof, abi, sha, update_key,
};
use acvm::{
    FieldElement,
    acir::{SerializationFormat, brillig::ForeignCallResult},
    pwg::ForeignCallWaitInfo,
};
use barretenberg_rs::{
    BarretenbergApi,
    backends::FfiBackend,
    generated_types::{CircuitInput, ProofSystemSettings},
};
use data_encoding::BASE64;
use nargo::foreign_calls::{ForeignCallError, ForeignCallExecutor};
use noirc_abi::input_parser::Format;
use noirc_artifacts::program::ProgramArtifact;
use serde::Deserialize;
use std::io::{Read, Write};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    scope: czkp::ProofScope,
    circuit: Vec<u8>,
    verification_key: Vec<u8>,
    srs_g1: Vec<u8>,
    srs_g1_digest: [u8; 32],
    num_points: u32,
    srs_g2: Vec<u8>,
    srs_g2_digest: [u8; 32],
    input: String,
    public_inputs: Vec<[u8; 32]>,
}
struct RefuseForeign;
impl ForeignCallExecutor<FieldElement> for RefuseForeign {
    fn execute(
        &mut self,
        _: &ForeignCallWaitInfo<FieldElement>,
    ) -> Result<ForeignCallResult<FieldElement>, ForeignCallError> {
        Err(ForeignCallError::Disabled(String::new()))
    }
}
fn settings() -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "poseidon2".into(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn prove(mut request: Request, stage: &mut u8) -> Result<Proof, Error> {
    *stage = 66; // Original bounds and complete-group identity.
    let input = Zeroizing::new(std::mem::take(&mut request.input));
    if request.circuit.is_empty()
        || request.circuit.len() > MAX_CIRCUIT
        || request.verification_key.is_empty()
        || request.verification_key.len() > MAX_PROOF
        || sha(&request.circuit)? != request.scope.circuit_digest
        || sha(&request.verification_key)? != request.scope.verifying_key_digest
        || request.num_points == 0
        || request.num_points > MAX_POINTS
        || request.srs_g1.len() > MAX_SETUP
        || !request.srs_g1.len().is_multiple_of(4 * 1024 * 1024)
        || request.srs_g1.len() != request.num_points as usize * 32
        || sha(&request.srs_g1)? != request.srs_g1_digest
        || request.srs_g2.len() != 128
        || sha(&request.srs_g2)? != request.srs_g2_digest
        || input.len() > 1024 * 1024
        || request.public_inputs.len() != 345
    {
        return Err(Error::Invalid);
    }
    *stage = 67; // Fixed original update artifact and ABI.
    #[derive(Deserialize)]
    struct Group {
        update: ProgramArtifact,
    }
    let Group { update: artifact } =
        serde_json::from_slice(&request.circuit).map_err(|_| Error::Invalid)?;
    let verification_key = update_key(&request.verification_key)?;
    if artifact.noir_version != "1.0.0-beta.26"
        && !artifact.noir_version.starts_with("1.0.0-beta.26+")
    {
        return Err(Error::Invalid);
    }
    abi::check(&artifact.abi)?;
    if abi::public_inputs(&artifact.abi, &input)? != request.public_inputs {
        return Err(Error::Invalid);
    }
    let inputs = Format::Json
        .parse(&input, &artifact.abi)
        .map_err(|_| Error::Invalid)?;
    let initial = artifact
        .abi
        .encode(&inputs, None)
        .map_err(|_| Error::Invalid)?;
    *stage = 68; // Maintained ACVM execution, with all foreign calls refused.
    let stack = nargo::ops::execute_program(
        &artifact.bytecode,
        initial,
        &bn254_blackbox_solver::Bn254BlackBoxSolver,
        &mut RefuseForeign,
    )
    .map_err(|_| Error::Crypto)?;
    // Explicit original compact MessagePack; ambient format variables cannot
    // change witness encoding. The compressed private buffer never reaches disk.
    *stage = 69; // Maintained compact witness encoding.
    let witness = Zeroizing::new(
        stack
            .serialize_with_format(SerializationFormat::MsgpackCompact)
            .map_err(|_| Error::Crypto)?,
    );
    if witness.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    *stage = 70; // Unchanged original compressed bytecode.
    #[derive(Deserialize)]
    struct Encoded {
        bytecode: String,
    }
    #[derive(Deserialize)]
    struct EncodedGroup {
        update: Encoded,
    }
    let EncodedGroup { update: encoded } =
        serde_json::from_slice(&request.circuit).map_err(|_| Error::Invalid)?;
    // Pass the unchanged original compressed bytecode, never serialize a new
    // circuit or compute a substitute verification key.
    let bytecode = BASE64
        .decode(encoded.bytecode.as_bytes())
        .map_err(|_| Error::Invalid)?;
    *stage = 71; // Maintained backend construction.
    let backend = FfiBackend::new().map_err(|_| Error::Crypto)?;
    let mut api = BarretenbergApi::new(backend);
    *stage = 72; // Authenticated original full setup.
    api.srs_init_srs(&request.srs_g1, request.num_points, &request.srs_g2)
        .map_err(|_| Error::Crypto)?;
    *stage = 73; // Maintained proving with the original VK and settings.
    let response = api
        .circuit_prove(
            CircuitInput {
                name: "account-genesis".into(),
                bytecode,
                verification_key: verification_key.clone(),
            },
            &witness,
            settings(),
        )
        .map_err(|_| Error::Crypto)?;
    *stage = 74; // Original result framing and VK equality.
    if response.vk.bytes != verification_key
        || response.public_inputs.len() != 345
        || response.proof.is_empty()
        || response.proof.len() > MAX_PROOF / 32
        || response.proof.iter().any(|v| v.len() != 32)
    {
        return Err(Error::Crypto);
    }
    *stage = 75; // Exact original ordered public fields.
    let public: Vec<[u8; 32]> = response
        .public_inputs
        .iter()
        .map(|v| v.as_slice().try_into().map_err(|_| Error::Crypto))
        .collect::<Result<_, _>>()?;
    if public != request.public_inputs {
        return Err(Error::Crypto);
    }
    for field in &public {
        czkp::field(field, false).map_err(|_| Error::Crypto)?;
    }
    *stage = 76; // Maintained local verification against that same original VK.
    let verified = api
        .circuit_verify(
            &verification_key,
            response.public_inputs,
            response.proof.clone(),
            settings(),
        )
        .map_err(|_| Error::Crypto)?;
    if !verified.verified {
        return Err(Error::Crypto);
    }
    let proof = response.proof.into_iter().flatten().collect();
    *stage = 77; // Backend teardown.
    api.destroy().map_err(|_| Error::Crypto)?;
    Ok(Proof {
        scope: request.scope,
        public_inputs: public,
        proof,
    })
}

fn run_at(stage: &mut u8) -> Result<(), Error> {
    *stage = 64; // Owned process resource limits.
    let memory: u64 = std::env::var("CWLT_NATIVE_MEMORY_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or(Error::Invalid)?;
    if !(256..=65_536).contains(&memory) {
        return Err(Error::Invalid);
    }
    rlimit::Resource::AS
        .set(memory * 1024 * 1024, memory * 1024 * 1024)
        .map_err(|_| Error::Crypto)?;
    rlimit::Resource::CORE
        .set(0, 0)
        .map_err(|_| Error::Crypto)?;
    *stage = 65; // Bounded private request decoding.
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(MAX_FRAME as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Crypto)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    let request = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    drop(bytes);
    let result = prove(request, stage)?;
    *stage = 78; // Public proof output only.
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &result).map_err(|_| Error::Crypto)?;
    stdout.write_all(b"\n").map_err(|_| Error::Crypto)
}

pub(super) fn run() -> Result<(), super::WorkerFailure> {
    let mut stage = 64;
    run_at(&mut stage).map_err(|_| super::WorkerFailure { code: stage })
}
