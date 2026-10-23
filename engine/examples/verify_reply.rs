//! Native verification of what the browser worker answered, for the browser tests: the same
//! maintained backend the native prover verifies with, the authenticated verification key from
//! the setup the engine handed the worker, and the public inputs the native engine expected.
//!
//! `verify-reply SETUP.json REPLY.json EXPECTED.json ARTIFACT_SETUP_DIR`
use barretenberg_rs::{
    BarretenbergApi, backends::FfiBackend, generated_types::ProofSystemSettings,
};
use data_encoding::HEXLOWER;
use serde::Deserialize;

#[derive(Deserialize)]
struct Setup {
    verification_key: String,
    srs: Srs,
}
#[derive(Deserialize)]
struct Srs {
    points: u32,
}
#[derive(Deserialize)]
struct Reply {
    verified: bool,
    public_inputs: Vec<String>,
    proof: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, setup, reply, expected, srs_dir] = args.as_slice() else {
        panic!("usage: verify-reply SETUP.json REPLY.json EXPECTED.json ARTIFACT_SETUP_DIR");
    };
    let read = |path: &str| std::fs::read(path).expect("readable file");
    let setup: Setup = serde_json::from_slice(&read(setup)).expect("setup");
    let reply: Reply = serde_json::from_slice(&read(reply)).expect("reply");
    let expected: Vec<String> = serde_json::from_slice(&read(expected)).expect("expected");
    assert!(
        reply.verified,
        "the worker reported the proof as not verified"
    );
    assert_eq!(
        reply.public_inputs, expected,
        "public inputs differ from the native engine's"
    );
    let key = HEXLOWER
        .decode(setup.verification_key.as_bytes())
        .expect("verification key");
    let public: Vec<Vec<u8>> = reply
        .public_inputs
        .iter()
        .map(|field| HEXLOWER.decode(field.as_bytes()).expect("public input"))
        .collect();
    let proof = HEXLOWER.decode(reply.proof.as_bytes()).expect("proof");
    assert!(!proof.is_empty() && proof.len() % 32 == 0);
    let proof: Vec<Vec<u8>> = proof.chunks(32).map(<[u8]>::to_vec).collect();
    let g1 = read(&format!("{srs_dir}/g1.dat"));
    let g2 = read(&format!("{srs_dir}/g2.dat"));
    let mut api = BarretenbergApi::new(FfiBackend::new().expect("backend"));
    api.srs_init_srs(&g1[..setup.srs.points as usize * 32], setup.srs.points, &g2)
        .expect("setup");
    let settings = ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "poseidon2".into(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    };
    let verdict = api
        .circuit_verify(&key, public, proof, settings)
        .expect("native verification ran");
    assert!(verdict.verified, "native verification refused the proof");
    println!(
        "native verification: verified ({} public inputs)",
        expected.len()
    );
    api.destroy().expect("teardown");
}
