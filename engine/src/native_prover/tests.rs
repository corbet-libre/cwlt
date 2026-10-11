//! Genuine original retained artifact inputs; these establish no admission owner.
use super::*;
use std::{fs::File, io::Read, path::Path};

fn read(path: &Path, maximum: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .expect("original retained prover fixture")
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= maximum, "original fixture allocation bound");
    bytes
}
fn pin(bytes: &[u8], expected: &str) {
    assert_eq!(
        data_encoding::HEXLOWER.encode(&sha(bytes).unwrap()),
        expected
    );
}
pub(crate) fn config() -> NativeProverConfig {
    let directory = std::env::var_os("CWLT_NATIVE_PROVER_FIXTURE")
        .expect("genuine original retained extension artifact prerequisite");
    let directory = PathBuf::from(directory);
    assert!(directory.is_absolute());
    let manifest = read(&directory.join("manifest.json"), 65_536);
    pin(
        &manifest,
        "f9481cd5933dff2a560ef08f2d710304c4a9fc6dee97c776176a6032669012ee",
    );
    let receipt = read(&directory.join("worker.json"), 65_536);
    pin(
        &receipt,
        "7270351d40c1ed49b1499ec82e59449e6d28ca715d5590485dee56e7ef757ff2",
    );
    let circuit = read(&directory.join("circuits.json"), MAX_CIRCUIT);
    pin(
        &circuit,
        "49b022b8356f0b331bcb5d8b2c86c14c619219d8e597c4abbd386ce98318b5e4",
    );
    let verification_key = read(&directory.join("keys.json"), MAX_PROOF);
    pin(
        &verification_key,
        "e1533badd256e63b7817018ba59a5cd822f3e936a723d7f31bd85a49a6190ae0",
    );
    let srs_g1 = read(&directory.join("setup/g1.dat"), MAX_SETUP);
    pin(
        &srs_g1,
        "23d5e6ef4d511367e83c0d909911b7cdd33f0b324d4106d57eefdf50fac6a59d",
    );
    let srs_g2 = read(&directory.join("setup/g2.dat"), 128);
    pin(
        &srs_g2,
        "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f",
    );
    let executable = PathBuf::from(
        std::env::var_os("CWLT_NATIVE_PROVER_WORKER")
            .expect("actual owned native worker prerequisite"),
    );
    assert!(executable.is_absolute());
    let executable_digest = sha(&read(&executable, 512 * 1024 * 1024)).unwrap();
    NativeProverConfig {
        executable,
        executable_digest,
        scope: ProofScope {
            circuit_digest: sha(&circuit).unwrap(),
            verifying_key_digest: sha(&verification_key).unwrap(),
        },
        circuit,
        verification_key,
        srs_g1_digest: sha(&srs_g1).unwrap(),
        srs_g1,
        num_points: 2_621_440,
        srs_g2_digest: sha(&srs_g2).unwrap(),
        srs_g2: srs_g2.try_into().unwrap(),
        timeout: Duration::from_secs(300),
        maximum_parallel: 1,
        threads: 2,
        memory_megabytes: 4096,
    }
}
#[test]
fn original_whole_group_scope_refuses_changes_to_other_members_and_wrong_scope() {
    let mut original = config();
    assert!(NativeProver::new(config()).is_ok());
    original.scope.circuit_digest[0] ^= 1;
    assert!(NativeProver::new(original).is_err());
    let mut changed = config();
    let mut group: serde_json::Value = serde_json::from_slice(&changed.circuit).unwrap();
    let update = group["update"].clone();
    group["record"]["noir_version"] = serde_json::json!("foreign");
    assert_eq!(group["update"], update);
    changed.circuit = serde_json::to_vec(&group).unwrap();
    assert!(NativeProver::new(changed).is_err());
    let mut changed = config();
    let mut keys: serde_json::Value = serde_json::from_slice(&changed.verification_key).unwrap();
    let update = keys["update"].clone();
    keys["deposit"] = serde_json::json!("00");
    assert_eq!(keys["update"], update);
    changed.verification_key = serde_json::to_vec(&keys).unwrap();
    assert!(NativeProver::new(changed).is_err());
}
#[test]
fn original_group_parser_refuses_single_program_missing_update_and_raw_key_projection() {
    let mut single = config();
    let group: serde_json::Value = serde_json::from_slice(&single.circuit).unwrap();
    single.circuit = serde_json::to_vec(&group["update"]).unwrap();
    single.scope.circuit_digest = sha(&single.circuit).unwrap();
    assert!(NativeProver::new(single).is_err());
    let mut missing = config();
    let mut group: serde_json::Value = serde_json::from_slice(&missing.circuit).unwrap();
    group.as_object_mut().unwrap().remove("update");
    missing.circuit = serde_json::to_vec(&group).unwrap();
    missing.scope.circuit_digest = sha(&missing.circuit).unwrap();
    assert!(NativeProver::new(missing).is_err());
    let mut raw = config();
    raw.verification_key = update_key(&raw.verification_key).unwrap();
    raw.scope.verifying_key_digest = sha(&raw.verification_key).unwrap();
    assert!(NativeProver::new(raw).is_err());
    let mut missing = config();
    let mut group: serde_json::Value = serde_json::from_slice(&missing.verification_key).unwrap();
    group.as_object_mut().unwrap().remove("update");
    missing.verification_key = serde_json::to_vec(&group).unwrap();
    missing.scope.verifying_key_digest = sha(&missing.verification_key).unwrap();
    assert!(NativeProver::new(missing).is_err());
}

#[test]
fn original_supplied_vk_response_is_absent_and_never_replaces_the_original_key() {
    use barretenberg_rs::generated_types::CircuitComputeVkResponse;
    let original = CircuitComputeVkResponse {
        bytes: vec![],
        fields: vec![],
        hash: vec![],
    };
    assert!(super::worker::supplied_vk_response(&original));
    for returned in [
        CircuitComputeVkResponse {
            bytes: vec![1],
            ..original.clone()
        },
        CircuitComputeVkResponse {
            fields: vec![vec![1]],
            ..original.clone()
        },
        CircuitComputeVkResponse {
            hash: vec![1],
            ..original.clone()
        },
    ] {
        assert!(!super::worker::supplied_vk_response(&returned));
    }
}

#[test]
fn maintained_backend_failures_have_only_fixed_nonsecret_categories() {
    use barretenberg_rs::BarretenbergError as Backend;
    let classify = super::worker::backend_stage;
    assert_eq!(classify(&Backend::Backend("std::bad_alloc".into())), 80);
    assert_eq!(
        classify(&Backend::Backend(
            "verification key has wrong size: expected 3680, got 1".into()
        )),
        81
    );
    assert_eq!(
        classify(&Backend::Backend(
            "acir_format::circuit_buf_to_acir_format: failed to convert msgpack data to Program"
                .into()
        )),
        82
    );
    assert_eq!(classify(&Backend::Backend("acir_format::witness_buf_to_witness_vector: failed to convert msgpack data to WitnessStack".into())), 83);
    assert_eq!(
        classify(&Backend::Serialization(
            "private fixture must remain redacted".into()
        )),
        84
    );
    assert_eq!(
        classify(&Backend::Deserialization(
            "private fixture must remain redacted".into()
        )),
        85
    );
    assert_eq!(
        classify(&Backend::InvalidResponse(
            "private fixture must remain redacted".into()
        )),
        86
    );
    assert_eq!(
        classify(&Backend::Backend(
            "unrecognized private fixture must remain redacted".into()
        )),
        87
    );
    assert_eq!(
        classify(&Backend::Ipc("private fixture must remain redacted".into())),
        88
    );
    assert_eq!(
        classify(&Backend::Backend(
            "prefix std::bad_alloc private fixture must remain redacted".into()
        )),
        87
    );
}
