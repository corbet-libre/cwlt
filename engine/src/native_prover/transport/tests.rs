//! Refusing real process fixtures; these never return or fabricate a valid proof.
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn python() -> PathBuf {
    // Reuse the original product route's already required Python. No install,
    // alternative runtime or unconfigured process-provider lookup is performed.
    std::env::split_paths(&std::env::var_os("PATH").expect("original product PATH"))
        .filter(|p| p.is_absolute())
        .map(|p| p.join("python3"))
        .find(|p| p.is_file())
        .expect("original product Python prerequisite")
        .canonicalize()
        .unwrap()
}
fn fixture(dir: &Path, name: &str, body: &str) -> NativeProverConfig {
    let path = dir.join(name);
    let source = format!("#!{}\n{body}\n", python().display());
    fs::write(&path, &source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    // Inert transport data never enters the public configuration validator or
    // claims a real circuit, setup, root, membership or cryptographic verdict.
    NativeProverConfig {
        executable: path,
        executable_digest: sha(source.as_bytes()).unwrap(),
        program: super::super::Program::Update,
        scope: czkp::ProofScope {
            circuit_digest: [1; 32],
            verifying_key_digest: [2; 32],
        },
        circuit: vec![],
        verification_key: vec![],
        srs_g1: vec![],
        srs_g1_digest: [0; 32],
        num_points: 0,
        srs_g2: [0; 128],
        srs_g2_digest: [0; 32],
        timeout: Duration::from_secs(5),
        maximum_parallel: 1,
        threads: 1,
        memory_megabytes: 256,
    }
}
#[test]
fn refusing_owned_process_discards_stderr_and_partial_or_oversized_output() {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in [
        (
            "partial",
            "import sys\nsys.stderr.write('private diagnostic must be discarded')\nsys.stdout.write('{')",
        ),
        ("oversized", "import sys\nsys.stdout.write('x' * 5300000)"),
        ("empty", "pass"),
        ("failed", "import sys\nsys.exit(2)"),
    ] {
        let config = fixture(dir.path(), name, body);
        assert!(
            prove(
                &config,
                Zeroizing::new("fictional inert fixture".into()),
                &[],
                Instant::now() + config.timeout,
                &NativeProverCancellation::default()
            )
            .is_err()
        );
    }
}
#[test]
fn original_whole_deadline_kills_and_reaps_a_worker_that_never_reads_its_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(dir.path(), "deadline", "import time\ntime.sleep(60)");
    let start = Instant::now();
    let result = prove(
        &config,
        Zeroizing::new("x".repeat(1024 * 1024)),
        &[],
        start + Duration::from_millis(100),
        &NativeProverCancellation::default(),
    );
    assert!(result.is_err());
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "pipe writer must join after child kill/reap"
    );
}
#[test]
fn sibling_cancellation_after_actual_child_start_is_terminal_and_releases_pipe_threads() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(
        dir.path(),
        "cancel",
        "import sys,time,pathlib\npathlib.Path(sys.argv[0]).with_suffix('.started').write_text('started')\ntime.sleep(60)",
    );
    let marker = config.executable.with_extension("started");
    let cancel = NativeProverCancellation::default();
    let sibling = cancel.clone();
    let join = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        let started = marker.exists();
        sibling.cancel();
        started
    });
    let start = Instant::now();
    assert!(
        prove(
            &config,
            Zeroizing::new("x".repeat(1024 * 1024)),
            &[],
            start + Duration::from_secs(5),
            &cancel
        )
        .is_err()
    );
    assert!(
        join.join().unwrap(),
        "must cancel after the real child starts"
    );
    assert!(cancel.check().is_err());
    assert!(cancel.clone().check().is_err());
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(
        prove(
            &config,
            Zeroizing::new("inert".into()),
            &[],
            Instant::now() + config.timeout,
            &cancel
        )
        .is_err()
    );
}
#[test]
fn changed_executable_bytes_and_expired_deadline_refuse_before_launch() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(
        dir.path(),
        "changed",
        "import sys,pathlib\npathlib.Path(sys.argv[0]).with_suffix('.started').write_text('started')",
    );
    fs::write(&config.executable, "untrusted replacement").unwrap();
    assert!(
        prove(
            &config,
            Zeroizing::new("inert".into()),
            &[],
            Instant::now() + config.timeout,
            &NativeProverCancellation::default()
        )
        .is_err()
    );
    assert!(!config.executable.with_extension("started").exists());
    assert!(
        prove(
            &config,
            Zeroizing::new("inert".into()),
            &[],
            Instant::now(),
            &NativeProverCancellation::default()
        )
        .is_err()
    );
}
