//! Original CVFY scoped process ownership, with private frames wiped on drop.
use super::{
    Error, MAX_FRAME, MAX_PROOF, NativeProverCancellation, NativeProverConfig, Proof, sha,
};
use serde::Serialize;
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(all(test, unix))]
mod tests;

#[derive(Serialize)]
pub(super) struct Request<'a> {
    pub scope: &'a czkp::ProofScope,
    pub circuit: &'a [u8],
    pub verification_key: &'a [u8],
    pub srs_g1: &'a [u8],
    pub srs_g1_digest: [u8; 32],
    pub num_points: u32,
    pub srs_g2: &'a [u8],
    pub srs_g2_digest: [u8; 32],
    pub input: &'a str,
    pub public_inputs: &'a [[u8; 32]],
}

pub(super) fn prove(
    config: &NativeProverConfig,
    input: Zeroizing<String>,
    public: &[[u8; 32]],
    deadline: Instant,
    cancel: &NativeProverCancellation,
) -> Result<Proof, Error> {
    cancel.check()?;
    if Instant::now() >= deadline {
        return Err(Error::Crypto);
    }
    let executable = std::fs::File::open(&config.executable).map_err(|_| Error::Crypto)?;
    let mut binary = Vec::new();
    executable
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut binary)
        .map_err(|_| Error::Crypto)?;
    if binary.len() > 256 * 1024 * 1024 || sha(&binary)? != config.executable_digest {
        return Err(Error::Crypto);
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Request {
            scope: &config.scope,
            circuit: &config.circuit,
            verification_key: &config.verification_key,
            srs_g1: &config.srs_g1,
            srs_g1_digest: config.srs_g1_digest,
            num_points: config.num_points,
            srs_g2: &config.srs_g2,
            srs_g2_digest: config.srs_g2_digest,
            input: &input,
            public_inputs: public,
        })
        .map_err(|_| Error::Invalid)?,
    );
    if bytes.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    drop(input);
    thread::scope(|scope| {
        cancel.check()?;
        if Instant::now() >= deadline {
            return Err(Error::Crypto);
        }
        let child = Command::new(&config.executable)
            .env_clear()
            .env(
                "CWLT_NATIVE_MEMORY_MIB",
                config.memory_megabytes.to_string(),
            )
            .env("HARDWARE_CONCURRENCY", config.threads.to_string())
            .env("RAYON_NUM_THREADS", config.threads.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Crypto)?;
        let mut worker = Worker(child);
        let mut stdin = worker.0.stdin.take().ok_or(Error::Crypto)?;
        let stdout = worker.0.stdout.take().ok_or(Error::Crypto)?;
        let writer = thread::Builder::new()
            .spawn_scoped(scope, move || {
                std::panic::catch_unwind(move || stdin.write_all(&bytes))
            })
            .map_err(|_| Error::Crypto)?;
        let reader = thread::Builder::new()
            .spawn_scoped(scope, move || {
                let mut bytes = Zeroizing::new(Vec::new());
                stdout
                    .take((MAX_PROOF * 5 + 32768 + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            })
            .map_err(|_| Error::Crypto)?;
        let status = loop {
            match worker.0.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if cancel.check().is_ok() && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2))
                }
                _ => break None,
            }
        };
        let timely = Instant::now() < deadline;
        drop(worker);
        let wrote = writer
            .join()
            .ok()
            .and_then(Result::ok)
            .is_some_and(|r| r.is_ok());
        let output = reader
            .join()
            .map_err(|_| Error::Crypto)?
            .map_err(|_| Error::Crypto)?;
        cancel.check()?;
        if !timely
            || Instant::now() >= deadline
            || !wrote
            || !status.is_some_and(|s| s.success())
            || output.len() > MAX_PROOF * 5 + 32768
        {
            return Err(Error::Crypto);
        }
        serde_json::from_slice(&output).map_err(|_| Error::Crypto)
    })
}
