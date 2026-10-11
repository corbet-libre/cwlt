//! Owned original Noir/BB worker; no private input is printed on refusal.
fn main() {
    if let Err(failure) = cwlt_engine::native_prover::run_worker() {
        std::process::exit(failure.exit_code());
    }
}
