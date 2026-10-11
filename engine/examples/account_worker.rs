//! Owned original Noir/BB worker; no private input is printed on refusal.
fn main() {
    if cwlt_engine::native_prover::run_worker().is_err() {
        std::process::exit(2);
    }
}
