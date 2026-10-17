//! The witness driver for the cblc proof jobs: JSON lines on stdin, answers on stdout
//! (`cwlt_engine::account::driver`). Blinds come from the operating system.
fn main() -> std::io::Result<()> {
    cwlt_engine::account::driver::serve(std::io::stdin().lock(), std::io::stdout().lock())
}
