//! Browser build of cwlt: the wasm-bindgen cdylib.
//!
//! The re-export makes this crate reference cwlt, so the linker keeps every `#[wasm_bindgen]` item of cwlt (the
//! exports of a crate that is never referenced are dropped).
#![forbid(unsafe_code)]
pub use cwlt::*;
