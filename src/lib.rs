//! Zero-knowledge accounting wallet (holder).
//!
//! Private member-side witness planning. Every result still needs a real proof
//! of the independently authenticated policy circuit before an issuer accepts it.
#![forbid(unsafe_code)]
pub mod witness;

/// Durable pending account-key custody. This grants no accepted account state.
#[cfg(feature = "account")]
pub mod account_owner;

/// Durable epoch-cache custody through Keys' exact engine and the original Store.
/// A committed proof cache supplies no proof or accepted-account authority.
#[cfg(feature = "record")]
pub mod record;

/// Nonexporting global-passport custody over the existing Pseudonyms engine.
#[cfg(feature = "passport")]
pub mod passport;

/// Wallet-owned global passport with no secret or opening accessors.
#[cfg(feature = "passport")]
pub use passport::{Holder as PassportHolder, PassportSession};

/// Prepare one private transition as JSON for the Noir/Barretenberg host adapter.
/// Neither inputs nor outputs may be logged, sent to an issuer, or stored unencrypted.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn prepare(input: &str) -> Result<String, String> {
    if input.len() > 8192 {
        return Err("witness input bound".into());
    }
    let request: witness::Request = serde_json::from_str(input).map_err(|_| "invalid witness")?;
    let result = request.prepare().map_err(|_| "invalid transition")?;
    // Plan contains only primitive integers and booleans: JSON encoding is total.
    Ok(serde_json::json!(result).to_string())
}

/// Extension-state counterpart reservation verification.
#[cfg(feature = "wave")]
pub mod wave;
