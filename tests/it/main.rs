//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). Each file's inner `#![cfg(feature = "…")]` keeps its meaning as a module
//! attribute; `tests/account_owner/` moved with its consumer, so the `#[path]` strings stay.
mod account_owner;
mod passport;
mod record;
mod transitions;
