// crates/platform-macos/src/lib.rs
//
// Native macOS integration — the enforcement boundary.
// This is the *only* crate that knows about BPF, pf, or (later) NetworkExtension.

pub mod protocol;
pub mod helper;
pub mod agent;
