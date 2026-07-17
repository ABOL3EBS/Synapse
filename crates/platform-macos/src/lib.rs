// crates/platform-macos/src/lib.rs
//
// Native macOS integration — the enforcement boundary.
// This is the *only* crate that knows about BPF, pf, or (later) NetworkExtension.
//
// The `helper` and `agent` directories contain the binary entry points (main.rs).
// They are NOT re-exported as library modules here because the binary directory
// names conflict with `pub mod helper` / `pub mod agent` declarations.
// Each binary manages its own internal modules via `mod` in its main.rs.

pub mod protocol;
