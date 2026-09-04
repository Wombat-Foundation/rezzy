//! Merged entry point for the ungated integration test files.
//!
//! These 20 files (19 test files + the `differential_harness` module) used to
//! each be their own `[[test]]` target (each a separately-compiled-and-linked
//! binary). None of them need distinct `required-features`, so there's no
//! reason for them to pay a separate link cost each: folding them into
//! submodules of one binary cuts the number of link steps
//! `cargo test`/`cargo build --tests` does for the default feature set from
//! 20 down to 1.
//!
//! Files that still have their own `required-features` (`test_snapshots`,
//! `stress_large_rooms`, `stress_unredacted_lounge`, `test_main`,
//! `test_resolve`) are deliberately NOT here — merging those in would force
//! every `cargo test` to compile against the union of all their heavier
//! optional deps (`ruma-*`, `clap`/`ureq`, `bincode`) instead of skipping
//! them by default. They keep their own `[[test]]` entries in `Cargo.toml`.
//!
//! This file lives at `tests/unit/main.rs` rather than `tests/unit.rs`
//! (which would need `#[path = "unit/X.rs"]` on every line below, since a
//! crate root's bare `mod X;` looks in its *own* directory) so plain
//! `mod X;` finds each sibling file directly, the same convention
//! `src/bin/<name>/main.rs` uses for binaries with submodules. Cargo's
//! `tests/*.rs` autodiscovery doesn't reach into `tests/unit/` at all, so
//! this target needs one explicit `[[test]]` entry in `Cargo.toml` (the
//! only one of these 20 files that does).
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

// Declared once here rather than separately by each child module below --
// they all reference this single instance via `use crate::utils;` instead
// of each re-declaring their own `mod utils;` (which would compile 9
// separate copies of the same file as nominally-distinct types).
#[path = "../utils/mod.rs"]
mod utils;

mod differential_harness;
mod test_auth;
mod test_bench_filters;
mod test_causal;
mod test_critique;
mod test_hashing;
mod test_integer_keys;
mod test_lib;
mod test_merkle;
mod test_pathologies;
mod test_reconcile_algebraic;
mod test_reconcile_e2e;
mod test_restricted_joins;
mod test_sanity;
mod test_semilattice;
mod test_state_at;
mod test_state_dag;
mod test_tombstone;
mod test_traversal;
mod test_utils;
