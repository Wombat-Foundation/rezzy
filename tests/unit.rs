//! Merged entry point for the ungated integration test files.
//!
//! These 16 files used to each be their own `[[test]]` target (each a
//! separately-compiled-and-linked binary). None of them need distinct
//! `required-features`, so there's no reason for them to pay a separate
//! link cost each: folding them into submodules of one binary cuts the
//! number of link steps `cargo test`/`cargo build --tests` does for the
//! default feature set from 16 down to 1.
//!
//! Files that still have their own `required-features` (`test_snapshots`,
//! `stress_large_rooms`, `stress_unredacted_lounge`, `test_main`,
//! `test_resolve`) are deliberately NOT here — merging those in would force
//! every `cargo test` to compile against the union of all their heavier
//! optional deps (`ruma-*`, `clap`/`ureq`, `bincode`) instead of skipping
//! them by default. They keep their own `[[test]]` entries in `Cargo.toml`.
//!
//! Each child lives in `tests/unit/` rather than directly under `tests/` so
//! Cargo's test autodiscovery (`tests/*.rs`) doesn't *also* independently
//! claim it as its own target -- autodiscovery only scans files directly in
//! `tests/`, not subdirectories, the same convention already used for
//! `tests/utils/` and `tests/bin/regen_oracles.rs`.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

// Declared once here rather than separately by each child module below --
// they all reference this single instance via `use crate::utils;` instead
// of each re-declaring their own `mod utils;` (which would compile 9
// separate copies of the same file as nominally-distinct types).
mod utils;

#[path = "unit/differential_harness.rs"]
mod differential_harness;
#[path = "unit/test_auth.rs"]
mod test_auth;
#[path = "unit/test_critique.rs"]
mod test_critique;
#[path = "unit/test_hashing.rs"]
mod test_hashing;
#[path = "unit/test_integer_keys.rs"]
mod test_integer_keys;
#[path = "unit/test_lattice.rs"]
mod test_lattice;
#[path = "unit/test_lib.rs"]
mod test_lib;
#[path = "unit/test_merkle.rs"]
mod test_merkle;
#[path = "unit/test_pathologies.rs"]
mod test_pathologies;
#[path = "unit/test_reconcile_algebraic.rs"]
mod test_reconcile_algebraic;
#[path = "unit/test_restricted_joins.rs"]
mod test_restricted_joins;
#[path = "unit/test_sanity.rs"]
mod test_sanity;
#[path = "unit/test_state_at.rs"]
mod test_state_at;
#[path = "unit/test_tombstone.rs"]
mod test_tombstone;
#[path = "unit/test_traversal.rs"]
mod test_traversal;
#[path = "unit/test_utils.rs"]
mod test_utils;
