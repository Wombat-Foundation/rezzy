//! Runs the correctness regression tests embedded in
//! `benches/math/filters.rs` under `cargo test`.
//!
//! That module lives in a `harness = false` bench binary (`benches/main.rs`),
//! which never invokes libtest's `#[test]` registry -- its `mod tests` is
//! otherwise dead code, never executed by `cargo bench` (custom `main()`,
//! ignores `#[test]` items) or `make test` (`cargo test --lib --tests`,
//! which doesn't reach `--benches`). Including the file here via `#[path]`
//! puts its `#[cfg(test)]` block under the standard test harness instead of
//! duplicating ~780 lines of filter implementations.
#[path = "../../benches/math/filters.rs"]
// Mirrors the same allow-list `benches/main.rs` sets crate-wide for the
// benchmark suite this file normally compiles under, plus `dead_code` for
// items only consumed by sibling bench files we don't include here.
#[allow(
    dead_code,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown,
    clippy::redundant_closure_for_method_calls
)]
mod filters;
