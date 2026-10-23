# Rust & High-Assurance Systems Style Guide (`rezzy`)

## 1. Safety & `#![no_std]` Discipline
- Enforce `#![deny(unsafe_code)]` across workspace crates unless explicitly justified, audited, and gated.
- Core library crates (`rezzy`, `rezzy-json`, `rezzy-recon`) must compile with `#![no_std]` + `extern crate alloc`.
- Never perform network or filesystem I/O inside state resolution, authorization, or set reconciliation kernels.

## 2. Determinism & Consensus Safety
- Never rely on randomized hash-table iteration order for consensus-critical outputs; always canonicalize or sort before emitting resolved state, JSON bytes, or trie proofs.
- Enforce strict numeric bounds (`[-2^53 + 1, 2^53 - 1]`) in canonical JSON serialization (`rezzy-json`); never silently cast wide integers via `as f64`.
- Make room boundary and authorization invariants mandatory in type signatures (avoid `Option<RoomId>` fail-open defaults).

## 3. Lints & Formatting
- All code must pass `cargo clippy --all-targets --all-features` with `rust_2018_idioms = "deny"` and `unused_must_use = "deny"`.
- Format according to `rustfmt.toml`.
