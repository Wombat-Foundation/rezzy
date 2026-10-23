# Implementation Plan: Track 15 — P0 Seal Permissive Canonical JSON, Fix `> u64::MAX` Fallthrough & Harden `as_f64`

## Phase 1: Red-Phase Boundary & Hash-Split Regression Tests
- [ ] Task: Add failing tests for `> u64::MAX` fallthrough in `validate_canonical_number` (`T10-F1`), permissive writer exposure (`T10-F2`), and lossy `as_f64` (`T10-F3`)
  - [ ] Add unit test in `src/basespec/rezzy_types.rs` asserting `validate_canonical_number` rejects integers $> \text{u64::MAX}$ (`18446744073709551616`) and $< \text{i64::MIN}$ when `as_i64()` and `as_u64()` both return `None`
  - [ ] Add unit tests in `rezzy-json` for `2^53` (`9007199254740992`) and `2^53 + 1` (`9007199254740993`) boundary rejection

## Phase 2: Fix `validate_canonical_number` Fallthrough, Seal Permissive Writers & Harden `Number::as_f64`
- [ ] Task: Fix `src/basespec/rezzy_types.rs:1144-1161` fallthrough and gate permissive canonical JSON writers in `rezzy-json`
  - [ ] Return `Err(JsonError::IntegerOutOfRange)` in `validate_canonical_number` when `n` is an integer token (`!n.as_str().contains(['.', 'e', 'E'])`) and both `as_i64()` and `as_u64()` are `None`
  - [ ] Gate permissive `write_raw_canonical_filtered` behind explicit legacy/test flags and add checked `try_as_f64_exact()`
  - [ ] Update `docs/json_numeric_limits.md` and run `cargo test --workspace --lib --tests`
