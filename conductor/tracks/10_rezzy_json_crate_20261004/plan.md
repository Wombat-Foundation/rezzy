# Implementation Plan: `rezzy-json` Crate Extraction, Dependency-Free Parser & Canonical Numeric Limits

## Phase 1: Workspace Extraction & `serde` Removal [checkpoint: 83a19c0]

- [x] Task: Split monolithic `src/` into workspace crates and extract JSON foundation `a636e18`
  - [x] Extract core, reconciliation, CLI, and JSON modules from the monolithic `src/` directory into isolated workspace members (`a636e18`, `fe39ad6`).
  - [x] Rename primitive workspace crates under the `rezzy-*` namespace (`rezzy-json`, `rezzy-recon`, `rezzy-cli`) and drop the intermediate facade crate (`0261bc3`, `21b411d`).
- [x] Task: Rip out `serde` and `serde_json` across workspace crates `83a19c0`
  - [x] Remove `serde` and `serde_json` dependencies from `Cargo.toml`, `rz-core`, `rz-reconcile`, and `rz-cli` (`83a19c0`).
  - [x] Isolate `serde_json` strictly to benchmark comparison harnesses in `benches/` (`b4b6d57`).
- [x] Task: Implement initial hand-rolled `#![no_std]` JSON parser and MXID/integer adapter helpers `c84ae6c`
  - [x] Build hand-rolled scalar tokenizer, `Value` DOM, and canonical JSON serializer in `rezzy-json/src/lib.rs` (`c84ae6c`, `64cd85a`).
  - [x] Expose `is_valid_mxid` and `coerce_json_integer_parts` in `rezzy-json` for Matrix event adapters (`f8842ad`).

## Phase 2: Tokenizer Refactoring, Decoded-Key Lookup & `simd-json` Experiment [checkpoint: cc84e6b]

- [x] Task: Deduplicate tokenizer state transitions, escape decoding, and `Value`/`ValueRef` accessors `a5d294d`
  - [x] Consolidate tokenizer advance/open/close helpers and simple escape decoding routines in `rezzy-json/src/lib.rs` (`a5d294d`, `a715220`).
  - [x] Share identical `Value` and `ValueRef` accessor implementations via declarative macro (`01b8ed5`).
- [x] Task: Match and look up `ValueRef` object keys by decoded text and allocation-free masked keys `d31adb3`
  - [x] Decode `\uXXXX` and escape sequences during `ValueRef` key lookup so escaped keys match literal strings (`d31adb3`).
  - [x] Implement allocation-free masked key matching for canonical filtering (`91a808f`, `188264d`).
- [x] Task: Evaluate opt-in safe `simd-json` parsing and differential oracle harness `cc84e6b`
  - [x] Add `simd-json` behind an opt-in feature and establish differential tests comparing `rezzy-json` against `simd-json` (`cc84e6b`, `fd6c533`).
  - [x] Fix doubled quotes in raw canonical escaped strings and fall back to the scalar parser on SIMD errors (`fa26a0a`).

## Phase 3: Wide Integer Spelling Preservation & Canonical Numeric Limits [checkpoint: 4e1d80a]

- [x] Task: Preserve arbitrary-width integer source spellings and prevent `f64` silent corruption `20cef47`
  - [x] Retain raw source digit strings inside `Number` so integers above `2^53 - 1` and `u64::MAX` round-trip byte-exactly in permissive paths instead of rewriting through `f64` (`20cef47`).
  - [x] Pin intentional divergence from `simd-json` on `> u64::MAX` integers via `wide_integers_are_preserved` in `src/basespec/rezzy_types.rs` (`20cef47`).
- [x] Task: Pin numeric range boundaries, float re-rendering, and recursion depth limits `28af64c`
  - [x] Add `numeric_range_boundaries_are_pinned` covering `2^53 - 1`, `2^53`, `2^53 + 1`, `i64::MAX`, `u64::MAX`, `u64::MAX + 1`, `2^100`, `1e21`, `1e308`, `1e400`, `-0`, lone surrogates, and 200-deep nesting (`28af64c`).
  - [x] Document in `docs/json_numeric_limits.md` and `rezzy-json/src/lib.rs` that only integers keep source spelling while floats are re-rendered via `ryu` (`d7cca71`, `4e1d80a`).

## Phase 4: Pure Scalar Architecture & Ergonomic API Completion [checkpoint: 1504cc7]

- [x] Task: Remove `simd-json` dependency and `simd` feature in favor of pure `#![no_std]` scalar parser `0970e94`
  - [x] Remove `simd-json` from `rezzy-json/Cargo.toml` and `Cargo.toml` after benchmarks confirmed the scalar parser was faster (238 MB/s vs 139 MB/s on events) (`0970e94`).
  - [x] Replace `simd-json` oracle tests with direct zero-copy vs. DOM writer differential tests and explicit numeric boundary assertions (`0970e94`).
- [x] Task: Implement `Display`/`FromStr`, RFC 6901 JSON Pointer, `parse_strict`, `parse_located`, and primitive integer conversions `ecc4f3c`
  - [x] Add `Display`, `FromStr`, RFC 6901 `pointer`/`pointer_mut`, `parse_strict`, and line/column `parse_located` diagnostics to `rezzy-json/src/lib.rs` (`ecc4f3c`).
  - [x] Implement `From` conversions for `u8`, `u16`, `i8`, `i16`, `isize`, and `i128` (`1504cc7`).

## History & Audit Traceability

| Commit SHA | Source / Implementation Files | Verification / Test Files | Linked `docs/` Files | Public-Safety Audit Observation (`../../audits/rezzy_docs_public_safety_audit.md`) |
| :--- | :--- | :--- | :--- | :--- |
| `a636e18`, `fe39ad6`, `0261bc3` | [`rezzy-json/Cargo.toml`](../../../rezzy-json/Cargo.toml), [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) | [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | [`docs/tech_debt.md`](../../../docs/tech_debt.md) | Isolates JSON parsing into `#![no_std]` crate; establishes boundary between parser and state engine. |
| `83a19c0`, `c84ae6c`, `d31adb3`, `91a808f` | [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) | [`tests/test_zero_alloc.rs`](../../../tests/test_zero_alloc.rs) | [`docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md) | Decoded-text key lookup (`d31adb3`) prevents duplicate/escaped key bypasses during canonicalization. |
| `cc84e6b`, `20cef47`, `d7cca71`, `4e1d80a` | [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs), [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) | [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md) | **Critical (Hash Split)**: Permissive `write_raw_canonical_filtered` accepts integers `> 2^53 - 1` and floats that `write_raw_canonical_filtered_strict` and `ruma` reject; `as_f64()` silently rounds from `2^53 + 1` (`9007199254740993` -> `9007199254740992.0`). Tracked for P0 remediation in Stage B. |
| `ecc4f3c`, `28af64c`, `0970e94`, `1504cc7` | [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) | [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) | [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md) | Removes `simd-json` DOM conversion overhead and pins 128-level recursion cap (`MAX_DEPTH = 128`). |
