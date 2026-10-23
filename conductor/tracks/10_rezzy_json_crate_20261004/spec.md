# Specification: `rezzy-json` Crate Extraction, Dependency-Free Parser & Canonical Numeric Limits

## 1. Overview & Historical Context

- **Epoch**: September 20, 2026 – October 12, 2026 (`0.6.0-rc.1` – `0.6.0-rc.2`)
- **Primary Commit Trajectory**: `a636e18`, `fe39ad6`, `83a19c0`, `c84ae6c`, `64cd85a`, `f8842ad`, `0261bc3`, `a5d294d`, `a715220`, `d31adb3`, `01b8ed5`, `cc84e6b`, `20cef47`, `fd6c533`, `d7cca71`, `fa26a0a`, `ecc4f3c`, `28af64c`, `4e1d80a`, `0970e94`, `1504cc7`
- **Motivation**:
  1. **Workspace Modularization**: Splitting the monolithic `rezzy` repository into focused crates (`rezzy`, `rezzy-json`, `rezzy-recon`, `rezzy-cli`) required a lightweight, `#![no_std]`-compatible JSON foundation without pulling `serde` procedural macros into every compilation unit.
  2. **Zero-Copy Canonical Serialization**: Matrix event reference hashes and Ed25519 signatures require deterministic lexicographical key sorting and strict numeric validation. Constructing a full heap DOM (`serde_json::Value` or `simd_json::OwnedValue`) just to filter top-level fields (`signatures`, `unsigned`) wasted allocations and CPU cycles.
  3. **Numeric Boundary Fidelity**: Differential testing against `ruma` and `simd-json` revealed subtle bugs when handling 64-bit Snowflake IDs, integers exceeding `2^53 - 1`, integers wider than `u64::MAX`, exponent-notation floats (`1e21`), and negative zero (`-0`).

## 2. Functional Requirements & Matrix Spec/MSC Mapping

1. **Matrix Canonical JSON Grammar**:
   - Must enforce the Matrix Canonical JSON specification: UTF-8 encoding, no insignificant whitespace, object keys sorted lexicographically by Unicode code point, shortest escape sequences (`\b`, `\t`, `\n`, `\f`, `\r`, `\"`, `\\`, and `\u00XX` for other control characters `<= 0x1F`), and strict integer bounds `[-9007199254740991, 9007199254740991]` (`[-(2^53 - 1), 2^53 - 1]`).
2. **Three-Tier Numeric Semantics (`docs/json_numeric_limits.md`)**:
   - **Canonical-Safe Range (`|n| <= 2^53 - 1`)**: Accepted by `Value::parse`, `write_raw_canonical_filtered`, `write_raw_canonical_filtered_strict`, and `ruma` (`js_int::Int`).
   - **Wide Integer Range (`2^53 <= |n| <= u64::MAX` and `|n| > u64::MAX`)**: `Number` preserves the exact source digit string so permissive canonicalization (`write_raw_canonical_filtered`) and `write_string_value` round-trip byte-for-byte without `f64` coercion. Strictly rejected with `Error::InvalidNumber` by `write_raw_canonical_filtered_strict` and `parse_strict`.
   - **Floats & Negative Zero**: Literals containing `.`, `e`, or `E` are parsed as `f64` and re-rendered via `ryu` (except literals overflowing `f64` like `1e400`, which retain source spelling in permissive paths). Source `-0` normalizes to `-0.0` with `as_f64() == Some(-0.0)`. All floats are rejected by `write_raw_canonical_filtered_strict`.
3. **Ergonomic `#![no_std]` DOM & Zero-Copy Views**:
   - Provide owned `Value` / `Object` / `Number` types alongside borrowed `ValueRef<'a>` zero-copy views.
   - Implement `Display`, `FromStr`, RFC 6901 JSON Pointer (`Value::pointer` / `Value::pointer_mut`), `parse_strict`, `parse_located` (returning byte offset, line, and column diagnostics), and `From` conversions for all primitive integer types (`u8`, `u16`, `u32`, `u64`, `usize`, `i8`, `i16`, `i32`, `i64`, `isize`, `i128`).
   - Match and look up `ValueRef` object keys by decoded text so escaped object keys (`\u0061`) compare identically to unescaped keys (`a`).

## 3. Architectural Decisions & Rejected Alternatives

1. **Rejected Alternative — `serde` and `serde_json` (`83a19c0`, `b4b6d57`)**:
   - *Decision*: Removed `serde` and `serde_json` from all workspace crates (isolating `serde_json` strictly to `benches/`).
   - *Rationale*: `serde` derive macros inflated compile times and binary footprint, and `serde_json` lacked a zero-copy raw byte canonicalizer with top-level predicate filtering.
2. **Rejected Alternative — `simd-json` Fast Path (`cc84e6b` -> `0970e94`)**:
   - *Decision*: Initially introduced `simd-json` behind a `simd` feature (`cc84e6b`) after ripping out `serde`, then completely removed `simd-json` four commits later (`0970e94`).
   - *Rationale*:
     1. **Performance Regression**: The `simd-json` path was slower than the hand-rolled scalar parser (139 MB/s vs. 238 MB/s on plain Matrix events; 91 MB/s vs. 101 MB/s on 1 MB arrays) because it had to copy the input buffer for in-place mutation, construct `simd-json`'s DOM, convert it into `rezzy_json::Value`, and fall back to the scalar parser for `-0`, long digit runs, and `\u` escapes.
     2. **Divergent Numeric Semantics**: `simd-json` rejects integers wider than `u64::MAX` (`18446744073709551616` -> `InvalidNumber`), whereas `rezzy-json`'s permissive DOM contract preserves arbitrary-width integer source spellings.
     3. **Dependency Hygiene**: Removing `simd-json` eliminated duplicate `hashbrown` (`0.16` vs `0.17`) trees and left `rezzy-json` depending only on `ryu`.
3. **Retired Defect — Rewriting Wide Integers Through `f64` (`20cef47`)**:
   - *Decision*: Fixed `Number` representation so wide integers are never routed through `f64`.
   - *Rationale*: An earlier revision rewrote integers above `u64::MAX` through `f64`, corrupting `18446744073709551616` into `1.8446744073709552e+19` and silently altering canonical bytes.

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 9, **Critical — Hash Split**):

1. **Permissive vs. Strict Canonical Writer Hazard**:
   - `write_raw_canonical_filtered` (permissive) and `write_raw_canonical_filtered_strict` (strict) coexist in the public API. If any signing or reference-hashing call site invokes the permissive writer, events containing floats or integers `>= 2^53` (such as unquoted 64-bit Snowflake IDs `175928847299117063`) will be hashed/signed locally by `rezzy` but rejected by `ruma` (`js_int::Int`) and strict Matrix homeservers, causing federation split-brain.
2. **Unchecked Lossy `Number::as_f64` Rounding (`docs/json_numeric_limits.md:174-176`)**:
   - `f64` represents `2^53` (`9007199254740992`) exactly because it is a power of two, so lossiness begins at `2^53 + 1` (`9007199254740993` rounds silently to `9007199254740992.0`).
   - Because `as_f64()` returns `Some(rounded)` for all finite `f64` values up to `1e308` and only returns `None` on infinity overflow (`1e400`), callers must never use `as_f64()` as a validity check or route 64-bit identifiers through `f64`.
3. **Recursion & Allocation Bounds**:
   - Nesting depth is strictly capped at 128 levels (`MAX_DEPTH = 128`), verified by explicit 200-deep nesting rejection tests.

## 5. Acceptance Criteria & Verification Oracles

1. **Boundary Pinning Oracle (`rezzy-json/src/lib.rs`, `src/basespec/rezzy_types.rs`)**:
   - `numeric_range_boundaries_are_pinned` and `wide_integers_are_preserved` explicitly verify `2^53 - 1`, `2^53`, `2^53 + 1`, `i64::MAX`, `u64::MAX`, `u64::MAX + 1`, `2^100`, `1e21`, `1e308`, `1e400`, `-0`, lone surrogates `"\ud800"`, and 200-deep nesting across parse, permissive, and strict paths.
2. **Zero-Copy vs. DOM Differential Equivalence (`rezzy-json/src/lib.rs`)**:
   - Zero-copy canonical writers (`write_raw_canonical_filtered` and `write_raw_canonical_filtered_strict`) match the DOM canonical writer byte-for-byte across escaped keys, Unicode surrogates, and filtered top-level predicates.
3. **Zero-Allocation Invariants (`tests/test_zero_alloc.rs`)**:
   - Drop-guard allocation tracking verifies zero heap allocations on hot lookup and masked-key matching paths.
