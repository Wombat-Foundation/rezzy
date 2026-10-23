# Track Review & Multi-Perspective Critique: `10_rezzy_json_crate_20261004`

- **Track ID**: `10_rezzy_json_crate_20261004`
- **Track Title**: `rezzy-json` Crate Extraction, Dependency-Free Parser & Canonical Numeric Limits (`0.6.0-rc.1`)
- **Commit Trajectory**: `a636e18..1504cc7`
- **Audit Risk Rating**: **Critical (Hash Split)** — see [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 9, P0 Item 3)
- **Review Status**: **COMPLETED WITH P0 REMEDIATION MANDATES FOR STAGE B**

---

## 1. Executive Review Summary (`/conductor-review`)

Track 10 successfully extracted JSON parsing and Matrix Canonical JSON serialization out of the monolithic `rezzy` crate into the standalone `#![no_std]` (`alloc`) [`rezzy-json`](../../../rezzy-json/src/lib.rs) workspace crate (`a636e18`, `fe39ad6`, `0261bc3`). Over the course of `a636e18..1504cc7`, the track eliminated `serde` and `serde_json` (`83a19c0`), evaluated and then rejected `simd-json` (`cc84e6b` $\to$ `0970e94`) after proving the hand-rolled scalar parser was both faster (238 MB/s vs. 139 MB/s on Matrix events) and free of `> u64::MAX` integer rejection defects, fixed an early bug that rewrote wide integers through `f64` (`20cef47`), and documented the three-tier numeric boundary contract in [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md).

However, from a public-safety and C2 consensus standpoint, **two `[Critical]` / `[High]` API-level hazards remain open in `rezzy-json` and `src/basespec/rezzy_types.rs`** and are designated for **P0 remediation in Stage B**:
1. **Unchecked Coexistence of Permissive & Strict Canonical Writers (`[Critical]`)**: [`write_raw_canonical_filtered`](../../../rezzy-json/src/lib.rs#L1027-L1032) (permissive) and [`write_raw_canonical_filtered_strict`](../../../rezzy-json/src/lib.rs#L1046-L1051) (strict) sit side-by-side in the public API, and [`reference_hash`](../../../src/basespec/rezzy_types.rs#L930-L960) / [`validate_canonical_number`](../../../src/basespec/rezzy_types.rs#L1144-L1161) have subtle behavior around integers $> \text{u64::MAX}$ where both `as_i64()` and `as_u64()` return `None`.
2. **Silent Lossy `Number::as_f64()` Rounding Above $2^{53}$ (`[High]`)**: [`Number::as_f64`](../../../rezzy-json/src/lib.rs#L169-L171) returns `Some(rounded)` for integers $\ge 2^{53} + 1$ (e.g., `9007199254740993` $\to$ `Some(9007199254740992.0)`), corrupting 64-bit Snowflake IDs without returning `None`.

### Verification Matrix Against Plan & Spec
- [x] **Workspace Modularity**: `rezzy-json` compiles with `#![no_std]` + `alloc` (`rezzy-json/src/lib.rs:32-34`), depending only on `ryu`.
- [x] **Decoded-Key Canonicalization**: Escaped object keys (`\u0061`) are decoded before sorting and lookup in [`Tokenizer::object_members`](../../../rezzy-json/src/lib.rs#L1297-L1306) and [`raw_key_eq`](../../../rezzy-json/src/lib.rs#L1895-L1900) (`d31adb3`, `91a808f`).
- [x] **Recursion Cap**: Strictly bounded at `MAX_DEPTH = 128` ([`rezzy-json/src/lib.rs:1247`](../../../rezzy-json/src/lib.rs#L1247), [`2184`](../../../rezzy-json/src/lib.rs#L2184)), verified by [`depth_limit_at_every_entry_point`](../../../rezzy-json/src/lib.rs#L2510-L2539).
- [x] **Numeric Boundary Pins**: Verified by [`numeric_range_boundaries_are_pinned`](../../../rezzy-json/src/lib.rs#L2984-L3077) and [`wide_integers_are_preserved`](../../../src/basespec/rezzy_types.rs#L4311-L4320).

---

## 2. Multi-Perspective Critiques (8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Assessment**: Splitting `rezzy` into `rezzy-json`, `rezzy-recon`, and `rezzy-cli` (`a636e18`, `0261bc3`) is a decisive product maturity milestone. Embedded and WASM/kernel-space C2 integrators can now consume `rezzy` and `rezzy-json` without transitive `std` or proc-macro dependencies (`serde_derive`, `syn`, `quote`), while `rezzy-cli` packages operational tooling cleanly.
- **Finding `[Low]` — Public Surface Positioning of `rezzy-json`**:
  - While `rezzy-json` provides general-purpose ergonomics (`Display`, `FromStr`, RFC 6901 `pointer`/`pointer_mut` in `ecc4f3c`, primitive `From` impls in `1504cc7`), its documentation should explicitly position it as a **Matrix Canonical JSON security primitive** rather than a drop-in general JSON library so downstream product teams do not misuse permissive serialization on signed federation payloads.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **Assessment**: The engineering discipline demonstrated in first benchmarking `simd-json` (`cc84e6b`) and then ripping it out four commits later (`0970e94`) when empirical data showed the scalar parser was $1.71\times$ faster on Matrix events (238 MB/s vs. 139 MB/s) is exemplary. Eliminating `simd-json` removed the mutable buffer copy, double DOM translation, and duplicate `hashbrown` (`0.16` vs. `0.17`) dependency trees.
- **Finding `[High]` — Dual Canonical Writers & `validate_canonical_number` Gap Above `u64::MAX`**:
  - In [`rezzy-json/src/lib.rs:64-79`](../../../rezzy-json/src/lib.rs#L64-L79), `is_canonical_integer_str` properly requires `value.parse::<i64>().is_ok_and(...) || value.parse::<u64>().is_ok_and(...)`, which returns `false` for integers $> \text{u64::MAX}$ (such as `18446744073709551616`).
  - However, in [`src/basespec/rezzy_types.rs:1144-L1161`](../../../src/basespec/rezzy_types.rs#L1144-L1161), `validate_canonical_number(n: &crate::json::Number)` checks:
    ```rust
    if let Some(v) = n.as_i64() {
        if v.unsigned_abs() > (1_u64 << 53) - 1 { return Err(CanonicalizationError::OutOfRangeNumber); }
    } else if let Some(v) = n.as_u64() {
        if v > (1_u64 << 53) - 1 { return Err(CanonicalizationError::OutOfRangeNumber); }
    }
    Ok(())
    ```
  - **Defect**: If an integer in a `Value::Number` is wider than `u64::MAX` (e.g., `18446744073709551616` or `-9223372036854775809`), **both `n.as_i64()` and `n.as_u64()` return `None`**, and `validate_canonical_number` falls through and returns `Ok(())`! Consequently, `write_content_hash_canonical` and `write_redacted_canonical` (`strict_numbers = true` for room v6+) will **accept** integers $> \text{u64::MAX}$ instead of returning `Err(CanonicalizationError::OutOfRangeNumber)`, even though `rezzy_json::is_canonical_integer_str` and `write_raw_canonical_filtered_strict` reject them!
  - **Remediation**: Replace the manual check in [`validate_canonical_number`](../../../src/basespec/rezzy_types.rs#L1144-L1161) with `if !n.is_canonical_integer() { return Err(...); }` or add an `else { return Err(CanonicalizationError::OutOfRangeNumber); }` branch when neither `as_i64()` nor `as_u64()` succeeds.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Assessment**: Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 9), canonical JSON serialization is the cryptographic foundation for Matrix V3+ content-addressed Event IDs (`reference_hash`), `hashes.sha256` (`compute_content_hash`), and Ed25519 PDU signatures (`verify_event_signatures`).
- **Finding `[Critical]` — Reference-Hash & Signature Split-Brain via Permissive Canonical Writer**:
  - Coexistence of [`write_raw_canonical_filtered`](../../../rezzy-json/src/lib.rs#L1027-L1032) and [`write_raw_canonical_filtered_strict`](../../../rezzy-json/src/lib.rs#L1046-L1051) in the public API creates a lethal footgun for C2 integrators. Furthermore, the doc comment on [`reference_hash`](../../../src/basespec/rezzy_types.rs#L920-L923) states *"Canonicalization is tolerant of out-of-range integers (like Synapse's `relaxed` mode)"*, which is only true for room versions 3–5 (and accidentally for $> \text{u64::MAX}$ due to the `validate_canonical_number` fallthrough noted above). In tactical federation rooms (Room Versions 6–12), any divergence between permissive acceptance and strict Matrix Canonical JSON causes participating emergency dispatch servers to compute different event rejections, partitioning the room.
- **Finding `[High]` — Silent Precision Loss in `Number::as_f64()`**:
  - As documented in [`docs/json_numeric_limits.md:73-98`](../../../docs/json_numeric_limits.md#L73-L98) and [`rezzy-json/src/lib.rs:155-171`](../../../rezzy-json/src/lib.rs#L155-L171), `as_f64()` silently rounds integers $\ge 2^{53} + 1$ (`9007199254740993` $\to$ `9007199254740992.0`) and returns `Some(rounded)`. In C2 telemetry or cross-agency bridge payloads carrying 64-bit Snowflake IDs (`175928847299117063` $\to$ `175928847299117060`), reading a number via `as_f64()` silently corrupts the target identifier.

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Assessment**: The zero-copy [`Tokenizer`](../../../rezzy-json/src/lib.rs#L1131-L1139) and [`ValueRef::parse_masked`](../../../rezzy-json/src/lib.rs#L1929-L1938) avoid heap allocations for skipped subtrees (verified in [`tests/test_zero_alloc.rs`](../../../tests/test_zero_alloc.rs)) and bound container recursion to a fixed stack array (`is_object: [bool; 128]`, `expecting_key: [bool; 128]`).
- **Finding `[Medium]` — Quadratic Key Lookup in `ValueRef::get` on Large Unmasked Objects**:
  - [`ValueRef::Object`](../../../rezzy-json/src/lib.rs#L1919) stores fields as `Vec<(&'a str, Self)>`, and [`ValueRef::get`](../../../rezzy-json/src/lib.rs#L2075-L2084) performs a linear `.iter().rev().find(|(k, _)| raw_key_eq(k, key))` scan decoding escapes on the fly via [`walk_key`](../../../rezzy-json/src/lib.rs#L1867-L1892). If a caller parses an object with thousands of keys into `ValueRef` (e.g., an empty `FieldMask` or a large `users` map in `m.room.power_levels`) and performs $M$ lookups, lookup complexity is $O(M \cdot N)$.
  - **Remediation**: Document that `ValueRef` is strictly designed for small `FieldMask` projections ($\le 16$ extracted keys), or cap the number of members retained per object when `FieldMask` is non-empty.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **Assessment**: Matrix Canonical JSON requires a total, deterministic function from valid JSON ASTs to canonical UTF-8 byte sequences.
- **Finding `[High]` — Non-Injective `Number::parse` Float Normalization vs. Integer Preservation**:
  - In [`Number::parse`](../../../rezzy-json/src/lib.rs#L114-L131), integer literals retain their exact source string, whereas literals containing `.`, `e`, or `E` are parsed as `f64` and formatted via `ryu::Buffer::format_finite` + [`normalize_exponent`](../../../rezzy-json/src/lib.rs#L186-L195) — **unless** `source.parse::<f64>()` overflows to `!value.is_finite()` (such as `1e400`), in which case `Number::parse` falls back to `Self(source.to_string())`!
  - Consequently, in permissive mode (`write_raw_canonical_filtered`), `1e400` and `1E+400` (which represent the same mathematical value) are emitted with their distinct source spellings (`1e400` vs `1E+400`), violating canonical equivalence on non-strict numbers.
  - **Remediation**: Restrict permissive canonicalization to test/inspection paths, and ensure all cryptographic hashing/signing paths unconditionally enforce strict integer-only canonical JSON (`is_canonical_integer_str`).

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Assessment**: Matrix Room Versions 1–5 allow fractional and out-of-range numbers in canonical JSON (historic Synapse `relaxed` behavior), whereas Room Versions 6+ ([Matrix Spec: Canonical JSON](https://spec.matrix.org/v1.12/appendices/#canonical-json)) strictly mandate integers in `[-(2^53 - 1), 2^53 - 1]` (`[-9007199254740991, 9007199254740991]`) and forbid `-0`, fractions, and exponents.
- **Finding `[High]` — Interop Divergence with `ruma` / Synapse on `> u64::MAX` Integers in Room Versions 6–12**:
  - Because [`validate_canonical_number`](../../../src/basespec/rezzy_types.rs#L1144-L1161) only checks `if let Some(v) = n.as_i64() { ... } else if let Some(v) = n.as_u64() { ... }`, a Room Version 10 or 12 event containing `"bad_int": 18446744073709551616` (`u64::MAX + 1`) will be accepted by `rezzy::reference_hash` and `rezzy::compute_content_hash`, whereas `ruma` (`js_int::Int`), Synapse (v6+ strict canonicaljson), Dendrite/Go, and `rezzy_json::write_raw_canonical_filtered_strict` will reject it!
  - **Remediation**: Delegate `validate_canonical_number` in `src/basespec/rezzy_types.rs:1144` directly to `n.is_canonical_integer()` so DOM-based v6+ canonicalization matches `write_raw_canonical_filtered_strict` and `ruma` across all integer widths.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Assessment**: The boundary test suite in [`numeric_range_boundaries_are_pinned`](../../../rezzy-json/src/lib.rs#L2984-L3077) and [`strict_version_rejects_out_of_range`](../../../src/basespec/rezzy_types.rs#L4380-L4385) is strong, explicitly testing `9_007_199_254_740_993_u64` (`2^53 + 1`).
- **Finding `[High]` — Missing Red-Team Vector for `> u64::MAX` and `< i64::MIN` in `reference_hash` / `compute_content_hash` (v6+)**:
  - While `rezzy-json/src/lib.rs` tests `18446744073709551616` against `write_raw_canonical_filtered_strict`, `src/basespec/rezzy_types.rs` only tested `9_007_199_254_740_993_u64` (which fits in `u64`) in `strict_version_rejects_out_of_range` (`rezzy_types.rs:4381`)!
  - Crafted red-team payload:
    ```json
    {"type":"m.room.message","sender":"@mallory:evil.org","origin_server_ts":1,"content":{"body":"split","nonce":18446744073709551616}}
    ```
    When passed to `compute_content_hash(&event, "12")` or `try_canonical_redacted_json(&event, "12")` (on a preserved field like `depth` or `m.room.create` content in v11+), `validate_canonical_number` returns `Ok(())` because `"18446744073709551616".parse::<i64>()` is `Err` and `.parse::<u64>()` is `Err`!
  - **Remediation**: Add explicit red-team unit tests in `src/basespec/rezzy_types.rs` asserting that `compute_content_hash`, `reference_hash`, and `try_canonical_redacted_json` reject `18446744073709551616` (`u64::MAX + 1`), `-9223372036854775809` (`i64::MIN - 1`), and `1267650600228229401496703205376` (`2^100`) for room version `"6"` and `"12"`.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Assessment**: The `#![no_std]` API of `rezzy-json` (`Value`, `Number`, `Object`, `ValueRef`, `FieldMask`, `json!`) is ergonomic and clean for downstream homeserver integrators.
- **Finding `[High]` — Unnecessary Public Exposure of `write_raw_canonical_filtered` and Unguarded `as_f64()`**:
  - Downstream homeserver developers integrating `rezzy_json` for federation signing see `write_raw_canonical_filtered` and `write_raw_canonical_filtered_strict` with identical signatures. Worse, `canonical_redacted_json` ([`src/basespec/rezzy_types.rs:1040-1045`](../../../src/basespec/rezzy_types.rs#L1040-L1045)) panics via `.expect(...)` if given a v6+ event with a non-canonical number, whereas `try_canonical_redacted_json` returns `Result`.
  - **Remediation**:
    1. Gate `write_raw_canonical_filtered` behind `#[cfg(test)]` (or rename it `write_raw_non_canonical_permissive_filtered` with `#[deprecated]` warning) so `write_raw_canonical_filtered_strict` is the unmistakable canonical byte writer.
    2. Make `Number::as_f64` reject integers outside `[-(2^53), 2^53]` (returning `None` when integer precision is lost) or replace it with `as_f64_exact()` (failing on lossy integer rounding) + `as_f64_lossy()`.

---

## 3. Consolidated Findings & Stage B Action Plan

| ID | Severity | Persona(s) | File / Line Reference | Finding Summary | Stage B Remediation Target |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **T10-F1** | **`[Critical]`** | `critic-eng-lead`, `critic-federation-interop`, `critic-redteam-qa` | [`src/basespec/rezzy_types.rs:1144-1161`](../../../src/basespec/rezzy_types.rs#L1144-L1161) | `validate_canonical_number` falls through and returns `Ok(())` when both `n.as_i64()` and `n.as_u64()` return `None`, silently accepting integers $> \text{u64::MAX}$ or $< \text{i64::MIN}$ in strict v6+ `reference_hash` and `compute_content_hash`. | Call `n.is_canonical_integer()` inside `validate_canonical_number` and add v6/v12 rejection tests for `u64::MAX + 1` and `i64::MIN - 1` (P0 Item 3). |
| **T10-F2** | **`[Critical]`** | `critic-compliance`, `critic-dx-integrator` | [`rezzy-json/src/lib.rs:1027-1051`](../../../rezzy-json/src/lib.rs#L1027-L1051) | Permissive `write_raw_canonical_filtered` coexists in the public API alongside `write_raw_canonical_filtered_strict`, risking federation signature/hash split-brain if called on signed bytes. | Gate `write_raw_canonical_filtered` behind `#[cfg(test)]` or rename to make strict canonicalization the default (P0 Item 3). |
| **T10-F3** | **`[High]`** | `critic-compliance`, `critic-dx-integrator` | [`rezzy-json/src/lib.rs:155-171`](../../../rezzy-json/src/lib.rs#L155-L171), [`docs/json_numeric_limits.md:174-176`](../../../docs/json_numeric_limits.md#L174-L176) | `Number::as_f64()` silently rounds integers $\ge 2^{53} + 1$ (`9007199254740993` $\to$ `Some(9007199254740992.0)`), corrupting 64-bit Snowflake IDs. | Make `as_f64()` return `None` for integer literals outside `[-(2^53), 2^53]`, or split into `as_f64_exact()` and `as_f64_lossy()` (P0 Item 3). |
| **T10-F4** | **`[Medium]`** | `critic-formal-crypto` | [`rezzy-json/src/lib.rs:114-131`](../../../rezzy-json/src/lib.rs#L114-L131) | `Number::parse` preserves raw source spelling when float literals overflow `f64` (`1e400` vs. `1E+400`), making permissive float normalization non-canonical above `f64::MAX`. | Document non-canonicality of `> f64::MAX` floats in `Number::parse` and ensure strict mode rejects all non-integers. |
| **T10-F5** | **`[Medium]`** | `critic-perf` | [`rezzy-json/src/lib.rs:2075-2084`](../../../rezzy-json/src/lib.rs#L2075-L2084) | `ValueRef::get` performs an $O(N)$ linear scan with on-the-fly escape decoding (`raw_key_eq`), yielding $O(M \cdot N)$ lookup cost if used on unmasked large objects. | Document `FieldMask` cardinality limits on `ValueRef` and recommend `Value` (`BTreeMap`) when full-object random access is required. |
| **T10-F6** | **`[Low]`** | `critic-pm` | [`rezzy-json/src/lib.rs:1-31`](../../../rezzy-json/src/lib.rs#L1-L31) | Crate-level docs describe `rezzy-json` as a general JSON value/parser without immediately foregrounding its role as a consensus-critical Matrix signing primitive. | Strengthen crate header documentation with an explicit `[!CAUTION]` callout on signing vs. display paths. |
