# Specification: Track 15 — P0 Seal Permissive Canonical JSON & Lossy `as_f64` Rounding

## 1. Overview & Public-Safety Rationale
Per [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md) and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #9 & P0 Remediation #3):
1. `rezzy-json` exposes both permissive (`to_canonical_bytes` / `write_raw_canonical_filtered`) and strict (`to_canonical_bytes_strict` / `write_raw_canonical_filtered_strict`) writers. A caller invoking the non-`_strict` API on untrusted federation payloads can emit out-of-range integers (`> 2^53 - 1`), causing a reference-hash/event-ID split against RFC 8785 / Matrix Spec compliant homeservers.
2. `Number::as_f64()` silently rounds wide `i64`/`u64` integers above $2^{53}$ (`9007199254740993` $\to$ `9007199254740992.0`).

## 2. Functional Requirements
1. **Default-Strict Canonical Serialization**:
   - Make strict `[-2^53 + 1, 2^53 - 1]` integer bounds and finite-number validation the default in production `rezzy-json` canonical writers; gate permissive legacy corpus writers behind an explicit feature/test gate or `unchecked_legacy` module.
2. **Safe Numeric Conversion API**:
   - Replace or deprecate lossy `Number::as_f64()` for integers outside `[-2^53 + 1, 2^53 - 1]` in favor of checked conversion (`try_as_f64_exact()`).

## 3. Acceptance Criteria
- [ ] Production hashing and signing pathways cannot accidentally invoke permissive canonical JSON serialization.
- [ ] Integers outside `[-2^53 + 1, 2^53 - 1]` fail closed during strict parsing/canonicalization and exact numeric access.
