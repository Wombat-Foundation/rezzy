# Specification: Track 24 — P2 Remediation: `rezzy-json` Float/Lookup Hardening, `rezzy-recon` Phase-1 Gate & `h64` Chunk Fix, `rezzy-cli` Zeroize & Cycle Signaling

- **Track ID**: `24_p2_json_recon_cli_hardening_and_zeroize`
- **Priority**: `P2`
- **Originating Tracks**: `09_perf_interning_benchmarks_20260920`, `10_rezzy_json_crate_20261004`, `11_rezzy_recon_pinsketch_trie_20261018`, `12_rezzy_cli_federation_agg_20261010`
- **Remediated Findings**: `F-09-07`, `F-09-08`, `T10-F4`, `T10-F5`, `T10-F6`, `T11-F4`, `T11-F5`, `T11-F6`, `T12-F3`, `T12-F4`, `T12-F5`

---

## 1. Overview & Finding Traceability Matrix

This track consolidates and remediates eleven P2 (`[Medium]` and `[Low]`) findings across the workspace sub-crates (`rezzy-json`, `rezzy-recon`, `rezzy-cli`) and repository tooling (`docs/format.sh`): `F-09-07`, `F-09-08`, `T10-F4`, `T10-F5`, `T10-F6`, `T11-F4`, `T11-F5`, `T11-F6`, `T12-F3`, `T12-F4`, and `T12-F5`.

| Finding ID | Severity | Persona(s) | Source File / Line Range | Root Cause & Impact |
| :--- | :---: | :--- | :--- | :--- |
| **`F-09-07`** | `[Medium]` | `critic-compliance`, `critic-federation-interop` | [`rezzy-cli/src/timeline_order.rs:187-235`](../../../rezzy-cli/src/timeline_order.rs#L187-L235) | `kahn_order_by` appends cyclic remainder nodes at the end sorted by `(key, id)` (`L228-233`) without signaling to the caller that the timeline DAG contained a cycle, masking protocol anomalies during forensic CLI inspection. |
| **`F-09-08`** | `[Low]` | `critic-eng-lead` | [`docs/format.sh:1-4`](../../../docs/format.sh#L1-L4) | **Audit #5**: `docs/format.sh` uses `#!/bin/bash -x` without `set -euo pipefail` and invokes an unpinned global `prettier` binary without checking presence or version. |
| **`T10-F4`** | `[Medium]` | `critic-formal-crypto` | [`rezzy-json/src/lib.rs:114-131`](../../../rezzy-json/src/lib.rs#L114-L131) | `Number::parse` preserves raw source spelling when float literals overflow `f64` (`!value.is_finite()`, e.g., `1e400` vs. `1E+400`), making permissive canonical output non-unique on overflowing floats. |
| **`T10-F5`** | `[Medium]` | `critic-perf` | [`rezzy-json/src/lib.rs:2075-2084`](../../../rezzy-json/src/lib.rs#L2075-L2084) | `ValueRef::get` performs an $O(N)$ linear scan with on-the-fly escape decoding (`raw_key_eq`), yielding $O(M \cdot N)$ lookup complexity when queried repeatedly on large JSON objects. |
| **`T10-F6`** | `[Low]` | `critic-pm` | [`rezzy-json/src/lib.rs:1-31`](../../../rezzy-json/src/lib.rs#L1-L31) | Crate-level rustdoc describes `rezzy-json` as a general JSON value/parser without foregrounding its role as a consensus-critical Matrix Canonical JSON serializer and signing primitive. |
| **`T11-F4`** | `[Medium]` | `critic-dx-integrator` | [`rezzy-recon/src/client.rs:717-749`](../../../rezzy-recon/src/client.rs#L717-L749) | Public `BucketExchange::advance` bypasses Phase-1 `NodeSummary` split consistency verification and the no-amplification retry policy (`advance_verified` / `advance_with_retry_policy`). |
| **`T11-F5`** | `[Medium]` | `critic-formal-crypto` | [`rezzy-recon/src/algebraic.rs:155-179`](../../../rezzy-recon/src/algebraic.rs#L155-L179) | `ElementHash::from_digest32` scans all 4 8-byte chunks for `h64`, so a ground digest with `digest[0..8] == 0` sets `h64 == q3` (`digest[8..16]` / `h128_hi`), correlating `h64` bucket prefix placement with `q3` strata estimation or `h128`. |
| **`T11-F6`** | `[Medium]` | `critic-perf` | [`rezzy-recon/src/triage.rs:343-347`](../../../rezzy-recon/src/triage.rs#L343-L347), [`460-475`](../../../rezzy-recon/src/triage.rs#L460-L475) | Clamping degree-256 overflow bucket decode budget to `single_call_work_ceiling(256)` (`10,092,544`) leaves less headroom than `MAX_FACTOR_WORK` (`16,000,000`) for unbalanced recursive root-finding splits. |
| **`T12-F3`** | `[Medium]` | `critic-perf`, `critic-eng-lead` | [`rezzy-cli/src/aggregate.rs:520`](../../../rezzy-cli/src/aggregate.rs#L520), [`rezzy-cli/src/jsonl_merge.rs:49-101`](../../../rezzy-cli/src/jsonl_merge.rs#L49-L101) | `read_raw_input_with_repair` clones every `JsonValue` before stripping (`let raw = event.clone()`), and `perform_connectivity_check` runs an $O(F^2 \cdot E)$ pairwise set intersection across all $F$ files. |
| **`T12-F4`** | `[Medium]` | `critic-eng-lead` | [`rezzy-cli/src/keyfile.rs:62`](../../../rezzy-cli/src/keyfile.rs#L62), [`115`](../../../rezzy-cli/src/keyfile.rs#L115) | `key.fill(0)` on a stack array immediately before return can be elided by LLVM dead-store elimination (DSE); must use `zeroize::Zeroize` / `Zeroizing` (or `core::hint::black_box` + volatile scrubbing). |
| **`T12-F5`** | `[Low]` | `critic-pm` | [`docs/jsonl-aggregation.md:142-176`](../../../docs/jsonl-aggregation.md#L142-L176), [`rezzy-cli/src/aggregate.rs:720-774`](../../../rezzy-cli/src/aggregate.rs#L720-L774) | Per-room report objects under `--check` (`"status": "current"`) omit `"output"` and `"metadata_output"`, forcing downstream scripts to branch on `status` to locate output paths. |

---

## 2. Functional & Architectural Remediation Requirements

### 2.1 `rezzy-json` Canonical Float Normalization, `ValueRef::get` Complexity & Crate Documentation (`T10-F4`, `T10-F5`, `T10-F6`)
1. **Overflowing Float Canonicality (`T10-F4`)**:
   - In [`rezzy-json/src/lib.rs:114-131`](../../../rezzy-json/src/lib.rs#L114-L131), normalize overflowing scientific/float literals (where `source.parse::<f64>()` yields `!value.is_finite()`, such as `1e400` and `1E+400`) to a canonical mantissa/exponent spelling (lowercasing `E` $\to$ `e`, stripping leading `+` in exponents, and canonicalizing significand zeros) or reject overflowing floats deterministically, and document the behavior in `docs/json_numeric_limits.md`.
2. **`ValueRef::get` Lookup Complexity & Mask Bounds (`T10-F5`)**:
   - In [`rezzy-json/src/lib.rs:2075-2084`](../../../rezzy-json/src/lib.rs#L2075-L2084), optimize `ValueRef::get` or provide a pre-decoded/sorted key lookup helper for large objects, and explicitly document on `ValueRef` and `FieldMask` that `ValueRef` is intended for bounded `FieldMask` projections ($\le 16$ keys) whereas `Value` (`BTreeMap`) should be used for repeated random access on large unmasked objects.
3. **Crate-Level Security Positioning (`T10-F6`)**:
   - Update [`rezzy-json/src/lib.rs:1-31`](../../../rezzy-json/src/lib.rs#L1-L31) to foreground `rezzy-json` as a consensus-critical Matrix Canonical JSON serializer with a prominent `[!CAUTION]` callout distinguishing strict cryptographic signing/hashing paths from display/inspection paths.

### 2.2 `rezzy-recon` Phase-1 Verification Gate, Disjoint `h64` Extraction & Overflow Decode Budget (`T11-F4`, `T11-F5`, `T11-F6`)
1. **Gate Unverified `BucketExchange::advance` (`T11-F4`)**:
   - In [`rezzy-recon/src/client.rs:717-749`](../../../rezzy-recon/src/client.rs#L717-L749), restrict `BucketExchange::advance` to `#[cfg(test)]` or private module scope so external callers must use `BucketExchange::advance_verified` (which enforces Phase-1 `NodeSummary` split consistency and the no-amplification retry policy).
2. **Strictly Disjoint `h64`, `q3`, and `h128` Digest Slices (`T11-F5`)**:
   - In [`ElementHash::from_digest32`](../../../rezzy-recon/src/algebraic.rs#L155-L179), extract `h64` exclusively from `digest[0..8]` (mapping `0` to `1` on the $2^{-64}$ zero edge case, matching `q3`'s fallback on `digest[8..16]`), ensuring `h64` (`digest[0..8]`), `q3` (`digest[8..16]`), and `h128` (`digest[16..32]`) read strictly disjoint byte ranges of the 32-byte SHA-256 digest even under adversarial prefix grinding.
3. **Degree-256 Overflow Bucket Decode Budget (`T11-F6`)**:
   - In [`rezzy-recon/src/triage.rs:343-347`](../../../rezzy-recon/src/triage.rs#L343-L347) (`recommended_bucket_decode_budget`) and [`460-475`](../../../rezzy-recon/src/triage.rs#L460-L475) (`decode_bucket_sketches`), grant `MAX_FACTOR_WORK` (`16_000_000`) as the per-bucket work ceiling when `request.overflow` is `true` (`capacity == MAX_OVERFLOW_BUCKET_CAPACITY == 256`) so slightly unbalanced recursive Frobenius trace splits at degree 256 do not prematurely exhaust the `10,092,544` single-call ceiling.

### 2.3 `rezzy-cli` Cycle Signaling, Zero-Clone Observation, $O(F + E)$ Connectivity, Key Zeroization & `--check` Report Schema (`F-09-07`, `T12-F3`, `T12-F4`, `T12-F5`, `F-09-08`)
1. **Cycle Detection Signaling in `kahn_order_by` (`F-09-07`)**:
   - In [`rezzy-cli/src/timeline_order.rs:187-235`](../../../rezzy-cli/src/timeline_order.rs#L187-L235), update `kahn_order_by` (or add `kahn_order_by_checked` returning a `KahnOrderResult { order: Vec<usize>, cyclic_count: usize }`) so callers in `timeline_order.rs` and `aggregate.rs` can surface/log cycle counts in CLI diagnostics while preserving deterministic `(key, id)` tie-breaking for remainder nodes.
2. **Zero-Clone Provenance Observation & $O(F + E)$ Connectivity Check (`T12-F3`)**:
   - In [`rezzy-cli/src/aggregate.rs:520`](../../../rezzy-cli/src/aggregate.rs#L520), call `provenance::observe_raw_event` on `&event` *before* calling `provenance::strip_non_envelope_fields(&mut event)`, eliminating the full `let raw = event.clone()` DOM allocation on every ingested event.
   - In [`rezzy-cli/src/jsonl_merge.rs:49-101`](../../../rezzy-cli/src/jsonl_merge.rs#L49-L101), replace the $O(F^2 \cdot E)$ nested loop in `perform_connectivity_check` with an inverted index mapping each `event_id` to its defining file indices so cross-file edge connectivity is computed in $O(F + E)$ time.
3. **DSE-Resistant Key Material Zeroization (`T12-F4`)**:
   - In [`rezzy-cli/src/keyfile.rs:62`](../../../rezzy-cli/src/keyfile.rs#L62) and [`115`](../../../rezzy-cli/src/keyfile.rs#L115), replace plain `key.fill(0)` with `zeroize::Zeroize` / `zeroize::Zeroizing<[u8; 32]>` (or volatile/black-boxed zeroization helper) so LLVM dead-store elimination cannot strip key scrubbing after encryption/decryption.
4. **Consistent `--check` Per-Room Report Fields (`T12-F5`)**:
   - In [`rezzy-cli/src/aggregate.rs:720-774`](../../../rezzy-cli/src/aggregate.rs#L720-L774) and [`docs/jsonl-aggregation.md:142-176`](../../../docs/jsonl-aggregation.md#L142-L176), include `"output"` and `"metadata_output"` in per-room JSON report objects even when `"status": "current"`.
5. **Hardened `docs/format.sh` Script (`F-09-08`)**:
   - Update [`docs/format.sh:1-4`](../../../docs/format.sh#L1-L4) to use `#!/usr/bin/env bash`, `set -euo pipefail`, and a pinned or verified `prettier` invocation.

---

## 3. Public-Safety & Consensus Invariants

- **Mandatory Phase-1 Verification in `BucketExchange` (`T11-F4`)**: Public callers of `BucketExchange` cannot accidentally advance reconciliation rounds without validating `NodeSummary` split invariants and the no-amplification retry policy.
- **Statistical Independence of `h64`, `q3`, and `h128` (`T11-F5`)**: Even if an adversary grinds a SHA-256 event digest with 64 leading zero bits (`digest[0..8] == 0`), `h64` (`1`), `q3` (`digest[8..16]`), and `h128` (`digest[16..32]`) remain derived from non-overlapping slices.
- **Cryptographic Key Hygiene (`T12-F4`)**: Derived 256-bit Argon2id/XChaCha20-Poly1305 keys in `rezzy-cli` are unconditionally zeroized in memory before stack frame return.

---

## 4. Acceptance Criteria & Verification Oracles

- [ ] **`F-09-07` Verified**: Unit test in `rezzy-cli/src/timeline_order.rs` confirms cyclic DAG inputs report the exact `cyclic_count > 0` while ordering cyclic remainder nodes deterministically.
- [ ] **`F-09-08` Verified**: `docs/format.sh` starts with `#!/usr/bin/env bash` and `set -euo pipefail` and passes `bash -n docs/format.sh`.
- [ ] **`T10-F4`, `T10-F5`, `T10-F6` Verified**: `Number::parse` normalizes `1e400` and `1E+400` identically (`rezzy-json/src/lib.rs:114-131`), `ValueRef::get` (`rezzy-json/src/lib.rs:2075-2084`) documents/bounds mask lookup complexity, and `rezzy-json/src/lib.rs:1-31` includes the consensus-critical `[!CAUTION]` header.
- [ ] **`T11-F4`, `T11-F5`, `T11-F6` Verified**: `BucketExchange::advance` (`rezzy-recon/src/client.rs:717-749`) is non-public, `ElementHash::from_digest32` (`rezzy-recon/src/algebraic.rs:155-179`) sets `h64 = 1` (not `q3`) when `digest[0..8] == 0`, and `decode_bucket_sketches` (`rezzy-recon/src/triage.rs:343-347, 460-475`) grants `MAX_FACTOR_WORK` (`16,000,000`) to overflow (`capacity = 256`) buckets.
- [ ] **`T12-F3`, `T12-F4`, `T12-F5` Verified**: `read_raw_input_with_repair` (`rezzy-cli/src/aggregate.rs:520`) no longer clones `event` before stripping, `perform_connectivity_check` (`rezzy-cli/src/jsonl_merge.rs:49-101`) uses an $O(F + E)$ index, `keyfile.rs:62,115` uses DSE-proof zeroization, and `--check` (`rezzy-cli/src/aggregate.rs:720-774`, `docs/jsonl-aggregation.md:142-176`) emits `"output"` and `"metadata_output"` on `"status": "current"`.
