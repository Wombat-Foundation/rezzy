# Implementation Plan: Track 24 — `rezzy-json` Float/Lookup Hardening, `rezzy-recon` Phase-1 Gate & `h64` Chunk Fix, `rezzy-cli` Zeroize & Cycle Signaling

## Phase 1: `rezzy-json` Float Canonicality, `ValueRef::get` Bounds & Crate Documentation (`T10-F4`, `T10-F5`, `T10-F6`)
- [ ] Task: Canonicalize overflowing float literals and harden `ValueRef::get` lookup complexity (`T10-F4`, `T10-F5`, `rezzy-json/src/lib.rs:114-131`, `rezzy-json/src/lib.rs:2075-2084`)
  - [ ] Normalize overflowing scientific/float literals in `Number::parse` (`rezzy-json/src/lib.rs:114-131`) so equivalent overflowing floats (`1e400` vs. `1E+400`) produce identical canonical representations, and add unit tests (`T10-F4`)
  - [ ] Document `FieldMask` cardinality limits and optimize/bound `ValueRef::get` (`rezzy-json/src/lib.rs:2075-2084`) to prevent accidental $O(M \cdot N)$ quadratic scans on unmasked large objects (`T10-F5`)
- [ ] Task: Foreground consensus-critical Matrix Canonical JSON guarantees in `rezzy-json` crate docs (`T10-F6`, `rezzy-json/src/lib.rs:1-31`)
  - [ ] Update the crate-level rustdoc header in `rezzy-json/src/lib.rs:1-31` and `docs/json_numeric_limits.md` with an explicit `[!CAUTION]` callout contrasting strict canonical signing/hashing paths against permissive display paths (`T10-F6`)

## Phase 2: `rezzy-recon` Phase-1 Verification Gate, Disjoint `h64` Slice & Overflow Decode Budget (`T11-F4`, `T11-F5`, `T11-F6`)
- [ ] Task: Gate unverified `BucketExchange::advance` and enforce disjoint `h64`/`q3`/`h128` digest slices (`T11-F4`, `T11-F5`, `rezzy-recon/src/client.rs:717-749`, `rezzy-recon/src/algebraic.rs:155-179`)
  - [ ] Make `BucketExchange::advance` (`rezzy-recon/src/client.rs:717-749`) private or `#[cfg(test)]` so external callers must use `BucketExchange::advance_verified` (`advance_with_retry_policy`) (`T11-F4`)
  - [ ] Restrict `h64` derivation in `ElementHash::from_digest32` (`rezzy-recon/src/algebraic.rs:155-179`) strictly to `digest[0..8]` with fallback `1` when `digest[0..8] == 0`, preventing `h64` from collapsing onto `q3` (`digest[8..16]`) or `h128` (`digest[16..32]`), and add a unit test with `digest[0..8] == [0; 8]` (`T11-F5`)
- [ ] Task: Raise degree-256 overflow bucket decode budget to `MAX_FACTOR_WORK` (`T11-F6`, `rezzy-recon/src/triage.rs:343-347, 460-475`)
  - [ ] Update `recommended_bucket_decode_budget` (`rezzy-recon/src/triage.rs:343-347`) and `decode_bucket_sketches` (`rezzy-recon/src/triage.rs:460-475`) to grant `MAX_FACTOR_WORK` (`16_000_000`) when `request.overflow` is `true` (`capacity == 256`), and add a unit test verifying the budget ceiling for degree-256 overflow buckets (`T11-F6`)

## Phase 3: `rezzy-cli` Cycle Signaling, Zero-Clone Observation, $O(F + E)$ Connectivity, Key Zeroize & Script Hardening (`F-09-07`, `F-09-08`, `T12-F3`, `T12-F4`, `T12-F5`)
- [ ] Task: Signal DAG cycles in `kahn_order_by` and eliminate redundant DOM clones and $O(F^2 \cdot E)$ connectivity checks (`F-09-07`, `T12-F3`, `rezzy-cli/src/timeline_order.rs:187-235`, `rezzy-cli/src/aggregate.rs:520`, `rezzy-cli/src/jsonl_merge.rs:49-101`)
  - [ ] Extend `kahn_order_by` (`rezzy-cli/src/timeline_order.rs:187-235`) to report the count of cyclic remainder nodes to callers and add a cycle-signaling unit test (`F-09-07`)
  - [ ] Observe raw provenance fields before `strip_non_envelope_fields` in `read_raw_input_with_repair` (`rezzy-cli/src/aggregate.rs:520`) to eliminate `let raw = event.clone()`, and refactor `perform_connectivity_check` (`rezzy-cli/src/jsonl_merge.rs:49-101`) to use an $O(F + E)$ inverted index (`T12-F3`)
- [ ] Task: Harden `keyfile.rs` zeroization against DSE, unify `--check` report fields, and harden `docs/format.sh` (`T12-F4`, `T12-F5`, `F-09-08`, `rezzy-cli/src/keyfile.rs:62,115`, `rezzy-cli/src/aggregate.rs:720-774`, `docs/jsonl-aggregation.md:142-176`, `docs/format.sh:1-4`)
  - [ ] Replace `key.fill(0)` in `rezzy-cli/src/keyfile.rs:62,115` with DSE-resistant zeroization (`zeroize::Zeroize` / `core::hint::black_box`) (`T12-F4`)
  - [ ] Emit `"output"` and `"metadata_output"` on `"status": "current"` room report entries in `rezzy-cli/src/aggregate.rs:720-774` and update `docs/jsonl-aggregation.md:142-176` (`T12-F5`)
  - [ ] Add `#!/usr/bin/env bash` and `set -euo pipefail` with prettier version/presence check to `docs/format.sh:1-4` (`F-09-08`)
