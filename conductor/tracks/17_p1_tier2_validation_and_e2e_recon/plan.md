# Implementation Plan: Track 17 — P1 Tier-2 Validation, Fair Prefix-Split Queueing & CLI Aggregation Hardening

## Phase 1: Fair Prefix-Split Scheduling, MSC4511 v2 Checked Counts & Multi-Round E2E Test (`T11-F1`..`T11-F3`)
- [~] Task: Replace lexicographic prefix starvation in `BucketExchange::advance` and add multi-round capacity-then-depth E2E test
  - [~] Sort `BucketExchange::pending` (`rezzy-recon/src/client.rs:686-743`) by `(prefix_depth, bucket_range_start)` (BFS order) to prevent low-prefix (`0x0000...`) starvation across `MAX_BUCKETS_PER_ROUND = 128` (`T11-F1`)
  - [~] Implement E2E capacity-split -> depth-limit overflow test in `tests/unit/test_reconcile_e2e.rs` (`T11-F2`, `docs/tech_debt.md:253-274`)
  - [~] Upgrade `src/merkle.rs:739` (`mod causal`) from `saturating_add` to MSC4511 v2 checked `u64` count addition (`T11-F3`)

## Phase 2: Implement Tier-2 Pre-Auth Validation (`validate.rs`, `fork.rs`) & Harden `rezzy aggregate` (`F-07-04`, `T12-F1`, `T12-F2`)
- [~] Task: Implement `src/auth/validate.rs` + `src/dag/fork.rs` and fix unredacted preservation in `rezzy-cli`
  - [~] Implement synchronous PDU structural validation (`src/auth/validate.rs`) and fork/hydra frontier width bounds (`src/dag/fork.rs`, `F-04-01`, `F-07-04`)
  - [~] Fix `rezzy-cli/src/jsonl_merge.rs:239-295` so unredacted events supersede redacted duplicates and union `signatures` (`T12-F1`), and preserve rejection status on replay (`T12-F2`)
