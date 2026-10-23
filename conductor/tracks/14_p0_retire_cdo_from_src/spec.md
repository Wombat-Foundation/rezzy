# Specification: Track 14 — P0 Relocate Retired CDO (`src/resolve/cdo.rs`) Out of Production `src/`

## 1. Overview & Public-Safety Rationale
As documented in [`docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md) and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #3 & P0 Remediation #2), the Causal Domination Operator (CDO) suffers from the **dominator-validity gap**: a pure DAG graph check (`y` is reachable from `x`) cannot know whether `x` will survive iterative authorization (Anomalies 19 & 20). While CDO was removed from the hot path in `prepare_conflicted_and_keys`, `src/resolve/cdo.rs` still resides in the production `src/resolve/` tree.

## 2. Functional Requirements
1. **Relocate `src/resolve/cdo.rs` to `tests/`**:
   - Move `src/resolve/cdo.rs` into `tests/support/` or `tests/cdo_historical.rs` so that historical counterexample regression tests (Anomalies 19 & 20) continue to run without compiling `cdo` into `librezzy`.
2. **Purge Production Module Exports**:
   - Remove `mod cdo;` and any internal re-exports from `src/resolve/mod.rs`.

## 3. Acceptance Criteria
- [ ] `src/resolve/cdo.rs` no longer exists in `src/`.
- [ ] Anomaly 19 & 20 regression tests in `tests/` still pass (`cargo test --workspace`).
