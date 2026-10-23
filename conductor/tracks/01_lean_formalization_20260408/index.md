# Track 01: Lean 4 Formalization, Kahn Topological Sort & Trace Compiler (`v0.1.0`–`v0.1.1`)

## Conductor Track Handshake

- **Track ID**: `01_lean_formalization_20260408`
- **Epoch**: `v0.1.0`–`v0.1.1` (April 8–14, 2026)
- **Commit Range**: `be1774b..5cf21de` (with StarGraph & AIR follow-ups `5817344`, `871a36a`, `0c0ad6e`, `995f139`, `a88b53a`)
- **Status**: `completed`

### Track Artifacts
- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques
- [Multi-Perspective Architectural Review (`./review.md`)](./review.md) — 8-persona critique covering `critic-pm`, `critic-eng-lead`, `critic-compliance`, `critic-perf`, `critic-formal-crypto`, `critic-federation-interop`, `critic-redteam-qa`, and `critic-dx-integrator`

### Linked Repository Documentation & Build Manifests
- [`../../../README.md`](../../../README.md) — Crate overview, supported Matrix room versions, and test-first development workflow
- [`../../../TODO.txt`](../../../TODO.txt) — Architectural notes on `KahnSortResult::CycleDetected`, `build_mainline_with_cache` cycle handling, arithmetization vs. set reconciliation, and Lean 4 `progressiveFold` gap assessment
- [`../../../Makefile`](../../../Makefile) — Build, test, coverage, and formal verification automation targets
- [`../../../Cargo.toml`](../../../Cargo.toml) — Workspace and `#![no_std]` (`alloc`) crate configuration

### Linked Source & Verification Modules
- [`../../../src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) — Reverse topological power sort (`kahn_sort`, `with_cycle_diagnostics`, `KahnSortResult`) and mainline ordering (`build_mainline`, `mainline_sort`)
- [`../../../src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) — Core iterative state resolution pipeline (`resolve_iterative_sort`)
- [`../../../src/lib.rs`](../../../src/lib.rs) — `#![no_std]` crate root and public re-exports
- [`../../../tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) — Topological sort, cycle detection, and mainline ordering unit tests
- [`../../../tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) — Core Kahn and StateRes baseline verification tests
