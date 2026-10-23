# Track 21: P1 Remediation — HAMT Domain Separation, PersistentOrdMap Rebalancing, Cold Snapshot Diffing & MSC4242 State DAG Bounds

## Artifacts
- [Specification](./spec.md)
- [Implementation Plan](./plan.md)
- [Track Metadata](./metadata.json)

## Upstream & Audit Traceability
- [Historical Track 04 Review (`04_hamt_delta_state_20260629`)](../04_hamt_delta_state_20260629/review.md)
- [Historical Track 05 Review (`05_lattice_v22_msc4242_20260630`)](../05_lattice_v22_msc4242_20260630/review.md)
- [Historical Track 09 Review (`09_perf_interning_benchmarks_20260920`)](../09_perf_interning_benchmarks_20260920/review.md)
- [Public-Safety & Architectural Audit](../../audits/rezzy_docs_public_safety_audit.md)
- [`docs/hamt_live_frontier_retention.md`](../../../docs/hamt_live_frontier_retention.md)
- [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md)
- [`docs/spec_coverage.csv`](../../../docs/spec_coverage.csv)

## Key Source Modules
- [`src/hamt/mod.rs`](../../../src/hamt/mod.rs)
- [`src/hamt/hash.rs`](../../../src/hamt/hash.rs)
- [`src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs)
- [`src/state/dag.rs`](../../../src/state/dag.rs)
- [`src/state/at.rs`](../../../src/state/at.rs)
- [`src/resolve/semilattice.rs`](../../../src/resolve/semilattice.rs)
- [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs)
- [`src/auth/mod.rs`](../../../src/auth/mod.rs)
- [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs)
- [`benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs)
