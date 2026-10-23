# Track 22: P1 Remediation — Thread-Safe `LeanEventCache`, Fallible `EventProvider` Error Propagation & `DenseIndex`/Roaring Consolidation

## Artifacts
- [Remediation Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)

## Upstream Historical Reviews & Audit Traceability
- [Track 07 Review (`../07_roaring_lazy_provider_20260703/review.md`)](../07_roaring_lazy_provider_20260703/review.md) — Findings `F-07-02`, `F-07-05`, `F-07-06`, `F-07-08`, `F-07-09`
- [Track 09 Review (`../09_perf_interning_benchmarks_20260920/review.md`)](../09_perf_interning_benchmarks_20260920/review.md) — Finding `F-09-06`
- [Public-Safety & Architectural Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Documentation & Source Files
- [`docs/architecture.md`](../../../docs/architecture.md)
- [`docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md)
- [`docs/tech_debt.md`](../../../docs/tech_debt.md)
- [`src/state/cache.rs`](../../../src/state/cache.rs)
- [`src/resolve/multi.rs`](../../../src/resolve/multi.rs)
- [`src/auth/roaring.rs`](../../../src/auth/roaring.rs)
- [`src/state/at.rs`](../../../src/state/at.rs)
- [`src/dense_index.rs`](../../../src/dense_index.rs)
- [`rezzy-recon/src/bitmap/mod.rs`](../../../rezzy-recon/src/bitmap/mod.rs)
