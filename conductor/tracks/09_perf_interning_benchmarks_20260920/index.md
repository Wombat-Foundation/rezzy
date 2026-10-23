# Track 09: Performance Audits, StateKey Interning, DenseIndex & Benchmark Suite

- **Track ID**: `09_perf_interning_benchmarks_20260920`
- **Type**: `chore`
- **Status**: `completed` (Historical Stage A Track — Audited)
- **Commit Range**: `5384219..0d0a87d` (`2026-09-20` – `2026-10-08`)

## Quick Links

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public Safety & Documentation Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques

- [Track Review & 8-Persona Critique (`./review.md`)](./review.md)

## Key Artifacts & Source Files

- `src/lib.rs` — `FastMap` and `FastSet` (`hashbrown::DefaultHashBuilder` / `foldhash`)
- `src/dense_index.rs` — `DenseIndex<T, Idx>`, `DenseIndexWidth`, and `IndexTooLarge`
- `src/basespec/interned_key.rs` & `src/basespec/rezzy_types.rs` — `Interner`, `InternId<'a>`, `InternedKey(Arc<str>)`, and `intern_events`
- `src/state/persistent_ord_map.rs` — 24-way persistent B+ tree (`PersistentOrdMap<K, V>`)
- `rezzy-cli/src/timeline_order.rs` — Deterministic `kahn_order_by` topological sorting
- `benches/state/interned_key.rs` & `benches/db/hamt_delta.rs` — Interning contention and HAMT vs. B+ tree benchmarks
- `docs/perf_audits.md`, `docs/tech_debt.md`, & `docs/format.sh` — Performance audits, tech-debt registry, and prose formatting script
