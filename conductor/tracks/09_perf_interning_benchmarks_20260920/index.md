# Track 09: Performance Audits, StateKey Interning, DenseIndex & Benchmark Suite (`09_perf_interning_benchmarks_20260920`)

- **Track ID**: `09_perf_interning_benchmarks_20260920`
- **Epoch**: Jul–Oct 2026 (`2026-07-02` to `2026-10-18`)
- **Commit Range**: `5384219..0d0a87d` (`5384219`, `f2b9efb`, `e74a5e8`, `f56b068`, `6ca3bf9`, `e99e268`, `125cfc6`, `3b7c76f`, `beede91`, `33f3dd6`, `f6245b7`, `791b0f7`, `826cb93`, `330f2ca`, `7e49c94`, `7f41793`, `3a30ab0`, `5a0af29`, `41fb17d`, `0d0a87d`)
- **Status**: Completed (`[x]`)

## Track Artifacts

- **[Track Specification (`./spec.md`)](./spec.md)** — Reverse-engineered requirements for macro vs. micro benchmark audits (`benches/`, `docs/perf_audits.md`), visitor-pattern power-level iterators (`5384219`), `EventType` & `StateKey` interning (`InternedKey` vs. `InternId`), `DenseIndex<T, Idx = u32>`, `PersistentOrdMap`, `foldhash` (`FastMap`/`FastSet`), and Public-Safety Audit invariants.
- **[Implementation Plan (`./plan.md`)](./plan.md)** — 4-phase historical execution plan mapping 14 verified git commits across July–October 2026.
- **[Track Metadata (`./metadata.json`)](./metadata.json)** — Machine-readable metadata, commit boundaries, linked documentation, and Public-Safety Audit risk summary.

## Linked Documentation & Public-Safety Audit

- **[`../../../docs/perf_audits.md`](../../../docs/perf_audits.md)** — Comprehensive 24 Aug 2026 performance audits explaining the 15x–25x auth-diff and 1,639x reachability speedups vs. the 1.07x–1.37x in-memory sorting shootout against `ruma-state-res`, plus the full inventory of landed zero-copy, `foldhash`, Schwartzian `mainline_sort`, and `Arc::ptr_eq` optimizations.
- **[`../../../docs/tech_debt.md`](../../../docs/tech_debt.md)** — Tracks `DenseIndex<T, u32>` deduplication across 5+ call sites, `InternedKey` (`Arc<str>`) cross-core atomic contention (+3% to +16% reversal at 5,000 members), the `InternId<'a>` (`u32` rank arena) HRTB `for<'q> Borrow<dyn StateKeyDyn + 'q>` lifetime wall, and open E2E bucket-split test debt.
- **[`../../../docs/format.sh`](../../../docs/format.sh)** — 4-line shellcheck-hardened documentation formatting script (`e99e268`, `125cfc6`).
- **[`../../audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md)** — Public-Safety Audit rows **#12 (`perf_audits.md` — High: HashDoS / Cold Cliff)**, **#16 (`tech_debt.md` — High: Degradation at Scale)**, and **#5 (`format.sh` — Low: Tooling Hygiene)**.

## Primary Source & Test Files

- [`../../../src/dense_index.rs`](../../../src/dense_index.rs) — Shared `DenseIndex<T, Idx = u32>` primitive with `IndexTooLarge` `Result`-based overflow handling.
- [`../../../src/basespec/event_types.rs`](../../../src/basespec/event_types.rs) & [`../../../src/basespec/interned_key.rs`](../../../src/basespec/interned_key.rs) — 1-byte discriminant `EventType` enum (`Custom(Arc<str>)`), `InternedKey`, and the `Interner` / `InternId<'a>` / `InternedRoomState` spike.
- [`../../../src/state/persistent_ord_map.rs`](../../../src/state/persistent_ord_map.rs) — In-tree `PersistentOrdMap` replacing `imbl::OrdMap` with optimized B-tree leaf layout (`beede91`, `7e49c94`).
- [`../../../benches/compare_ruma.rs`](../../../benches/compare_ruma.rs), [`../../../benches/state/interned_key.rs`](../../../benches/state/interned_key.rs), [`../../../benches/db/state_backend.rs`](../../../benches/db/state_backend.rs), and [`../../../benches/db/hamt_delta.rs`](../../../benches/db/hamt_delta.rs) — Macro and micro benchmark harnesses.
