# Specification: Track 18 — P1 HashDoS Hardening & Large-Room `u32` Arena Interning (`InternId`)

## 1. Overview & Public-Safety Rationale
Per [`docs/perf_audits.md`](../../../docs/perf_audits.md), [`docs/tech_debt.md`](../../../docs/tech_debt.md), and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows #12, #16 & P1 Remediation #6):
1. Using fixed-seed non-cryptographic `foldhash` on untrusted network-supplied string keys (`event_id`, `state_key`, `sender`) exposes in-memory hash tables (`FastMap`/`FastSet`) to quadratic HashDoS collision attacks unless keys are first interned into `DenseIndex<T, u32>` or hashed with a CSPRNG-seeded SipHash/foldhash state.
2. In 5,000+ member rooms, `InternedKey` (`Arc<str>`) suffers a `+3%` to `+16%` atomic refcount contention penalty during HAMT/OrdMap clones. Replacing `Arc<str>` with a `Copy` `u32` index (`InternId(u32)` backed by a call-scoped arena) eliminates both atomic contention and the lifetime infection documented in `docs/tech_debt.md`.

## 2. Functional Requirements
1. **Land Non-Lifetime `InternId(u32)` Arena Interning**:
   - Complete the `InternId(u32)` design from `docs/tech_debt.md` so `StateKey` and `EventId` map to `Copy` `u32` indices without infecting `StateMap<K, V>` with a `'a` lifetime.
2. **Eliminate Unseeded `foldhash` on Untrusted String Keys**:
   - Ensure external string ingestion uses CSPRNG-seeded hashing (`RandomState` or per-arena random seed) while internal graph walks operate on `DenseIndex<Id, u32>`.

## 3. Acceptance Criteria
- [ ] External string-keyed maps use randomized hash seeds or `DenseIndex<Id, u32>`.
- [ ] `InternId(u32)` eliminates `Arc<str>` atomic refcount traffic in 5,000-member room benchmarks (`benches/`).
