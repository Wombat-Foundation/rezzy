# Implementation Plan: Track 18 — P1 HashDoS Hardening, `DenseIndex` Short-Circuit & `InternId(u32)` Arena Interning

## Phase 1: CSPRNG-Seeded Ingestion Hashing & `DenseIndex::try_build_bounded` Short-Circuit (`F-09-01`, `F-09-02`) [checkpoint: aed1bd9]
- [x] Task: Harden `FastMap`/`FastSet` against unseeded external string HashDoS and fix `DenseIndex::try_build_bounded` `aed1bd9`
  - [x] Seed external string lookup tables with per-instance random seeds or SipHash-1-3 (`src/lib.rs:197-213`, `F-09-01`) and sort `AuthGraph::build` Kahn seed queue deterministically (`F-07-07`)
  - [x] Short-circuit `DenseIndex::try_build_bounded` (`src/dense_index.rs:168-204`) immediately in $O(1)$ when `items.len() >= bound` instead of allocating a `HashSet` and draining the iterator (`F-09-02`)

## Phase 2: Fix `InternId` Rank Ordering & Land Non-Lifetime `InternId(u32)` Arena Interning (`F-09-03`, `F-09-04`) [checkpoint: aed1bd9]
- [x] Task: Fix `InternId` `Ord`/`Hash` string-dereference bug and land `InternId(u32)` without `'a` lifetime infection `aed1bd9`
  - [x] Fix `src/basespec/interned_key.rs:155-170` so `Ord` and `Hash` compare `self.rank: u32` in $O(1)$ rather than dereferencing and comparing strings (`F-09-03`)
  - [x] Implement `Send + Sync` arena-backed `InternId(u32)` to eliminate the `+3%` to `+16%` `Arc<str>` atomic contention at 5,000+ room members (`F-09-04`)
