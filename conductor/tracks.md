# Tracks Registry

This registry tracks the complete historical feature trajectory of `rezzy` (`01`–`12`) across 924 commits and 16 technical/audit documents, followed by **12 standalone Stage B remediation tracks (`13`–`24`)** that account for **100% (82/82)** of the structured findings across the 8-perspective critiques (`review.md`) and [`rezzy_docs_public_safety_audit.md`](./audits/rezzy_docs_public_safety_audit.md).

---

- [x] **Track: 01 — Lean 4 Formalization, Kahn Topological Sort & Trace Compiler (`v0.1.0`–`v0.1.1`)**
  *Link: [./tracks/01_lean_formalization_20260408/index.md](./tracks/01_lean_formalization_20260408/index.md)*

---

- [x] **Track: 02 — Core `#![no_std]` State Resolution V1/V2/V2.1 & CDO Soundness Retirement (`v0.1.2`–`v0.1.4`)**
  *Link: [./tracks/02_stateres_v2_cdo_20260510/index.md](./tracks/02_stateres_v2_cdo_20260510/index.md)*

---

- [x] **Track: 03 — Version-Aware Auth Engine, `EventLike` Trait & Streaming Auth Cache (`v0.2.0`)**
  *Link: [./tracks/03_auth_engine_eventlike_20260628/index.md](./tracks/03_auth_engine_eventlike_20260628/index.md)*

---

- [x] **Track: 04 — Persistent HAMT Delta State Compression & Live-Frontier Citation GC (`v0.2.0`–`v0.5.2`)**
  *Link: [./tracks/04_hamt_delta_state_20260629/index.md](./tracks/04_hamt_delta_state_20260629/index.md)*

---

- [x] **Track: 05 — Iterative Sort vs. Lattice Fold (`V2.1.1` & `V2.2` / `MSC4242`) & Security Comparison (`v0.3.0`–`v0.4.0`)**
  *Link: [./tracks/05_lattice_v22_msc4242_20260630/index.md](./tracks/05_lattice_v22_msc4242_20260630/index.md)*

---

- [x] **Track: 06 — Matrix Room V1–V12 Spec Compliance, 3PI Delegation, Knocking & PDU Invariants (`v0.4.0`–`v0.5.0`)**
  *Link: [./tracks/06_spec_compliance_v1_v12_20260702/index.md](./tracks/06_spec_compliance_v1_v12_20260702/index.md)*

---

- [x] **Track: 07 — Synchronous I/O Sandwich, `RoaringBitmap` Auth-Difference & Lazy `EventProvider` (`v0.5.0`–`v0.5.2`)**
  *Link: [./tracks/07_roaring_lazy_provider_20260703/index.md](./tracks/07_roaring_lazy_provider_20260703/index.md)*

---

- [x] **Track: 08 — `MSC4500` Homomorphic `LtHash` State Checksumming (BLAKE3 & AES-CTR Profiles) (`v0.5.0`–`0.6.0-rc.1`)**
  *Link: [./tracks/08_lthash_cryptography_20260705/index.md](./tracks/08_lthash_cryptography_20260705/index.md)*

---

- [x] **Track: 09 — Macro/Micro Performance Audits, `foldhash`, `Arc::ptr_eq` & Large-Room Interning Debt (`0.6.0-rc.1`)**
  *Link: [./tracks/09_perf_interning_benchmarks_20260920/index.md](./tracks/09_perf_interning_benchmarks_20260920/index.md)*

---

- [x] **Track: 10 — `rezzy-json` Crate Extraction, Dependency-Free Parser & Canonical Numeric Limits (`0.6.0-rc.1`)**
  *Link: [./tracks/10_rezzy_json_crate_20261004/index.md](./tracks/10_rezzy_json_crate_20261004/index.md)*

---

- [x] **Track: 11 — `rezzy-recon`: `MSC4521` $\text{GF}(2^{64})$ PinSketch Reconciliation, `h64` Prefix Grinding & `MSC4511` Causal Tries (`0.6.0-rc.1`)**
  *Link: [./tracks/11_rezzy_recon_pinsketch_trie_20261018/index.md](./tracks/11_rezzy_recon_pinsketch_trie_20261018/index.md)*

---

- [x] **Track: 12 — `rezzy-cli`: Deterministic JSONL Aggregation, `.rezzy-meta.jsonl` Sidecar & Signed Federation Crawler (`0.6.0-rc.1`)**
  *Link: [./tracks/12_rezzy_cli_federation_agg_20261010/index.md](./tracks/12_rezzy_cli_federation_agg_20261010/index.md)*

---

- [ ] **Track: 13 — P0 Remediation: Enforce Unconditional Fail-Closed Cross-Room Auth Rejection (`MSC4307` Rule 2.5) & V12 Rule 10.4**
  *Link: [./tracks/13_p0_msc4307_fail_closed_auth/index.md](./tracks/13_p0_msc4307_fail_closed_auth/index.md)*

---

- [ ] **Track: 14 — P0 Remediation: Relocate Retired Causal Domination Operator (`cdo.rs`) Out of Production `src/` & Harden Sorting**
  *Link: [./tracks/14_p0_retire_cdo_from_src/index.md](./tracks/14_p0_retire_cdo_from_src/index.md)*

---

- [x] **Track: 15 — P0 Remediation: Seal Permissive Canonical JSON, Fix `> u64::MAX` Fallthrough & Lossy `as_f64` (`rezzy-json`)**
  *Link: [./tracks/15_p0_strict_canonical_json_bounds/index.md](./tracks/15_p0_strict_canonical_json_bounds/index.md)*

---

- [ ] **Track: 16 — P0 Remediation: Prevent Mixed-Federation Split-Brain (`V2.1.1` `SEND01`, Lazy `unconflicted_state` & `LtHash` Guards)**
  *Link: [./tracks/16_p0_federation_consensus_guards/index.md](./tracks/16_p0_federation_consensus_guards/index.md)*

---

- [ ] **Track: 17 — P1 Remediation: Implement Tier-2 Pre-Auth Validation (`validate.rs`, `fork.rs`), Fair Prefix Queueing & Bucket-Split E2E**
  *Link: [./tracks/17_p1_tier2_validation_and_e2e_recon/index.md](./tracks/17_p1_tier2_validation_and_e2e_recon/index.md)*

---

- [~] **Track: 18 — P1 Remediation: Harden Hash Tables Against HashDoS, `DenseIndex` Short-Circuit & `u32` Arena Interning (`InternId`)**
  *Link: [./tracks/18_p1_hashdos_and_arena_interning/index.md](./tracks/18_p1_hashdos_and_arena_interning/index.md)*

---

- [ ] **Track: 19 — P1 Remediation: State Resolution Conflicted-Keys Isolation, Cycle Tie-Breaks & Lean 4 Proof Parity (`F-01.3`..`F-02.7`)**
  *Link: [./tracks/19_p1_stateres_api_panics_and_conflicted_keys/index.md](./tracks/19_p1_stateres_api_panics_and_conflicted_keys/index.md)*

---

- [ ] **Track: 20 — P1 Remediation: I/O Sandwich Subgraph Bounds, `LocalAuthCache` Zero-Clone, Ingest Hash Verification & Rule 11 (`F-03.2`..`F-06-06`)**
  *Link: [./tracks/20_p1_auth_memory_bounds_and_ingest_hardening/index.md](./tracks/20_p1_auth_memory_bounds_and_ingest_hardening/index.md)*

---

- [ ] **Track: 21 — P1 Remediation: HAMT Domain Separation, `PersistentOrdMap` Rebalancing, Cold Snapshot Diffing & `MSC4242` State DAG Bounds (`F-04-02`..`F-09-05`)**
  *Link: [./tracks/21_p1_hamt_ordmap_and_state_dag_hardening/index.md](./tracks/21_p1_hamt_ordmap_and_state_dag_hardening/index.md)*

---

- [ ] **Track: 22 — P1 Remediation: Thread-Safe `LeanEventCache`, Fallible `EventProvider` Error Propagation & `DenseIndex`/Roaring Consolidation (`F-07-02`..`F-09-06`)**
  *Link: [./tracks/22_p1_lazy_cache_sync_and_roaring_consolidation/index.md](./tracks/22_p1_lazy_cache_sync_and_roaring_consolidation/index.md)*

---

- [ ] **Track: 23 — P2 Remediation: `LtHash` Custom DST Length-Prefix Framing, `AES-256-CTR` Profile, Stack Reduction & Constant-Time Equality (`F-08-04`..`F-08-08`)**
  *Link: [./tracks/23_p2_lthash_domain_framing_and_constant_time/index.md](./tracks/23_p2_lthash_domain_framing_and_constant_time/index.md)*

---

- [ ] **Track: 24 — P2 Remediation: `rezzy-json` Float/Lookup Hardening, `rezzy-recon` Phase-1 Gate & `h64` Chunk Fix, `rezzy-cli` `Zeroize` & Cycle Signaling (`F-09-07`..`T12-F5`)**
  *Link: [./tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md](./tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md)*
