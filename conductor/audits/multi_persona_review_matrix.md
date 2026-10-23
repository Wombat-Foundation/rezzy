# Master 8-Perspective Critique Matrix Across All 12 Historical Tracks (`01`–`12`)

This executive matrix synthesizes the multi-agent reviews (`review.md`) conducted across all 12 historical Conductor tracks (`01`–`12`) using 8 specialized domain perspectives:
1. **Product Management (`critic-pm`)**
2. **Principal Engineering Lead (`critic-eng-lead`)**
3. **Public-Safety & C2 Compliance (`critic-compliance`)**
4. **Performance & Adversarial Liveness (`critic-perf`)**
5. **Formal Verification & Mathematical Soundness (`critic-formal-crypto`)**
6. **Matrix Federation Protocol Interop (`critic-federation-interop`)**
7. **Adversarial Red-Team & Verification QA (`critic-redteam-qa`)**
8. **Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)**

---

## 1. Track-by-Track Review Summary & Severity Rollup

| Track ID | Historical Epoch & Commits | Critical | High | Medium | Low | Top Source-Level Findings & Linked Remediation Track |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| [`01_lean_formalization_20260408`](../tracks/01_lean_formalization_20260408/review.md) | `v0.1.0`–`v0.1.1`<br>(`be1774b..a88b53a`) | 0 | 3 | 3 | 1 | `F-01.1`..`F-01.7` (7 findings): `F-01.1`/`F-01.2`/`F-01.4` $\to$ [Track 14](../tracks/14_p0_retire_cdo_from_src/index.md); `F-01.3`/`F-01.5`/`F-01.6`/`F-01.7` $\to$ [Track 19](../tracks/19_p1_stateres_api_panics_and_conflicted_keys/index.md) |
| [`02_stateres_v2_cdo_20260510`](../tracks/02_stateres_v2_cdo_20260510/review.md) | `v0.1.2`–`v0.1.4`<br>(`5cf21de..f56b068`) | 1 | 2 | 3 | 1 | `F-02.1`..`F-02.7` (7 findings): `F-02.1`/`F-02.4` $\to$ [Track 14](../tracks/14_p0_retire_cdo_from_src/index.md); `F-02.2`/`F-02.3`/`F-02.5`/`F-02.6`/`F-02.7` $\to$ [Track 19](../tracks/19_p1_stateres_api_panics_and_conflicted_keys/index.md) |
| [`03_auth_engine_eventlike_20260628`](../tracks/03_auth_engine_eventlike_20260628/review.md) | `v0.2.0`<br>(`34fde0c..71e2f3e`) | 2 | 2 | 3 | 1 | `F-03.1`..`F-03.8` (8 findings): `F-03.1`/`F-03.3`/`F-03.4` $\to$ [Track 13](../tracks/13_p0_msc4307_fail_closed_auth/index.md); `F-03.2`/`F-03.5`/`F-03.6`/`F-03.7`/`F-03.8` $\to$ [Track 20](../tracks/20_p1_auth_memory_bounds_and_ingest_hardening/index.md) |
| [`04_hamt_delta_state_20260629`](../tracks/04_hamt_delta_state_20260629/review.md) | `v0.2.0`–`0.6.0-rc.1`<br>(`65b627b..0d0a87d`) | 0 | 3 | 2 | 1 | `F-04-01`..`F-04-06` (6 findings): `F-04-01` $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md); `F-04-02`..`F-04-06` $\to$ [Track 21](../tracks/21_p1_hamt_ordmap_and_state_dag_hardening/index.md) |
| [`05_lattice_v22_msc4242_20260630`](../tracks/05_lattice_v22_msc4242_20260630/review.md) | `v0.3.0`–`v0.4.0`<br>(`60dd404..f56b068`) | 2 | 3 | 1 | 0 | `F-05-01`..`F-05-06` (6 findings): `F-05-01`/`F-05-03` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md); `F-05-02`/`F-05-04`/`F-05-05`/`F-05-06` $\to$ [Track 21](../tracks/21_p1_hamt_ordmap_and_state_dag_hardening/index.md) |
| [`06_spec_compliance_v1_v12_20260702`](../tracks/06_spec_compliance_v1_v12_20260702/review.md) | `v0.4.0`–`v0.5.0`<br>(`3d9368b..85464d3`) | 1 | 3 | 1 | 1 | `F-06-01`..`F-06-06` (6 findings): `F-06-01`/`F-06-02` $\to$ [Track 13](../tracks/13_p0_msc4307_fail_closed_auth/index.md); `F-06-03`..`F-06-06` $\to$ [Track 20](../tracks/20_p1_auth_memory_bounds_and_ingest_hardening/index.md) |
| [`07_roaring_lazy_provider_20260703`](../tracks/07_roaring_lazy_provider_20260703/review.md) | `v0.5.0`–`v0.5.2`<br>(`3caa4ca..95a8ffb`) | 2 | 4 | 2 | 1 | `F-07-01`..`F-07-09` (9 findings): `F-07-01`/`F-07-03` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md); `F-07-04` $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md); `F-07-07` $\to$ [Track 18](../tracks/18_p1_hashdos_and_arena_interning/index.md); `F-07-02`/`F-07-05`/`F-07-06`/`F-07-08`/`F-07-09` $\to$ [Track 22](../tracks/22_p1_lazy_cache_sync_and_roaring_consolidation/index.md) |
| [`08_lthash_cryptography_20260705`](../tracks/08_lthash_cryptography_20260705/review.md) | `v0.5.0`–`0.6.0-rc.1`<br>(`b28ffbb..8dcd1c1`) | 0 | 3 | 3 | 2 | `F-08-01`..`F-08-08` (8 findings): `F-08-01`..`F-08-03` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md); `F-08-04`..`F-08-08` $\to$ [Track 23](../tracks/23_p2_lthash_domain_framing_and_constant_time/index.md) |
| [`09_perf_interning_benchmarks_20260920`](../tracks/09_perf_interning_benchmarks_20260920/review.md) | `0.6.0-rc.1`<br>(`5384219..0d0a87d`) | 0 | 4 | 3 | 1 | `F-09-01`..`F-09-08` (8 findings): `F-09-01`..`F-09-04` $\to$ [Track 18](../tracks/18_p1_hashdos_and_arena_interning/index.md); `F-09-05` $\to$ [Track 21](../tracks/21_p1_hamt_ordmap_and_state_dag_hardening/index.md); `F-09-06` $\to$ [Track 22](../tracks/22_p1_lazy_cache_sync_and_roaring_consolidation/index.md); `F-09-07`/`F-09-08` $\to$ [Track 24](../tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md) |
| [`10_rezzy_json_crate_20261004`](../tracks/10_rezzy_json_crate_20261004/review.md) | `0.6.0-rc.1`<br>(`a636e18..1504cc7`) | 2 | 1 | 2 | 1 | `T10-F1`..`T10-F6` (6 findings): `T10-F1`..`T10-F3` $\to$ [Track 15](../tracks/15_p0_strict_canonical_json_bounds/index.md); `T10-F4`..`T10-F6` $\to$ [Track 24](../tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md) |
| [`11_rezzy_recon_pinsketch_trie_20261018`](../tracks/11_rezzy_recon_pinsketch_trie_20261018/review.md) | `0.6.0-rc.1`<br>(`3fe8542..7e81097`) | 0 | 3 | 3 | 0 | `T11-F1`..`T11-F6` (6 findings): `T11-F1`..`T11-F3` $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md); `T11-F4`..`T11-F6` $\to$ [Track 24](../tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md) |
| [`12_rezzy_cli_federation_agg_20261010`](../tracks/12_rezzy_cli_federation_agg_20261010/review.md) | `0.6.0-rc.1`<br>(`dd74d21..35a0457`) | 0 | 2 | 2 | 1 | `T12-F1`..`T12-F5` (5 findings): `T12-F1`/`T12-F2` $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md); `T12-F3`..`T12-F5` $\to$ [Track 24](../tracks/24_p2_json_recon_cli_hardening_and_zeroize/index.md) |
| **TOTALS (12 Historical Tracks)** | **924 Commits (`v0.1.0`–`HEAD`)** | **10** | **33** | **28** | **11** | **82/82 Findings (100%) Accounted For Across Stage B Tracks `13`–`24`** |

---

## 2. Cross-Track Synthesis by Perspective

### 2.1 Product Management (`critic-pm`)
- **Spec Coverage vs. Reality**: While [`docs/spec_coverage.csv`](../../docs/spec_coverage.csv) marks 31/35 rows as `full`, 8-perspective code inspection shows that PDU syntactic limits, Ed25519 signature verification, and `MSC4307` cross-room bindings are either caller-delegated or opt-in (`Track 06`, `Track 13`).
- **Homeserver Utility Gap**: Tier-1 hot-path APIs shipped in `v0.5.0`–`v0.5.2`, but Tier-2 protective guards (`src/auth/validate.rs` and `src/dag/fork.rs` in [`docs/homeserver_utilities.md`](../../docs/homeserver_utilities.md)) remain unimplemented (`Track 07`, `Track 17`).

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **Retired Code in Production**: `src/resolve/cdo.rs` (`apply_cdo_filter`) remains compiled and publicly exported in `src/lib.rs:82` despite proven soundness counterexamples (`Track 02`, `Track 14`).
- **Fail-Open Trait Defaults**: `EventContent` and `EventVerifier<Id>` (`src/basespec/rezzy_types.rs:2537-2700`) provide default methods returning `Ok(())` / `true`, silently bypassing validation if a homeserver integrator omits a method override (`Track 03`, `Track 13`).

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Newly Discovered Source-Level Compliance Bugs**:
  1. `T10-F1 [Critical]` (`src/basespec/rezzy_types.rs:1144-1161`): `validate_canonical_number` returns `Ok(())` when both `n.as_i64()` and `n.as_u64()` are `None`, accepting $> \text{u64::MAX}$ integers during v6+ event hashing (`Track 10`, `Track 15`).
  2. `F-06-02 [High]` (`src/auth/mod.rs:908-917`): Room V12 Rule 10.4 checks `create_content.get_creator()` instead of `create_event.sender()`, allowing V12 room creators to be placed into `m.room.power_levels.users` when `content.creator` is absent (`Track 06`, `Track 13`).
  3. `F-07-01 [Critical]` (`src/resolve/multi.rs:698-721`): `resolve_state_maps_lazy_with_diff` fails to stop at `unconflicted_state` ($U$) when `precomputed_auth_diff` is `None` (`Track 07`, `Track 16`).

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Subtree Starvation in `rezzy-recon`**: Sorting `BucketExchange::pending` strictly by `bucket_range_start` allows an attacker who grinds low numeric `h64` prefixes (`0x0000...`) to monopolize all 128 per-round bucket slots across all 20 rounds (`Track 11`, `Track 17`).
- **Broken Bounded Short-Circuit & `InternId` Comparator**: `DenseIndex::try_build_bounded` drains the entire iterator into a `HashSet` after exceeding `bound`, and `InternId<'a>::cmp` compares full strings instead of `self.rank: u32` (`Track 09`, `Track 18`).
