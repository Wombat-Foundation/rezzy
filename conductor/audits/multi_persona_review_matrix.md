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
| [`01_lean_formalization_20260408`](../tracks/01_lean_formalization_20260408/review.md) | `v0.1.0`–`v0.1.1`<br>(`be1774b..a88b53a`) | 0 | 3 | 1 | 1 | `F-01.1` (`src/resolve/sorting.rs:30-81`): fallback to unverified `event.power_level()`; `F-01.2` (`sorting.rs:293-355`): silent mainline cycle truncation; `F-01.3`: `progressiveFold` mutual-demotion proof gap $\to$ [Track 14](../tracks/14_p0_retire_cdo_from_src/index.md) |
| [`02_stateres_v2_cdo_20260510`](../tracks/02_stateres_v2_cdo_20260510/review.md) | `v0.1.2`–`v0.1.4`<br>(`5cf21de..f56b068`) | 1 | 2 | 1 | 0 | `F-02.1 [Critical]` (`src/resolve/cdo.rs:1-688`, `src/lib.rs:82`): retired CDO (`apply_cdo_filter`) with Anomalies 19 & 20 still exported in `librezzy`; `F-02.4` (`iterative.rs:487-492`): slow-path `m.room.create` omits `rejected` filter $\to$ [Track 14](../tracks/14_p0_retire_cdo_from_src/index.md) |
| [`03_auth_engine_eventlike_20260628`](../tracks/03_auth_engine_eventlike_20260628/review.md) | `v0.2.0`<br>(`34fde0c..71e2f3e`) | 2 | 2 | 2 | 0 | `F-03.1 [Critical]`: opt-in `room_id: Option<RoomId>` (`MSC4307` Rule 2.5); `F-03.2 [Critical]`: synchronous I/O Sandwich OOM on $10^4+$ forks; `F-03.3`/`F-03.4`: fail-open default methods on `EventContent` & `EventVerifier` $\to$ [Track 13](../tracks/13_p0_msc4307_fail_closed_auth/index.md) |
| [`04_hamt_delta_state_20260629`](../tracks/04_hamt_delta_state_20260629/review.md) | `v0.2.0`–`0.6.0-rc.1`<br>(`65b627b..0d0a87d`) | 0 | 3 | 2 | 0 | `F-04-01 [High]` (`rezzy-cli/src/format.rs:397-418`): wide "hydra" DAG frontiers hold `child_citations > 0`, pinning `Arc<HamtNode>` trees in RAM; `F-04-03`: cold deserialization breaks `Arc::ptr_eq` fast paths $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md) |
| [`05_lattice_v22_msc4242_20260630`](../tracks/05_lattice_v22_msc4242_20260630/review.md) | `v0.3.0`–`v0.4.0`<br>(`60dd404..f56b068`) | 2 | 3 | 1 | 0 | `F-05-01 [Critical]` (`iterative.rs:240-250`): `V2.1.1` `SEND01` divergence from Stock `V2.1`; `F-05-02 [Critical]`: DAG branch withholding ("DAG honesty"); `F-05-03`: non-monotone auth approximation in `resolve_semilattice_fold` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md) |
| [`06_spec_compliance_v1_v12_20260702`](../tracks/06_spec_compliance_v1_v12_20260702/review.md) | `v0.4.0`–`v0.5.0`<br>(`3d9368b..85464d3`) | 1 | 3 | 1 | 0 | `F-06-01 [Critical]` (`src/auth/mod.rs:1995-2191`): `check_foreign_room_citation` only wired in `check_auth_chain` and no-ops on `None`; `F-06-02 [High]` (`src/auth/mod.rs:908-917`): V12 Rule 10.4 checks `create_content.get_creator()` instead of `create_event.sender()` $\to$ [Track 13](../tracks/13_p0_msc4307_fail_closed_auth/index.md) |
| [`07_roaring_lazy_provider_20260703`](../tracks/07_roaring_lazy_provider_20260703/review.md) | `v0.5.0`–`v0.5.2`<br>(`3caa4ca..95a8ffb`) | 2 | 3 | 3 | 0 | `F-07-01 [Critical]` (`src/resolve/multi.rs:698-721`): `resolve_state_maps_lazy_with_diff` fails to stop at `unconflicted_state` ($U$), loading entire $\text{auth}(C)$ to `m.room.create`; `F-07-03 [High]` (`src/state/at.rs:1718-1799`): Byzantine wire `ev.depth` manipulation in `compute_auth_chain_diff` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md) |
| [`08_lthash_cryptography_20260705`](../tracks/08_lthash_cryptography_20260705/review.md) | `v0.5.0`–`0.6.0-rc.1`<br>(`b28ffbb..8dcd1c1`) | 0 | 3 | 3 | 0 | `F-08-01 [High]`: silent `u16::MAX` (64 KiB) key truncation collision; `F-08-02 [High]`: missing deduplication in `RedactionOverlay` / `ResolutionInputRecord` under $\mathbb{Z}_{2^{16}}^{1024}$; `F-08-03 [High]` (`src/state/at.rs:2697`): panic on empty `prev_states` $\to$ [Track 16](../tracks/16_p0_federation_consensus_guards/index.md) |
| [`09_perf_interning_benchmarks_20260920`](../tracks/09_perf_interning_benchmarks_20260920/review.md) | `0.6.0-rc.1`<br>(`5384219..0d0a87d`) | 0 | 4 | 3 | 1 | `F-09-01 [High]`: unseeded `foldhash` HashDoS; `F-09-02 [High]` (`dense_index.rs:168-204`): `try_build_bounded` fails to short-circuit on overflow; `F-09-03 [High]` (`interned_key.rs:155-170`): `InternId` `Ord`/`Hash` compares full strings instead of `self.rank: u32` $\to$ [Track 18](../tracks/18_p1_hashdos_and_arena_interning/index.md) |
| [`10_rezzy_json_crate_20261004`](../tracks/10_rezzy_json_crate_20261004/review.md) | `0.6.0-rc.1`<br>(`a636e18..1504cc7`) | 2 | 2 | 2 | 0 | `T10-F1 [Critical]` (`src/basespec/rezzy_types.rs:1144-1161`): `validate_canonical_number` returns `Ok(())` when both `as_i64()` and `as_u64()` are `None` (accepting integers $> \text{u64::MAX}$ in v6+ `reference_hash`); `T10-F2 [Critical]`: permissive writer exposure; `T10-F3 [High]`: lossy `as_f64` $\to$ [Track 15](../tracks/15_p0_strict_canonical_json_bounds/index.md) |
| [`11_rezzy_recon_pinsketch_trie_20261018`](../tracks/11_rezzy_recon_pinsketch_trie_20261018/review.md) | `0.6.0-rc.1`<br>(`3fe8542..7e81097`) | 0 | 3 | 2 | 1 | `T11-F1 [High]` (`rezzy-recon/src/client.rs:686-743`): lexicographic `bucket_range_start` sort allows low-prefix (`0x0000...`) grinding to starve higher prefixes across all 20 rounds; `T11-F3 [High]` (`src/merkle.rs:739`): v1 `saturating_add` instead of v2 checked `u64` $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md) |
| [`12_rezzy_cli_federation_agg_20261010`](../tracks/12_rezzy_cli_federation_agg_20261010/review.md) | `0.6.0-rc.1`<br>(`dd74d21..35a0457`) | 0 | 2 | 3 | 0 | `T12-F1 [High]` (`rezzy-cli/src/jsonl_merge.rs:239-295`): deduplicating by redacted canonical JSON lets an earlier redacted duplicate erase unredacted `content` and secondary `signatures`; `T12-F2 [High]`: `__rejected` stripping replay hazard $\to$ [Track 17](../tracks/17_p1_tier2_validation_and_e2e_recon/index.md) |
| **TOTALS (12 Historical Tracks)** | **924 Commits (`v0.1.0`–`HEAD`)** | **10** | **33** | **21** | **3** | **67 Actionable Findings Mapped to Standalone Tracks `13`–`18`** |

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
