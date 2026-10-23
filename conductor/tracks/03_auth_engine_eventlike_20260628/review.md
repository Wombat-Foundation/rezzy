# Architectural & Multi-Perspective Review: Track 03 — Version-Aware Auth Engine, `EventLike` Trait & Streaming Auth Cache (`v0.2.0`)

## 1. Executive Review Summary (`/conductor-review`)

- **Track ID**: `03_auth_engine_eventlike_20260628`
- **Epoch**: `v0.2.0` (May 20–June 30, 2026, plus `0cce801`, `a83ec17`, `71e2f3e` through July 2, 2026)
- **Commit Range**: `4abfb43..6268aab` (plus `0cce801`, `a83ec17`, `71e2f3e`)
- **Review Verdict**: **COMPLETED WITH ACTIONABLE STAGE B REMEDIATIONS**
- **Cross-Referenced Audit**: [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #2 `architecture.md`, Row #4 `design_notes.md`, Row #14 `spec_audit.md`), [`docs/architecture.md`](../../../docs/architecture.md), [`docs/design_notes.md`](../../../docs/design_notes.md), [`TODO.txt`](../../../TODO.txt)

### Plan & Guideline Compliance Checklist
- [x] **Plan Completion**: All 4 phases in [`plan.md`](./plan.md) (`34fde0c` through `71e2f3e`) are verified in repository history.
- [x] **Modular Crate Decomposition**: Monolithic `src/lib.rs` cleanly decomposed into `src/auth/`, `src/resolve/`, `src/state/`, and `src/basespec/` (`34fde0c`, `3f62797`).
- [x] **Generic Zero-Copy Traits (`EventId`, `StateKey`, `DagNode`, `EventContent`, `EventLike`, `RawEvent`, `ParsedEvent`)**: Implemented in [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) and [`src/raw_event.rs`](../../../src/raw_event.rs).
- [x] **Streaming State Reconstruction & `LocalAuthCache`**: Implemented in [`src/state/at.rs`](../../../src/state/at.rs) (`StreamingInputs::try_compute`, `StreamingInputs::try_compute_optimized`, `LocalAuthCache`).
- [ ] **Open Audit & Security Hardening Debt**: Fail-open default validation methods on [`EventContent`](../../../src/basespec/rezzy_types.rs#L2515-L2643), opt-in foreign-room `MSC4307` Rule 2.5 checking (`room_id: Option<RoomId>`), and unbounded memory / executor starvation risks in the synchronous "I/O Sandwich" pre-fetch model under $10^4+$ event adversarial forks.

---

## 2. Multi-Perspective Critique (8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Milestone Maturity & Ecosystem Fit**: Track 03 (`v0.2.0`) delivered the architectural leap required for real-world Rust Matrix homeservers (Continuwuity, Tuwunel, Conduit) to adopt `rezzy`: integer `EventId` support (`u32`/`u64`), zero-copy `SortContext`, streaming state reconstruction (`StreamingInputs`), and a standalone version-aware PDU authorization engine (`check_auth`, `check_auth_with_context`, `validate_forward_extremity`).
- **Finding `[Medium]` — Documentation Drift in `docs/design_notes.md` Code Examples**:
  - In [`docs/design_notes.md:174-190`](../../../docs/design_notes.md#L174-L190), the integer-keyed resolution snippet calls `resolve_iterative_sort(&unconflicted, &events, &auth_ctx, StateResVersion::V2, &mut pl_cache, &String::new())` with 6 positional arguments instead of wrapping them in [`IterativeInputs::new(...)`](../../../src/resolve/iterative.rs#L559-L575), and [`docs/design_notes.md:17`](../../../docs/design_notes.md#L17) refers to `compute_state_at_streaming` whereas the current public API is [`StreamingInputs::compute`](../../../src/state/at.rs#L661-L684) / [`StreamingInputs::try_compute`](../../../src/state/at.rs#L620-L625). Keeping `docs/design_notes.md` synchronized with the refactored struct-bundled entry points avoids integrator friction.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **Trait Architecture & Memory Ownership**:
  - Rejecting the intermediate `TypedContent` enum (`add27da`) in favor of `EventContent` + `EventLike` + `RawEvent` (`ecb07fe`, `0cce801`, `a83ec17`) and introducing topological reference consuming in [`src/state/at.rs`](../../../src/state/at.rs) (`c304630`) to keep `Arc::strong_count == 1` along linear chains are textbook systems-engineering wins.
  - Replacing infallible `ParsedEvent::new` (which silently degraded invalid JSON to `Value::Null`) with fallible [`ParsedEvent::try_new`](../../../src/basespec/rezzy_types.rs#L1982-L1988) (`b189ffc`) closed a subtle silent-corruption trap.
- **Finding `[High]` — Permissive Default Implementations on `EventContent` Create a Silent Spec-Compliance Footgun**:
  - In [`src/basespec/rezzy_types.rs:2515-2643`](../../../src/basespec/rezzy_types.rs#L2515-L2643), `EventContent` provides default implementations for critical syntactic and Room Version 10–12 validation predicates that return **permissive ("valid") defaults**:
    - `has_malformed_room_version(&self) -> bool { false }` (line 2545)
    - `additional_creators_are_valid(&self) -> bool { true }` (line 2565)
    - `find_non_integer_scalar_pl(&self) -> Option<&'static str> { None }` (line 2616, Rule 10.1 V10+ integer power levels)
    - `find_non_integer_map_pl(&self) -> Option<&'static str> { None }` (line 2622, Rule 10.2 V10+)
    - `has_non_integer_users_pl(&self, strict: bool) -> bool { false }` (line 2629, Rule 10.3 all versions)
    - `has_user_in_users(&self, _user_id: &str) -> bool { false }` (line 2640, Rule 10.4 V12 creator-in-`users` rejection)
  - As highlighted in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #4 `design_notes.md`), any downstream homeserver implementing `EventContent` on a custom struct without explicitly overriding these 6 default methods will **silently bypass Room Version 10–12 power-level type checks and V12 `MSC4289` creator immutability rules (`Rule 10.4`)**! These 6 validation methods must either have no default implementation (forcing the compiler to require an explicit implementation) or be gated behind an explicit `UncheckedEventContent` marker.
- **Finding `[Low]` — Per-Check Heap Allocations in `required_auth_types_for` and `seen_tuples` (`src/auth/mod.rs`)**:
  - In [`check_auth_with_context`](../../../src/auth/mod.rs#L763-L800), `seen_tuples` allocates `(auth_type.into_owned(), String::from(sk))` for every `auth_event`, and `required_auth_types_for` compares via `(req_type.to_string(), req_key.to_string())` (lines 793–799). As noted in [`TODO.txt:569-588`](../../../TODO.txt#L569-L588), keying `seen_tuples` by borrowed `(Cow<'_, str>, &str)` or `(EventType, &str)` eliminates 6–15 small heap allocations per `check_auth_with_context` call.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Authorization Hardening**:
  - Track 03 hardened creator power levels in Room Version 12 (`MSC4289`) using `MAX_POWER_LEVEL_RUST` (`i64::MAX`) in [`src/auth/user.rs:48`](../../../src/auth/user.rs#L48) and [`src/resolve/sorting.rs:62`](../../../src/resolve/sorting.rs#L62) while clamping JSON wire power levels to `MAX_POWER_LEVEL_JSON` ($\pm(2^{53}-1)$) (`a56a6b8`), making creator authority unreachable by any wire integer and immune to `i64` overflow.
  - Self-bans (`sender == state_key` with `membership == "ban"`) are explicitly rejected (`5767d0d`), and rejected auth state events are blocked by [`reject_flagged_auth_state`](../../../src/auth/mod.rs#L424-L461).
- **Finding `[Critical]` — Opt-In Cross-Room Auth Rejection (`MSC4307` Rule 2.5) and `EventLike` Trait Gap (`P0 #1`)**:
  - Cross-referencing [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #14 `spec_audit.md` and P0 Item #1):
    1. `LeanEvent::room_id` ([`src/basespec/rezzy_types.rs:2148`](../../../src/basespec/rezzy_types.rs#L2148)) is `Option<RoomId>` and defaults to `None`. When `room_id` is `None` on the citing event, `AuthError::ForeignRoomEvent` ([`src/auth/mod.rs:85-101`](../../../src/auth/mod.rs#L85-L101)) is completely bypassed.
    2. Worse, [`EventLike`](../../../src/basespec/rezzy_types.rs#L1662-L1799) and [`RawEvent`](../../../src/basespec/rezzy_types.rs#L1893-L1940) do **not** even expose a `fn room_id(&self) -> Option<&str>` method, and [`check_auth_with_context`](../../../src/auth/mod.rs#L533-L800) does not check `ForeignRoomEvent` (only `check_auth_chain` on `LeanEvent` does)! If a homeserver uses `check_auth_with_context` over `EventLike` (or forgets to stamp `room_id: Some(...)` on `LeanEvent`), a cross-room event injection attack ([CVE-2025-49090](https://matrix.org/blog/2025/08/project-hydra-improving-state-res/) / `MSC4307`) will not be caught by `check_auth_with_context`.
- **Finding `[High]` — `EventVerifier` Methods Default to `Ok(())` (No-Op Verification)**:
  - In [`src/basespec/rezzy_types.rs:2663-2700`](../../../src/basespec/rezzy_types.rs#L2663-L2700), every method on `EventVerifier<Id>` (`verify_event_id_hash`, `verify_signatures`, `verify_content_hash`, `verify_third_party_invite`, `verify_join_authorised_via_users_server`) has a default implementation returning `Ok(())`. If a security-critical integrator implements `EventVerifier` and typos or omits one of the 5 methods, signature or hash verification silently succeeds (`Ok(())`).

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Zero-Copy & Streaming Gains**:
  - `StreamingInputs::try_compute_optimized` ([`src/state/at.rs:636-641`](../../../src/state/at.rs#L636-L641)) bounds peak state-map memory to the active DAG frontier width, and `LocalAuthCache` ([`src/state/at.rs:71-84`](../../../src/state/at.rs#L71-L84)) amortizes `local_auth` construction across fork resolutions.
- **Finding `[Critical]` — Synchronous "I/O Sandwich" Pre-Fetch OOM & Async Executor Starvation on Wide Adversarial Forks (`Row #2`)**:
  - [`docs/architecture.md:202-211`](../../../docs/architecture.md#L202-L211) and [`docs/design_notes.md:97-98`](../../../docs/design_notes.md#L97-L98) claim that even a "Catastrophic" fork comprises only `500–700` events and fits in L1/L2 cache. As documented in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #2 `architecture.md`: **Critical (OOM / Starvation)** and Row #4 `design_notes.md`), tactical network partitions or adversarial fork-bombing in federated rooms routinely span $10^4$ to $5 \times 10^4+$ conflicted events.
  - Furthermore, in [`compute_local_auth`](../../../src/state/at.rs#L253-L342), `LocalAuthCache` stores a full `BTreeMap<(EventType, K), LocalAuthEntry<Id, C, K>>` for **every visited event ID** in `cache.map` without any capacity bound or eviction policy, and returns an owned `BTreeMap<(EventType, K), LeanEvent<Id, C, K>>` by cloning `(*entry.event).clone()` on every cache hit (lines 267–272 and 336–339)! Across $10^4+$ events, `LocalAuthCache` grows unboundedly in RAM while deep-cloning `LeanEvent`s per lookup.
  - Running `resolve_iterative_sort` synchronously on a Tokio async worker thread over a $10^4$-event fork will block the executor for数百 milliseconds to seconds, starving heartbeat and C2 message processing unless dispatched via `spawn_blocking` with a bounded memory/event budget.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **OverlayState & Version-Gated Local Auth Semantics**:
  - [`OverlayState::get_event`](../../../src/state/at.rs#L104-L168) formalizes how `IterativeAuthChecks` resolves state keys during Phase 1 (power) and Phase 2 (non-power): consulting `resolved` first, then falling back to `local_auth`, and finally `create_ev` for `m.room.create`.
- **Finding `[Medium]` — Transitive BFS `compute_local_auth` in `V2_1_1` / `V2_2` vs. Immediate `auth_events` in `V2_1`**:
  - In [`compute_local_auth`](../../../src/state/at.rs#L297-L331), when `version` is `V2_1_1` or `V2_2`, the function recursively walks `aev.auth_events` (`current_depth.saturating_add(1)`) and merges `cached_ancestor` entries by minimum `auth_depth`, whereas for `V1`, `V2`, and `V2_1` it only inspects immediate `event.auth_events` (depth 1).
  - Notice the `TODO` at [`src/state/at.rs:324`](../../../src/state/at.rs#L324): `// TODO: confirm the V2.2 auth traversal rule remains aligned with V2.1.1.` Because `compute_local_auth` uses a `FastSet` (`visited`, line 282) during BFS, if two paths in the auth DAG reach the same cached ancestor `aid` at different depths, the first BFS visit wins (`if !visited.insert(aid) { continue; }`) because BFS guarantees shortest-path discovery in unweighted graphs. However, if `cached_ancestor` was populated during an earlier call, its `entry.auth_depth` values are relative to `aid`, which is mathematically sound ($d(e, x) = d(e, \text{aid}) + d(\text{aid}, x)$), *except* that `visited.insert(aid)` does not mark the transitive keys inside `cached_ancestor` as visited — which is handled by `if total_depth < e.get().auth_depth` in the `BTreeMap`. This invariant should be backed by a property test comparing cached vs. uncached `compute_local_auth` across diamond auth DAGs.

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Room Version 1–12 Authorization Fidelity**:
  - [`check_auth_with_context`](../../../src/auth/mod.rs#L533-L800) accurately distinguishes collapsed `StateResVersion` from literal room version strings in `m.room.create` (`room_version_str_or_v1` at lines 386–394), ensuring that:
    - Rule 4 (`m.room.aliases` state_key domain check) applies strictly to Room Versions `"1"` through `"5"` ([`src/auth/mod.rs:648-662`](../../../src/auth/mod.rs#L648-L662)).
    - Rule 11 (`m.room.redaction` domain/PL check) applies strictly to Room Versions `"1"` and `"2"` ([`src/auth/mod.rs:671-688`](../../../src/auth/mod.rs#L671-L688)).
    - Rule 2.4 (`m.room.create` required in `auth_events` for V1–V11, forbidden in V12+ per `MSC4297`) is enforced at [`src/auth/mod.rs:714-754`](../../../src/auth/mod.rs#L714-L754).
- **Finding `[Medium]` — Redaction Rule 11 Event ID Domain Extraction Uses `Display` Formatting (`src/auth/mod.rs:676-681`)**:
  - In [`src/auth/mod.rs:676-681`](../../../src/auth/mod.rs#L676-L681), Rule 11 checks whether the redaction event and the redacted target event share a server domain via:
    ```rust
    let same_domain = event.get_redacts().is_some_and(|target| {
        crate::basespec::rezzy_types::domain_matches(
            target,
            &alloc::format!("{}", event.event_id()),
        )
    });
    ```
    If a homeserver uses integer keys (`Id = u32` or `u64`, as promoted by Track 03!) where `Display` formats `event_id` as `"42"` rather than `"$abc:example.com"`, `domain_matches(target, "42")` will always return `false`! Even with string IDs, `alloc::format!("{}", event.event_id())` allocates a temporary `String` when `event.sender()` (or a domain accessor on `EventId`) could be checked, or `EventLike` should provide an explicit `event_id_str()` / domain check for V1/V2 rooms.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Verification Oracles**:
  - Comprehensive unit and stress tests in [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs), [`tests/unit/test_integer_keys.rs`](../../../tests/unit/test_integer_keys.rs), [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs), and [`tests/stress_unredacted_lounge.rs`](../../../tests/stress_unredacted_lounge.rs) verify batch/streaming parity, `LocalAuthCache` hit equivalence (`c9bb62f`), and integer-keyed resolution.
- **Finding `[Medium]` — Missing Differential Test for Custom `EventContent` vs. `JsonValue` Across Adversarial Auth Fixtures**:
  - While `tests/unit/test_auth.rs` tests `EventContent` default methods on synthetic structs, there is no differential test running the full `tests/critique_data/*.jsonl` and Room Version 1–12 auth rejection suites through a custom non-`JsonValue` `EventContent` implementation to verify that custom `EventContent` implementations cannot drift from `rezzy_json::Value`.
- **Finding `[Low]` — Hard Panic on `extremities.len() > 8` in `compute_merge_bases`**:
  - [`compute_merge_bases`](../../../src/state/at.rs#L775-L791) asserts `extremities.len() <= 8` (`u8` bitmask) and panics if a room has $>8$ forward extremities. While documented in `# Panics`, federation rooms under flood or partition attacks frequently accumulate $>8$ forward extremities; widening the mask to `u64` (up to 64 extremities) or returning a typed `Result` / chunking avoids a panic footgun for homeserver callers.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Trait Ergonomics**:
  - The two-tier trait hierarchy (`DagNode` for topology-only consumers vs. `EventLike` for full auth/resolution, plus `RawEvent` + `ParsedEvent::try_new` for zero-boilerplate wrapping) is well-structured and ergonomic.
- **Finding `[Medium]` — `OverlayState` Stores Owned `BTreeMap<(EventType, K), LeanEvent<Id, C, K>>` Requiring Full `LeanEvent` Clones**:
  - Even though `LocalAuthCache` stores `Arc<LeanEvent<Id, C, K>>` inside [`LocalAuthEntry`](../../../src/state/at.rs#L51-L56), [`compute_local_auth`](../../../src/state/at.rs#L253-L272) dereferences and deep-clones `(*entry.event).clone()` into a fresh `BTreeMap<(EventType, K), LeanEvent<Id, C, K>>` on every single event auth check so [`OverlayState::local_auth`](../../../src/state/at.rs#L90) can return `Option<&LeanEvent<Id, C, K>>` in `StateProvider::get_event`!
  - Changing `OverlayState::local_auth` to hold `BTreeMap<(EventType, K), Arc<LeanEvent<Id, C, K>>>` (or borrowing `&'a LocalAuthCacheMap<Id, C, K>` directly from the cache entry!) would eliminate all `LeanEvent` deep clones and `BTreeMap` reconstructions on `LocalAuthCache` hits (`O(1)` borrow or `Arc::clone`).

---

## 3. Summary of Findings & Severity Classification

| ID | Severity | Persona | Location | Summary |
| :--- | :---: | :--- | :--- | :--- |
| **F-03.1** | `[Critical]` | `critic-compliance` | [`src/auth/mod.rs:85-101,533-800`](../../../src/auth/mod.rs#L85-L101), [`src/basespec/rezzy_types.rs:1662,2148`](../../../src/basespec/rezzy_types.rs#L2148) | Cross-room `MSC4307` Rule 2.5 (`ForeignRoomEvent`) is opt-in (`room_id: Option<RoomId>`) and missing from `EventLike` / `check_auth_with_context` (`rezzy_docs_public_safety_audit.md` Row #14, P0 #1). |
| **F-03.2** | `[Critical]` | `critic-perf`, `critic-compliance` | [`docs/architecture.md:67-84,202-211`](../../../docs/architecture.md#L67-L84), [`src/state/at.rs:253-342`](../../../src/state/at.rs#L253-L342) | Synchronous "I/O Sandwich" pre-fetch and unbounded `LocalAuthCache` risk OOM and Tokio executor starvation on $10^4+$ event adversarial forks (`rezzy_docs_public_safety_audit.md` Row #2 & Row #4). |
| **F-03.3** | `[High]` | `critic-eng-lead`, `critic-dx-integrator` | [`src/basespec/rezzy_types.rs:2537-2643`](../../../src/basespec/rezzy_types.rs#L2537-L2643) | `EventContent` provides fail-open default implementations (`false`/`None`/`true`) for malformed room version, V10+ non-integer PLs, and V12 creator validation (`rezzy_docs_public_safety_audit.md` Row #4). |
| **F-03.4** | `[High]` | `critic-compliance`, `critic-dx-integrator` | [`src/basespec/rezzy_types.rs:2663-2700`](../../../src/basespec/rezzy_types.rs#L2663-L2700) | `EventVerifier<Id>` default methods all return `Ok(())`, silently skipping hash and Ed25519 signature verification if a method is omitted. |
| **F-03.5** | `[Medium]` | `critic-perf`, `critic-dx-integrator` | [`src/state/at.rs:90,267-272,336-341`](../../../src/state/at.rs#L267-L272) | `compute_local_auth` deep-clones every `LeanEvent` out of `Arc<LeanEvent>` into a new `BTreeMap` on every `LocalAuthCache` hit instead of borrowing or sharing `Arc`. |
| **F-03.6** | `[Medium]` | `critic-federation-interop` | [`src/auth/mod.rs:676-681`](../../../src/auth/mod.rs#L676-L681) | Redaction Rule 11 (V1–V2) formats `event.event_id()` via `Display` to extract the server domain, which breaks when `Id` is an integer (`u32`/`u64`). |
| **F-03.7** | `[Medium]` | `critic-pm` | [`docs/design_notes.md:17,174-190`](../../../docs/design_notes.md#L174-L190) | Code examples in `docs/design_notes.md` use outdated 6-argument `resolve_iterative_sort` signature and `compute_state_at_streaming` name. |
| **F-03.8** | `[Low]` | `critic-redteam-qa` | [`src/state/at.rs:788-791`](../../../src/state/at.rs#L788-L791) | `compute_merge_bases` panics when `extremities.len() > 8` (`u8` mask) instead of using `u64` (up to 64 extremities) or returning a `Result`. |

---

## 4. Actionable Recommendations for Stage B Remediation Tracks

1. **P0 Remediation — Make `MSC4307` Rule 2.5 Unconditionally Fail-Closed Across `EventLike` and `check_auth_with_context` (Stage B Track 13 / P0 Item #1)**:
   - Add `fn room_id(&self) -> Option<&str>` to [`EventLike`](../../../src/basespec/rezzy_types.rs#L1662) and [`RawEvent`](../../../src/basespec/rezzy_types.rs#L1893).
   - Enforce `AuthError::ForeignRoomEvent` directly inside [`check_auth_with_context`](../../../src/auth/mod.rs#L734-L770) and require a mandatory room context token (or non-optional `RoomId`) so cross-room `auth_events` citations are unconditionally rejected.
2. **Harden `EventContent` and `EventVerifier` Against Fail-Open Defaults (Stage B Track 13/17)**:
   - Remove the permissive default bodies from `has_malformed_room_version`, `additional_creators_are_valid`, `find_non_integer_scalar_pl`, `find_non_integer_map_pl`, `has_non_integer_users_pl`, and `has_user_in_users` on [`EventContent`](../../../src/basespec/rezzy_types.rs#L2537-L2643) so custom implementors are forced by the compiler to wire all syntactic validation checks.
   - Remove the `Ok(())` defaults from [`EventVerifier<Id>`](../../../src/basespec/rezzy_types.rs#L2663-L2700) (or provide a separate `NoopVerifier` for tests) so production verifiers cannot accidentally omit a verification step.
3. **Eliminate `Arc<LeanEvent>` Deep-Cloning in `compute_local_auth` & Bound `LocalAuthCache` (Stage B Track 18)**:
   - Store `Arc<LeanEvent<Id, C, K>>` in `OverlayState::local_auth` (or borrow `&'a LocalAuthCacheMap<Id, C, K>` from `LocalAuthCache`) in [`src/state/at.rs:90,253-342`](../../../src/state/at.rs#L253-L342) to turn cache hits into zero-event-clone lookups, and document bounded `spawn_blocking` + subgraph size caps in [`docs/architecture.md`](../../../docs/architecture.md).
