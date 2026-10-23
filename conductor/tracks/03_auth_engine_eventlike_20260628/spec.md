# Specification: Version-Aware Auth Engine, `EventLike` Trait & Streaming Auth Cache (`v0.2.0`)

## 1. Overview & Historical Context

Track `03_auth_engine_eventlike_20260628` traces the architectural transformation of `rezzy` into a modular, zero-copy, generic library across the `v0.2.0` epoch (`4abfb43..6268aab`, May 20–June 30, 2026, plus the immediate `EventLike` and trivial-conflict merges `0cce801`, `a83ec17`, `71e2f3e` on July 1–2, 2026).

Prior to this track, `rezzy` was a monolithic `src/lib.rs` + `src/main.rs` codebase keyed exclusively by heap-allocated `String` event IDs and `serde_json::Value` payloads. To support high-throughput Rust homeservers (such as Continuwuity and Tuwunel) that represent events using 64-bit integer `ShortEventId`s and pre-parsed or zero-copy raw JSON buffers, Track 03 executed five foundational engineering shifts documented in [`docs/architecture.md`](../../../docs/architecture.md) and [`docs/design_notes.md`](../../../docs/design_notes.md):
1. **Modular Crate Decomposition & Version-Aware Auth (`34fde0c`, `f1b23e7`, `deb92fe`, `3f62797`, `5cb835e`)**: Split the 3,500-line `src/lib.rs` into dedicated domain modules (`src/auth/`, `src/resolve/`, `src/state/`, `src/basespec/`), implementing a spec-compliant, room-version-aware PDU authorization engine (`check_auth`, `auth_types_for_event`).
2. **V2 vs. V2.1 Power-Event Routing & Auth Hardening (`4e281f1`, `1ef1301`, `765a956`, `91abf6e`, `5767d0d`, `cb6b58a`)**: Corrected critical divergences between Room Version 2–11 (V2) and Room Version 12 (V2.1 / `MSC4297`) power-event classification, enforced self-ban rejection (`sender == state_key`), removed non-spec previous-sender and event-type whitelists (`014a937`, `96ab609`), and used `i64::MAX` for `MSC4289` room creator privileges to prevent integer overflow exploits (`a56a6b8`).
3. **Generic `EventId`, `EventContent`, and `EventLike` / `RawEvent` Traits (`195ecca`, `83967d0`, `ecb07fe`, `7b24749`, `0cce801`, `e4746da`, `a83ec17`)**: Decoupled the resolution and auth engines from `String` and `serde_json::Value`, allowing callers to resolve over `u32`/`u64` integer IDs and custom `EventContent` / `EventLike` types without JSON parsing on the hot path.
4. **Batch & Streaming State Reconstruction with `LocalAuthCache` (`65b627b`, `6e14836`, `ab8bf2f`, `cbe0053`, `30ca472`)**: Introduced `compute_state_at_batch` and `compute_state_at_streaming` (bounding memory to the active DAG frontier width) and hoisted `LocalAuthCache` across resolution invocations.
5. **Zero-Copy `SortContext` & Trivial-Conflict Fast Path (`c304630`, `64feeec`, `2a26709`, `71e2f3e`)**: Eliminated `O(N)` `LeanEvent` cloning via borrowed references in `SortContext`, avoided the `Arc::make_mut` deep-clone trap via topological reference consuming (`c304630`), and added a fast path in `src/state/at.rs` (`71e2f3e`) for single-key non-power conflicts.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Matrix Spec / MSC Reference | Functional Description | Implementation & Verification |
| :--- | :--- | :--- | :--- |
| **FR-03.1** | Matrix Room v1–v12 Auth Rules & `MSC4297` (`auth_types_for_event`) | Provide a version-aware `auth_types_for_event` and `check_auth` engine that omits `m.room.create` from required `auth_events` in V2.1+ (`MSC4297`), enforces `MSC4289` infinite (`i64::MAX`) creator power levels in V12, forbids self-bans, and validates invite/membership transitions. | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/auth/user.rs`](../../../src/auth/user.rs) (`f1b23e7`, `deb92fe`, `eac80c2`, `014a937`, `512c439`, `0abe086`, `5767d0d`, `a56a6b8`, `5cb835e`) |
| **FR-03.2** | State Res V2 vs. V2.1 Power-Event Routing & Step 2 Auth Check | Route `m.room.member` leave/ban events and power events according to room version, and restrict V2.1 Step 2 conflicted auth checks to `m.room.power_levels` and `m.room.join_rules`. | [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) (`4e281f1`, `1ef1301`, `765a956`, `91abf6e`, `2ae713d`, `cb6b58a`) |
| **FR-03.3** | Generic `EventId`, `EventContent`, `DagNode`, and `EventLike` Abstractions | Parameterize `LeanEvent<Id, C, K>`, `SharedState<Id, K>`, `resolve_iterative_sort`, and `check_auth` over `Id: EventId` (`String`, `u32`, `u64`), `C: EventContent`, and `E: EventLike` (supertrait of `DagNode` with `RawEvent` / `ParsedEvent` adapters). | [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs), [`src/raw_event.rs`](../../../src/raw_event.rs), [`src/auth/mod.rs`](../../../src/auth/mod.rs) (`195ecca`, `83967d0`, `a196b41`, `ecb07fe`, `7b24749`, `0cce801`, `e4746da`, `a83ec17`) |
| **FR-03.4** | Batch & Frontier-Bounded Streaming State Reconstruction | Reconstruct state across an entire room DAG via `compute_state_at_batch` and `compute_state_at_streaming`, yielding states via callback and reusing `LocalAuthCache` across forks. | [`src/state/at.rs`](../../../src/state/at.rs) (`65b627b`, `b3dd913`, `78174e6`, `c304630`, `ab8bf2f`, `cbe0053`, `30ca472`) |
| **FR-03.5** | Zero-Copy `SortContext` & Trivial-Conflict Fast Path | Perform Kahn and mainline sorting over borrowed event references (`SortContext`) with stack-safe iterative DFS, and bypass full iterative sort when a fork only disagrees on a single non-power state key (`71e2f3e`). | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs), [`src/state/at.rs`](../../../src/state/at.rs) (`64feeec`, `2a26709`, `71e2f3e`) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Synchronous "I/O Sandwich" Over `async` Lazy-Loading (`docs/architecture.md`)**:
   - *Context*: Homeservers store events in async databases (Postgres, RocksDB/MDBX). A naive state resolution library might expose an `async fn resolve(...)` that fetches missing `auth_events` one by one.
   - *Decision*: As formalized in [`docs/architecture.md`](../../../docs/architecture.md) (lines 49–89), async lazy-loading during resolution causes the **N+1 Query Problem** (serializing 50 sequential DB round-trips) and couples CPU sorting to database latency. Instead, `rezzy` enforces a strict synchronous "I/O Sandwich": the homeserver bulk-fetches the **Auth Difference** ($\text{auth}(C) - \text{auth}(U)$) in 1–3 queries (or 1 query via pre-computed `RoaringTreemap` transitive closure indexes), passes a self-contained `HashMap` to `rezzy`'s `#![no_std]` CPU layer, and persists the result asynchronously.
2. **Trait-Based `EventContent` & `EventLike` Over Enum `TypedContent` (`08c7837` -> `add27da`, `ecb07fe`, `0cce801`)**:
   - *Context*: Commits `08c7837` and `8dd936f` (`2026-06-28`) experimented with a concrete `TypedContent` enum to replace `serde_json::Value`.
   - *Decision*: Commit `add27da` ("remove TypedContent completely for zero-allocation") rejected the fixed enum because converting a homeserver's native PDU representation into an intermediate `TypedContent` enum still required per-event allocation and copying. Instead, `ecb07fe` introduced the `EventContent` trait and `7b24749`/`0cce801`/`e4746da` introduced `EventLike` + `RawEvent` + `ParsedEvent`, allowing zero-boilerplate borrowing directly from a homeserver's existing structs or raw JSON bytes.
3. **Topological Reference Consuming to Defeat `Arc::make_mut` Clones (`c304630`)**:
   - *Context*: During DAG state reconstruction (`compute_state_at`), cloning `SharedState` (`Arc<OrdMap<...>>`) for every child event kept `Arc::strong_count > 1`, forcing `Arc::make_mut` to deep-copy the state map when mutating along linear chains.
   - *Decision*: Commit `c304630` implemented topological reference counting so the *last* child consuming a parent's state takes ownership of the `SharedState` when `strong_count == 1`, mutating it in place in $O(1)$ without cloning.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #2 `architecture.md` and Row #4 `design_notes.md`):

> [!WARNING]
> **Public-Safety Audit Finding 1 — Synchronous I/O Sandwich Pre-Fetch OOM & Executor Starvation (`docs/architecture.md`, Row #2: Critical)**:
> While pre-materializing $\text{auth}(C) - \text{auth}(U)$ into a `HashMap<EventId, LeanEvent>` is optimal for normal forks (10–50 events), in adversarial or partition-recovery scenarios (e.g., an emergency dispatch room reconnecting after a prolonged tactical network split with $10^4+$ conflicted events), materializing the entire subgraph eagerly in RAM before invoking a synchronous CPU-bound function on an async executor thread risks **OOM termination** or **Tokio worker thread starvation** if not bounded by a semaphore/blocking pool and memory budget.

> [!IMPORTANT]
> **Public-Safety Audit Finding 2 — Custom `EventContent` Trait Implementation Drift (`docs/design_notes.md`, Row #4: High)**:
> [`docs/design_notes.md`](../../../docs/design_notes.md) invites homeservers to implement `EventContent` and `EventLike` directly on their own types to skip JSON parsing. However, Matrix authorization rules (especially Room Version 10–12 integer vs. float power levels, `MSC4289` `additional_creators`, and malformed field rejection) depend on exact extraction semantics. If a downstream homeserver's custom `EventContent` implementation silently defaults a malformed field to `None` instead of flagging `has_malformed_fields()`, it can bypass syntactic rejection rules (`b189ffc`).

- **Integer Overflow Hardening on Creator Power Levels (`a56a6b8`)**:
  - Room Version 12 (`MSC4289`) grants room creators an "infinite" power level above any integer expressible in `m.room.power_levels` (`[-2^53+1, 2^53-1]`). `rezzy` represents creator PL as `i64::MAX` (`MAX_POWER_LEVEL`) and uses saturating comparisons so an attacker cannot overflow `i64` arithmetic.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Version-Aware Auth & Power-Event Routing (`tests/unit/test_auth.rs`, `tests/unit/test_lib.rs`)**:
   - Verified by unit tests covering `auth_types_for_event` omitting `m.room.create` in V2.1+ (`f1b23e7`), V2 vs. V2.1 member power-event routing (`2ae713d`), self-ban rejection (`5767d0d`), unban requiring only `ban_pl` (`512c439`), non-member auth bypass prevention (`0abe086`), and `i64::MAX` creator power levels (`a56a6b8`, `5cb835e`).
2. **Generic `EventId`, `EventContent` & `EventLike` Adapters (`tests/unit/test_integer_keys.rs`, `tests/unit/test_auth.rs`)**:
   - Verified by integer-keyed resolution tests (`195ecca`), `EventContent` default method coverage (`1e5db9a`, `5ca61a3`), and `ParsedEvent::try_new` / `EventLike` malformed member event rejection tests (`b189ffc`, `faa296d`).
3. **Streaming State Reconstruction & Unredacted Lounge Oracles (`tests/stress_unredacted_lounge.rs`, `tests/unit/test_state_at.rs`)**:
   - Verified by parity tests asserting `compute_state_at_streaming` == `compute_state_at_batch` == `compute_state_at` (`01e03e4`, `e37e6d9`), falsifiable `LocalAuthCache` hit tests (`c9bb62f`), and real-world partial-join / subgraph tests on the unredacted lounge DAG (`8d81294`, `1a1537f`).
