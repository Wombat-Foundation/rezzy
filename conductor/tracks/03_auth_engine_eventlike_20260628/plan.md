# Implementation Plan: Version-Aware Auth Engine, `EventLike` Trait & Streaming Auth Cache (`v0.2.0`)

## Phase 1: Modular Decomposition, Integer-Keyed Generics & Version-Aware `auth_types_for_event` [checkpoint: deb92fe]

- [x] Task: Decompose monolithic `src/lib.rs` into domain modules and harden baseline auth checks 34fde0c
  - [x] Split `src/lib.rs` and `src/main.rs` into `src/auth/`, `src/resolve.rs`, `src/sorting.rs`, `src/state_at.rs`, `src/subgraph.rs`, and `src/types.rs` (`34fde0c`)
  - [x] Restrict member power-level checks to kick/ban/unban, enforce exact-integer power levels, and implement `auth_types_for_event` (`34fde0c`)
- [x] Task: Migrate `LeanEvent` and resolution pipeline to generic `Id: EventId` integer/string keys 195ecca
  - [x] Parameterize `LeanEvent<Id>`, `SharedState<Id>`, and `resolve_lean` over generic `EventId` supporting `u32`, `u64`, and `String` (`195ecca`)
  - [x] Refine generic API trait bounds, public error types, and release test profiles (`83967d0`, `eefafa8`, `c86b7f3`)
- [x] Task: Make `auth_types_for_event` room-version-aware for `MSC4297` (V2.1+) and implement batch `compute_state_at` deb92fe
  - [x] Update `auth_types_for_event` to accept `StateResVersion` and omit `m.room.create` for V2.1+ per `MSC4297` (`f1b23e7`, merged in `deb92fe`)
  - [x] Implement high-performance `compute_state_at_batch` (`65b627b`), deduplicate the state-after walk into `run_state_pipeline` (`b3dd913`, `78174e6`, `6e14836`), and implement topological reference consuming to avoid the `Arc::make_mut` clone trap (`c304630`)

## Phase 2: V2 Power-Event Routing, Spec-Compliant Auth Fixes & `MSC4289` Creator Hardening [checkpoint: cb6b58a]

- [x] Task: Correct V2 vs. V2.1 power-event routing and Step 2 conflicted auth checks 4e281f1
  - [x] Route power events accurately by room version (`5b766f2`, `4e281f1`) and add V2 vs. V2.1 member power-event routing regression tests (`2ae713d`, `279efb2`)
  - [x] Enforce spec-compliant conflicted auth event validation in Step 2 power phase restricted to `m.room.power_levels` and `m.room.join_rules` (`1ef1301`, `765a956`)
- [x] Task: Align membership transition rules, forbid self-bans, and remove non-spec auth heuristics 91abf6e
  - [x] Align invite transition authorization to the Matrix spec and remove the non-spec Previous Sender Rule and event-type whitelist (`eac80c2`, `014a937`, `96ab609`)
  - [x] Require only `ban_pl` (not `kick_pl`) for `unban` (`512c439`), prevent membership auth bypass for non-members (`0abe086`), and validate `event_type` + forbid self-bans (`91abf6e`, `5767d0d`, merged in `cb6b58a`)
- [x] Task: Make `src/auth/` version-aware with `MSC4289` `i64::MAX` creator privileges and `basespec` extraction 5cb835e
  - [x] Use `i64::MAX` for creator power levels to prevent integer overflow exploits (`a56a6b8`) and gate `additional_creators` on V2.1+ (`a27bb63`, `5cb835e`)
  - [x] Extract `types` and `event_types` into `src/basespec/` with `version_props` (`3f62797`, `0bc3e53`), migrate state map keys to `(String, String)` (`180917f`, `159ae88`), and add `warn_unexpected_auth_events()` (`e8e3a59`)

## Phase 3: Streaming State Reconstruction, `LocalAuthCache` Hoisting & Zero-Copy `SortContext` (`v0.2.0`) [checkpoint: 6268aab]

- [x] Task: Implement frontier-bounded `compute_state_at_streaming` and hoist `LocalAuthCache` 30ca472
  - [x] Hoist `LocalAuthCache` across resolution invocations to amortize auth context lookups (`ab8bf2f`, `8810dbd`, `e37e6d9`)
  - [x] Implement `compute_state_at_streaming` to bound peak memory to active DAG frontier width with batch/streaming parity tests (`cbe0053`, `01e03e4`, `f74a771`, merged in `30ca472`)
- [x] Task: Eliminate `O(N)` event cloning via zero-copy `SortContext` and memoized BFS auth walks 2a26709
  - [x] Implement zero-copy `SortContext` (`KahnSortInputs`) and stack-safe iterative DFS in `src/resolve/sorting.rs` (`64feeec`, `03a0d3d`, `fbe90d4`, `132f858`, merged in `2a26709`)
  - [x] Enable pure memoized BFS for V2.1.1 transitive auth context and eliminate $O(N)$ auth context iteration (`cd0c1b3`, `58c29ba`, `60dd404`, tagged `v0.2.0` at `6268aab`)

## Phase 4: `EventContent`, `EventLike` / `RawEvent` Trait Hierarchy & Trivial-Conflict Fast Path [checkpoint: 71e2f3e]

- [x] Task: Extract generic `DagNode` and `EventContent` traits for zero-JSON-parsing hot paths ecb07fe
  - [x] Extract `DagNode` trait for generic DAG traversal (`a196b41`) and remove intermediate `TypedContent` enum for zero allocation (`08c7837`, `8dd936f`, `add27da`)
  - [x] Extract `EventContent` trait on `LeanEvent<Id, C>` with blanket `serde_json::Value` support and finalize generic bounds (`ecb07fe`, `68c98ac`, `1e5db9a`)
- [x] Task: Implement `EventLike`, `RawEvent`, and `ParsedEvent` zero-boilerplate adapters for the auth engine a83ec17
  - [x] Define `EventLike` as a supertrait of `DagNode` (`7b24749`), migrate the auth engine (`src/auth/mod.rs`, `src/auth/user.rs`) to `EventLike` trait methods (`6e45f95`, `dcba8ac`, `0cce801`), and return `Cow<str>` from `event_type()` (`0e2c709`)
  - [x] Add `EventLike::Content` associated type (`01a6b61`), implement `RawEvent` + `ParsedEvent::try_new` adapters rejecting malformed member events (`e4746da`, `b189ffc`, `faa296d`, merged in `a83ec17`)
- [x] Task: Add single-key non-power trivial-conflict fast path and `OverlayState` constant optimizations 71e2f3e
  - [x] Cache `event_type` in `check_auth` and optimize subgraph intersection (`1f7f1e1`, `2aa39bf`, `0709b1c`)
  - [x] Implement the trivial-conflict fast path in [`src/state/at.rs`](../../../src/state/at.rs), extract `is_power_event`, and constify `OverlayState` strings (`71e2f3e`)

---

## History & Audit Traceability

| Commit SHA | Date | Core Files Modified | Verification / Test Files | Linked Docs & Public-Safety Audit Findings |
| :--- | :--- | :--- | :--- | :--- |
| `34fde0c` | 2026-06-27 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs), [`tests/unit/test_lib.rs`](../../../tests/unit/test_lib.rs) | Modular decomposition of `src/lib.rs` into `auth`, `resolve`, `sorting`, `state_at` |
| `195ecca` | 2026-06-27 | [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | [`tests/unit/test_integer_keys.rs`](../../../tests/unit/test_integer_keys.rs) | Generic integer-keyed `EventId` (`u32`, `u64`) migration (`83967d0`; [`docs/design_notes.md`](../../../docs/design_notes.md)) |
| `deb92fe` | 2026-06-28 | [`src/auth/mod.rs`](../../../src/auth/mod.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | Version-aware `auth_types_for_event` omitting `m.room.create` for V2.1+ (`f1b23e7`) |
| `c304630` | 2026-06-28 | [`src/state/at.rs`](../../../src/state/at.rs) | [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | Batch `compute_state_at_batch` (`65b627b`) & topological reference consuming |
| `91abf6e` | 2026-06-28 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs), [`tests/stress_unredacted_lounge.rs`](../../../tests/stress_unredacted_lounge.rs) | V2 power event routing (`4e281f1`), self-ban rejection (`5767d0d`), merge `cb6b58a` |
| `5cb835e` | 2026-06-29 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/basespec/version_props.rs`](../../../src/basespec/version_props.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | `MSC4289` version-aware creator privileges with `i64::MAX` overflow guard (`a56a6b8`, `3f62797`) |
| `ecb07fe` | 2026-06-29 | [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | Generic `EventContent` trait (`68c98ac`); see **High (Heuristic Bypass)** in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #4, [`docs/design_notes.md`](../../../docs/design_notes.md)) |
| `30ca472` | 2026-06-29 | [`src/state/at.rs`](../../../src/state/at.rs), [`src/auth/mod.rs`](../../../src/auth/mod.rs) | [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs), [`tests/stress_large_rooms.rs`](../../../tests/stress_large_rooms.rs) | `compute_state_at_streaming` (`cbe0053`) & `LocalAuthCache` (`ab8bf2f`); see **Critical (OOM / Starvation)** in [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #2, [`docs/architecture.md`](../../../docs/architecture.md)) |
| `2a26709` | 2026-06-29 | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | Zero-copy `SortContext` & stack-safe DFS (`64feeec`, tagged `v0.2.0` at `6268aab`) |
| `0cce801` | 2026-07-01 | [`src/auth/mod.rs`](../../../src/auth/mod.rs), [`src/raw_event.rs`](../../../src/raw_event.rs) | [`tests/unit/test_auth.rs`](../../../tests/unit/test_auth.rs) | `EventLike` supertrait (`7b24749`), `RawEvent`/`ParsedEvent` (`e4746da`, `b189ffc`, merged in `a83ec17`) |
| `71e2f3e` | 2026-07-02 | [`src/state/at.rs`](../../../src/state/at.rs), [`src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) | [`tests/unit/test_state_at.rs`](../../../tests/unit/test_state_at.rs) | Trivial-conflict fast path, `is_power_event` extraction, and `OverlayState` const strings |
