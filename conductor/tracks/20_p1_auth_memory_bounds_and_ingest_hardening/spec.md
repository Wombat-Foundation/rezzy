# Specification: Track 20 — P1 I/O Sandwich Subgraph Bounds, LocalAuthCache Zero-Clone, Ingest Hash Verification & Redaction Rule 11

## 1. Overview & Finding Traceability Matrix

Track 20 remediates 9 findings (`F-03.2`, `F-03.5`, `F-03.6`, `F-03.7`, `F-03.8`, `F-06-03`, `F-06-04`, `F-06-05`, `F-06-06`) originating from the multi-perspective architectural reviews of Track 03 ([`../03_auth_engine_eventlike_20260628/review.md`](../03_auth_engine_eventlike_20260628/review.md)) and Track 06 ([`../06_spec_compliance_v1_v12_20260702/review.md`](../06_spec_compliance_v1_v12_20260702/review.md)). It establishes memory and capacity bounds on `LocalAuthCache` and documents `spawn_blocking` / subgraph budgets for the "I/O Sandwich" model (`F-03.2`), eliminates `LeanEvent` deep-cloning on `LocalAuthCache` hits (`F-03.5`), fixes V1–V2 Redaction Rule 11 domain extraction for integer `Id`s (`F-03.6`), widens `compute_merge_bases` beyond 8 extremities (`F-03.8`), enforces mandatory `hashes.sha256` verification at ingest and removes `.expect()` panics in `canonical_redacted_json` (`F-06-03`), removes silent `Ok(())` defaults from `EventVerifier` (`F-06-04`), eliminates intermediate `BTreeMap` allocations in `check_power_levels_rules` (`F-06-06`), and synchronizes `docs/design_notes.md` (`F-03.7`), `docs/spec_coverage.csv`, and `docs/spec_audit.md` (`F-06-05`).

| Finding ID | Severity | Persona(s) | Source File / Lines | Root Cause & Impact |
| :--- | :---: | :--- | :--- | :--- |
| **`F-03.2`** | `[Critical]` | `critic-perf`, `critic-compliance` | [`docs/architecture.md:67-84,202-211`](../../../docs/architecture.md#L67-L84), [`src/state/at.rs:253-342`](../../../src/state/at.rs#L253-L342) | Synchronous "I/O Sandwich" pre-fetch and unbounded `LocalAuthCache` risk OOM and Tokio async executor starvation on $10^4+$ event adversarial forks (`rezzy_docs_public_safety_audit.md` Row #2 & Row #4). |
| **`F-03.5`** | `[Medium]` | `critic-perf`, `critic-dx-integrator` | [`src/state/at.rs:90,267-272,336-341`](../../../src/state/at.rs#L267-L272) | `compute_local_auth` dereferences and deep-clones every `LeanEvent` out of `Arc<LeanEvent>` into a new `BTreeMap` on every `LocalAuthCache` hit instead of borrowing or storing `Arc<LeanEvent>` in `OverlayState::local_auth`. |
| **`F-03.6`** | `[Medium]` | `critic-federation-interop` | [`src/auth/mod.rs:676-681`](../../../src/auth/mod.rs#L676-L681) | Redaction Rule 11 (Room V1–V2) formats `event.event_id()` via `Display` (`alloc::format!("{}", event.event_id())`) to extract the server domain, breaking integer `Id`s (`u32`/`u64`) and allocating unnecessarily. |
| **`F-03.7`** | `[Medium]` | `critic-pm` | [`docs/design_notes.md:17,174-190`](../../../docs/design_notes.md#L174-L190) | Code snippets in `docs/design_notes.md` reference outdated 6-argument `resolve_iterative_sort` and `compute_state_at_streaming` signatures instead of `IterativeInputs::new` and `StreamingInputs::try_compute`. |
| **`F-03.8`** | `[Low]` | `critic-redteam-qa` | [`src/state/at.rs:788-791`](../../../src/state/at.rs#L788-L791) | `compute_merge_bases` asserts `extremities.len() <= 8` (`u8` bitmask) and panics when a room accumulates $>8$ forward extremities instead of using `u64` / dynamic bitset or returning a `Result`. |
| **`F-06-03`** | `[High]` | `critic-federation-interop`, `critic-formal-crypto` | [`src/basespec/rezzy_types.rs:920-960,1040-1045,1457-1462`](../../../src/basespec/rezzy_types.rs#L920-L960) | `ingest_events` only calls `verify_content_hash` `if pdu.get(FIELD_HASHES).is_some()`, allowing stripped federation PDUs to bypass content-hash verification; `canonical_redacted_json` (line 1040) panics via `.expect()` on non-canonical v6+ numbers; stale `reference_hash` doc comment claims relaxed number tolerance. |
| **`F-06-04`** | `[High]` | `critic-dx-integrator`, `critic-compliance` | [`src/basespec/rezzy_types.rs:2645-2665`](../../../src/basespec/rezzy_types.rs#L2645-L2665), [`src/auth/mod.rs:491-502,1894-1904`](../../../src/auth/mod.rs#L491-L502) | `EventVerifier` trait methods all default to `Ok(())`, and `validate_forward_extremity` / `check_auth` silently skip signature and 3PI/restricted-join verification if a method is omitted by the implementor. |
| **`F-06-05`** | `[Medium]` | `critic-pm`, `critic-compliance` | [`docs/spec_coverage.csv:1-36`](../../../docs/spec_coverage.csv#L1-L36), [`docs/spec_audit.md:1-6,128-136`](../../../docs/spec_audit.md#L1-L6) | `docs/spec_coverage.csv` marks 31/35 rows `full` despite top-of-file V1-only disclaimers in `docs/spec_audit.md`, delegated Rule 5.2 signature checks, and open `# TODO(compliance)` PDU field checks. |
| **`F-06-06`** | `[Low]` | `critic-perf` | [`src/auth/mod.rs:1076-1140`](../../../src/auth/mod.rs#L1076-L1140) | `check_power_levels_rules` collects zero-allocation visitor callbacks (`visit_event_power_levels`, `visit_notification_power_levels`, `visit_user_power_levels`) into 6 temporary heap-allocated `BTreeMap<&str, i64>` instances per PL event check. |

---

## 2. Functional & Architectural Remediation Requirements

### 2.1 `LocalAuthCache` Zero-Clone, Capacity Bounds & `compute_merge_bases` Scaling (`F-03.2`, `F-03.5`, `F-03.8`)
1. **Zero-Clone `OverlayState::local_auth` & Bounded `LocalAuthCache` (`F-03.2`, `F-03.5`)**:
   - Refactor [`OverlayState::local_auth`](../../../src/state/at.rs#L90) and [`compute_local_auth`](../../../src/state/at.rs#L253-L342) (`lines 267-272, 336-341`) so `OverlayState` stores `BTreeMap<(EventType, K), Arc<LeanEvent<Id, C, K>>>` (or borrows `&'a BTreeMap<(EventType, K), LocalAuthEntry<Id, C, K>>` directly from `LocalAuthCache`), completely eliminating `(*entry.event).clone()` deep-clones on cache hits (`F-03.5`).
   - Add a configurable `max_entries: usize` capacity bound (defaulting to a safe ceiling, e.g., `4_096`) to `LocalAuthCache` in [`src/state/at.rs:71-84,253-342`](../../../src/state/at.rs#L253-L342) and update [`docs/architecture.md:67-84,202-211`](../../../docs/architecture.md#L67-L84) to replace the `500–700` event assumption with realistic $10^4+$ adversarial fork sizing, explicit `tokio::task::spawn_blocking` offloading guidelines, and subgraph admission budgets (`F-03.2`).
2. **Eliminate 8-Extremity Panic in `compute_merge_bases` (`F-03.8`)**:
   - In [`src/state/at.rs:775-791`](../../../src/state/at.rs#L775-L791), widen the extremity bitmask from `u8` (8 extremities) to `u64` (up to 64 extremities) with a dynamic bitset / chunked fallback (or fallible `Result`) when `extremities.len() > 64`, eliminating the `assert!(extremities.len() <= 8)` panic.

### 2.2 Ingest Hash Enforcement, Fallible Canonical Redaction & Mandatory `EventVerifier` (`F-06-03`, `F-06-04`)
1. **Enforce Mandatory `hashes.sha256` at Ingest & Fallible `canonical_redacted_json` (`F-06-03`)**:
   - In [`ingest_events`](../../../src/basespec/rezzy_types.rs#L1457-L1462) (`src/basespec/rezzy_types.rs:1457-1462`), require the `hashes` object (`hashes.sha256`) to be present on federation PDUs before invoking `verify_content_hash`, rejecting stripped PDUs that omit `hashes` with `IngestError`.
   - In [`canonical_redacted_json`](../../../src/basespec/rezzy_types.rs#L1040-L1045) (`src/basespec/rezzy_types.rs:1040-1045`), replace the panicking `.expect(...)` on `write_redacted_canonical` with a fallible `try_canonical_redacted_json -> Result<String, CanonicalJsonError>` (and make `canonical_redacted_json` non-panicking or deprecated), and update the stale doc comment on `reference_hash` (`src/basespec/rezzy_types.rs:920-960`) to accurately state that v6+ strict canonical number bounds ($\pm(2^{53}-1)$, no floats) are enforced.
2. **Remove Silent No-Op `Ok(())` Defaults from `EventVerifier` (`F-06-04`)**:
   - In [`src/basespec/rezzy_types.rs:2645-2665`](../../../src/basespec/rezzy_types.rs#L2645-L2665), remove the default `Ok(())` bodies from `EventVerifier` trait methods (`verify_event_id_hash`, `verify_signatures`, `verify_content_hash`, `verify_third_party_invite`, `verify_join_authorised_via_users_server`), providing an explicit `NoopEventVerifier` struct for unit tests that intentionally skip cryptographic checks, and tighten [`src/auth/mod.rs:491-502,1894-1904`](../../../src/auth/mod.rs#L491-L502) documentation and verification flow.

### 2.3 Integer-Safe Redaction Rule 11, Zero-Alloc Power-Level Diffing & Doc Synchronization (`F-03.6`, `F-03.7`, `F-06-05`, `F-06-06`)
1. **Fix V1–V2 Redaction Rule 11 Domain Extraction for Integer `Id`s (`F-03.6`)**:
   - In [`src/auth/mod.rs:676-681`](../../../src/auth/mod.rs#L676-L681), replace `alloc::format!("{}", event.event_id())` with a trait method on `EventLike` (e.g., `event.sender()` domain fallback or `event.event_id_domain()` / `event_id_str()`) so V1/V2 redaction domain matching works correctly when `Id` is `u32`/`u64` and avoids heap-allocating a formatted `String` on every redaction check.
2. **Eliminate Intermediate `BTreeMap` Allocations in `check_power_levels_rules` (`F-06-06`)**:
   - Refactor [`check_power_levels_rules`](../../../src/auth/mod.rs#L1076-L1140) (`src/auth/mod.rs:1076-1140`) to diff old and new `events`, `notifications`, and `users` power levels using direct point lookups on `EventContent` (or streaming visitor comparisons) without allocating 6 intermediate `BTreeMap<&str, i64>` instances per PL event.
3. **Synchronize `docs/design_notes.md`, `docs/spec_coverage.csv` & `docs/spec_audit.md` (`F-03.7`, `F-06-05`)**:
   - Update [`docs/design_notes.md:17,174-190`](../../../docs/design_notes.md#L174-L190) to use `IterativeInputs::new(...)` and `StreamingInputs::try_compute` (`F-03.7`).
   - Recalibrate [`docs/spec_coverage.csv:1-36`](../../../docs/spec_coverage.csv#L1-L36) and [`docs/spec_audit.md:1-6,128-136`](../../../docs/spec_audit.md#L1-L6) so delegated HS/crypto checks (such as Restricted Join Rule 5.2 and `MSC0501` HTTP wiring) and room-version support status are accurately represented without contradicting top-of-file disclaimers (`F-06-05`).

---

## 3. Public-Safety & Consensus Invariants

1. **Bounded Memory & Executor Liveness (`F-03.2`, `F-03.5`, `F-03.8`)**: `LocalAuthCache` MUST enforce a hard upper bound on retained entries, `OverlayState` MUST NOT clone `LeanEvent` payloads on cache hits, and `compute_merge_bases` MUST NOT panic on rooms with $>8$ forward extremities.
2. **Fail-Closed Cryptographic & Content-Hash Ingest (`F-06-03`, `F-06-04`)**: Federation PDU ingestion MUST reject events missing `hashes.sha256`, `canonical_redacted_json` MUST NOT panic on malformed v6+ numbers, and `EventVerifier` implementors MUST explicitly implement all 5 verification callbacks.
3. **Representation Invariance Across `EventId` Types (`F-03.6`)**: Room V1–V2 Redaction Rule 11 MUST produce identical authorization verdicts whether events are keyed by string `$event_id:domain` or interned integer `u32`/`u64` IDs.

---

## 4. Acceptance Criteria & Verification Oracles

- [ ] **`F-03.2`**: `LocalAuthCache` (`src/state/at.rs:253-342`) enforces a bounded capacity (`max_entries`), and `docs/architecture.md:67-84,202-211` documents $10^4+$ adversarial fork bounds and `spawn_blocking` execution.
- [ ] **`F-03.5`**: `OverlayState::local_auth` (`src/state/at.rs:90,267-272,336-341`) borrows or stores `Arc<LeanEvent>` without calling `(*entry.event).clone()`; verified by unit/benchmark tests.
- [ ] **`F-03.6`**: `src/auth/mod.rs:676-681` extracts the V1–V2 redaction server domain without `alloc::format!("{}", event.event_id())`; verified by a new integer-keyed (`u32`/`u64`) V1 redaction unit test in `tests/unit/test_integer_keys.rs`.
- [ ] **`F-03.7`**: `docs/design_notes.md:17,174-190` matches current `IterativeInputs::new` and `StreamingInputs::try_compute` signatures.
- [ ] **`F-03.8`**: `compute_merge_bases` (`src/state/at.rs:788-791`) supports $>8$ forward extremities (`u64` / dynamic bitset) without panicking; verified by a 16-extremity unit test in `tests/unit/test_state_at.rs`.
- [ ] **`F-06-03`**: `ingest_events` (`src/basespec/rezzy_types.rs:1457-1462`) rejects PDUs missing `hashes`, `canonical_redacted_json` (`src/basespec/rezzy_types.rs:1040-1045`) handles invalid v6+ numbers without `.expect()` panic, and `reference_hash` (`src/basespec/rezzy_types.rs:920-960`) doc comment is accurate.
- [ ] **`F-06-04`**: `EventVerifier` (`src/basespec/rezzy_types.rs:2645-2665`) has no silent `Ok(())` default bodies; `src/auth/mod.rs:491-502,1894-1904` and tests use explicit verifier implementations or `NoopEventVerifier`.
- [ ] **`F-06-05`**: `docs/spec_coverage.csv:1-36` and `docs/spec_audit.md:1-6,128-136` are reconciled with accurate `full` vs. `partial` / `delegated` classifications.
- [ ] **`F-06-06`**: `check_power_levels_rules` (`src/auth/mod.rs:1076-1140`) validates PL transitions without allocating 6 intermediate `BTreeMap`s.
