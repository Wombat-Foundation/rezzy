# Specification: Track 13 — P0 Unconditional Fail-Closed `MSC4307` Rule 2.5 Cross-Room Auth Rejection

## 1. Overview & Public-Safety Rationale
In [`docs/spec_audit.md`](../../../docs/spec_audit.md) and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #14 & P0 Remediation #1), cross-room `auth_events` rejection (`MSC4307` / Authorization Rule 2.5) is currently **opt-in**: `LeanEvent::room_id()` returns `Option<RoomId>`, and if callers leave `room_id: None`, the authorization engine silently skips cross-room verification.

In public-safety and C2 Matrix deployments, a missing cross-room check allows an attacker who holds `m.room.power_levels` or membership events in an untrusted room to inject foreign `auth_events` into a restricted dispatch room if the caller's ingestion layer fails to populate `Some(room_id)`.

## 2. Functional Requirements
1. **Mandatory Room Context in Authorization APIs**:
   - Require an explicit `room_id` (or non-optional `EventLike::room_id`) in `check_auth_rules`, `check_auth_chain`, and state resolution entry points, or reject events when `e.room_id() != auth_event.room_id()`.
2. **Eliminate Silent `None` Bypass**:
   - Remove the fail-open `if let (Some(r1), Some(r2)) = ...` branch in `src/auth/` so missing or mismatched room identifiers fail closed (`AuthError`).
3. **Update `docs/spec_audit.md` and `docs/spec_coverage.csv`**:
   - Reflect mandatory enforcement of `MSC4307` Rule 2.5 and clarify any remaining caller-delegated checks (e.g., Ed25519 signatures).

## 3. Acceptance Criteria
- [ ] Foreign-room `auth_events` are unconditionally rejected across all room versions without requiring callers to opt in via `Some(room_id)`.
- [ ] Unit and adversarial integration tests verify rejection of cross-room `m.room.create`, `m.room.power_levels`, and `m.room.member` events in `check_auth_chain` and `resolve_iterative_sort`.
- [ ] `cargo test --workspace --lib --tests` and `cargo clippy --all-targets --all-features` pass with zero warnings.
