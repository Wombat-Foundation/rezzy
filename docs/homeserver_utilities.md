# Homeserver Utility Roadmap

Pure, synchronous utilities rezzy can expose to simplify
homeserver implementations. All follow rezzy's philosophy:
no I/O, no async, `no_std`-compatible, generic over
`EventId`.

---

## Tier 1 — High Value (hot path simplifiers)

### 1. Auth Chain Difference (public API)

**Status**: ✅ Implemented and public

`compute_auth_chain_diff` exists in `src/state/at.rs`. It computes
`auth(C) \ auth(U)` — the auth-chain events reachable
from conflicted state but not from unconflicted state.

This is THE input to state resolution that every
homeserver must compute. Exposing it as a public API
saves homeservers from reimplementing the bounded
dual-heap traversal.

---

### 2. Auth Chain Difference (roaring bitmap variant)

**Status**: ✅ Implemented

`AuthGraph` in `src/auth/roaring.rs` builds roaring
bitmap auth chains. `AuthGraph::auth_difference` enables O(|bitmap|)
set-difference on pre-computed bitmaps — the fast path
homeservers with pre-computed auth chains need.

---

### 3. Power Level Query API

**Status**: ✅ Already implemented and public

`src/auth/user.rs` already exposes:

- `get_sender_power_level`
- `user_can_invite` / `user_can_ban` / `user_can_kick`
  / `user_can_redact`

These are threshold-only checks. Full auth goes through
`check_auth`.

**Work**: None — already done. Consider adding:

- `user_can_send_event(type, state_key)` — checks
  the `events` map in power levels.
- `user_can_set_state(type)` — checks `state_default`
  or `events` override.

---

### 4. State Diff

**Status**: ✅ Implemented

`src/state/diff.rs` produces a typed diff showing what changed between
two state snapshots. Useful for:

- Client sync (computing incremental state updates)
- Admin tooling ("what changed in this fork?")
- Delta compression validation

---

## Tier 2 — Medium Value (correctness helpers)

### 5. Event Well-Formedness Validation

**Status**: ❌ Not implemented

Structural validation before auth checking:

- Required fields present (type, sender, room_id, etc.)
- `prev_events` non-empty (except `m.room.create`)
- `depth` >= 0 and consistent with parents
- `auth_events` reference correct types
- `state_key` present iff state event
- Event ID format matches room version

```rust
pub enum ValidationError {
    MissingSender,
    MissingRoomId,
    EmptyPrevEvents,
    DepthInconsistency { expected_min: i64, actual: i64 },
    InvalidAuthEvents(String),
    // ...
}

pub fn validate_event_structure<Id>(
    event: &LeanEvent<Id>,
    version: StateResVersion,
) -> Result<(), Vec<ValidationError>>
```

**Work**: New `src/auth/validate.rs`, ~200 lines.

---

### 6. Redaction Engine

**Status**: ✅ Implemented

Redaction rules per room version, stripping fields that should not survive
redaction.

Implemented in `src/basespec/rezzy_types.rs`:

- `redaction_preserved_keys(event_type, room_version)` — per-event-type,
  per-version preserved-key matrix (v1→v11; v12 inherits v11).
- `redact_json(value, room_version)` — the full spec redaction algorithm on a
  raw PDU `Value`: drops top-level keys outside the whitelist (v11+ no longer
  protects `origin`/`membership`/`prev_state`) and strips `content` to the
  preserved keys.
- `LeanEvent::redacted(room_version)` — lean-model wrapper over the content half.
- `apply_redaction(target, redaction, room_version)` — applies a redaction to
  a target lean event (target mismatch → `None`).

`m.room.create` is redactable like any other event; the spec does not forbid
it — its content is preserved by the rules (all keys in v11+, `creator`
before that).

Room versions differ in which fields survive:

- V1-V10: original rules
- V11+: updated redaction algorithm (v12 inherits v11)

The reference-hash (event ID for room v4+) path uses `redact_json` so that
redaction never changes an event's ID (`event_id(e) == event_id(redact(e))`).

---

### 7. DAG Health Metrics

**Status**: ❌ Not implemented

Diagnostic queries over the event graph:

```rust
pub struct DagHealth {
    pub total_events: usize,
    pub forward_extremities: usize,
    pub backward_extremities: usize,
    pub max_fork_width: usize,
    pub avg_depth: f64,
    pub max_depth: i64,
    pub orphaned_events: usize,
}

pub fn compute_dag_health<Id>(
    events: &HashMap<Id, LeanEvent<Id>>,
) -> DagHealth
```

**Work**: New utility, ~80 lines.

---

## Tier 3 — Niche (lower priority)

### 8. Room Upgrade Validation

Verify that a tombstone → new `m.room.create` chain is
structurally valid. Checks `replacement_room` field,
`predecessor` in new room's create event, and room
version upgrade compatibility.

### 9. Restricted Join Rule Evaluation

Given current state, enumerate which rooms allow
restricted joins, and whether a given user qualifies
via membership in an allowed room.

### 10. Canonical JSON Helpers

Deterministic JSON serialization for event signing
and hashing. May be better in a separate crate
(`serde_canonical_json` already exists).

---

## Already Done (no work needed)

| Feature                      | Location                               |
| ---------------------------- | -------------------------------------- |
| Auth checking                | `auth::check_auth`                     |
| Power level queries          | `auth::user::*`                        |
| Forward extremity validation | `auth::validate_forward_extremity`     |
| Backward extremity detection | `state::at::find_backward_extremities` |
| Auth chain graph (roaring)   | `auth::roaring::AuthGraph`             |
| State delta compression      | `state::delta::*`                      |
| N-way fork resolution        | `resolve::multi::resolve_state_maps`   |
| State-at computation         | `state::at::compute_state_at`          |
| Auth types enumeration       | `auth::auth_types_for_event`           |
