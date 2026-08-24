# Tech debt / performance backlog

Tracked items to circle back on, now that the spec-compliance work is mostly
in place (though not yet fully tested/feature-complete — see
`docs/spec_audit.md`/`spec_coverage.csv` for the compliance side of that).
This file is for things that are _correct as-is_ but not yet as fast, as
generic, or as complete as they should eventually be. Move an item to a
commit + delete it from here once it's actually done; don't let this become
a second, stale spec_audit.md.

## Performance

### `K` genericity: `InternedKey` isn't threaded through yet

`InternedKey` (`src/basespec/rezzy_types.rs`) exists as an opt-in `StateKey`
for callers who want `Arc<str>`-cheap `state_key` clones instead of
`String`'s per-clone allocation, but it's a standalone type today — not
wired through resolution/HAMT/auth as a default/recommended `K`, and there's
no conversion helper to/from the plain-`String` wire format at the
ingest/checkpoint boundary. Circle back for the full generic refactor:
thread it through call sites, add the wire-format conversions, and benchmark
the actual win before recommending it broadly. (See the `TODO` comment
directly above `InternedKey`'s definition.)

### No true zero-copy identifiers (RocksDB-slice-backed views)

`RoomId`/`InternedKey` (and any future identifier type built the same way)
are `Arc<str>`-backed: cheap to _clone_ (refcount bump) but not zero-copy to
_construct_ — `Arc<str>::from(&str)` always allocates and copies once. A
homeserver reading events straight out of a RocksDB (or similar) slice can't
get a genuinely zero-allocation `&'a RoomId` view into that buffer the way
ruma's `#[repr(transparent)] struct RoomId(str)` DST pattern allows (see the
`../ruma` Slack thread on `TimelineEventType`/`Pdu<'a>` for the motivating
example — their event-type enum has the identical problem: everything else
in a borrowed `Pdu<'a>` is a genuine zero-copy DST view, event type isn't).

Blocked by `Cargo.toml`'s `[lints.rust] unsafe_code = "deny"` — the DST
pattern needs an `unsafe` pointer-cast (or a crate like `ref-cast` /
`zerocopy` that's already done that unsafe work behind a safe API). Decide:
carve out a narrow, audited exception to the lint for one module, or take on
one of those crates as a dependency, before attempting this.

### `required_auth_types_for` allocates per push

`src/auth/mod.rs`'s `required_auth_types_for` builds `Vec<(String, String)>`
via `String::from(...)` for every entry (`M_ROOM_CREATE`/`M_ROOM_MEMBER`
constants are already `&'static str`; `event.sender()`/`event.state_key()`
are already borrowed) — a handful of small allocations per event
auth-checked. Not hot-path (bounded by the conflicted set, not the full
resolved-state size), but could return borrowed `&str`/`Cow<'_, str>` pairs
instead with no loss of correctness, since its only consumer
(`state.get_event(&req_type, &req_key)`) just wants `&str` anyway.

### `derive_all_conflicted_keys` double-derives `EventType`

`src/resolve/iterative.rs:83` (pre-existing `TODO(perf)`): calls
`EventType::from(ev.event_type.as_str())` once to build the gate set, then
again later when actually inserting into `resolved`. Cheap for well-known
types, a duplicate `Box<str>` heap allocation per conflicted event for
`EventType::Custom`. Fix means threading the already-interned `EventType`
alongside each event through `route_power_events`/`power_events`/
`non_power_events` (currently keyed by `Id` only) instead of re-deriving it.

## Correctness-adjacent / completeness

### `is_sender_banned` only checks bans, not under-powered senders

The CDO-replacement design doc (`src/resolve/cdo.rs`'s module docs) frames
the sound resolved-state screening predicate as "is this sender banned /
**under-powered** in `resolved`?" — but the actual implementation
(`is_sender_banned`, `src/resolve/iterative.rs`) only checks the ban case.
A sender who was demoted below the power level their conflicted event
requires (not banned outright) still gets the full mainline-sort + iterative
auth treatment instead of being screened out early. Not a soundness bug
(the same "iterative auth would reject it anyway" argument applies — see
the commit message on `080fd2a`, which explicitly notes this as "not yet
[done]"), just an incomplete optimization.

### Dead CDO module (`src/resolve/cdo.rs`)

`apply_cdo_filter` is retired from the live resolution path (superseded by
`is_sender_banned`'s resolved-state screening pass) but the module is still
compiled, still has its own test suite, and is still exercised by
`tests/unit/differential_harness.rs`'s `cdo_drop_rate_measured` /
`dominated_winner_generator` (as a _soundness regression check_ against the
live path, not because it's live itself). Worth a deliberate decision: keep
it as a permanent regression fixture, or extract just the invariant the
differential harness needs and delete the rest.
