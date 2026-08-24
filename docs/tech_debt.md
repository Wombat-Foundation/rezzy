# Tech debt / performance backlog

Tracked items to circle back on, now that the spec-compliance work is mostly in
place (though not yet fully tested/feature-complete — see
`docs/spec_audit.md`/`spec_coverage.csv` for the compliance side of that). This
file is for things that are _correct as-is_ but not yet as fast, as generic, or
as complete as they should eventually be. Move an item to a commit + delete it
from here once it's actually done; don't let this become a second, stale
spec_audit.md.

## Performance

### Dense-index (`id_to_index`/`index_to_id`) pattern reimplemented 5+ times independently

The "assign dense integer indices to an arbitrary ID/hash set, both directions,
so a `RoaringBitmap` or a plain array can address it" pattern is hand-rolled
independently in at least five places, with real, meaningful variation between
copies:

1. `src/auth/roaring.rs`, `AuthGraph`: `id_to_index: HashMap<Id, u32>` +
   `index_to_id: Vec<Id>` (owned `Id`), feeds
   `auth_bitmaps: Vec<RoaringBitmap>`. Overflow handling:
   `u32::try_from(idx).unwrap()` -- **panics** past `u32::MAX` entries, doesn't
   return an error.
2. `src/hamt/audit.rs`, `IndexedUniverse`: `hashes: Vec<StructuralHash>` +
   `index_by_hash: HashMap<StructuralHash, u32>` -- hardcoded to
   `StructuralHash`, not generic over an arbitrary `Id`. Feeds
   `bitmap_node_reachability_audit`'s `RoaringBitmap`s. **The one correct copy
   on overflow**: `try_build`/`try_build_bounded` return
   `Result<_, UniverseTooLarge>` instead of panicking, and keep counting the
   _true_ distinct count past the bound rather than reporting a content-free
   `bound + 1`.
3. `src/resolve/reachability.rs`: **two separate versions in the same file** --
   a standalone `index_topology()` (owned `Id`, `FastMap<Id, u32>`) and a struct
   at lines ~400-404 with its own `id_to_index`/`index_to_id` pair, both
   `u32`-indexed like (1).
4. `src/state/at.rs`, `collect_ancestor_short_ids_batch`:
   `FastMap<&Id, usize>` + `Vec<&Id>` -- **borrowed** `&Id` (not owned),
   **`usize`** indices (not `u32`, so no overflow risk in practice). Used at 8+
   call sites within that one file (topological sort / depth computation
   helpers).
5. `src/bin/rezzy/format.rs` and `tests/stress_large_rooms.rs`: two more ad hoc
   versions, `HashMap<&str, usize>`, for display/formatting and stress-test
   graph construction respectively.

None of these are wrong in isolation, but the duplication means: the
overflow-handling fix only exists in one of the five (`IndexedUniverse`), any
future bugfix to the dense-indexing logic itself has to be found and applied up
to five times, and each copy independently made its own ownership (`Id` vs
`&Id`) and width (`u32` vs `usize`) choice without a documented reason to prefer
one over another at a given call site.

**Recommended approach** (not started, deliberately not attempted as a drive-by
fix given the size): extract a single generic primitive -- something like
`DenseIndex<T, Idx = u32>`, parameterized over both the indexed type `T` (so it
can replace `StructuralHash`-specific `IndexedUniverse` too) and the index width
`Idx` (so `state/at.rs`'s `usize`-indexed, overflow-free use case doesn't get
forced into `u32`) -- with `IndexedUniverse`'s `Result`-based overflow handling
as the baseline, since it's the only one of the five that actually gets this
right. Offer both an owned and a borrowed (`&T`) construction path, since
(1)/(2)/(3) need to own and (4) needs to borrow. Migrate each of the five call
sites onto it one at a time rather than in one sweeping change, verifying no
behavioral change at each step (this touches auth/hamt/resolve/state/bin -- a
real multi-module refactor, not a small follow-up). Do NOT copy any one of the
five implementations directly into another's call site as a shortcut -- the
ownership/width mismatches make that actively wrong at at least the (1)-into-(4)
and (4)-into-(1) directions.

### `K` genericity: `InternedKey` isn't threaded through yet

`InternedKey` (`src/basespec/rezzy_types.rs`) exists as an opt-in `StateKey` for
callers who want `Arc<str>`-cheap `state_key` clones instead of `String`'s
per-clone allocation, but it's a standalone type today — not wired through
resolution/HAMT/auth as a default/recommended `K`, and there's no conversion
helper to/from the plain-`String` wire format at the ingest/checkpoint boundary.
Circle back for the full generic refactor: thread it through call sites, add the
wire-format conversions, and benchmark the actual win before recommending it
broadly. (See the `TODO` comment directly above `InternedKey`'s definition.)

### No true zero-copy identifiers (RocksDB-slice-backed views)

`RoomId`/`InternedKey` (and any future identifier type built the same way) are
`Arc<str>`-backed: cheap to _clone_ (refcount bump) but not zero-copy to
_construct_ — `Arc<str>::from(&str)` always allocates and copies once. A
homeserver reading events straight out of a RocksDB (or similar) slice can't get
a genuinely zero-allocation `&'a RoomId` view into that buffer the way ruma's
`#[repr(transparent)] struct RoomId(str)` DST pattern allows (see the `../ruma`
Slack thread on `TimelineEventType`/`Pdu<'a>` for the motivating example — their
event-type enum has the identical problem: everything else in a borrowed
`Pdu<'a>` is a genuine zero-copy DST view, event type isn't).

Blocked by `Cargo.toml`'s `[lints.rust] unsafe_code = "deny"` — the DST pattern
needs an `unsafe` pointer-cast (or a crate like `ref-cast` / `zerocopy` that's
already done that unsafe work behind a safe API). Decide: carve out a narrow,
audited exception to the lint for one module, or take on one of those crates as
a dependency, before attempting this.

### `required_auth_types_for` allocates per push

`src/auth/mod.rs`'s `required_auth_types_for` builds `Vec<(String, String)>` via
`String::from(...)` for every entry (`M_ROOM_CREATE`/`M_ROOM_MEMBER` constants
are already `&'static str`; `event.sender()`/`event.state_key()` are already
borrowed) — a handful of small allocations per event auth-checked. Not hot-path
(bounded by the conflicted set, not the full resolved-state size), but could
return borrowed `&str`/`Cow<'_, str>` pairs instead with no loss of correctness,
since its only consumer (`state.get_event(&req_type, &req_key)`) just wants
`&str` anyway.

### `derive_all_conflicted_keys` double-derives `EventType`

`src/resolve/iterative.rs:83` (pre-existing `TODO(perf)`): calls
`EventType::from(ev.event_type.as_str())` once to build the gate set, then again
later when actually inserting into `resolved`. Cheap for well-known types, a
duplicate `Box<str>` heap allocation per conflicted event for
`EventType::Custom`. Fix means threading the already-interned `EventType`
alongside each event through `route_power_events`/`power_events`/
`non_power_events` (currently keyed by `Id` only) instead of re-deriving it.

## Correctness-adjacent / completeness

### `is_sender_banned` only checks bans, not under-powered senders

The CDO-replacement design doc (`src/resolve/cdo.rs`'s module docs) frames the
sound resolved-state screening predicate as "is this sender banned /
**under-powered** in `resolved`?" — but the actual implementation
(`is_sender_banned`, `src/resolve/iterative.rs`) only checks the ban case. A
sender who was demoted below the power level their conflicted event requires
(not banned outright) still gets the full mainline-sort + iterative auth
treatment instead of being screened out early. Not a soundness bug (the same
"iterative auth would reject it anyway" argument applies — see the commit
message on `080fd2a`, which explicitly notes this as "not yet [done]"), just an
incomplete optimization.

### `Warning` channel only wired into `validate_syntactic` so far

`src/warnings.rs`'s `Warning<Id>`/`Outcome<T, Id>` (a structured, stably-coded
channel for spec-undefined/homeserver-policy conditions rezzy detects but
doesn't decide on) is live end-to-end for exactly one case: pre-v11 byte-limit
overages, via `LeanEvent::validate_syntactic`. `Warning::UnknownPrevEvent`
exists and converts `From<BackwardExtremity<Id>>`, but nothing in the crate
actually constructs one that way yet -- `find_backward_extremities` still just
returns `Vec<BackwardExtremity<Id>>` directly, and `check_auth_chain`/
`ingest_events`/`resolve_iterative_sort*` don't emit or collect warnings at all.
Circle back to wire the flagship entry points (`check_auth_chain` first, per the
original ask) through `Outcome`, and decide whether `find_backward_extremities`
should also feed into the general channel or stay as its own more-detailed
opt-in analysis (current lean: keep it separate, since `BackwardExtremity`
groups multiple missing parents per event more richly than the one-line
`Warning` variant does).

### Dead CDO module (`src/resolve/cdo.rs`)

`apply_cdo_filter` is retired from the live resolution path (superseded by
`is_sender_banned`'s resolved-state screening pass) but the module is still
compiled, still has its own test suite, and is still exercised by
`tests/unit/differential_harness.rs`'s `cdo_drop_rate_measured` /
`dominated_winner_generator` (as a _soundness regression check_ against the live
path, not because it's live itself). Worth a deliberate decision: keep it as a
permanent regression fixture, or extract just the invariant the differential
harness needs and delete the rest.
