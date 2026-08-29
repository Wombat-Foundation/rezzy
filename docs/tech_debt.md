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
independently at five logical locations (seven distinct implementations once the
two-in-one files below are counted), with real, meaningful variation between
copies:

1. `src/auth/roaring.rs`, `AuthGraph`: `id_to_index: HashMap<Id, u32>` +
   `index_to_id: Vec<Id>` (owned `Id`), feeds
   `auth_bitmaps: Vec<RoaringBitmap>`. Overflow handling:
   `u32::try_from(idx).unwrap()` -- **panics** past `u32::MAX` entries, doesn't
   return an error.
2. `src/hamt/audit.rs`, `IndexedUniverse`: **migrated onto the shared
   [`DenseIndex`](crate::DenseIndex) primitive** (`src/dense_index.rs`) — now a
   thin wrapper over `DenseIndex<StructuralHash>` (generic indexed type, `u32`
   width). `IndexedUniverse`/`UniverseTooLarge` public API is unchanged; the
   overflow handling (the one correct, `Result`-based copy) now lives once in
   the generic engine.
3. `src/resolve/reachability.rs`: **two separate versions in the same file** --
   a standalone `index_topology()` (owned `Id`, `FastMap<Id, u32>`) and a struct
   at lines ~400-404 with its own `id_to_index`/`index_to_id` pair, both
   `u32`-indexed like (1). Not yet migrated.
4. `src/state/at.rs`, `collect_ancestor_short_ids_batch`:
   `FastMap<&Id, usize>` + `Vec<&Id>` -- **borrowed** `&Id` (not owned),
   **`usize`** indices (not `u32`, so no overflow risk in practice). Used at 8+
   call sites within that one file (topological sort / depth computation
   helpers). A queue/BFS order rather than plain first-seen, so it's the least
   natural fit for the `DenseIndex` engine. Not yet migrated.
5. `src/bin/rezzy/format.rs` and `tests/stress_large_rooms.rs`: two more ad hoc
   versions, `HashMap<&str, usize>`, for display/formatting and stress-test
   graph construction respectively. Not yet migrated.

None of these are wrong in isolation, but the duplication means: the
overflow-handling fix only exists in one of the seven (`IndexedUniverse`), any
future bugfix to the dense-indexing logic itself has to be found and applied up
to seven times, and each copy independently made its own ownership (`Id` vs
`&Id`) and width (`u32` vs `usize`) choice without a documented reason to prefer
one over another at a given call site.

**Status:** the shared primitive [`DenseIndex<T, Idx = u32>`](crate::DenseIndex)
now exists (`src/dense_index.rs`) with `Result`-based overflow handling (from
`IndexedUniverse`'s corrected counting) as the baseline, generic over both the
indexed type `T` and the index width `Idx`, with owned and borrowed (`&T`)
construction paths. **Done so far:** `IndexedUniverse` (item 2) migrated onto
it, preserving its public API and behavior (895 tests pass; clippy clean).
**Remaining (do one at a time, verifying no behavioral change at each step):**
migrate items 1 (`AuthGraph`), 3 (`reachability`'s `index_topology` + the `~400`
struct), and 5 (`format.rs`/`stress_large_rooms.rs`) onto `DenseIndex`; item 4
(`at.rs` BFS) is the weakest fit and should only be migrated if the
borrowed/`usize` path proves clean, otherwise leave as-is. Do NOT copy any one
of the remaining implementations directly into another's call site as a shortcut
-- the ownership/width mismatches make that actively wrong at at least the
(1)-into-(4) and (4)-into-(1) directions.

### `K` genericity: `InternedKey` isn't threaded through yet

`InternedKey` (`src/basespec/rezzy_types.rs`) exists as an opt-in `StateKey` for
callers who want `Arc<str>`-cheap `state_key` clones instead of `String`'s
per-clone allocation, but it's a standalone type today — not wired through
resolution/HAMT/auth as a default/recommended `K`, and there's no conversion
helper to/from the plain-`String` wire format at the ingest/checkpoint boundary.
Circle back for the full generic refactor: thread it through call sites, add the
wire-format conversions, and benchmark the actual win before recommending it
broadly. (See the `TODO` comment directly above `InternedKey`'s definition.)

`benches/interned_key.rs` also carries a `K = InternedKey` (`Arc<str>`) variant
alongside plain `String`, benchmarked across room sizes 100/1000/5000: it wins
at small N (-9 to -11%) but the atomic refcount's cross-core cache-line
contention under the parallel `thread::scope` fold erodes and then reverses the
win at 5000 members (+3 to +16%). So `InternedKey`'s value is real but
size-dependent — don't default to it without checking the target workload's room
sizes.

#### Investigated: `u32`-arena-interned `K` (`InternId`) — perf win confirmed, parked on one lifetime bound

A no-atomics, `Copy` `u32` index into a string arena (`InternId`, prototyped in
`benches/interned_key.rs` at commit `fdddb31`) was investigated as a genuinely
C-style alternative to `InternedKey`'s `Arc<str>` — the motivating idea being
that integer compare/copy should beat both allocation (`String`) and atomic
refcounting (`Arc<str>`) regardless of key collisions. The prototype (sorted
first-seen ids, no lifetime constraint) confirmed the hypothesis: -17% to -23%
across all three room sizes, unlike `InternedKey`'s reversal at 5000.

That result does not survive contact with the real pipeline — but only one of
the two reasons originally logged here is actually structural. The other was an
implementation shortcut in the Phase 1 rewrite that got mistaken for a hard
constraint; corrected below.

1. **Ordering, NOT actually forced through the interner.** `RoomState`'s
   `BTreeMap` lookups are sound only because every `K` used as a key agrees with
   lexicographic string `Ord` (see [`StateKeyDyn`](../src/auth/mod.rs) and its
   `Borrow<dyn StateKeyDyn>` impl) — that part is real. But every resolution
   entry point (`compute_state_at`/`_batch`/`_streaming`, `src/state/at.rs`)
   takes the full event set as an already-materialized `&HashMap` argument;
   "streaming" only describes results flowing out via callback, not events
   streaming in. The complete vocabulary of distinct `state_key`s for one call
   is therefore known before resolution starts, so a **per-call** interner can
   collect every key, sort once, and assign rank-based `u32` ids matching that
   sort — giving a plain `u32` compare for `Ord`, zero string touches, for the
   whole call. The "ids can't be sorted up front" objection only applies to a
   _global, server-lifetime_ interner (whose vocabulary genuinely grows across
   calls as new members join); the Phase 1 prototype used first-seen ids and
   resolved `Ord` through the interner (string compare) as a shortcut to avoid
   the two-phase collect-then-sort build, not because the entry points required
   it. That shortcut is what the re-bench below actually measured eroding.
2. **Lifetime soundness — this one is real.** Any borrowing `InternId<'a>` fails
   to satisfy the resolution entry points' existing bound
   `for<'q> (String, K): Borrow<dyn StateKeyDyn + 'q>` (`src/auth/mod.rs`): the
   blanket `Borrow` impl requires `K: 'a` for the same `'a` on every invocation,
   and satisfying that `for<'q>` universally-quantified bound forces
   `K: 'static`. A per-resolution-run, stack-borrowed interner is therefore not
   viable as `K` under the current signatures without also threading a `'static`
   requirement through every consumer.

With `Ord` forced through the interner (string compare, the Phase 1 shortcut
above) _and_ the interner forced `'static` (leaked, for the bench),
re-benchmarking the real lib type against `String` reproduced an erosion: the
win shrinks from small to mid room sizes and disappears or reverses at 5000
members (repeated runs: roughly -12% → -4% → anywhere from -0.1% to +31%
depending on run). That number measured the string-compare `Ord` shortcut, not a
proper sort-once-per-call `Ord` — so it is not yet the honest answer to whether
`u32` interning wins in production.

**Status: performance-justified, parked on a lifetime bound.** The `'static`
requirement described in point 2 as coming from the `StateKey` trait itself no
longer applies verbatim — the trait bound was dropped (see commit
`58c9a5c`/`2a29da0`). The residual blocker moved, not away: the resolution entry
points (`compute_state_at`/`_batch`/`_streaming` and their auth call-through)
still carry a function-level
`for<'q> (EventType, K): Borrow<dyn StateKeyDyn + 'q>` bound on every
`K`-generic signature in `src/state/at.rs` and `src/resolve/iterative.rs` (the
`(String, K)` form instead appears on `src/auth/mod.rs`'s `StateProvider` impl
for `RoomState`, not a function signature — both are the same `K: 'a` shape, so
the conclusion below is unaffected), which independently forces `K: 'static` via
the universally-quantified `'q`. A borrowing `InternId<'a>` still can't satisfy
it without either relaxing that bound to a concrete lifetime or replacing the
`Borrow<dyn StateKeyDyn>` lookup with a `K`-generic query seam (id-lookup for
`InternId`, unchanged borrowed lookup for `String`) — see
`src/basespec/interned_key.rs`'s `InternedRoomState` spike, which sidesteps the
shared blanket impl entirely rather than relaxing it. The sort-once redo was
run: the current `u32`-rank variant in `benches/interned_key.rs` (collect every
`state_key` in the call's `events_map`, sort once, assign rank ids — `Ord`
genuinely `u32`-cheap) reproduces **-13% to -21%** against `String` across room
sizes 100/1000/5000, batch and serial, with no reversal at 5000. The performance
case is therefore met; the only open question is whether threading a `'static`
interner (or a lifetime/redesigned `Borrow<dyn StateKeyDyn>` bound) through the
public API is worth that cost. Revisit if either lands. The Phase 1 prototype
work (`8bf6680`, `99d1cfb`, `9fa73b3`, `39dd517`) was reverted from `dev`;
`benches/interned_key.rs` still carries both variants from `fdddb31` side by
side: `InternedKey` (`Arc<str>`), whose win over `String` reverses at 5000
members (+3% to +16%, the erosion described above), and the separate `InternId`
(`u32`-rank) variant, whose -13% to -21% figure is the one quoted above and does
not reverse.

### No true zero-copy identifiers (RocksDB-slice-backed views)

`RoomId`/`InternedKey` (and any future identifier type built the same way) are
`Arc<str>`-backed: cheap to _clone_ (refcount bump) but not zero-copy to
_construct_ — `Arc<str>::from(&str)` always allocates and copies once. A
homeserver reading events straight out of a RocksDB (or similar) slice can't get
a genuinely zero-allocation `&'a RoomId` view into that buffer the way ruma's
`#[repr(transparent)] struct RoomId(str)` DST pattern allows. Ruma's
`TimelineEventType`/`Pdu<'a>` is the motivating example for the same shape: in a
borrowed `Pdu<'a>` every field is a genuine zero-copy DST view except the event
type, which (like a `RoomId`) would otherwise have to copy -- the identical
problem a DST-backed identifier type solves.

Blocked by `Cargo.toml`'s `[lints.rust] unsafe_code = "deny"` — the DST pattern
needs an `unsafe` pointer-cast (or a crate like `ref-cast` / `zerocopy` that's
already done that unsafe work behind a safe API). Decide: carve out a narrow,
audited exception to the lint for one module, or take on one of those crates as
a dependency, before attempting this.

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

The resolved-state screening pass (`is_sender_banned`,
`src/resolve/iterative.rs`) is deliberately ban-only: it drops exactly those
conflicted events whose sender is banned in the power-phase `resolved` state.
That is the narrow, sound guarantee — the pass rejects only banned senders and
never reorders the surviving set (a sender banned in the power-phase `resolved`
is banned throughout the non-power phase, so the iterative auth would reject
such an event regardless). A sender who was demoted below the power level their
conflicted event requires (not banned outright) is **not** screened here and
still gets the full mainline-sort + iterative auth treatment. This is
intentional: the ban-only predicate is exact (it looks up `MEM_BAN` on the
sender's member key), whereas distinguishing a pre-demotion-authorized event
from a genuinely rejected one is not a simple predicate — see
`test_anomaly_19_demoted_but_still_authorized`, where a demoted Priya's ban must
still survive because it was authorized against an earlier PL grant that her
later demotion cannot retroactively invalidate. Screening demoted senders out
early would require such a predicate, which does not exist yet — an incomplete
optimization, not a soundness bug.

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

### `RefcountTable`/`hamt::gc` has no live caller either

Same shape as the dead CDO module below, checked while answering "does anything
still need a similar 'is this actually wired in' check": nothing in the crate
outside `src/hamt/gc.rs` itself and its own tests calls
`apply_new`/`apply_superseded`/`bootstrap`. It's a complete, tested, documented
incremental-GC primitive (the replacement for periodic `hamt::audit` sweeps)
that no ingest/resolution lifecycle actually invokes yet -- `delta.rs`'s doc
comment points to it as "a ready-made incremental [...]" but nothing follows
that pointer. Not a correctness problem (it's inert, not wrong), but it means
the crate doesn't yet have an actual GC story end-to-end -- a caller adopting
rezzy today gets `hamt::audit`'s one-shot sweep only, unless they hand-wire
`RefcountTable` themselves. Circle back to either wire it into a real call site
(state group retirement is the obvious candidate) or document it explicitly as a
BYO-integration primitive rather than implying it's already the crate's GC
strategy.

### No deterministic end-to-end test for the bucket-split retry path

`tests/unit/test_reconcile_e2e.rs` drives the real client<->server
`ReconciliationClient`/`BucketExchange` round-trip loop (not just
`estimate_strata`/`PinSketch` in isolation) and covers a clean single-round
decode and a `low_confidence`-estimate case that still converges. It
deliberately does **not** cover `retry_or_split_bucket`'s multi-round
capacity-then-depth escalation end-to-end: a uniformly random delta rarely
overflows any single auto-sized bucket (so it doesn't reliably force a retry),
and a hand-constructed "hot bucket" skewed enough to force one tended to either
overshoot `MAX_RECONCILIATION_ROUNDS` (bailing to `ExtremityDiff`) or undershoot
it, depending on exact construction -- turning the assertion into something that
would flake rather than reliably exercise the path. `benches/reconcile.rs`'s
`benchmark_bucket_exchange_from_pool` already runs this path at scale, just
without assertions (it's a timing harness, not a correctness gate). Circle back
with a construction that provably lands a chosen delta in exactly one prefix
range at a chosen depth (rather than approximating it via hash clustering) so
the round count is an exact, assertable function of the inputs instead of an
empirical one.

### Dead CDO module (`src/resolve/cdo.rs`)

`apply_cdo_filter` is retired from the live resolution path (superseded by
`is_sender_banned`'s resolved-state screening pass) but the module is still
compiled, still has its own test suite, and is still exercised by
`tests/unit/differential_harness.rs`'s `cdo_drop_rate_measured` /
`dominated_winner_generator` (as a _soundness regression check_ against the live
path, not because it's live itself). Worth a deliberate decision: keep it as a
permanent regression fixture, or extract just the invariant the differential
harness needs and delete the rest.
