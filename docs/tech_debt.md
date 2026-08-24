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
overflow-handling fix only exists in one of the seven (`IndexedUniverse`), any
future bugfix to the dense-indexing logic itself has to be found and applied up
to seven times, and each copy independently made its own ownership (`Id` vs
`&Id`) and width (`u32` vs `usize`) choice without a documented reason to prefer
one over another at a given call site.

**Recommended approach** (not started, deliberately not attempted as a drive-by
fix given the size): extract a single generic primitive -- something like
`DenseIndex<T, Idx = u32>`, parameterized over both the indexed type `T` (so it
can replace `StructuralHash`-specific `IndexedUniverse` too) and the index width
`Idx` (so `state/at.rs`'s `usize`-indexed, overflow-free use case doesn't get
forced into `u32`) -- with `IndexedUniverse`'s `Result`-based overflow handling
as the baseline, since it's the only one of the seven that actually gets this
right. Offer both an owned and a borrowed (`&T`) construction path, since
(1)/(2)/(3) need to own and (4) needs to borrow. Migrate each of the seven
implementations onto it one at a time rather than in one sweeping change,
verifying no behavioral change at each step (this touches auth/hamt/resolve/
state/bin -- a real multi-module refactor, not a small follow-up). Do NOT copy
any one of the seven implementations directly into another's call site as a
shortcut -- the ownership/width mismatches make that actively wrong at at least
the (1)-into-(4) and (4)-into-(1) directions.

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

## CI / benchmark tooling

### `.github/workflows/benches.yml` security & robustness

Found by the CodeRabbit/cubic PR review. The bench workflow has several open
issues, all valid and worth fixing before it's trusted as a gate:

- **PR runs get `contents: write`.** `permissions: contents: write` is set at
  workflow level, so a same-repo PR can execute arbitrary build/bench code with
  a writable repo token. Fix: split into a read-only bench job (contents: read,
  `persist-credentials: false` on checkout) and a separate publish job
  (contents: write) gated to main/master only.
- **Unpinned action tags.** `actions/checkout@v4`,
  `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2` are mutable tags;
  pin to verified commit SHAs.
- **No `pipefail`.** `cargo bench 2>&1 | tee bench-output.txt` returns `tee`'s
  exit status, so a bench failure can pass/publish partial metrics. Enable
  `set -o pipefail`.
- **Publish always fails after `_metadata/badges` exists.** The fetched
  `bench.json` (untracked, from
  `git show _metadata/badges:bench.json > bench.json`) collides with the tracked
  `bench.json` on that branch, so
  `git checkout -B _metadata/badges origin/_metadata/badges` refuses. Stash it
  (e.g. `mv bench.json bench-prev.json`) before the branch switch.
- **No publish concurrency group.** Two main/master runs race on the
  `_metadata/badges` push (non-fast-forward rejection). Serialize the publisher.

### `scripts/compare_bench.py` fail-open + label collisions (from cubic review)

- **Empty parse passes CI.** If `bench-output.txt` is empty or the format
  changes, `current` is `{}` and the script exits 0 — the gate silently passes.
  Fail with a nonzero exit when no metrics are parsed.
- **Checkpoint labels collide.** The cumulative benchmark's checkpoint metrics
  reuse identical labels, so `metrics[label] = value` (last-wins) keeps only the
  final checkpoint. Preserve checkpoint context or require unique labels so
  every checkpoint is compared.

## Scripts & docs cleanup (low-risk quick wins)

- `docs/perf_audits.md` pastes raw AI-session transcript blocks ("Thought for
  Ns", tool-call lines, absolute paths like `/run/media/shane/...`). Strip to
  the benchmark conclusions / takeaways only.
- `tests/unit/test_lib.rs:803` stale float-coercion comment (describes
  `Number::from_f64(...).as_i64()` that the code no longer uses).
- `scripts/export_room_dag.py` / `scripts/fetch_matrix_state.py`: a 200 response
  with malformed JSON raises `JSONDecodeError`/`ValueError` uncaught, aborting
  the fetch; handle it as a per-event failure and return `None`.
- `scripts/gen_10mil_uuid_sets.py:9` parenthesized `with` requires Python 3.10+
  (previous comma form worked on 3.7+); revert unless 3.10+ is required.
- `docs/tech_debt.md` "dense-index" section: reconcile "seven implementations"
  vs "up to five"/"five call sites" wording; `RoomId` DST note has a
  non-navigable `../ruma` Slack reference.
