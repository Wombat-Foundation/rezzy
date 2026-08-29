# Rezzy: Matrix State Resolution Engine

[![CI](https://img.shields.io/github/actions/workflow/status/gamesguru/rezzy/rust.yml?branch=master&label=CI)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![Benchmarks](https://img.shields.io/github/actions/workflow/status/gamesguru/rezzy/benches.yml?branch=master&label=benchmarks)](https://github.com/gamesguru/rezzy/actions/workflows/benches.yml)
[![codecov](https://codecov.io/gh/gamesguru/rezzy/graph/badge.svg)](https://codecov.io/gh/gamesguru/rezzy)
[![crates.io](https://img.shields.io/crates/v/rezzy.svg)](https://crates.io/crates/rezzy)
[![TDD](https://img.shields.io/badge/development-TDD-green.svg)](https://en.wikipedia.org/wiki/Test-driven_development)

[![Tests](https://raw.githubusercontent.com/gamesguru/rezzy/badges/tests.svg)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![Complement](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fgamesguru%2Fcontinuwuity%2F_metadata%2Fbadges%2Fbadge-guru-dev-2026-03-27-b1-presence-b2-federation.json)](https://github.com/gamesguru/continuwuity/actions/workflows/complement.yml?query=branch%3Aguru%2Fdev-2026-03-27%2Bb1-presence%2Bb2-federation)

Rezzy is a high-performance, dependency-free Rust engine
for Matrix State Resolution — both a research model and
highly-efficient reference implementation for state
resolution `v2`, `v2.1`, `v2.1.1` (experimental), and
**V2.2** (experimental [MSC4242]).

## Supported Room Versions

<!-- markdownlint-disable MD013 -->

|      Room Version       | State Resolution | Notes                                     |
| :---------------------: | :--------------: | ----------------------------------------- |
|         _1_ \*          |       _V1_       | _Legacy — depth-based ordering_           |
|         _2_ \*          |       _V2_       | _Mainline sort + iterative auth_          |
|           3–6           |        V2        | Event ID format changes only              |
|          7–10           |        V2        | Knocking, restricted joins                |
|           11            |        V2        | Redaction rules update                    |
|         **12**          |     **V2.1**     | [MSC4297] — conflicted subgraph expansion |
| _org.matrix.msc4242_ \* |      _V2.2_      | Experimental — State DAGs ([MSC4242])     |

<!-- markdownlint-enable MD013 -->

> \* Room versions 1–2 are legacy and not actively supported.

## Features

- Auth check engine.
- Full state resolution pipeline.
- Topological & mainline sorting.
- `n-way` fork resolution.
- In-place bitshift heaps and roaring bitmaps
  for fast graph computations.
- **Lazy projection**: Fast, memory-efficient state
  resolution by only loading required membership events.

## Core Philosophy: TDD

Development in this repository strictly follows
Test-Driven Development (TDD):

1. **Write tests first**. New features or bug fixes must
   begin with failing tests that codify the expected
   behavior.
2. **Implement the logic**. Write the minimal code
   required to make the tests pass.
3. **Prove the fix**. After the dust settles on an
   implementation, we verify that the new tests _fail_
   when run against the old code, proving the tests are
   valid and the fix is strictly necessary.

## API

Everything re-exports from the crate root —
`use rezzy::*` gets you `LeanEvent`, `SharedState`,
`StateResVersion`, `HashMap`, the works.

- **`resolve_iterative_sort`** — the main entry point.
  Unconflicted baseline, conflicted events, auth
  context, algorithm version, power-level cache, and
  empty state key → winning `SharedState`.
- **`resolve_lattice_fold`** — parallel alternative
  (lattice fold instead of sequential mainline sort).
- **`resolve_iterative_sort_with_deltas`** — diagnostic
  variant, also emits per-event `ResolutionDelta` traces.
- **`compute_state_at`** /
  **`compute_state_at_streaming`** — reconstruct resolved
  state at any DAG position. Streaming variant bounds
  memory to frontier width.
- **`auth::check_auth`** /
  **`auth::check_auth_with_context`** — spec-compliant
  auth engine. Implement `StateProvider` to plug in your
  own backend.
- Generic **`EventId`** and **`StateKey`** traits —
  `EventId` accepts `String`, `u32`, `u64`, or
  `ruma::OwnedEventId`; `StateKey` accepts any string-like
  key (`String`, `Arc<str>`, or interned arena keys).
- **`EventContent`** trait — skip JSON parsing in the hot
  path. `serde_json::Value` works via default impl.
- Generic `EventId` support across delta compression
  (`StateDelta`, `CompactedCheckpoint`) and core data
  structures.
- Explicit API/return variants
  (`ForwardExtremityResult`,
  `validate_forward_extremity`) for "soft-fail"
  evaluation and forward extremity validation.

## Performance settings

`rezzy` is designed for extreme performance out of the
box.

For the even better tuning, use the `release-max-perf`
Cargo profile:

```toml
[profile.release-max-perf]
inherits = "release"
strip = "symbols"
lto = "fat"
codegen-units = 1
panic = "abort"
```

If you are building the binary _for_ a specific machine,
you can unlock native CPU instructions (i.e., `avx-512`)
with:

```bash
RUSTFLAGS="-C target-cpu=native" make build install
```

## Development setup

The `res/` submodule contains large test fixtures. It
uses `update = none` in `.gitmodules` so downstream Cargo
consumers don't fetch it. For local development, init it
with:

```bash
git -c submodule.res.update=checkout submodule update --init --recursive
```

Then generate synthetic fixtures and run the test suite:

```bash
make test
```

## Test coverage

To install and run test coverage:

```bash
cargo install cargo-llvm-cov
make cov
```

## Architecture & Algorithms

Under the hood:

- **MSC4297 / MSC4242 resolution**: Conflicted state subgraph expansion and
  state DAG validation.
- **Power ordering & mainline sort**: Reverse topological power sorting via
  Kahn's algorithm and mainline distance ranking.
- **Resolved-state screening**: Sound post-power ban enforcement
  (`is_sender_banned`) for hardened state resolution.
- **Structural sharing & merge fast-paths**: `Arc`-backed `SharedState` with
  pointer-equality bypass for identical parent states.
- **State DAG traversal**: Iterative, stack-safe ancestor crawling, merge base
  computation, and extremity discovery.
- **Native n-way resolution**: Resolve and merge arbitrary DAG forks in a single
  pass.
- **Streaming & batch state reconstruction**: `compute_state_at_streaming`
  bounds peak memory to the DAG's active frontier width.
- **Compacted state deltas**: Forward delta chains with auto-snapshotting for
  fast checkpoint-based reconstruction.
- **Roaring bitmaps & dense indexing**: SIMD-accelerated set operations for
  reachability, auth differences, and HAMT node audits.
- **Content-addressed state hashing**: Incremental lattice hashing (`LtHash`)
  and Canonical JSON SHA-256 reference hashing.
- **Minisketch set reconciliation**: GF(2^64) PinSketch with SIMD-accelerated
  root finding for federation sync.
- **Generic type decoupling**: Parameterized over `Id: EventId`,
  `K: StateKey`, `C: EventContent`, and `S: BuildHasher`.
- **`no_std` compatible**: Pure `#![no_std]` core with `alloc` support and zero
  system dependencies.

## Synchronous model

Rezzy is **synchronous by design**. It accepts a fully
materialized `HashMap` and returns resolved state without
performing any I/O. This is not a limitation, it's a
design choice.

State resolution does **not** operate on the entire room
history. It operates on the **Auth Difference**:
`auth(C) - auth(U)` — the auth-chain events reachable
from conflicted events `C` that aren't already in the
agreed-upon unconflicted state `U`.

Determining the auth difference is relatively easy and
quick: either compute it on the fly (recursively in
20-50 database hops), or pre-compute and store in a
"chain closure" index (for near-instant runtime
performance).

### The three layers

```text
┌───────────────────────────────────────────────┐
│  Homeserver    (async I/O)                    │
│  Bulk-fetch auth difference in 1-50 queries   │
├───────────────────────────────────────────────┤
│  Rezzy        (sync: pure-CPU)                │
│  Topological sort + iterative auth in µs-ms   │
├───────────────────────────────────────────────┤
│  Homeserver   (async I/O)                     │
│  Persist PDUs/resolved state; notify clients  │
└───────────────────────────────────────────────┘
```

Typical working set: **10–50 conflicting events** for a
normal fork, fitting entirely in `L1` cache.

### Transitive closure: auth chain vs. timeline DAG

Both Synapse and Rust servers pre-compute the transitive
closure of the **auth chain**, but they **cannot**
realistically do this for the **timeline DAG**
(`prev_events`).

#### Transitive auth chain: `O(1)` size (pre-computed)

Homeservers should pre-compute and store the transitive
closure of the auth chain for every event (as a
`RoaringTreemap` of `ShortEventId`s).

The auth chain _should_ only contain state events that
authorize other state events (e.g., `m.room.create`,
`m.room.power_levels`, and membership transitions). Even
in a room with 1,000,000 chat messages, the auth chain
for a given event typically contains fewer than
**50–100 events**.

Live computing and storing of a 100-integer roaring
bitmap `auth_chain` per event is _extremely_ cheap, and
it greatly speeds up real-time federation!

#### How Conduwuit and Synapse bypass need for timeline DAG closure

Because we don't have the timeline DAG's closure, we
have two different techniques at our disposal:

**For state _resolution_:** We only need the
**auth difference** (`auth(C) - auth(U)`). Because we
have the pre-computed transitive auth chain bitmaps for
the conflicted tips `C`, we can perform this set
difference entirely in memory on integers and fetch the
exact list of missing PDUs in a single batch database
query—no timeline walking required.

**For state _reconstruction_ (`state_at`):** Instead of
walking the timeline DAG backward to build state, we use
**compressed state snapshots and delta chains** (keyed by
`shortstatehash`). It fetches a recent state snapshot and
applies a small sequence of forward deltas, bypassing the
need for full traversal.

---

## Completed

### Typed content fields (`EventContent` trait) ✓

The generic `EventContent` trait: homeservers implement
`EventContent` on their own content type to provide
pre-extracted fields (`membership`, `join_rule`, `ban`,
`kick` power levels, etc.) without JSON parsing in the
hot path. `serde_json::Value` remains the default via a
blanket impl.

### Per-Event State Deltas ✓

`resolve_iterative_sort_with_deltas` emits per-step
`ResolutionDelta`s alongside the final resolved state,
capturing `event_id`, acceptance status, replaced event,
and phase (power/non-power) for every conflicted event
processed.

### Batch state compute (`compute_state_at_batch`) ✓

Compute state at `N` events in topological order,
sharing the ancestor traversal and topological sort
across all targets.

### Streaming state compute ✓

Like `compute_state_at_batch` but yields each resolved
state to a callback as soon as it's ready, bounding peak
memory to the streaming of the DAG's live frontier width.

### `auth_types_for_event` ✓

Pure function that returns the list of
`(event_type, state_key)` pairs required in auth state
for a given event type.

### Integer-keyed resolution ✓

`resolve_iterative_sort` is generic over `Id: EventId`,
and `EventId` has a blanket impl for any
`T: Clone + Eq + Hash + Ord + Debug + Display`. This means `u32`,
`u64`, and any interned short ID type work out of the
box:

```rust
use rezzy::{resolve_iterative_sort, LeanEvent, SharedState, StateResVersion, HashMap};

let unconflicted: SharedState<u64> = SharedState::new();
let events: HashMap<u64, LeanEvent<u64>> = HashMap::new();
let auth_ctx: HashMap<u64, LeanEvent<u64>> = HashMap::new();
let mut pl_cache = HashMap::new();

let resolved: SharedState<u64> = resolve_iterative_sort(
    &unconflicted,
    &events,
    &auth_ctx,
    StateResVersion::V2,
    &mut pl_cache,
    &String::new(),
);
```

### Snapshot/checkpoint (partial-join support) ✓

`resolve_iterative_sort` supports this — pass a trusted
state snapshot as `unconflicted_state`. The conflicted
events and auth context only need to cover the divergent
portion of the DAG.

### State delta compression ✓

Full delta chain support with Synapse-like compaction:

- `compute_state_delta` / `apply_state_delta` —
  single-event delta math
- `compute_compacted_delta_chain_from_resolved` — bulk
  backfill with auto-snapshot every
  `MAX_DELTA_CHAIN_HOPS` (default: `100`) events
- `reconstruct_state_at` / `reconstruct_state_batch` —
  reconstruct state from stored delta chains
- All checkpoint types derive `Serialize` /
  `Deserialize` for direct storage in RocksDB, bincode,
  etc.

[MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242
[MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
