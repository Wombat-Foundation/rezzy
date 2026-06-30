# Rezzy: Matrix State Resolution Engine

[![CI](https://img.shields.io/github/actions/workflow/status/gamesguru/rezzy/rust.yml?branch=master&label=CI)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![Tests](https://raw.githubusercontent.com/gamesguru/rezzy/badges/tests.svg)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/gamesguru/rezzy/graph/badge.svg)](https://codecov.io/gh/gamesguru/rezzy)
[![crates.io](https://img.shields.io/crates/v/rezzy.svg)](https://crates.io/crates/rezzy)

Rezzy is a high-performance, dependency-free Rust engine for Matrix State Resolution — both a research model and highly-efficient reference implementation for Matrix state resolution `v1`, `v2`, `v2.1`, and `v2.1.1` (with experimental `v2.2`), designed for correctness and compliance.

## Features

- Auth check engine.
- Full state resolution pipeline.
- Topological & mainline Sorting.
- `n-way` fork resolution
- In-place bitshift heaps and roaring bitmaps for fast graph computations.
- **Lazy projection**: Fast, memory-efficient state resolution by only loading required membership events.

## API

Everything re-exports from the crate root — `use rezzy::*` gets you `LeanEvent`, `SharedState`, `StateResVersion`, `HashMap`, the works.

- **`resolve_lean`** — the main entry point. Unconflicted state + conflicted events + auth context + version → winning `SharedState`.
- **`resolve_lattice_coordinatized`** — parallel alternative (lattice fold instead of sequential mainline sort).
- **`resolve_lean_with_deltas`** — diagnostic variant, also emits per-event `ResolutionDelta` traces.
- **`compute_state_at`** / **`compute_state_at_streaming`** — reconstruct resolved state at any DAG position. Streaming variant bounds memory to frontier width.
- **`auth::check_auth`** — spec-compliant auth engine. Implement `StateProvider` to plug in your own backend.
- Generic `EventId` trait — `String`, `u32`, `u64`, `ruma::OwnedEventId` all just work.
- `EventContent` trait — skip JSON parsing in the hot path. `serde_json::Value` works via default impl.
- **TODO:** ancillary tools (subgraph, delta, auth graph) are `String`-only currently

## Performance settings

`rezzy` is designed for extreme performance out of the box.

For the even better tuning, use the `release-max-perf` Cargo profile:

```toml
[profile.release-max-perf]
inherits = "release"
strip = "symbols"
lto = "fat"
codegen-units = 1
panic = "abort"
```

If you are building the binary _for_ a specific machine, you can unlock native CPU instructions (i.e., `avx-512`) with:

```bash
RUSTFLAGS="-C target-cpu=native" make build install
```

## Test coverage

To install and run test coverage:

```bash
cargo install cargo-tarpaulin --features vendored-openssl
make cov
```

## Algorithmic & architectural engineering

Because we care about raw performance and mechanical efficiency, `rezzy` is built on a foundation of blazingly fast ideas. Under the hood of our production code, you will find:

- _Causal domination_ operator (CDO) pre-filtering
- Experimental V2.1.1 State Resolution with supplemental narrowing
- Batched/strip-mined **SWAR** (SIMD within a register) matrix sweeps
- `O(1)` _causal coordinatization_ projection
- Filtered _commutative join-semilattice_ folding
- Integer "interning" (`ShortID`) graph-based traversal
- Flat-array "stride matrices"
- Fully-featured, spec-compliant authorization engine
- Reverse topological power ordering (Kahn's algorithm)
- `Arc`-based copy-on-write (CoW) structural sharing
- `O(1)` fast-path _merge resolution_ via "pointer-equality bypass"
- Native **n-way state resolution** (resolve/merge arbitrary DAG forks in a single pass)
- Zero-allocation stack-safe DAG crawling
- Generic `BuildHasher` decoupling
- Supremum deletion attack (Byzantine fault mitigation)
- Optimal conflicted state sub-graph computation (MSC4297)
- **Roaring bitmaps** (SIMD-optimized set operations)
- `FNV-1a` 128-bit lexicographical state hashing
- Compacted delta chains with auto-snapshot (bounded reconstruction cost)
- Per-event resolution tracing (`ResolutionDelta` + phase tracking)
- Checkpoint/partial-join resolution (trusted snapshot as unconflicted base)
- Batch state computation with shared topological traversal
- `no_std` compatible (`alloc`-only, no system dependencies)

## Synchronous model

Rezzy is **synchronous by design**. It accepts a fully materialized `HashMap` and returns resolved state without performing any I/O. This is not a limitation, it's a design choice.

State resolution does **not** operate on the entire room history. It operates on the **Auth Difference**: `auth(C) - auth(U)` — the auth-chain events reachable from conflicted events `C` that aren't already in the agreed-upon unconflicted state `U`.

Determining the auth difference is relatively easy and quick: either compute it on the fly (recursively in 20-50 database hops), or pre-compute and store in a "chain closure" index (for near-instant runtime performance).

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

Typical working set: **10–50 conflicting events** for a normal fork, fitting entirely in `L1` cache.

### Transitive closure: auth chain vs. timeline DAG

Both Synapse and Rust servers pre-compute the transitive closure of the **auth chain**, but they **cannot** realistically do this for the **timeline DAG** (`prev_events`).

#### Transitive auth chain: `O(1)` size (pre-computed)

Homeservers should pre-compute and store the transitive closure of the auth chain for every event (as a `RoaringTreemap` of `ShortEventId`s).

The auth chain _should_ only contain state events that authorize other state events (e.g., `m.room.create`, `m.room.power_levels`, and membership transitions). Even in a room with 1,000,000 chat messages, the auth chain for a given event typically contains fewer than **50–100 events**.

Live computing and storing of a 100-integer roaring bitmap `auth_chain` per event is _extremely_ cheap, and it greatly speeds up real-time federation!

#### How Conduwuit and Synapse bypass need for timeline DAG closure

Because we don't have the timeline DAG's closure, we have two different techniques at our disposal:

**For state _resolution_:** We only need the **auth difference** (`auth(C) - auth(U)`). Because we have the pre-computed transitive auth chain bitmaps for the conflicted tips `C`, we can perform this set difference entirely in memory on integers and fetch the exact list of missing PDUs in a single batch database query—no timeline walking required.

**For state _reconstruction_ (`state_at`):** Instead of walking the timeline DAG backward to build state, we use **compressed state snapshots and delta chains** (keyed by `shortstatehash`). It fetches a recent state snapshot and applies a small sequence of forward deltas, bypassing the need for full traversal.

---

## Completed

### Typed content fields (`EventContent` trait) ✓

The generic `EventContent` trait: homeservers implement `EventContent` on their own content type to provide pre-extracted fields (`membership`, `join_rule`, `ban`, `kick` power levels, etc.) without JSON parsing in the hot path. `serde_json::Value` remains the default via a blanket impl.

### Per-Event State Deltas (`resolve_lean_with_deltas`) ✓

`resolve_lean_with_deltas` emits per-step `ResolutionDelta`s alongside the final resolved state, capturing `event_id`, acceptance status, replaced event, and phase (power/non-power) for every conflicted event processed.

### Batch state compute (`compute_state_at_batch`) ✓

Compute state at `N` events in topological order, sharing the ancestor traversal and topological sort across all targets.

### Streaming state compute (`compute_state_at_streaming`) ✓

Like `compute_state_at_batch` but yields each resolved state to a callback as soon as it's ready, bounding peak memory to the streaming of the DAG's live frontier width.

### `auth_types_for_event` ✓

Pure function that returns the list of `(event_type, state_key)` pairs required in auth state for a given event type.

### Integer-keyed resolution ✓

`resolve_lean` is generic over `Id: EventId`, and `EventId` has a blanket impl for any `T: Clone + Eq + Hash + Ord + Debug`. This means `u32`, `u64`, and any interned short ID type work out of the box:

```rust
let unconflicted: imbl::OrdMap<(String, String), u64> = /* ... */;
let events: HashMap<u64, LeanEvent<u64>> = /* ... */;
let auth_ctx: HashMap<u64, LeanEvent<u64>> = /* ... */;

let resolved: imbl::OrdMap<(String, String), u64> =
    resolve_lean(unconflicted, events, &auth_ctx, StateResVersion::V2);
```

### Snapshot/checkpoint (partial-join support) ✓

`resolve_lean` supports this — pass a trusted state snapshot as `unconflicted_state`. The conflicted events and auth context only need to cover the divergent portion of the DAG.

### State delta compression ✓

Full delta chain support with Synapse-like compaction:

- `compute_state_delta` / `apply_state_delta` — single-event delta math
- `compute_compacted_delta_chain_from_resolved` — bulk backfill with auto-snapshot every `MAX_DELTA_CHAIN_HOPS` (default: `100`) events
- `reconstruct_state_at` / `reconstruct_state_batch` — reconstruct state from stored delta chains
- All checkpoint types derive `Serialize` / `Deserialize` for direct storage in RocksDB, bincode, etc.
