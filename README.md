# Rezzy: Matrix State Resolution Engine

[![CI](https://img.shields.io/github/actions/workflow/status/gamesguru/rezzy/rust.yml?branch=master&label=CI)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/rezzy.svg)](https://crates.io/crates/rezzy)
[![codecov](https://codecov.io/gh/gamesguru/rezzy/graph/badge.svg)](https://codecov.io/gh/gamesguru/rezzy)

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

- **`resolve_lean`** is the main entry point. Give it unconflicted state, conflicted events, auth context, and a version — get back the winning `SharedState`.
- **`resolve_lattice_coordinatized`** is the parallel alternative — same inputs, same output, different strategy (lattice fold instead of sequential mainline sort).
- **`resolve_lean_with_deltas`** is the diagnostic variant — also returns per-event `ResolutionDelta` traces showing what won, what got rejected, and why.
- **`compute_state_at`** / **`compute_state_at_streaming`** — walk the DAG backwards and reconstruct resolved state at any event. The streaming variant yields states via callback so memory stays bounded to the DAG frontier width.
- **`auth::check_auth`** — full spec-compliant authorization engine. Implement the `StateProvider` trait to plug in your own state backend.
- Generalized `EventId` trait — blanket impl for `Clone + Eq + Hash + Ord + Debug`, so `String`, `u32`, `u64`, `ruma::OwnedEventId` all just work.
- `EventContent` trait — implement on your own content type to skip JSON parsing in the hot path. `serde_json::Value` works out of the box via default impl.
- **TODO:** ancillary tools (subgraph, delta, auth graph) are `String`-only currently

## Usage

### Build

```bash
cargo build --release
```

_Note: Building the `rezzy` binary automatically injects `mimalloc` as the global allocator for a 10-20% throughput boost. The `rezzy` library crate remains strictly allocator-agnostic and will use whatever allocator your project configures._

### Maximum Performance

`rezzy` is designed for extreme performance, but to squeeze every last drop out of the engine, homeserver authors and binary consumers should opt-in to advanced compiler optimizations in their own `Cargo.toml`:

```toml
[profile.release]
lto = "fat"
codegen-units = 1
```

For even higher performance use this:

```toml
[profile.release-max-perf]
inherits = "release"
strip = "symbols"
lto = "fat"
codegen-units = 1
panic = "abort"
```

Additionally, if you are building the binary for the specific machine it will run on, you can unlock native CPU instructions (like AVX-512) by building with:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Test

```bash
make test         # Run unit and integration tests
make rust/e2e     # Run E2E parity tests
```

### Test Coverage

To install and run test coverage via `cargo-tarpaulin`:

```bash
cargo install cargo-tarpaulin --features vendored-openssl
cargo tarpaulin
```

### Format & Lint

```bash
make format
make lint
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

## Architecture: The I/O Sandwich

Rezzy is **synchronous by design**. It accepts a fully materialized `HashMap` and returns resolved state without performing any I/O. This is not a limitation — it's the architecturally correct choice.

### Why not async?

State resolution does **not** operate on the entire room history. It operates on the **Auth Difference**: `auth(C) \ auth(U)` — the auth-chain events reachable from conflicted events `C` that aren't already in the agreed-upon unconflicted state `U`.

Because `U` is already trusted, auth chains only need to be walked until they intersect `U`. Auth chains are shallow (Create → PL → Join → event = 3-4 hops), so homeservers can bulk-fetch the entire auth difference in **1–3 database queries**:

| Approach                      | Queries | Used by      |
| ----------------------------- | ------- | ------------ |
| Bulk BFS against `U` boundary | 2–3     | Rust servers |
| Pre-computed auth-chain index | 1       | Synapse      |

If `resolve_lean` were async, every `auth_events` lookup would become a sequential `await` — triggering the **N+1 query problem** (50 serial DB calls instead of 1 batch). The synchronous API forces callers to batch-fetch upfront, which is always faster.

### The three layers

```text
┌───────────────────────────────────────────────┐
│  Homeserver (async I/O)                       │
│  Bulk-fetch auth difference in 1-3 queries    │
├───────────────────────────────────────────────┤
│  Rezzy (sync CPU, #![no_std])                 │
│  Topological sort + iterative auth in µs      │
├───────────────────────────────────────────────┤
│  Homeserver (async I/O)                       │
│  Persist resolved state, notify clients       │
└───────────────────────────────────────────────┘
```

Typical working set: **10–50 events** for a normal fork, fitting entirely in L1 cache. See [`docs/architecture.md`](docs/architecture.md) for details.

## Completed

### Typed Content Fields (`EventContent` trait) ✓

The generic `EventContent` trait replaces the need for a monolithic `LeanEventTyped`. Homeservers implement `EventContent` on their own content type to provide pre-extracted fields (`membership`, `join_rule`, `ban`, `kick` power levels, etc.) without JSON parsing in the hot path. `serde_json::Value` remains the default via a blanket impl.

### Per-Event State Deltas (`resolve_lean_with_deltas`) ✓

`resolve_lean_with_deltas` emits per-step `ResolutionDelta`s alongside the final resolved state, capturing event_id, acceptance status, replaced event, and phase (power/non-power) for every conflicted event processed. See [`resolve_lean_with_deltas`](src/resolve.rs).

### Batch State Computation (`compute_state_at_batch`) ✓

Compute state at N events in topological order, sharing the ancestor traversal and topological sort across all targets. See [`compute_state_at_batch`](src/state_at.rs).

### Streaming State Computation (`compute_state_at_streaming`) ✓

Like `compute_state_at_batch` but yields each resolved state to a callback as soon as it's ready, bounding peak memory to the live DAG frontier width. See [`compute_state_at_streaming`](src/state_at.rs).

### `auth_types_for_event` ✓

Pure function that returns the list of `(event_type, state_key)` pairs required in auth state for a given event type. See [`auth_types_for_event`](src/auth/mod.rs).

### Integer-Keyed Resolution ✓

`resolve_lean` is generic over `Id: EventId`, and `EventId` has a blanket impl for any `T: Clone + Eq + Hash + Ord + Debug`. This means `u32`, `u64`, and any interned short ID type work out of the box:

```rust
let events: HashMap<u64, LeanEvent<u64>> = /* ... */;
let resolved = resolve_lean(unconflicted, events, &auth_ctx, StateResVersion::V2);
```

### Checkpoint / Partial-Join Support ✓

`resolve_lean` already supports this by design — pass a trusted state snapshot as `unconflicted_state`. The conflicted events and auth context only need to cover the divergent portion of the DAG.

### State Delta Compression ✓

Full delta chain support with Synapse-compatible compaction:

- `compute_state_delta` / `apply_state_delta` — single-event delta math
- `compute_compacted_delta_chain_from_resolved` — bulk backfill with auto-snapshot every `MAX_DELTA_CHAIN_HOPS` (default: 100) events
- `reconstruct_state_at` / `reconstruct_state_batch` — reconstruct state from stored delta chains
- All checkpoint types derive `Serialize` / `Deserialize` for direct storage in RocksDB, bincode, etc.
