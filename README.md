# Rezzy: Matrix State Resolution Engine

Rezzy is a high-performance, dependency-free Rust engine for Matrix State Resolution — both a research model and highly-efficient reference implementation for Matrix state resolution `v2`, `v2.1`, and `v2.1.1`, designed for correctness and compliance (soon to support `v2.2` or State DAGs, too).

## Features

- **Causal domination operator (CDO)**: Safely and optimally resolves conflicting state in DAGs.
- **Lazy projection**: Fast, memory-efficient state resolution by only loading required membership events.
- **Topological & mainline Sorting**: Fast and robust DAG sorting to order events correctly.
- **Pure lattice-coordinatized projection**: Employs `O(1)` causal coordinatization projection and commutative join-semilattice folding.

## Usage

### Build

```bash
cargo build --release
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

- _Causal domination_ operator (CDO) filtering
- Batched/strip-mined **SWAR** (SIMD within a register) matrix sweeps
- `O(1)` _causal coordinatization_ projection
- Filtered _commutative join-semilattice_ folding
- Integer "interning" (`ShortID`) graph-based traversal
- Flat-array "stride matrices"
- Reverse topological power ordering (Kahn's algorithm)
- `Arc`-based copy-on-write (CoW) structural sharing
- `O(1)` fast-path _merge resolution_ via "pointer-equality bypass"
- Zero-allocation stack-safe DAG crawling
- Generic `BuildHasher` decoupling
- Supremum deletion attack (Byzantine fault mitigation)
- Optimal conflicted state sub-graph computation (MSC4297)
- **Roaring bitmaps** (SIMD-optimized set operations)
- `FNV-1a` lexicographical state hashing

## TODO

### Per-Event State Deltas (`resolve_lean_with_deltas`)

Currently `resolve_lean` only outputs the final resolved state snapshot. For observability and debugging (e.g. visualizing state evolution through a fork), we need a variant that emits per-step deltas:

- Hook into the iterative auth-check loop and capture insertions/replacements at each step
- Emit a `Vec<ResolutionDelta>` alongside the final `BTreeMap` result
- Each delta captures: event_id applied, (type, state_key) modified, old value evicted, new value inserted, phase (power/non-power)
- Useful for: timeline replay, state-res visualization, debugging ban/PL conflicts

### Typed Content Fields (`LeanEventTyped`)

Replace `content: serde_json::Value` with pre-extracted typed fields to eliminate JSON parsing in the hot path.
See [`res/docs/TYPED_CONTENT_FIELDS.md`](res/docs/TYPED_CONTENT_FIELDS.md) for the full design proposal.

## Completed

### Batch State Computation (`compute_state_at_batch`) ✓

Compute state at N events in topological order, sharing the ancestor traversal and topological sort across all targets. See [`compute_state_at_batch`](src/state_at.rs).

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
- `compute_compacted_delta_chain` — bulk backfill with auto-snapshot every `MAX_DELTA_CHAIN_HOPS` (100) events
- `reconstruct_state_at` / `reconstruct_state_batch` — reconstruct state from stored delta chains
- All checkpoint types derive `Serialize` / `Deserialize` for direct storage in RocksDB, bincode, etc.
