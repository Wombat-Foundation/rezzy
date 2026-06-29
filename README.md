# Rezzy: Matrix State Resolution Engine

[![CI](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml/badge.svg)](https://github.com/gamesguru/rezzy/actions/workflows/rust.yml)
[![Docs](https://github.com/gamesguru/rezzy/actions/workflows/docs.yml/badge.svg)](https://gamesguru.github.io/rezzy/)
[![crates.io](https://img.shields.io/crates/v/rezzy.svg)](https://crates.io/crates/rezzy)

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

### Per-Event State Deltas (`resolve_with_deltas`)

Currently `resolve_lean` only outputs the final resolved state snapshot. For observability and debugging (e.g. visualizing state evolution through a fork), we need a variant that emits per-step deltas:

- Hook into the iterative auth-check loop and capture insertions/replacements at each step
- Emit a `Vec<StateDelta>` alongside the final `BTreeMap` result
- Each delta captures: event_id applied, (type, state_key) modified, old value evicted, new value inserted
- Useful for: timeline replay, state-res visualization, debugging ban/PL conflicts

### Checkpoint / Partial-Join Support

For simulating partial joins (e.g. federated rooms where a server doesn't have the full history):

- Allow starting resolution from a trusted state snapshot (checkpoint) as the unconflicted base
- Still require the full auth chain for any _conflicting_ events that diverge from the checkpoint
- Truncating the auth chain for conflicted events breaks topological ordering and can cause state resets (ref: CVE-2025-49090)
- API: accept an optional `checkpoint: BTreeMap<(String, Option<String>), String>` as the pre-resolved base state

### Auth Chain Subset Safety

Document and enforce the invariant: you can trust a snapshot for the unconflicted base, but the auth chain for conflicted events must be complete and uninterrupted. Partial auth chains lead to:

- Sorting failures (cannot establish mainline order)
- Auth check failures (missing historical power levels)
- Potential state reset attacks

### `auth_types_for_event`

Expose a pure function that returns the list of `(event_type, state_key)` pairs required in auth state for a given event type. Currently only available in ruma's `state_res` — adding it to rezzy would eliminate the last ruma `state_res` dependency for downstream consumers.

### Integer-Keyed Resolution (`resolve_lean_indexed`)

Accept `HashMap<u32, LeanEvent>` instead of `HashMap<String, LeanEvent>`. All internal lookups use `u32` keys instead of hashing 44-byte base64 event ID strings.

- The caller builds a `String → u32` intern table once and remaps all event IDs
- `LeanEvent::auth_events` and `LeanEvent::prev_events` become `Vec<u32>` instead of `Vec<String>`
- **Impact**: 10-40x faster HashMap lookups in debug mode, measurable improvement in release

This is especially valuable for homeservers like continuwuity that already maintain `shorteventid: u64` mappings — they can go straight from DB shorts to rezzy without any string conversion.

### Typed Content Fields (`LeanEventTyped`)

Replace `content: serde_json::Value` with pre-extracted typed fields to eliminate JSON parsing in the hot path:

```rust
pub struct LeanEventTyped {
    pub membership: Option<String>,
    pub users_pl: Option<BTreeMap<String, i64>>,
    pub join_rule: Option<String>,
    pub ban_level: Option<i64>,
    pub kick_level: Option<i64>,
    pub events_default: Option<i64>,
    pub creator: Option<String>,
}
```

The caller's PDU type already has typed access to these fields (via ruma deserialization). Currently the adapter serializes them back to JSON, and rezzy re-parses them — a completely redundant round-trip.

### Batch State Computation (`compute_state_at_batch`)

Compute state at N events in topological order, reusing the resolved state from previous events. This is the incremental state walk pattern that homeservers implement manually in their `rebuild-state` commands.

Internalizing this in rezzy would:

- Eliminate per-event adapter overhead (PDU→LeanEvent conversion, auth chain fetch)
- Allow rezzy to skip resolution entirely when an event has a single parent (fast-path)
- Enable internal caching of power level context across consecutive events
