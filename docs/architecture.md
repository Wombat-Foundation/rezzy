# Architecture: The I/O Sandwich

Rezzy uses a **synchronous, pure-compute** design — it accepts a fully materialized
`HashMap` of events and returns the resolved state without performing any I/O.
This is intentional and architecturally superior to an async lazy-loading design.

## The Auth Difference

Matrix state resolution does not operate on the entire room history.
It operates on the **Auth Difference**: the set of auth-chain events reachable
from the conflicted set that are _not_ already in the unconflicted (agreed-upon)
state.

$$\text{Auth Difference} = \text{auth}(C) - \text{auth}(U)$$

Where:

- **U** (Unconflicted State): events that all forks agree on — already trusted.
- **C** (Conflicted Events): events where the forks disagree.

Because the unconflicted state `U` is already mathematically proven valid,
any auth event inside `U` acts as a **hard stop** for the auth-chain traversal.
You never need to fetch the full historical auth chain back to `m.room.create`.

## How Homeservers Fetch the Auth Difference

Homeservers do not fetch events one-by-one. They use bulk fetching strategies
that complete in 1–3 database round-trips:

### Method 1: Bulk-Fetch BFS

1. Identify all `auth_events` referenced by the conflicted events `C`.
2. Filter out any IDs already present in the unconflicted state `U`.
3. Execute a single batch query: `SELECT * FROM events WHERE id IN (...)`.
4. Extract `auth_events` from the new batch, filter against `U`, repeat.

Auth chains are shallow (Create → PL → Join → event), so this BFS hits the
unconflicted boundary in **2–3 iterations**. Total: ~3 database queries for
even massive forks.

### Method 2: Auth-Chain Indexing (Synapse, Tuwunel, Continuwuity)

When an event is persisted, the server pre-computes its transitive auth chain
and stores it as an indexed column (e.g. `shorteventid_shortauthevents` in
Continuwuity's RocksDB, or integer arrays in Synapse's Postgres). When a fork
occurs, a single query computes the set difference to produce the exact auth
context. Total: **1 database query**.

## Why Async State Resolution is an Anti-Pattern

If `resolve_iterative_sort` were `async` and lazy-loaded events during resolution:

1. Process an event, see an `auth_event` ID, `await` a database fetch.
2. Process the next event, `await` another fetch.
3. Result: the **N+1 Query Problem** — 50 sequential round-trips instead of 1
   batched fetch.

This serializes I/O that could have been parallelized, and makes the resolution
algorithm dependent on the database driver's latency characteristics.

## The I/O Sandwich

By keeping `resolve_iterative_sort` strictly synchronous, the architecture naturally
splits into three clean layers:

```text
┌─────────────────────────────────────────────┐
│  Homeserver I/O Layer (async)               │
│  • Identify state boundaries (U, C)         │
│  • Bulk-fetch auth difference in 1-3 queries│
│  • Materialize HashMap<EventId, LeanEvent>  │
├─────────────────────────────────────────────┤
│  Rezzy CPU Layer (sync, #![no_std])         │
│  • Accepts compact, self-contained HashMap  │
│  • Topological sort + iterative auth checks │
│  • L1 cache-friendly imbl::OrdMap traversal │
│  • Completes in microseconds               │
├─────────────────────────────────────────────┤
│  Homeserver I/O Layer (async)               │
│  • Persist resolved state                   │
│  • Notify clients                           │
└─────────────────────────────────────────────┘
```

The homeserver owns all I/O and uses its database's batching capabilities.
Rezzy owns all CPU-bound computation and uses its `#![no_std]` + `imbl` stack
for maximum cache locality and zero-allocation structural sharing.

## Internal Implementation

The bounded dual-heap traversal in `src/state_at.rs` is the in-memory equivalent
of the homeserver's BFS fetch. When `rezzy` processes a batch, it dynamically
computes `auth(C) \ auth(U)` internally and terminates traversal the instant
it touches the unconflicted boundary — preventing unbounded memory crawls even
on rooms with millions of events.

## The Transitive Closure Index

The I/O sandwich above describes the **normal case**: a single fork arrives,
the homeserver bulk-fetches the auth difference, and `resolve_iterative_sort` runs once.
But there's a second scenario that demands a fundamentally different strategy:
**full room state rebuilds**.

### The Problem: O(F × D) Auth Chain Walks

During a full rebuild (e.g., `rebuild-state`, database repair, or initial
federation sync of a large room), the homeserver must resolve state at _every_
fork point in the DAG — potentially thousands of forks across tens of thousands
of events. If each fork independently walks the auth chain via BFS to compute
the auth difference, the total cost becomes:

$$O(F \times D)$$

Where _F_ is the number of forks and _D_ is the average auth chain depth.
For a 60K-event room with 5,000 forks, this means millions of redundant
traversals through heavily overlapping auth chains.

### The Solution: Pre-Computed Roaring Bitmaps

Instead of re-walking the auth DAG at every fork, the homeserver pre-computes
the **transitive closure** of each event's auth chain in a single bottom-up
pass. Each event is assigned a compact integer index, and its full transitive
auth chain is stored as a compressed `roaring::RoaringBitmap`:

```text
Phase 1: Index all events → eid_to_idx (HashMap<EventId, u32>)
Phase 2: Iterative post-order DFS over auth DAG:
         bitmap[i] = bitmap[auth₁] ∪ bitmap[auth₂] ∪ ... ∪ {auth₁, auth₂, ...}
```

This is an `O(V + E)` operation (one pass over all events and their auth edges),
and produces a `Vec<RoaringBitmap>` that answers any auth chain query in `O(1)`:

| Operation                   | Without Index   | With Index     |
| --------------------------- | --------------- | -------------- |
| Auth chain of event `e`     | `O(D)` BFS      | `O(1)` lookup  |
| Auth diff at fork (`A ⊕ B`) | `O(D)` per fork | `O(1)` XOR     |
| Auth chain intersection     | `O(D)` per fork | `O(1)` AND     |
| Full rebuild (F forks)      | `O(F × D)`      | `O(V + E + F)` |

### Continuwuity's Three-Layer Auth Chain Architecture

Continuwuity uses three complementary representations:

#### 1. Adjacency List: `shorteventid_shortauthevents` (Source of Truth)

- Stores the **direct** auth parents: `event → [auth₁, auth₂, auth₃]` (1 hop)
- Written at `append_pdu` time — just 3-4 `u64`s per event (~32 bytes)
- Always correct (raw data, not derived), composable, tiny on disk
- Used by `get_auth_chain_inner()` to BFS-walk the auth DAG on demand

#### 2. Transitive Closure Cache: `shorteventid_authchain` (Derived)

- Stores the **full transitive closure** as serialized `RoaringTreemap`
- Precomputed from the adjacency list to turn N-hop BFS into a single
  lookup — critical for the live federation path where `get_auth_chain`
  needs the full closure immediately
- Can become stale/corrupt; regenerated by `reindex-short`

#### 3. Ephemeral Rebuild Index: `rebuild_auth_chains()` (In-Memory)

- Computed as `Vec<RoaringBitmap>` with `u32` temporary array indices
- Built from scratch via single `O(V+E)` DFS over raw event JSON
- **Does NOT read either DB table** — computing a throwaway index from
  the in-memory event cache is faster than 60K async DB lookups
- Used only by `resolve_fork_with_states()` during full room rebuilds

The architecture is:

```text
shortauthevents  = adjacency list  (source of truth, tiny, O(1) write)
authchain        = closure cache   (derived, large, O(1) read)
rebuild bitmaps  = ephemeral index (throwaway, built from JSON, O(V+E))
```

### Why This Lives in the Homeserver, Not Rezzy

The transitive closure index is a homeserver-level optimization for batch
workloads. Rezzy's `resolve_iterative_sort` API is designed for single-invocation
resolution with a pre-materialized `HashMap`. The homeserver is responsible for:

1. **Building the index** during the streaming phase (one `O(V+E)` DFS pass).
2. **Using the index** to extract the minimal `HashMap` for each fork.
3. **Passing the extract** to `resolve_iterative_sort` (which completes in microseconds).

This keeps Rezzy's API clean and stateless while allowing homeservers to
amortize auth chain computation across thousands of forks.

### Memory Characteristics

Roaring bitmaps use run-length encoding on sorted integer sequences, achieving
excellent compression on auth chains (which are dense, monotonically increasing
integer sets). For a 60K-event room:

- **Raw**: 60K × 4 bytes × 60K = ~14 GB (dense bitmatrix)
- **Roaring**: ~50–100 MB (compressed, sharing common prefixes)
- **Peak**: bounded by the number of unique auth chain shapes in the DAG

## Typical Working Set Sizes

| Scenario         | Conflicted | Auth Diff | Total   |
| ---------------- | ---------- | --------- | ------- |
| Simple (2 heads) | 2–5        | 5–15      | 10–20   |
| Moderate (3)     | 5–20       | 10–30     | 20–50   |
| Large (10+)      | 50–200     | 50–100    | 100–300 |
| Catastrophic     | 500+       | 100–200   | 500–700 |

Even the worst case fits comfortably in L1/L2 cache.

### Asymptotic Complexity (Iterative vs Lattice Fold)

Let:

- **$N$** = The number of conflicted events (`NumForks` × `ForkDepth`).
- **$A$** = The number of events in the auth chain required to authorize the conflicted events.
- **$E$** = The number of graph edges (parent/child relationships).

#### 1. Iterative Sort (Standard Matrix State Res v2)

**Rough Complexity: $O(N \log N + A \log A + E)$**

The standard approach uses Kahn's algorithm to perform a topological sort over the conflicted events, breaking ties via the Mainline Auth Chain.

- **The bottleneck:** To break ties dynamically, it must pull the entire auth chain ($A$), compute the "mainline", and sort all auth events by depth and power level. This takes $O(A \log A)$.
- It then uses a Priority Queue (or equivalent sort) to yield the conflicted events one by one, adding an $O(N \log N)$ factor.
- Because the auth chain ($A$) scales linearly (or worse) with $N$ in highly branched DAGs, the repetitive tie-breaking and sorting causes performance to degrade rapidly as the graph gets dense.

#### 2. Lattice Fold (`rezzy` specific approach)

**Rough Complexity: $O(N + E)$**

The Lattice Fold completely abandons the global Kahn's topological sort and the massive $O(A \log A)$ auth chain sorting step.

- **The speedup:** It treats the event DAG as a strict mathematical semi-lattice. It traverses the graph structure locally and "folds" branches together at their exact merge points using deterministic pairwise joins.
- Because it only cares about local graph boundaries and structural properties, it visits each conflicted event and edge a constant number of times.
- Assuming hash map lookups are $O(1)$, this scales almost purely linearly $O(N + E)$ relative to the size of the conflict, completely bypassing the heavy global sorting overhead.
