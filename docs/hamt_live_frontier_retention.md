# HAMT live-frontier retention in the live walk

Status: implemented. `rezzy-cli/src/format.rs`, `run_hamt_live_walk`
(`format.rs:128`); commits `610b1b5` (Kahn order), `8e8de61` (citation GC +
conditional buffering), `ffadb38` (helper dedupe/format).

This covers the live event walk that builds one HAMT root per event. It does not
cover `compute_state_at_streaming`, the separate streaming state-reconstruction
path described in the README.

## Traversal order

`run_hamt_live_walk` reorders the event set with `reorder_by_kahn` before
walking it (`format.rs:143`; definition at `format.rs:1048`):

```rust
let sorted_events = reorder_by_kahn(&raw_events, tie_break, ctx.stream_order);
```

Kahn's algorithm emits parents strictly before their children, driven only by
the explicit `prev_events` DAG — independent of wire depth. Depth,
`origin_server_ts`, and the requested stream component are consulted solely as
tie-breakers among events that are simultaneously ready on the frontier queue
(`build_key` / `kahn_order_by`). That strict ordering is what makes the
out-degree accounting below sound: when child C is visited, every parent P in
`C.prev_events` has already been evaluated.

Before the loop it precomputes every event's out-degree over deduplicated
parents (`format.rs:161`):

```text
child_citations[P] = |{ C in DAG | P in C.unique_prevs }|
```

Repeated occurrences of the same `prev_event` in one event's list count once. A
parent missing from a partial DAG gets a count but is never visited; it is
ignored gracefully (saturating decrement, never underflow).

## Frontier retention

For each processed event:

- `root_hashes_map` (`format.rs:174`) always records the event's 32-byte
  `StructuralHash` string. Parent references (`format.rs:206`) and output
  emission read from it.
- `roots_map` (`format.rs:172`) keeps the `Arc<HamtNode>` only while
  `child_citations[event] > 0` (`format.rs:319`).
- Visiting an event decrements each parent's count and evicts the parent's `Arc`
  from `roots_map` when the count reaches 0 (`format.rs:331`).

| State                | Condition                 | Held as                                                                                   |
| -------------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| Active frontier root | `child_citations[P] > 0`  | `Arc<HamtNode>` in `roots_map`; usable as a parent's base root (read/mutate)              |
| Retired root         | `child_citations[P] == 0` | dropped from `roots_map`; only the `StructuralHash` survives, in `root_hashes_map`/output |

Ordering safety: a parent's root is read by its final child before that child
decrements the count to 0 and evicts it.

Output lifetimes are decoupled from live roots: evicting an `Arc` from
`roots_map` never removes or alters its `root_hashes_map` entry, and the emitted
`roots`/`nodes`/`checkpoints` are JSON values, so a retired root stays
addressable by its 32-byte hash downstream.

## Bounds

- Live root/spine references: O(frontier_width × log₃₂ S) CHAMP nodes.
- Per-event allocation: O(log₃₂ S) path-copied spine nodes; unchanged subtrees
  are shared via `Arc`.
- The bound covers _live references only_. `root_hashes_map` still grows with N
  (32-byte hashes), and with `--format hamt` the emitted node output grows with
  the total number of unique nodes — both independent of the frontier width.

## Node buffering

`need_nodes = matches!(ctx.args.format, OutputFormat::Hamt)` (`format.rs:171`)
gates decoding and accumulation of `PersistedInternalNode` JSON, for both merged
roots (`format.rs:263`) and per-event mutations (`format.rs:289`). Under
`--format deltas` no node list is built; under `--format hamt` the final
`{roots, nodes}` output requires the records, so they are retained.

## Preconditions

- The walk must be topologically ordered (it is).
- No path may retain an `Arc<HamtNode>` past `roots_map`. The emitted
  `roots`/`nodes`/`checkpoints` are JSON values, not `Arc`s (holds).

## Verification

Clean at `ffadb38`: `cargo test -p rezzy-cli` (105 pass),
`cargo +nightly fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
`jscpd` (0 clones).

## Related

The boundary-pinned multi-collection read snapshot (an mtxdb API) is documented
separately in the Sithnapse tree at
`res/docs/2026-09-30-hamt-retention-and-boundary-pinned-read-snapshot.md`.
