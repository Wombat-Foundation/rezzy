<!-- markdownlint-disable MD013 MD033 -->

# Ruma "Lean"

[![Rust](https://github.com/gamesguru/ruma-lean/actions/workflows/rust.yml/badge.svg)](https://github.com/gamesguru/ruma-lean/actions/workflows/rust.yml)
[![Lean](https://github.com/gamesguru/ruma-lean/actions/workflows/lean.yml/badge.svg)](https://github.com/gamesguru/ruma-lean/actions/workflows/lean.yml)
[![Docs](https://github.com/gamesguru/ruma-lean/actions/workflows/docs.yml/badge.svg)](https://github.com/gamesguru/ruma-lean/actions/workflows/docs.yml)
[![E2E](https://github.com/gamesguru/ruma-lean/actions/workflows/e2e.yml/badge.svg)](https://github.com/gamesguru/ruma-lean/actions/workflows/e2e.yml)

Formal proofs of **Kahn's sort** and **State Res** (v1, v2, and v2.1) using `Lean 4`.

Reference standard and light-weight implementation in `rust`.

Used in zero-knowledge proofs by host homeservers, so they can sign off on zkVM-proofs as deterministically equivalent in output to their own.

## Matrix Federation `send_join`

The `ruma-lean` CLI computes the exact `send_join` response payload required for "full joins" over the Matrix Server-Server (Federation) API.

When a server joins a room via `/send_join`, the resident homeserver must compute the resolved room state at the join event and recursively traverse the DAG to provide the `auth_chain` for that state. This state resolution and auth chain generation is the most computationally expensive part of serving full joins for large rooms. `ruma-lean` optimizes this exact workload and outputs the required JSON payload (using `--format federation`).

### The Fundamental Bottleneck

Matrix's State Resolution V2 requires resolving conflicted events via **Kahn's Topological Sort** over the `auth_events` DAG. In rooms with thousands of state events (and heavy `prev_events`/`auth_events` branching), finding cycles and breaking sorting ties using Deep Lexicographical Tie-Breaks (`power_level`, `origin_server_ts`, `event_id`) becomes a massive computational chokepoint. Doing this safely without breaking protocol consensus requires heavily defensive graph-traversal logic.

`ruma-lean` replaces this bottleneck by extracting the topological graph structures into hyper-optimized `BTreeMap` and `HashMap` iterations in native Rust, stripped of application-level overhead. Most crucially, because the core invariants (like acyclic verification and tie-breaker sorting logic) are formally verified via **Lean 4**, it removes the need for defensive, bloated tie-break checks during runtime—providing mathematical certainty that the highly-optimized execution exactly conforms to the Matrix spec, allowing it to easily outpace standard implementations like Synapse or Conduwuit.

### ZKVM Execution & Trace Compiler

To support verifiable execution within a zkVM (Zero-Knowledge Virtual Machine), the Matrix DAG is embedded into a multi-column execution trace. This trace is designed for maximum STARK performance:

- The graph topology is modeled as an **$S_5$ Star Graph** (a permutation graph of 120 nodes), where state transitions are constrained strictly to `(0, i)` swaps.
- The trace compiler uses a `[BabyBear; 4]` multi-column state matrix (`is_active`, `permutation_id`, `event_id`, `swap_index`) to bound the **Routing Tax** (dummy padding nodes) required to linearize the irregular Kahn-sorted DAG.
