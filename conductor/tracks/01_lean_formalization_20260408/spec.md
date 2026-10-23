# Specification: Lean 4 Formalization, Kahn Topological Sort & Trace Compiler (`v0.1.0`–`v0.1.1`)

## 1. Overview & Historical Context

Track `01_lean_formalization_20260408` spans the genesis of the `rezzy` repository from its initial commit (`be1774b`, April 8, 2026) through tags `v0.1.0` (`0c8baa5`, April 10, 2026) and `v0.1.1` (`5cf21de`, April 11, 2026), culminating in the StarGraph trace compiler and Lean 4 arithmetization commits (`5817344`, `871a36a`, `0c0ad6e`, `995f139`, `a88b53a` on April 13–14, 2026).

The project originated as a dual-language formalization and high-performance reference implementation effort (`RumaLean` in Lean 4 alongside a `#![no_std]`-compatible Rust crate):
1. **Formal Verification First (`RumaLean`)**: Before optimizing the Rust state resolution engine, the author modeled Directed Acyclic Graphs (`RumaLean/DirectedAcyclicGraph.lean`), Kahn's topological sort (`RumaLean/Kahn.lean`), Matrix State Resolution (`RumaLean/StateRes.lean`), and topological reduction over symmetric interconnection networks (`RumaLean/TopologicalReduction.lean`, `RumaLean/StarGraph.lean`). Placeholder `sorry` proofs were systematically replaced with executable assertions and ordering proofs (`904fee0`, `566c810`, `5b25c2f`).
2. **Rust `#![no_std]` Kernel & Cycle-Safe Kahn Sort**: Parallel to the Lean 4 proofs, the Rust library (`src/lib.rs`, later modularized into [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) and [`src/resolve/iterative.rs`](../../../src/resolve/iterative.rs)) implemented lexicographical power-event tie-breaking, deterministic Kahn topological sorting with explicit cycle detection (`b9f48cb`), and `#![no_std]` (`alloc`) portability (`5cb5d4a`).
3. **CLI & Experimental StarGraph Trace Compiler**: Commit `5cb5d4a` introduced the initial CLI binary for ingesting room DAGs from `stdin` or JSON files and cross-validating against upstream Ruma (`scripts/e2e_test.py`, `scripts/e2e_shuffled.py`). Commits `5817344` through `a88b53a` explored compiling execution traces over a StarGraph topology (`src/ctopology.rs`, `src/trace_compiler.rs`) and proving $O(\log N)$ diameter complexity bounds in `RumaLean/StarGraph.lean` (`995f139`) before the repository pivoted in Track 02 (`013603f`, `ae41adc`) toward pure Matrix state resolution and away from zero-knowledge AIR trace compilation.

---

## 2. Functional Requirements & Matrix Spec/MSC Mapping

| Requirement ID | Matrix Spec / Formal Target | Functional Description | Implementation & Verification |
| :--- | :--- | :--- | :--- |
| **FR-01.1** | Matrix State Res v2 Step 3 (Reverse Topological Power Sort) | Sort conflicted power events in reverse topological order using Kahn's algorithm with a deterministic min-heap tie-breaker: `(-power_level, origin_server_ts, event_id)`. | `RumaLean/Kahn.lean` (`99e11bd`), [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) (`b9f48cb`, `5cb5d4a`) |
| **FR-01.2** | Graph Cycle Resilience & Deterministic Fallback | Detect malformed or adversarial cycles in the event graph during Kahn sorting (`KahnSortResult::CycleDetected { sorted, stuck }`) and deterministically tie-break stuck nodes without infinite loops. | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) (`b9f48cb`), [`TODO.txt`](../../../TODO.txt) |
| **FR-01.3** | Matrix State Res v2 Step 4 (Mainline Ordering) | Construct the power-level mainline from the resolved `m.room.power_levels` event backward to room creation, computing mainline distances and sorting non-power events by `(mainline_position, origin_server_ts, event_id)`. | `RumaLean/StateRes.lean` (`904fee0`), [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs) |
| **FR-01.4** | Lean 4 `TopologicalReduction` & `StarGraph` Proofs | Formalize topological reduction and prove $O(\log N)$ diameter complexity bounds on the StarGraph network model, enforcing `-DwarningAsError=true` in Lake and generating documentation via `doc-gen4`. | `RumaLean/TopologicalReduction.lean` (`3a5a906`), `RumaLean/StarGraph.lean` (`995f139`), `lakefile.toml` (`dd1ceea`, `698eb0e`) |
| **FR-01.5** | `#![no_std]` Library Core & Feature-Gated CLI | Compile the core state resolution library under `#![no_std]` with `alloc`, gating standard-library CLI argument parsing (`clap`), file/stdin I/O, and live Matrix room fetching (`--room`, `--homeserver`, `--token`) behind the `cli` feature. | [`Cargo.toml`](../../../Cargo.toml), [`src/lib.rs`](../../../src/lib.rs) (`5cb5d4a`, `871a36a`, `0c0ad6e`) |

---

## 3. Architectural Decisions & Rejected Alternatives

1. **Pivot from Hypercube (`Bitwise.lean`) to StarGraph (`StarGraph.lean`) (`995f139`)**:
   - *Context*: Early topological reduction proofs (`5cb5d4a`) modeled node routing over a boolean hypercube (`RumaLean/Bitwise.lean`).
   - *Decision*: Commit `995f139` replaced the hypercube model with the symmetric group StarGraph (`RumaLean/StarGraph.lean`), proving tighter $O(\log N)$ complexity bounds relative to network size and removing `RumaLean/Bitwise.lean`.
2. **Eventual Retirement of In-Crate ZK Trace Compilation (`5817344` -> `013603f`, `ae41adc`)**:
   - *Context*: Commits `5817344` and `a88b53a` added `src/ctopology.rs`, `src/trace_compiler.rs`, and `RumaLean/Arithmetization.lean` to compile state resolution traces into Algebraic Intermediate Representation (AIR) polynomials.
   - *Decision*: As documented in [`TODO.txt`](../../../TODO.txt) (lines 601–626), while boolean/comparison predicates in auth checks *can* be arithmetized into polynomial constraints for succinct verification (SNARKs/STARKs), field arithmetic per branch is orders of magnitude slower than native CPU execution and orthogonal to the core `#![no_std]` state resolution engine. The experimental trace compiler was removed in `013603f` (`2026-05-04`) and the Lean files were moved into the external `res/` research submodule in `ae41adc` (`2026-06-26`).
3. **Strict `#![no_std]` + `alloc` Separation (`5cb5d4a`)**:
   - *Context*: Early prototypes mixed `std` I/O and core resolution logic.
   - *Decision*: `5cb5d4a` enforced `#![no_std]` in `src/lib.rs` so `rezzy` can execute inside constrained, embedded, or WASM/zkVM environments without OS dependencies, isolating CLI and network tooling behind `#[cfg(feature = "cli")]`.

---

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) and [`TODO.txt`](../../../TODO.txt):

- **Liveness Under Malformed / Cyclic Graphs (`b9f48cb`, `TODO.txt` lines 6–18)**:
  - In emergency response federations, a buggy or malicious peer injecting a cycle into `auth_events` or `prev_events` must never hang the homeserver in an infinite loop. `kahn_sort` tracks visited degrees and returns `KahnSortResult::CycleDetected { sorted, stuck }`, sorting remaining `stuck` nodes deterministically.
  - *Audit Observation*: As noted in [`TODO.txt`](../../../TODO.txt) (lines 6–18), `sort()` previously emitted `std::eprintln!("KAHN CYCLE DETECTED! ...")` to stderr when `feature = "std"` is active, while `build_mainline_with_cache` (`src/resolve/sorting.rs:317`) returns a bare `Vec<Id>`, silently truncating the mainline on a cycle instead of surfacing a typed `Result` or cycle diagnostic to the caller.
- **Formal vs. Behavioral Verification Gap (`TODO.txt` lines 41–70)**:
  - While `RumaLean` proved linear ordering of `(depth, event_id)` and candidate tie-breakers (`5b25c2f`), [`TODO.txt`](../../../TODO.txt) documents that `FinalPassFixedPoint.lean` and `ProgressiveAuth.lean` still lacked a unified behavioral theorem proving that single-pass `progressiveFold` terminates with the exact intended state for mutual demotions under V2.1.1's empty-start-state semantics.

---

## 5. Acceptance Criteria & Verification Oracles

1. **Deterministic Topological & Mainline Sorting**:
   - Verified by unit tests in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) and [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) (originating in `99e11bd`, `e52e965`, `b2cb429`, `13ec7d8`), confirming that shuffled DAG inputs produce identical topological orderings and resolved states.
2. **Cycle Detection Termination**:
   - Verified by cycle-injection tests in [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) (`with_cycle_diagnostics` returning `KahnSortResult::CycleDetected`) ensuring zero hangs on 2-node and multi-node cycles (`b9f48cb`).
3. **Cross-Implementation Oracle Parity**:
   - Verified by `scripts/e2e_test.py` and `scripts/e2e_shuffled.py` (`5cb5d4a`) comparing `rezzy` CLI output against Ruma's `state_res` across synthetic and real Matrix room DAGs.
