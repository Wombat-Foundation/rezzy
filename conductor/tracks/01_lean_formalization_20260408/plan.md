# Implementation Plan: Lean 4 Formalization, Kahn Topological Sort & Trace Compiler (`v0.1.0`–`v0.1.1`)

## Phase 1: Initial Lean 4 Formalization & Ordering Foundations [checkpoint: 0c8baa5]

- [x] Task: Scaffold repository, Lake build environment, and initial `RumaLean` DAG/StateRes modules be1774b
  - [x] Initialize `lakefile.toml`, `lean-toolchain`, `RumaLean.lean`, `RumaLean/Basic.lean`, `RumaLean/Graph.lean`, `RumaLean/Kahn.lean`, and `RumaLean/StateRes.lean` (`be1774b`)
  - [x] Configure GitHub Actions CI workflows (`.github/workflows/ci.yml`) and Node/Lean runners (`4431d6b`, `d2ab8ac`, `a8da438`)
- [x] Task: Formalize Kahn topological sort and StateRes executable test suites in Lean 4 99e11bd
  - [x] Rename `RumaLean/Graph.lean` to `RumaLean/DirectedAcyclicGraph.lean` and expand DAG invariants (`99e11bd`)
  - [x] Add executable `#eval` and theorem test cases in `RumaLean/Kahn.lean` and `RumaLean/StateRes.lean` (`99e11bd`)
- [x] Task: Replace placeholder `sorry` proofs with real assertions and migrate to Lean 4 ordering principles 904fee0
  - [x] Replace `sorry` stubs in `RumaLean/StateRes.lean` with concrete assertions and calls (`904fee0`)
  - [x] Update comparator definitions to use Lean 4's `Ordering` principles (`566c810`) and document initial architecture in `README.md` (`2ea7a51`)
- [x] Task: Build initial Rust Kahn sort and StateRes prototype with 90% test coverage and Apache/MIT licensing 0c8baa5
  - [x] Implement Rust Kahn topological sort and baseline state resolution in `src/lib.rs` with unit tests (`e52e965`, `b2cb429`)
  - [x] Clean up Clippy lints to reach 54/60 (90%) line coverage (`3d94e87`) and tag release `v0.1.0` with crate licensing (`0c8baa5`)

## Phase 2: Topological Reduction, `doc-gen4` & Strict Lean CI Linting [checkpoint: 13ec7d8]

- [x] Task: Introduce `RumaLean/TopologicalReduction.lean` and equivalence proof documentation 3a5a906
  - [x] Format equivalence proof tables in `README.md` (`c4fe731`) and configure Cargo package exclusions (`db22d6c`)
  - [x] Implement `RumaLean/TopologicalReduction.lean` modeling DAG reduction steps (`3a5a906`, `163fefa`)
- [x] Task: Expand Lean 4 formal proofs and enforce zero-warning compilation dd1ceea
  - [x] Add auxiliary lemmas and proofs across `RumaLean` modules (`5127725`, `8ff661f`, `5164a2f`)
  - [x] Enable `-DwarningAsError=true` in `lakefile.toml` (`dd1ceea`) and wire Lean linting into `Makefile` and CI (`77af12e`)
- [x] Task: Integrate `doc-gen4` and dry-run publishing automation 13ec7d8
  - [x] Add `doc-gen4` dependency to `lakefile.toml` and `lake-manifest.json` (`698eb0e`)
  - [x] Add `make publish` target defaulting to `--dry-run` (`91f43dc`) and expand Cargo unit tests + Lean doc comments (`13ec7d8`)

## Phase 3: Cycle Detection, `#![no_std]` Core & Feature-Gated CLI (`v0.1.1`) [checkpoint: 5cf21de]

- [x] Task: Implement deterministic cycle detection and fix trait contracts in Rust topological sort b9f48cb
  - [x] Import benchmark scripts from parent research repository (`1aa23fe`) and synchronize Lean/Rust models (`2ebea6a`, `b97e17d`)
  - [x] Implement cycle detection in Kahn sort (`b9f48cb`), ensuring cyclic graphs terminate deterministically
- [x] Task: Gate `#![no_std]` (`alloc`) core library and build feature-gated CLI binary (`v0.1.1`) 5cb5d4a
  - [x] Refactor [`src/lib.rs`](../../../src/lib.rs) for `#![no_std]` + `alloc` compatibility and add `src/main.rs` behind `--features cli` (`5cb5d4a`)
  - [x] Add `scripts/e2e_test.py`, `scripts/e2e_shuffled.py`, and `scripts/fetch_matrix_state.py` for shuffled E2E oracle verification against Ruma (`5cb5d4a`)
  - [x] Split GitHub Actions into dedicated `rust.yml`, `lean.yml`, and `e2e.yml` workflows and merge `dev` for `v0.1.1` (`803a240`, `5cb5d4a`, `5cf21de`)

## Phase 4: StarGraph Trace Compiler, CLI Room Queries & AIR Complexity Proofs [checkpoint: a88b53a]

- [x] Task: Implement StarGraph trace compiler prototype and `ctopology` module 5817344
  - [x] Add initial `TODO` documentation (`60c6961`)
  - [x] Implement `src/ctopology.rs` and `src/trace_compiler.rs` compiling execution traces over a StarGraph topology (`5817344`)
- [x] Task: Enhance CLI with direct Matrix `--room` federation queries and `Events` default output 0c0ad6e
  - [x] Implement `Default` for `StarGraph` and add `--room`, `--homeserver`, and `--token` CLI options using `ureq` (`871a36a`)
  - [x] Add `OutputFormat::Events` as the default JSON array output format in `src/main.rs` (`0c0ad6e`)
- [x] Task: Prove $O(\log N)$ StarGraph complexity bounds and add AIR commitment formalizations in Lean 4 995f139
  - [x] Replace `RumaLean/Bitwise.lean` hypercube model with `RumaLean/StarGraph.lean` and prove $O(\log N)$ diameter bounds in `RumaLean/TopologicalReduction.lean` (`995f139`)
  - [x] Add `RumaLean/Arithmetization.lean`, `RumaLean/Commitment.lean`, and `RumaLean/StarGraphEmbedding.lean` (`a88b53a`)

---

## History & Audit Traceability

| Commit SHA | Date | Core Files Modified | Verification / Test Files | Linked Docs & Public-Safety Audit Findings |
| :--- | :--- | :--- | :--- | :--- |
| `be1774b` | 2026-04-08 | `RumaLean.lean`, `RumaLean/Kahn.lean`, `RumaLean/StateRes.lean` | `RumaLean/Kahn.lean` | Initial formalization foundation ([`README.md`](../../../README.md)) |
| `99e11bd` | 2026-04-08 | `RumaLean/DirectedAcyclicGraph.lean`, `RumaLean/Kahn.lean`, `RumaLean/StateRes.lean` | `RumaLean/StateRes.lean` | Formal DAG & Kahn sort test cases |
| `904fee0` | 2026-04-08 | `RumaLean/StateRes.lean` | `RumaLean/StateRes.lean` | Elimination of `sorry` placeholders with concrete assertions |
| `0c8baa5` | 2026-04-10 | `src/lib.rs`, `Cargo.toml`, `Makefile` | [`tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) | Tag `v0.1.0`; baseline Rust Kahn + StateRes |
| `3a5a906` | 2026-04-10 | `RumaLean/TopologicalReduction.lean`, `Cargo.toml` | `RumaLean/TopologicalReduction.lean` | Topological reduction formalization |
| `dd1ceea` | 2026-04-10 | `lakefile.toml`, `Makefile` | CI `lean.yml` | Strict `-DwarningAsError=true` enforcement in Lean 4 |
| `b9f48cb` | 2026-04-10 | [`src/resolve/sorting.rs`](../../../src/resolve/sorting.rs), `Makefile` | [`tests/unit/test_traversal.rs`](../../../tests/unit/test_traversal.rs) | Cycle detection (`KahnSortResult::CycleDetected`); see [`TODO.txt`](../../../TODO.txt) lines 6–18 on `build_mainline_with_cache` cycle truncation & [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) |
| `5cb5d4a` | 2026-04-10 | [`src/lib.rs`](../../../src/lib.rs), `src/main.rs`, [`Cargo.toml`](../../../Cargo.toml) | `scripts/e2e_test.py`, `scripts/e2e_shuffled.py` | `#![no_std]` (`alloc`) core split and feature-gated CLI (`v0.1.1` via `5cf21de`) |
| `5817344` | 2026-04-13 | `src/ctopology.rs`, `src/trace_compiler.rs` | `src/trace_compiler.rs` | StarGraph trace compiler prototype (later retired in `013603f`; see [`TODO.txt`](../../../TODO.txt) lines 601–626) |
| `871a36a` | 2026-04-13 | `src/main.rs`, `src/ctopology.rs` | `src/main.rs` | CLI `--room` live Matrix state query option (`0c0ad6e` default `Events` format) |
| `995f139` | 2026-04-13 | `RumaLean/StarGraph.lean`, `RumaLean/TopologicalReduction.lean` | `RumaLean/StarGraph.lean` | $O(\log N)$ StarGraph diameter proof replacing `Bitwise.lean` (`a88b53a` AIR commitment logic) |
