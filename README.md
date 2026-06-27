# Ruma-Lean: Matrix State Resolution v2.1.1

Ruma-Lean is a dependency-free, high-performance Rust reference engine for Matrix State Resolution. It serves as the reference implementation for the proposed **v2.1.1** standard, addressing critical topological anomalies and accumulator-retention defects found in production implementations (like Ruma v2.1 and Synapse).

_Note: Lean theorem-proving and ZK (Zero-Knowledge) acceleration experiments are no longer at the forefront of this repository, which is now primarily focused on stable algorithmic research, correctness, and reference compliance._

## Architectural Innovations

Ruma-Lean introduces several mathematically rigorous solutions to state resolution, heavily leveraging applied graph theory and distributed systems security:

### 1. The Causal Domination Operator (CDO)

A vectorized topological filter executing on the Conflicted State Subgraph. By enforcing a strict partial order of administrative actions via a Bounded BFS algorithmic fix, CDO eliminates bypass windows like Phantom Join Rules and Mod Membership Evaporation.

### 2. $I_{\text{PL}}$ Fallback Context (Semantic vs. Syntactic)

Production engines often conflate **Syntactic Representation** (JSON payloads) with **Semantic Authority** (evaluated permissions), leading to strict schema panics when `m.room.power_levels` are redacted. Ruma-Lean decouples evaluation from validation: $I_{\text{PL}}$ is defined purely as an Evaluation-Time Closure parameterized by the immutable `m.room.create` event. It bypasses schema assertions while preserving total function safety.

### 3. $\mathcal{O}(1)$ Lazy Projection

To solve the accumulator-retention defect without the massive memory bottleneck of _Eager State Supplementation_, Ruma-Lean employs a Lazy Projection closure (`.or_else(|| unconflicted_state.get(&key))`). This $\mathcal{O}(1)$ memory/time logical union safely preloads unconflicted memberships into the initial auth overlay ($S_0$), completely neutralizing state reset attacks without scaling penalties.

### 4. Z3 SMT Verification

Instead of interactive game-theoretic models, safety is proven using a post-hoc Z3 SMT/CDCL topological framework. By universally quantifying over the unbounded space of all topologically valid partial orders (DAG configurations), the solver inherently proves deterministic safety against _any_ adversarial server collusion or network scheduler.

## Limitations: Model vs. Upstream Code

To ensure the highest level of scientific integrity, we explicitly distinguish between this research model and production homeserver libraries:

- **`ruma-lean` Model:** This repository serves as a _formal verification reference model_. While it strictly replicates the core state resolution equations and implements the proposed CDO and Lazy Projection logic, it operates in a clean, dependency-free environment. Its evaluation results should be read as **ruma-lean Model (v2.1)** and **ruma-lean Model (v2.1.1)**. It does not contain the millions of lines of real-world asynchronous networking code found in production libraries.
- **Synapse Baseline:** In contrast, references to Synapse in our test harnesses invoke the _actual, unmodified upstream production `matrix-synapse` Python library_, capturing authentic production exploits.

## Usage

## Usage

```bash
# Run the core standard compliance test suite
cargo test

# Run the upstream runner against official Ruma integration tests
cargo test --test upstream_runner --features="mock-ruma"
```
