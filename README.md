# Ruma-Lean: ZK-Accelerated Matrix State Resolution

Ruma-Lean is a high-performance, formally verified implementation of Matrix State Resolution (v2.1), featuring a native Zero-Knowledge STARK prover.

## The Architecture: "The Whitepaper with Teeth"

Unlike traditional Zero-Knowledge projects that rely on heavy RISC-V emulators (zkVMs), Ruma-Lean uses a **Custom AIR (Algebraic Intermediate Representation)**. This separates the mathematical truth from the cryptographic execution.

### Layer 1: The Formal Specification (Lean 4)

The `RumaLean/` directory contains the mathematical bedrock of the protocol.

- **`Kahn.lean` & `StateRes.lean`**: Proves that the sorting and resolution logic is strictly deterministic and arrival-order independent (using `Finset`).
- **`Arithmetization.lean`**: Proves that the polynomial constraints ($X \cdot (X-1) = 0$) perfectly represent the state transition logic.
- **`Merkle.lean` & `MergeBase.lean`**: Formalizes the cryptographic boundary and fork-resolution logic.

### Layer 2: The Cryptographic Engine (Rust)

The `src/` directory contains the high-speed implementation of the math proved in Lean.

- **Custom STARK Prover**: Built with **Plonky3** and **Binius**, targeting the **Boolean Hypercube** for $O(\log N)$ verification.
- **Trace Compiler**: Natively compiles Matrix event DAGs into a continuous hypercube walk, including the 31,000 "padding nodes" required for hypercube symmetry.

## Performance & Scalability

By mapping the Matrix DAG onto a **Boolean Hypercube**, Ruma-Lean achieves:

- **Logarithmic Verification**: Servers verify proofs in milliseconds, regardless of room size.
- **No zkVM Tax**: Bypassing RISC-V emulation reduces prover overhead by 100x-1000x.
- **Heterogeneous Federation**: Different languages (Python, Go, JS) can verify the same **Verification Key (VK)** metadata, ensuring global consensus without identical binaries.

## Usage

```bash
# Run the formally verified Kahn sort and State Res
cargo run --release -- -i res/benchmark_1k.json

# Generate a ZK trace benchmark (Hypercube routing tax)
cargo run --release -- --benchmark-trace -i res/benchmark_1k.json
```
