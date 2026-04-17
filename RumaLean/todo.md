# Ruma-Lean: ZK Formalization Roadmap (Latest Pivot)

## Architectural Vision: The Hypercube Supremacy

Following a deep dive into ZK scalability and verification complexity, we are pivoting back to the Boolean Hypercube (H_d) for event routing.

### Why Hypercubes?

- Logarithmic Verification: Modern ZK protocols (GKR, Sum-Check, Binius, Jolt, Lasso) are optimized for hypercubes, achieving O(log N) verification.
- Memory Harmony: Hypercubes map perfectly to binary address spaces (2^d = N), whereas Star Graphs (n!) suffer from catastrophic padding overhead.
- Spectral Stability: Hypercubes maintain excellent expansion properties at scale, unlike Star Graphs whose spectral gap decays at 1/n.

### Repository Cleanup

- Moved StarGraph.lean and its dependents to RumaLean/unstable/.
- Re-focusing on Hypercube.lean and Bitwise.lean for the formal trace embedding.

## Done

- [x] Deterministic Kahn Sort (Kahn.lean).
- [x] State Resolution Convergence Proof (StateRes.lean).
- [x] Formalized Finset as the input for arrival-order independence.

## Next Steps

- [ ] Hypercube Trace Embedding: Formally prove that any Matrix DAG can be embedded into a Hypercube with O(log N) routing steps.
- [ ] ZKVM Arithmetization: Refine Arithmetization.lean to target O(log N) sum-check rounds over the hypercube.
- [ ] Rust Integration: Update src/ctopology.rs to reflect the hypercube/GKR routing logic.

---

Note: This roadmap reflects the theoretical pivot from the O(1) constant-time goal (Expanders/Star Graphs) to the O(log N) logarithmic-time reality (Hypercubes) for engineering efficiency.
