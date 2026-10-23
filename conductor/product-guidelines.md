# Product Guidelines: `rezzy`

## 1. Architectural & Engineering Principles
1. **Fail-Closed by Construction**:
   - Security-critical authorization invariants (such as cross-room `auth_events` rejection in `MSC4307` Rule 2.5, Room V12 creator immunity in Rules 10.1–10.5, and canonical JSON `[-2^53+1, 2^53-1]` integer bounds) must be **unconditionally enforced by the type system** rather than opt-in via `Option<T>` or permissive fallback APIs.
2. **Strict "I/O Sandwich" Purity (`#![no_std]` + `alloc`)**:
   - The core `rezzy`, `rezzy-json`, and `rezzy-recon` crates must remain synchronous, deterministic, and free of network/filesystem I/O, thread spawning, or ambient wall-clock state.
3. **Zero Retired/Unsound Code in Production `src/`**:
   - Experimental or retired algorithms that have known soundness counterexamples (such as the Causal Domination Operator in `cdo.rs`, retired after Anomalies 19 & 20) must be isolated in `tests/` or `benches/`, never compiled into the production library tree.
4. **Adversarial Liveness & Bounded Resource Consumption**:
   - All graph traversals, hash maps on network-supplied keys, HAMT frontier caches, Argon2 key derivation buffers, and `MSC4521` prefix-split queues must enforce explicit memory, depth, and CPU bounds.

## 2. Documentation & Traceability Standards
- **Spec-to-Code Traceability**: Every Matrix specification section and MSC implemented in `rezzy` must map to concrete modules in `src/`, verified test vectors in `tests/`, and an accurate status entry in [`docs/spec_coverage.csv`](../docs/spec_coverage.csv).
- **Candid Risk Disclosure**: Documentation in [`docs/`](../docs/) must clearly distinguish between **implemented and enforced guarantees**, **caller-delegated responsibilities** (e.g., Ed25519 signature verification, pre-fetch subgraph bounds), and **planned roadmap items** (`validate.rs`, `fork.rs`).

## 3. Multi-Perspective Review Gate
Every Conductor track is subject to structured evaluation across eight engineering and governance perspectives:
1. **Product Management (`critic-pm`)**
2. **Principal Engineering Lead (`critic-eng-lead`)**
3. **Public-Safety & C2 Compliance (`critic-compliance`)**
4. **Performance & Adversarial Liveness (`critic-perf`)**
5. **Formal Verification & Cryptographic Soundness (`critic-formal-crypto`)**
6. **Federation Protocol Interop (`critic-federation-interop`)**
7. **Adversarial Red-Team & Verification QA (`critic-redteam-qa`)**
8. **Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)**
