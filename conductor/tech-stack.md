# Technology Stack: `rezzy`

## 1. Workspace & Crate Topology
- **Language & Toolchain**: Rust (`edition = "2021"` / `"2024"` compatible, `rust-version = "1.88"`, `#![deny(unsafe_code)]` at workspace lint level).
- **Core Library (`rezzy` — root crate)**:
  - `#![no_std]` + `alloc` Matrix state resolution engine (`V1`, `V2`, `V2.1`, `V2.1.1`, `V2.2`/`MSC4242`).
  - Modules: `src/auth/` (Room V1–V12 PDU authorization), `src/resolve/` (Kahn lexical sort, mainline sort, iterative auth, lattice fold), `src/state/` (persistent HAMT delta trees, `OverlayState`, `RoaringBitmap` auth-difference), `src/lthash.rs` (`MSC4500` homomorphic checksums).
- **Canonical JSON Engine (`rezzy-json`)**:
  - `#![no_std]` + `alloc` dependency-minimal JSON parser, canonical serializer, RFC 6901 JSON Pointer accessor, and Matrix event redaction/signing engine.
- **Set Reconciliation & Causal Trie Engine (`rezzy-recon`)**:
  - `#![no_std]` + `alloc` implementation of `MSC4521` $\text{GF}(2^{64})$ PinSketch set reconciliation (Berlekamp-Massey + Chien search + `h64` prefix-grinding ladder) and `MSC4511` v2 leaf-compressed Patricia causal tries.
- **CLI & Federation Harness (`rezzy-cli`)**:
  - Binary (`rezzy`) providing `rezzy aggregate` JSONL deduplication, `.rezzy-meta.jsonl` provenance sidecar generation, TLS-gated signed Matrix federation DAG crawling, and Argon2/ChaCha20-Poly1305 passphrase-encrypted signing keys.
- **Formal Verification Heritage (`RumaLean/`)**:
  - Lean 4 + Mathlib4 formalization of topological reduction (`TopologicalReduction.lean`) and `StarGraph` complexity bounds (established in Epoch 1).

## 2. Core Dependencies
- **Hashing & Cryptography**: `sha2` (`0.11`), `blake3` (`1.5`), `ed25519-zebra` (`5`), `argon2` (`0.6`, 64 MiB bounded), `chacha20poly1305` (`0.11`), `getrandom` (`0.4`), `zeroize`.
- **Collections & Numeric**: `hashbrown` (`0.17`, `default-hasher` / `foldhash`), `ryu` (`1.0`), `base64` (`0.23`).
- **CLI & Runtime (`rezzy-cli` only)**: `clap` (`4.5`), `ureq` (`3`), `rpassword` (`7.5`), `mimalloc` (`0.1`).

## 3. Build, Lint, and Verification Infrastructure
- **Build & Test**: `cargo test --workspace --lib --tests`, `cargo clippy --all-targets --all-features`.
- **Benchmarks**: `benches/` (Criterion / custom micro & macro state-resolution and HAMT delta benchmarks).
- **Formatting & Static Analysis**: `rustfmt`, `prettier`, `markdownlint`, `shellcheck`, `typos`, `cargo-machete`, `jscpd`.
