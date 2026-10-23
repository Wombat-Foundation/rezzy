# Product Definition: `rezzy`

## 1. Executive Vision
`rezzy` is a high-assurance, `#![no_std]`-compatible (`alloc`) Rust reference implementation of Matrix protocol state resolution (`V1`, `V2` / [MSC1693](https://spec.matrix.org/proposals/), `V2.1` / [MSC4297](https://matrix.org/docs/spec-guides/state-res-2.1/), experimental `V2.1.1`, and experimental `V2.2` / [MSC4242](https://spec.matrix.org/proposals/)), accompanied by `rezzy-json` (strict/permissive canonical JSON), `rezzy-recon` ([MSC4521](https://matrix.org/blog/2026/07/31/this-week-in-matrix-2026-07-31/) $\text{GF}(2^{64})$ PinSketch set reconciliation and [MSC4511](https://matrix.org/blog/2026/07/24/this-week-in-matrix-2026-07-24/) leaf-compressed causal tries), and `rezzy-cli` (federation DAG crawling and JSONL corpus aggregation).

In public-safety, emergency response, defense, and government command-and-control (C2) deployments of Matrix, **state resolution is the distributed access-control, permission enforcement, and revocation kernel**.

## 2. Core Product Pillars
1. **Deterministic Consensus Kernel (`rezzy`)**:
   - Synchronous, zero-I/O ("I/O Sandwich") execution model ensuring deterministic state resolution across heterogeneous federation homeservers (Room Versions 1–12 + experimental `MSC4242`).
   - Full PDU authorization engine (`src/auth/`), Kahn topological & mainline sorting (`src/resolve/`), persistent HAMT delta state compression (`src/state/`), `RoaringBitmap` auth-difference calculation, and `MSC4500` homomorphic `LtHash` checksumming.
2. **Cryptographic Canonical Serialization (`rezzy-json`)**:
   - Dependency-minimal canonical JSON parser and writer enforcing RFC 8785 / Matrix Spec canonical JSON rules, explicit integer bounds (`[-2^53 + 1, 2^53 - 1]`), and redaction/signing pipelines.
3. **Algebraic Set Reconciliation & Causal Proofs (`rezzy-recon`)**:
   - Bandwidth-minimal $\text{GF}(2^{64})$ BCH/PinSketch set reconciliation (`MSC4521`) with bounded `h64` prefix-grinding fallback ladders and leaf-compressed Patricia causal tries (`MSC4511`).
4. **Federation Diagnostics & Forensic Corpus Tooling (`rezzy-cli`)**:
   - Deterministic `rezzy aggregate` JSONL deduplication with `.rezzy-meta.jsonl` provenance sidecars, TLS-gated signed federation DAG crawlers, and Argon2 passphrase-protected signing keys.

## 3. Public-Safety Threat Model & Operational Invariants
Every architectural feature and track in `rezzy` is evaluated against three primary operational failure modes documented in [Public-Safety & Architectural Audit](./audits/rezzy_docs_public_safety_audit.md):
1. **Federation Split-Brain (Consensus Divergence)**: Participating dispatch homeservers must never compute divergent resolved states for the same incident room due to tie-break ambiguities, canonical JSON rounding, or mixed room-version semantics.
2. **State Reset / Revocation Bypass ([CVE-2025-49090](https://matrix.org/blog/2025/08/project-hydra-improving-state-res/))**: Revoked or compromised principals must never retain administrative privileges or bypass room boundary checks (`MSC4307` Rule 2.5).
3. **Asymmetric Denial of Service (Liveness Collapse)**: Pathological DAG structures, wide "hydra" frontiers, hash collisions, or prefix-grinding attacks must never exhaust CPU, RAM, or reconciliation queues during partition recovery.
