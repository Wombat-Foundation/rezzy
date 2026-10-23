# Specification: Track 16 — P0 Mixed-Federation Split-Brain Guards (`V2.1.1` `SEND01` & `Ed25519`)

## 1. Overview & Public-Safety Rationale
Per [`docs/rezzy_msc4242_security_comparison.md`](../../../docs/rezzy_msc4242_security_comparison.md) and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row #13 & P0 Remediation #4):
1. Experimental `StateResVersion::V2_1_1` intentionally diverges from Stock `V2.1` (`MSC4297`) on the `SEND01` vector. If a Room Version 12 deployment mixes Stock `V2.1` homeservers with `V2.1.1` homeservers, a single `SEND01`-shaped fork permanently splits the room's resolved state.
2. Similarly, mixing ZIP-215 (`ed25519-zebra`) and strict RFC 8032 (`ed25519-dalek`) signature verification rules across federation peers creates an asymmetric acceptance split on non-canonical small-order Ed25519 signatures.

## 2. Functional Requirements
1. **Explicit Experimental Feature Gate for `V2.1.1` and `V2.2` (`MSC4242`)**:
   - Require an explicit `experimental-state-res` feature or distinct experimental room-version identifiers so standard Room Version 12 (`RoomVersion::V12`) strictly maps to Stock `StateResVersion::V2_1`.
2. **Standardize Deterministic Ed25519 Verification Policy**:
   - Document and enforce uniform ZIP-215 / Matrix Spec signature validation semantics in `signing-core` and `docs/spec_audit.md`.

## 3. Acceptance Criteria
- [ ] Standard `RoomVersion::V12` never routes to `V2.1.1` unless an explicit experimental room version is negotiated.
- [ ] Parity tests confirm Stock `V2.1` and `V2.1.1` behavior on `SEND01` are explicitly isolated by room version.
