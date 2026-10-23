# Specification: Track 17 — P1 Tier-2 Pre-Auth Validation & Multi-Round Bucket-Split E2E Tests

## 1. Overview & Public-Safety Rationale
Per [`docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md), [`docs/tech_debt.md`](../../../docs/tech_debt.md), and [`rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Rows #8, #16 & P1 Remediation #5):
1. Tier-2 homeserver guard utilities (`src/auth/validate.rs` for pre-auth PDU structural validation and `src/dag/fork.rs` for fork width/branch diagnostics) are specified in `docs/homeserver_utilities.md` but not yet implemented.
2. In `rezzy-recon`, `docs/tech_debt.md` identifies an open testing gap: an end-to-end session test exercising a capacity-exceeded bucket split (`MAX_BUCKET_CAP`) that subsequently hits `MAX_PREFIX_DEPTH` on a deeper round and verifies `reconcile_Complete` holds off until the overflow sub-range resolves.

## 2. Functional Requirements
1. **Multi-Round Capacity-then-Depth E2E Reconciliation Test**:
   - Add the adversarial multi-round capacity-then-depth retry test to `rezzy-recon/tests/test_reconcile_e2e.rs` and close the open item in `docs/tech_debt.md`.
2. **Tier-2 Pre-Auth PDU Validation & Fork Diagnostics**:
   - Implement `src/auth/validate.rs` (`validate_pdu_invariants`) and `src/dag/fork.rs` (`detect_forks` / frontier width guard) to protect homeservers against wide-frontier OOM before invoking synchronous state resolution.

## 3. Acceptance Criteria
- [ ] `test_reconcile_e2e.rs` exercises capacity-split followed by depth-limit fallback to completion.
- [ ] `src/auth/validate.rs` and `src/dag/fork.rs` are implemented, exported, and covered by unit tests.
