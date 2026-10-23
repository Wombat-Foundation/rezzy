# Track 07: Roaring Bitmap Auth-Difference, Lazy EventProvider & Homeserver Utilities

- **Track ID**: `07_roaring_lazy_provider_20260703`
- **Type**: `feature`
- **Status**: `completed` (Historical Stage A Track — Audited)
- **Commit Range**: `3caa4ca..95a8ffb` (`2026-07-03` – `2026-07-04`)

## Quick Links

- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public Safety & Documentation Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques

- [Track Review & 8-Persona Critique (`./review.md`)](./review.md)

## Key Artifacts & Source Files

- `src/auth/roaring.rs` & `src/auth/mod.rs` — `AuthGraph<Id>` Roaring bitmap reachability and `auth_difference`
- `rezzy-recon/src/bitmap/mod.rs` & `src/bitmap/mod.rs` — Two-tier (`Array` / `Dense`) Roaring bitmap and `Chunk::union_assign`
- `src/resolve/multi.rs` — `EventProvider`, `partition_state_maps`, and `resolve_state_maps_lazy_with_diff`
- `src/state/cache.rs` — `LeanEventCache<Id, C>` bounded LRU cache implementing `EventProvider`
- `src/state/at.rs` — `compute_auth_chain_diff` and `find_forward_extremities_roaring`
- `src/raw_event.rs` & `src/basespec/rezzy_types.rs` — `LeanEventRef`, `MatrixEventView`, and `OwnedMatrixEvent::extract_batch`
- `docs/architecture.md` & `docs/homeserver_utilities.md` — Integration architecture and homeserver utility reference
