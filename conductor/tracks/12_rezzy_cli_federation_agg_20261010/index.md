# Track 12: `rezzy-cli`: Deterministic JSONL Aggregation, `.rezzy-meta.jsonl` Sidecar & Signed Federation Crawler (`0.6.0-rc.1`)

## Track Handshake & Navigation

- **Track ID**: `12_rezzy_cli_federation_agg_20261010`
- **Status**: `completed`
- **Epoch**: Sep–Oct 2026 (`0.6.0-rc.1` – `0.6.0-rc.2`, Commit Range `dd74d21..35a0457`)
- **Track Artifacts**:
  - [Track Specification (`./spec.md`)](./spec.md)
  - [Implementation Plan (`./plan.md`)](./plan.md)
  - [Track Metadata (`./metadata.json`)](./metadata.json)
- **Public-Safety & Architectural Audit**:
  - [Master Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md) — **Risk Rating: Moderate (Forensic Integrity & Replay Pollution)**
- **Primary Documentation & Source Files**:
  - [`../../../docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md) — Raw JSONL deduplication, `.rezzy-meta.jsonl` provenance sidecar, gap inspection, `hash lthash`, and timeline ordering
  - [`../../../docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — CLI federation crawler, key encryption, and event ID repair reference
  - [`../../../rezzy-cli/src/aggregate.rs`](../../../rezzy-cli/src/aggregate.rs) — `rezzy aggregate` room discovery (`--room`, `-i`, scan), redacted canonical deduplication, Kahn sort, and atomic write/check
  - [`../../../rezzy-cli/src/provenance.rs`](../../../rezzy-cli/src/provenance.rs) — `.rezzy-meta.jsonl` manifest, per-source observation records, and `source_disagreement` detection
  - [`../../../rezzy-cli/src/federation.rs`](../../../rezzy-cli/src/federation.rs) — Signed `X-Matrix` federation requests, `get-remote-dag`, `gap-fill`, and durable atomic frontier checkpointing
  - [`../../../rezzy-cli/src/keyfile.rs`](../../../rezzy-cli/src/keyfile.rs) — Argon2id (64 MiB cap) + XChaCha20-Poly1305 passphrase-encrypted signing key storage
  - [`../../../rezzy-cli/src/repair.rs`](../../../rezzy-cli/src/repair.rs) — Missing Matrix event ID reference-hash reconstruction and room version inference
  - [`../../../rezzy-cli/src/timeline_order.rs`](../../../rezzy-cli/src/timeline_order.rs) — Causal Kahn vs. Synapse `stream_ordering` timeline sorting

## Executive Summary

Track 12 captures the end-to-end engineering of [`rezzy-cli`](../../../rezzy-cli/src/lib.rs) for forensic Matrix room corpus acquisition, deduplication, and inspection. Between September 24 and October 12, 2026, the CLI gained: (1) `rezzy aggregate` ([`rezzy-cli/src/aggregate.rs`](../../../rezzy-cli/src/aggregate.rs), [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md)), which merges raw `unmerged/*.jsonl` captures into causally sorted `merged/merged-<room>.jsonl` files while preserving stripped non-envelope fields (`__rejected`, `__soft_fail`, `__pducount`) and source disagreements in a `<output>.rezzy-meta.jsonl` provenance sidecar (`e3d1a55`); (2) automatic Matrix event ID repair and room version inference (`43ad27c`, `8eeec74`); (3) a TLS-gated, `X-Matrix`-signed federation crawler (`get-remote-dag`, `gap-fill`, `inspect gaps`) with streaming writes and atomic frontier checkpointing (`49d8a6e`, `3e0aaef`, `bc471bf`); and (4) an architectural pivot from OS keyring storage (`e197f8a`, `bc276b8`) to portable Argon2id + XChaCha20-Poly1305 encrypted keyfiles (`e44c5e1`) with a 64 MiB Argon2 memory cap (`2703bb2`).

## Reviews & Critiques

- [Multi-Perspective Track Review (`./review.md`)](./review.md) — 8-persona architectural, forensic chain-of-custody, federation interop, and public-safety critique (identifies `T12-F1`..`T12-F5`, including redacted-over-unredacted event shadowing in `jsonl_merge.rs` and `__rejected` stripping replay pollution risks).

