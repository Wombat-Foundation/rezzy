# Implementation Plan: `rezzy-cli` (Deterministic JSONL Aggregation, `.rezzy-meta.jsonl` Sidecar & Signed Federation Crawler)

## Phase 1: Raw JSONL Aggregation, Slug Discovery & Atomic Durability [checkpoint: 681ea0a]

- [x] Task: Implement `rezzy aggregate` workflow, strict merge policy, and Kahn causal sorting `dd74d21`
  - [x] Create `rezzy-cli/src/aggregate.rs` and `docs/jsonl-aggregation.md` to discover raw `.jsonl` inputs, deduplicate by `event_id`, reject conflicting payloads, and order events via Kahn topological sort (`dd74d21`, `34532cf`, `51b44c3`, `7446e03`, `7c6e324`).
  - [x] Enforce one strict merge policy across aggregation and multi-`--input` resolution (`305b4e6`, `d93196e`) and add lifecycle test coverage (`6767bf0`, `257274d`, `bba030b`).
- [x] Task: Add atomic temp-file durability, overlap guards, and self-identifying room slugs `5f8704e`
  - [x] Write outputs via temporary `.tmp-*` files with `fsync` and atomic rename, surfacing durability warnings (`5f8704e`).
  - [x] Make room-named aggregates self-identifying (`2c843fa`, `fbb7fb9`) and reject bare input/output directory and file overlap (`5a13509`, `24dd0e4`, `5e4f8ae`, `a73a57f`).
- [x] Task: Add `-i` explicit inputs, directory scan mode, shell completions, and `--check` status reporting `d7404a6`
  - [x] Implement `rezzy completions` and `aggregate -i` explicit file grouping (`d7404a6`), plus default `--input-dir` multi-room scan mode (`944c8e3`).
  - [x] Report `"status": "current"` in `--check` mode and document `--quiet` and per-status JSON report fields (`397eb7a`, `681ea0a`, `4d8a000`).

## Phase 2: Event ID Repair, Canonical Output & `.rezzy-meta.jsonl` Provenance Sidecar [checkpoint: e3d1a55]

- [x] Task: Implement missing Matrix event ID repair and automatic room version inference `43ad27c`
  - [x] Create `rezzy-cli/src/repair.rs` to reconstruct missing `$`-prefixed event IDs from Matrix reference hashes (`43ad27c`).
  - [x] Infer repair room versions during aggregation from `m.room.create` or filename tokens (`8eeec74`) and reject unsupported V1/V2 sender-chosen event ID repair (`a959792`).
- [x] Task: Canonicalize aggregate event output and build `.rezzy-meta.jsonl` provenance sidecar `5a5a9db`
  - [x] Canonicalize merged event JSON output and compare events by their Matrix redacted canonical form (`5a5a9db`).
  - [x] Implement `rezzy-cli/src/provenance.rs` and `rezzy-cli/src/timeline_order.rs` to strip non-envelope fields (`__rejected`, `__soft_fail`, `__pducount`) into `<output>.rezzy-meta.jsonl`, track `source_disagreement`, and support `--timeline-order causal|synapse` (`e3d1a55`).

## Phase 3: Signed Federation Crawler, TLS Gating & Durable Checkpointing [checkpoint: e8501f5]

- [x] Task: Build `X-Matrix` signed federation client, `get-remote-dag`, and `gap-fill` workflows `49d8a6e`
  - [x] Implement `rezzy-cli/src/federation.rs` with Ed25519 `X-Matrix` request signing, remote DAG backfill (`get-remote-dag`), and multi-round missing event/auth chain recovery (`gap-fill`) (`49d8a6e`, `5d6c269`).
  - [x] Gate federation behind the `tls` feature (`3e0aaef`), refuse plaintext HTTP, preserve logical `Host` headers across SRV delegation, and cache negative delegation lookups without caching transient failures (`f64d6b7`, `e8501f5`, `91a808f`).
- [x] Task: Stream federation fetches to disk and checkpoint crawl frontiers durably `bc471bf`
  - [x] Flush fetched events after every backfill batch or auth response in `get-remote-dag` and `gap-fill`, and atomically checkpoint the remaining frontier via temp-file + rename for safe `--from-file` resume (`bc471bf`, `1d94a64`).
  - [x] Document `rezzy inspect gaps` and skip duplicate per-event fallback requests (`bc471bf`, `19b7f36`, `2674a56`, `ba4d594`).

## Phase 4: Passphrase-Encrypted Signing Keys (Argon2id + XChaCha20-Poly1305) & CLI Hardening [checkpoint: 35a0457]

- [x] Task: Replace OS keyring with Argon2id + XChaCha20-Poly1305 encrypted signing keyfiles `e44c5e1`
  - [x] Replace initial OS keyring integration (`e197f8a`, `bc276b8`) with `rezzy-cli/src/keyfile.rs` (`federation encrypt-key`), sealing signing keys with Argon2id + XChaCha20-Poly1305 and cutting workspace dependencies from 200 to 127 crates (`e44c5e1`).
  - [x] Bound the Argon2id password verification memory buffer on read from 2 GiB down to 64 MiB (`2703bb2`).
- [x] Task: Harden provenance verification, Kahn tie-breaks, and CLI path aliasing guards `cb9ee5d`
  - [x] Harden CLI provenance sidecar payload-hash binding (`cb9ee5d`, `94dc056`, `0b6a2bc`) and enforce deterministic `event_id` tie-breaking in `kahn_order_by` (`7f41793`).
  - [x] Reject `--emit-missing` paths that alias `--output`, add regression tests for cross-sidecar stream conflicts (`7b79c42`), and refactor oversized CLI functions (`35a0457`).

## History & Audit Traceability

| Commit SHA | Source / Implementation Files | Verification / Test Files | Linked `docs/` Files | Public-Safety Audit Observation (`../../audits/rezzy_docs_public_safety_audit.md`) |
| :--- | :--- | :--- | :--- | :--- |
| `dd74d21`, `305b4e6`, `24dd0e4`, `944c8e3`, `397eb7a`, `5a5a9db` | [`rezzy-cli/src/aggregate.rs`](../../../rezzy-cli/src/aggregate.rs), [`rezzy-cli/src/jsonl_merge.rs`](../../../rezzy-cli/src/jsonl_merge.rs) | [`rezzy-cli/src/lib.rs`](../../../rezzy-cli/src/lib.rs) | [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md) | **Moderate (Forensic Integrity)**: Deduplicating by redacted canonical JSON merges events that differ in `signatures` or `unsigned`, requiring downstream consumers to verify `.rezzy-meta.jsonl` observations. |
| `e3d1a55`, `cb9ee5d`, `94dc056`, `7f41793`, `7b79c42`, `35a0457` | [`rezzy-cli/src/provenance.rs`](../../../rezzy-cli/src/provenance.rs), [`rezzy-cli/src/timeline_order.rs`](../../../rezzy-cli/src/timeline_order.rs), [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) | [`rezzy-cli/src/provenance.rs`](../../../rezzy-cli/src/provenance.rs), [`rezzy-cli/src/format.rs`](../../../rezzy-cli/src/format.rs) | [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md) | **Moderate (Replay Pollution)**: Stripping `__rejected` and `__soft_fail` markers into `.rezzy-meta.jsonl` (or omitting them under `--no-provenance`) risks replaying rejected events if `merged-<room>.jsonl` is ingested without sidecar filtering. |
| `43ad27c`, `8eeec74`, `a959792`, `0b6a2bc` | [`rezzy-cli/src/repair.rs`](../../../rezzy-cli/src/repair.rs) | [`rezzy-cli/src/repair.rs`](../../../rezzy-cli/src/repair.rs) | [`docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md) | Repairs missing V3+ content-hashed event IDs while failing closed on V1/V2 sender-chosen IDs (`a959792`). |
| `49d8a6e`, `3e0aaef`, `bc471bf`, `f64d6b7`, `e8501f5`, `e44c5e1`, `2703bb2` | [`rezzy-cli/src/federation.rs`](../../../rezzy-cli/src/federation.rs), [`rezzy-cli/src/network.rs`](../../../rezzy-cli/src/network.rs), [`rezzy-cli/src/keyfile.rs`](../../../rezzy-cli/src/keyfile.rs) | [`rezzy-cli/src/federation.rs`](../../../rezzy-cli/src/federation.rs), [`rezzy-cli/src/network.rs`](../../../rezzy-cli/src/network.rs) | [`docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md), [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md) | Enforces TLS, logical `Host` SRV verification, atomic crawl checkpointing, and 64 MiB-bounded Argon2id + XChaCha20-Poly1305 signing key encryption (`2703bb2`). |
