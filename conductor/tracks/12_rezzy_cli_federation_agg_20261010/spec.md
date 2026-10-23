# Specification: `rezzy-cli` (Deterministic JSONL Aggregation, `.rezzy-meta.jsonl` Sidecar & Signed Federation Crawler)

## 1. Overview & Historical Context

- **Epoch**: September 24, 2026 – October 12, 2026 (`0.6.0-rc.1` – `0.6.0-rc.2`)
- **Primary Commit Trajectory**: `dd74d21`, `6767bf0`, `34532cf`, `51b44c3`, `4d8a000`, `7446e03`, `7c6e324`, `d93196e`, `5f8704e`, `305b4e6`, `2c843fa`, `24dd0e4`, `d7404a6`, `944c8e3`, `397eb7a`, `681ea0a`, `49d8a6e`, `e197f8a`, `43ad27c`, `8eeec74`, `a959792`, `5a5a9db`, `e3d1a55`, `3e0aaef`, `bc276b8`, `bc471bf`, `1d94a64`, `2674a56`, `ba4d594`, `f64d6b7`, `19b7f36`, `e8501f5`, `e44c5e1`, `2703bb2`, `cb9ee5d`, `94dc056`, `7f41793`, `0b6a2bc`, `7b79c42`, `35a0457`
- **Motivation**:
  1. **Forensic Corpus Management (`unmerged/` -> `merged/`)**: Incident response and state-resolution benchmarking require combining raw JSONL dumps from multiple homeservers (`local-room-v12.jsonl`, `remote-room-v12.jsonl`, database exports with `__rejected` or `__pducount` columns) without mutating the original evidence files.
  2. **Deterministic Causal Ordering & Provenance Preservation**: Different homeservers attach different `unsigned` blocks, `signatures`, and local stream orderings (`__pducount`, `__stream_ordering`) to the same Matrix event. Merging requires comparing events by their Matrix redacted canonical form while preserving per-source metadata and flagging disagreements in a companion `.rezzy-meta.jsonl` sidecar.
  3. **Resumable Federation Backfill & Portable Key Security**: Fetching missing `prev_events` and `auth_events` across Matrix federation (`get-remote-dag`, `gap-fill`) requires `X-Matrix` Ed25519 request signing, SRV/well-known delegation with TLS enforcement, streaming output flushing, and crash-safe frontier checkpointing, backed by a dependency-lean encrypted keyfile rather than heavyweight OS keyring bindings.

## 2. Functional Requirements & Matrix Spec/MSC Mapping

1. **`rezzy aggregate` Workflow & Selection Modes (`rezzy-cli/src/aggregate.rs`, `docs/jsonl-aggregation.md`)**:
   - **Three Input Selection Modes**:
     1. `--room <slug>`: Selects all `.jsonl` files in `--input-dir` matching `<slug>` as a delimiter-bounded substring; returns a bare single-room JSON report.
     2. `-i <files...>`: Groups explicit files by derived room slug (requiring a `-v<number>` token); aborts if any file lacks a versioned slug.
     3. Directory Scan (default when neither `--room` nor `-i` is given): Scans `--input-dir`, aggregates every versioned room family, and records unversioned files in `skipped[]`.
   - **Redacted Canonical Deduplication & Conflict Rejection (`305b4e6`, `5a5a9db`)**:
     - Deduplicates events by `event_id` after comparing their Matrix redacted canonical form (reference-hash input). Events differing only in `unsigned`, `signatures`, or non-envelope top-level fields merge cleanly; conflicting canonical payloads are rejected with `error` status and `[warn]` diagnostics.
   - **Causal Kahn Topological Sort (`7c6e324`, `7f41793`)**:
     - Orders merged events via Kahn topological sort so parents always precede children, tie-breaking concurrent events deterministically by `(origin_server_ts, depth, event_id)`.
   - **Atomic Output & `--check` Mode (`397eb7a`, `24dd0e4`)**:
     - Prevents input/output directory overlap (`24dd0e4`), writes via temporary `.tmp-*` files with `fsync` + atomic rename (`5f8704e`), and supports non-destructive `--check` verification returning `"status": "current"`.
2. **`.rezzy-meta.jsonl` Provenance Sidecar & Timeline Ordering (`rezzy-cli/src/provenance.rs`, `rezzy-cli/src/timeline_order.rs`)**:
   - Strips non-envelope top-level fields (`__rejected`, `__soft_fail`, `__pducount`, `__pdu_count`, `__stream_ordering`, `__stream_order`, and unknown top-level keys) from `merged-<room>.jsonl` while keeping `signatures`, `unsigned`, and custom `content` fields intact (`e3d1a55`).
   - Writes `<output>.rezzy-meta.jsonl` starting with a manifest line (schema, `room_id`, `room_version`, input file SHA-256 hashes) followed by per-event observation records (`signatures`, `unsigned`, stripped fields, rejection/soft-fail claims, normalized `stream_ordering`, and `"metadata_status": "source_disagreement"` when sources conflict).
   - Supports `rezzy -f timeline --timeline-order causal|synapse --tie-break <keys> --metadata <path>`, verifying sidecar room ID/version and payload hashes (`94dc056`, `7b79c42`).
3. **Missing Event ID Repair & Room Version Inference (`rezzy-cli/src/repair.rs`)**:
   - Reconstructs missing `$`-prefixed event IDs for Room Versions 3+ by computing the SHA-256 reference hash over the redacted canonical event (`43ad27c`), inferring the room version from `m.room.create` or filename tokens during aggregation (`8eeec74`), and rejecting unsupported V1/V2 sender-chosen ID repair (`a959792`).
4. **Signed Federation Crawler, Gap Inspection & Keyfile Security (`rezzy-cli/src/federation.rs`, `rezzy-cli/src/keyfile.rs`)**:
   - `rezzy inspect gaps` reports missing `prev_events` and `auth_events` references for piping into `federation get-remote-dag --from-file -` or multi-round `federation gap-fill` (`bc471bf`).
   - Gates federation support behind the `tls` Cargo feature (`3e0aaef`), refuses plaintext HTTP URLs, preserves the logical `Host` header across `.well-known` and DNS SRV delegation, and caches negative delegation lookups without caching transient network failures (`f64d6b7`, `e8501f5`, `91a808f`).
   - Streams fetched events to disk and flushes before atomically checkpointing the remaining crawl frontier (`bc471bf`), rejecting `--emit-missing` paths that alias `--output` (`7b79c42`).
   - Seals Ed25519 federation signing keys on disk via `federation encrypt-key` using **Argon2id** (bounded to a 64 MiB memory buffer on read, `2703bb2`) + **XChaCha20-Poly1305** with authenticated header metadata (`e44c5e1`).

## 3. Architectural Decisions & Rejected Alternatives

1. **Rejected Alternative — OS Keyring Integration (`e197f8a`, `bc276b8` -> `e44c5e1`)**:
   - *Decision*: Initially added `keyring` crate support (`--signing-key-keyring`, `MATRIX_SERVER_SIGNING_KEY_KEYRING*`) in `e197f8a`/`bc276b8`, then completely replaced it six days later (`e44c5e1`) with passphrase-encrypted keyfiles (`rezzy-cli/src/keyfile.rs`).
   - *Rationale*: Platform keyrings (`dbus`/SecretService on Linux, Keychain on macOS, CredMan on Windows) broke headless server/container workflows and bloated the Cargo dependency graph. Replacing `keyring` with Argon2id + XChaCha20-Poly1305 (`federation encrypt-key` + TTY prompt / `REZZY_KEY_PASSPHRASE`) shrank the workspace dependency tree from 200 to 127 crates while providing portable, authenticated at-rest key protection.
2. **Retired Defect — 2 GiB Argon2 KDF Memory Cap (`2703bb2`)**:
   - *Decision*: Lowered `MAX_M_COST_KIB` in `rezzy-cli/src/keyfile.rs` from 2 GiB (`2_097_152` KiB) to 64 MiB (`65_536` KiB).
   - *Rationale*: Allowing a crafted or mistuned keyfile header to request a 2 GiB Argon2id allocation risked local OOM termination on constrained CLI or container hosts.
3. **Architectural Pivot — Stripping Non-Envelope Fields into `.rezzy-meta.jsonl` (`e3d1a55`)**:
   - *Decision*: Moved non-Matrix top-level keys (`__rejected`, `__soft_fail`, `__pducount`) out of `merged-<room>.jsonl` into `<output>.rezzy-meta.jsonl` while keeping full Matrix envelopes (`signatures`, `unsigned`) in the primary file.
   - *Rationale*: Keeping proprietary database dump columns in `merged-<room>.jsonl` broke strict Matrix schema consumers and distorted canonical byte comparisons.

## 4. Non-Functional & Public-Safety Invariants

Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 10, **Moderate — Forensic Integrity & Replay Pollution**):

1. **Redacted Canonical Deduplication & `unsigned` / `signatures` Divergence**:
   - Because `rezzy aggregate` deduplicates events by comparing their **redacted canonical form** (`docs/jsonl-aggregation.md:32-34`), two captures of the same `event_id` where one has valid `signatures` and the other has forged/stripped `signatures` (or poisoned `unsigned` state) will collapse into a single merged event, recording `"metadata_status": "source_disagreement"` only in `.rezzy-meta.jsonl`.
2. **Stripping `__rejected` / `__soft_fail` Markers & `--no-provenance` Hazard**:
   - Stripping `__rejected` and `__soft_fail` from `merged-<room>.jsonl` into `.rezzy-meta.jsonl` (or discarding them entirely when `--no-provenance` is passed) means `merged-<room>.jsonl` contains both accepted and rejected events as indistinguishable top-level JSON lines. Downstream public-safety tools that replay `merged-<room>.jsonl` into state resolution without consulting `.rezzy-meta.jsonl` or re-running full auth-chain verification risk **Replay Pollution** (admitting previously rejected events into room state).
3. **Crash-Safe Federation Crawling & Path Aliasing Guards**:
   - Federation crawls flush event batches before atomically renaming the checkpoint file (`bc471bf`), refuse plaintext HTTP (`f64d6b7`), and reject input/output or `--emit-missing`/`--output` path aliasing (`24dd0e4`, `7b79c42`).

## 5. Acceptance Criteria & Verification Oracles

1. **Aggregation Lifecycle & Conflict Accounting Oracles (`rezzy-cli/src/aggregate.rs`, `rezzy-cli/src/provenance.rs`)**:
   - Unit and integration tests (`6767bf0`, `257274d`, `bba030b`, `7b79c42`) verify `--room`, `-i`, and scan discovery, redacted-canonical deduplication, conflicting payload rejection, `.rezzy-meta.jsonl` manifest/observation generation, `source_disagreement` detection across `unsigned`/`rejection_reason`/`stripped` fields, and `--check` idempotence.
2. **Federation Crawl, TLS & Keyfile Oracles (`rezzy-cli/src/federation.rs`, `rezzy-cli/src/network.rs`, `rezzy-cli/src/keyfile.rs`)**:
   - Tests verify Argon2id + XChaCha20-Poly1305 key encryption/decryption and 64 MiB KDF bounds (`e44c5e1`, `2703bb2`), logical `Host` preservation on SRV targets, plaintext refusal (`f64d6b7`), negative delegation caching (`e8501f5`), and `--emit-missing` aliasing rejection (`7b79c42`).
3. **Hash Inspection & Timeline Ordering Oracles (`rezzy-cli/src/format.rs`, `rezzy-cli/src/timeline_order.rs`)**:
   - Tests verify `rezzy hash lthash` homomorphic lattice addition (`docs/jsonl-aggregation.md:226-265`), deterministic Kahn `event_id` tie-breaking (`7f41793`), and Synapse `stream_ordering` sidecar fallback (`e3d1a55`, `94dc056`).
