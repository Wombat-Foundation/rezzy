# Track Review & Multi-Perspective Critique: `12_rezzy_cli_federation_agg_20261010`

- **Track ID**: `12_rezzy_cli_federation_agg_20261010`
- **Track Title**: `rezzy-cli`: Deterministic JSONL Aggregation, `.rezzy-meta.jsonl` Sidecar & Signed Federation Crawler (`0.6.0-rc.1`)
- **Commit Trajectory**: `dd74d21..35a0457`
- **Audit Risk Rating**: **Moderate (Forensic Integrity & Replay Pollution)** — see [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 10)
- **Review Status**: **COMPLETED WITH FORENSIC & REPLAY-SAFETY RECOMMENDATIONS FOR STAGE B**

---

## 1. Executive Review Summary (`/conductor-review`)

Track 12 transforms [`rezzy-cli`](../../../rezzy-cli/src/lib.rs) into a comprehensive forensic acquisition, deduplication, and inspection toolkit for Matrix DAGs (`dd74d21..35a0457`). Key deliverables verified in the codebase include:
1. **Deterministic Raw JSONL Aggregation (`rezzy aggregate`, [`rezzy-cli/src/aggregate.rs`](../../../rezzy-cli/src/aggregate.rs))**: Supports `--room`, `-i`, and directory scan modes (`944c8e3`), deduplicates events by their Matrix redacted canonical form (`305b4e6`, `5a5a9db`), orders output via Kahn topological sort with deterministic `(origin_server_ts, depth, event_id)` tie-breaking (`7c6e324`, `7f41793`), enforces input/output overlap guards (`24dd0e4`), stages writes via `.tmp-*` + `sync_all` + atomic rename (`5f8704e`), and provides `--check` staleness verification (`397eb7a`).
2. **`.rezzy-meta.jsonl` Provenance Sidecar ([`rezzy-cli/src/provenance.rs`](../../../rezzy-cli/src/provenance.rs), [`timeline_order.rs`](../../../rezzy-cli/src/timeline_order.rs))**: Strips non-envelope fields (`__rejected`, `__soft_fail`, `__pducount`, `__stream_ordering`, etc.) into `<output>.rezzy-meta.jsonl`, binds the sidecar manifest to the aggregate's SHA-256 (`cb9ee5d`, `94dc056`), flags `"metadata_status": "source_disagreement"`, and enables `--timeline-order synapse` (`e3d1a55`).
3. **Missing Event ID Repair ([`rezzy-cli/src/repair.rs`](../../../rezzy-cli/src/repair.rs))**: Reconstructs V3+ content-addressed `$event_id` values via `rezzy::reference_hash` (`43ad27c`, `8eeec74`) while rejecting V1/V2 sender-chosen IDs (`a959792`).
4. **TLS-Gated Signed Federation Crawler & Portable Encrypted Keyfiles ([`rezzy-cli/src/federation.rs`](../../../rezzy-cli/src/federation.rs), [`keyfile.rs`](../../../rezzy-cli/src/keyfile.rs))**: Implements `get-remote-dag` and `gap-fill` with `X-Matrix` Ed25519 request signing, SRV logical `Host` preservation, atomic frontier checkpointing (`bc471bf`), and Argon2id + XChaCha20-Poly1305 encrypted signing keys (`e44c5e1`) capped at 64 MiB (`MAX_M_COST_KIB = 64 * 1024`, `2703bb2`).

However, from a public-safety forensic and replay-integrity perspective, **four `[High]` and `[Medium]` findings** require hardening to prevent **Replay Pollution** and **First-Seen Signature/Unsigned Poisoning**.

### Verification Matrix Against Plan & Spec
- [x] **Immutable Evidence Contract**: `unmerged/` is never modified; input/output aliasing is rejected in [`reject_input_output_overlap`](../../../rezzy-cli/src/aggregate.rs#L633-L645) and [`ensure_paths_distinct`](../../../rezzy-cli/src/repair.rs#L31-L53).
- [x] **Argon2id 64 MiB Memory Bound**: Enforced before allocation at [`rezzy-cli/src/keyfile.rs:21`](../../../rezzy-cli/src/keyfile.rs#L21) and [`108-110`](../../../rezzy-cli/src/keyfile.rs#L108-L110), tested in [`garbage_and_hostile_params_rejected`](../../../rezzy-cli/src/keyfile.rs#L156-L161).
- [x] **Provenance Manifest Binding**: Sidecar manifest binds `aggregate_sha256` ([`aggregate.rs:820-840`](../../../rezzy-cli/src/aggregate.rs#L820-L840)), and `--no-provenance` removes any stale sidecar ([`aggregate.rs:806-812`](../../../rezzy-cli/src/aggregate.rs#L806-L812)).
- [x] **Deterministic Kahn Tie-Breaking**: [`kahn_order_by`](../../../rezzy-cli/src/timeline_order.rs#L187-L235) breaks ties by `(&keys[index], &ids[index], index)` (`7f41793`).

---

## 2. Multi-Perspective Critiques (8 Specialized Personas)

### 2.1 Product Management (`critic-pm`)
- **Assessment**: The workflow of `rezzy inspect gaps` $\to$ `rezzy federation gap-fill` $\to$ `rezzy aggregate` $\to$ `rezzy -f resolve-state` / `rezzy hash lthash` provides a cohesive, UNIX-composable CLI pipeline for incident response teams investigating federated room splits.
- **Finding `[Medium]` — Asymmetric JSON Report Shape Between `--room` and `-i` / Scan Mode**:
  - As documented in [`docs/jsonl-aggregation.md:142-176`](../../../docs/jsonl-aggregation.md#L142-L176), `rezzy aggregate --room <slug>` returns a bare single-room JSON object (`{"status": "written", "output": ...}`), whereas `rezzy aggregate -i ...` and scan mode return a wrapper object (`{"status": "written", "failed": 0, "skipped": [], "rooms": [...]}`). Furthermore, per-room objects under `"status": "current"` omit `"output"` and `"metadata_output"`. Automated C2 forensic pipelines must branch on both invocation mode and `status` to parse the output.

### 2.2 Principal Engineering Lead (`critic-eng-lead`)
- **Assessment**: Ripping out the OS-specific `keyring` crate (`e197f8a` $\to$ `e44c5e1`) in favor of `rezzy-cli/src/keyfile.rs` (170 lines of audited Argon2id + XChaCha20-Poly1305 with header AAD binding) and lowering `MAX_M_COST_KIB` from 2 GiB to 64 MiB (`2703bb2`) eliminated 73 transitive crates, fixed headless container/SSH operation, and closed a pre-authentication OOM vector.
- **Finding `[Medium]` — Key Zeroization & Temp-File Nonce Collision Under Parallel Invocations**:
  - In [`rezzy-cli/src/keyfile.rs:62`](../../../rezzy-cli/src/keyfile.rs#L62) and [`115`](../../../rezzy-cli/src/keyfile.rs#L115), `key.fill(0)` is a plain mutable array write immediately before `key` goes out of scope, which LLVM dead-store elimination (DSE) is permitted to optimize away; moreover, the `Vec<u8>` returned by `open()` (`keyfile.rs:93`) and the passphrase `String` in [`federation.rs:348`](../../../rezzy-cli/src/federation.rs#L348) are not zeroized on drop.
  - In [`rezzy-cli/src/aggregate.rs:591-617`](../../../rezzy-cli/src/aggregate.rs#L591-L617), `stage_file` names the temp file `.{name}.tmp-{pid}-{nanos}`. Because `OpenOptions::new().write(true).create_new(true)` is used, it is safe against symlink clobbering, which is good practice.
  - **Remediation**: Use `core::hint::black_box(&mut key)` after `key.fill(0)` (or `zeroize::Zeroizing`) in `keyfile.rs` so the compiler cannot elide key scrubbing.

### 2.3 Public-Safety & C2 Compliance (`critic-compliance`)
- **Assessment**: Cross-referencing [`conductor/audits/rezzy_docs_public_safety_audit.md`](../../audits/rezzy_docs_public_safety_audit.md) (Row 10), `rezzy aggregate` is designed to preserve raw captures in `unmerged/` as immutable forensic evidence while producing normalized `merged/merged-<room>.jsonl` files.
- **Finding `[High]` — Replay Pollution via Unfiltered `__rejected` / `__soft_fail` Stripping (`aggregate.rs:520-528`)**:
  - During `read_raw_input_with_repair` ([`rezzy-cli/src/aggregate.rs:520-528`](../../../rezzy-cli/src/aggregate.rs#L520-L528)), `provenance::observe_raw_event` records `rejected` (`__rejected` / `rejected`) and `soft_failed` (`__soft_fail` / `soft_fail`), and `provenance::strip_non_envelope_fields(event)` **strips those markers from the event written to `merged-<room>.jsonl`**.
  - Crucially:
    1. An event marked `"__rejected": true` in a Synapse/Conduwuit database export is **still included in `merged-<room>.jsonl`** with its `__rejected` flag removed!
    2. If the operator passes `--no-provenance`, the `.rezzy-meta.jsonl` sidecar is not even written, permanently erasing the fact that the event was rejected!
    3. Even when `.rezzy-meta.jsonl` exists, feeding `merged-<room>.jsonl` into downstream analysis or `rezzy` state-resolution commands that do not consult the sidecar's `rejected` claims will **admit rejected events as valid room history (Replay Pollution)**.
  - **Remediation**:
    1. By default, `rezzy aggregate` should either **quarantine/exclude** events where all observations claim `rejected: true` into a separate `merged-<room>.rejected.jsonl` file (unless `--include-rejected` is explicitly passed), OR `rezzy`'s state-resolution CLI ingestion path (`-i merged-<room>.jsonl`) must automatically load `<input>.rezzy-meta.jsonl` and restore `LeanEvent::rejected = true` / `soft_fail = true` when present!
    2. Forbid `--no-provenance` when any input event contains `__rejected` or `__soft_fail` markers unless `--allow-strip-rejected` is explicitly set.

### 2.4 Performance & Adversarial Liveness (`critic-perf`)
- **Assessment**: `rezzy-cli` bounds network connect timeouts to 10s (`CONNECT_TIMEOUT`) and request timeouts to 120s (`REQUEST_TIMEOUT` in [`rezzy-cli/src/federation.rs:20-23`](../../../rezzy-cli/src/federation.rs#L20-L23)), and limits Argon2id KDF parameters to `m <= 64 MiB, t <= 3, p <= 1` (`keyfile.rs:21-23`).
- **Finding `[Medium]` — Full In-Memory Materialization in `rezzy aggregate` & Quadratic `perform_connectivity_check`**:
  - In [`rezzy-cli/src/aggregate.rs:681-708`](../../../rezzy-cli/src/aggregate.rs#L681-L708), `aggregate` reads all raw input files into `Vec<RawInput>`, clones every event during observation (`let raw = event.clone()` at line 520), builds the full merged `output` and `sidecar` byte buffers in RAM, and in [`rezzy-cli/src/jsonl_merge.rs:49-101`](../../../rezzy-cli/src/jsonl_merge.rs#L49-L101), `perform_connectivity_check` runs an $O(F^2 \cdot E)$ pairwise `HashSet` intersection across all $F$ input files. For a 1M-event room split across 50 backfill shard files, this consumes multiple gigabytes of RAM.
  - **Remediation**: Replace `let raw = event.clone()` at `aggregate.rs:520` by running `provenance::observe_raw_event` *before* `provenance::strip_non_envelope_fields(event)` (eliminating a full DOM clone per event!), and optimize `perform_connectivity_check` using an inverted index `HashMap<&str, Vec<usize>>` mapping each `event_id` to the file indices that own/reference it in $O(F + E)$ time.

### 2.5 Formal Verification & Mathematical Soundness (`critic-formal-crypto`)
- **Assessment**: The cryptographic primitives in `rezzy-cli` — SHA-256 reference hashing (`repair.rs`), BLAKE3 homomorphic `LtHash` inspection (`rezzy hash lthash`), Ed25519 `X-Matrix` signing (`federation.rs`), and Argon2id + XChaCha20-Poly1305 (`keyfile.rs`) — are well-chosen.
- **Finding `[Medium]` — First-Seen Retention of `signatures` and `unsigned` Under Redacted-Canonical Deduplication (`jsonl_merge.rs:239-295`)**:
  - In [`rezzy-cli/src/jsonl_merge.rs:239-260`](../../../rezzy-cli/src/jsonl_merge.rs#L239-L260), when `room_version` is `Some`, `comparison_key` computes the Matrix **redacted canonical JSON** (which strips `signatures`, `unsigned`, and redactable `content` fields!).
  - When two input files contain the same `event_id`:
    - File A (alphabetically first, e.g., `a-redacted-or-corrupt.jsonl`) has a **redacted** copy of `$event1` (with `content: {}` and corrupted/empty `signatures: {}`).
    - File B (`b-full-archive.jsonl`) has the **unredacted** copy of `$event1` (with full `content: {"body": "urgent dispatch"}` and valid `signatures`).
  - Because `comparison_key` compares their **redacted canonical form**, both produce the **exact same comparison key**, so `merge_event_sets_internal` treats them as identical duplicates and **retains only the first-seen event (File A's redacted/unsigned copy), silently discarding File B's unredacted `content` and valid `signatures` from `merged-<room>.jsonl`!**
  - **Remediation**:
    1. When two copies of an `event_id` have identical redacted canonical form, `merge_event_sets_internal` MUST prefer the **unredacted** copy (the one with more preserved/unredacted `content` keys) over a redacted copy, and **merge** the `signatures` objects across all observations rather than keeping only the first file's `signatures`!

### 2.6 Matrix Federation Interop (`critic-federation-interop`)
- **Assessment**: [`SrvResolver`](../../../rezzy-cli/src/federation.rs#L42-L80) in `rezzy-cli/src/federation.rs` accurately implements the Matrix Server-Server specification for `.well-known` and DNS SRV delegation by dialing the delegated `host:port` while preserving the logical server name in the TLS SNI and HTTP `Host` header.
- **Finding `[Low]` — `SrvResolver` 16-Address Truncation & Global `OnceLock<Mutex<BTreeMap>>` Cache**:
  - `srv_targets()` ([`federation.rs:35-38`](../../../rezzy-cli/src/federation.rs#L35-L38)) stores SRV mappings in a process-wide static `BTreeMap` without TTL expiration. While acceptable for short-lived CLI commands (`get-remote-dag`, `gap-fill`), long-running `--rounds 0` crawls across dynamic DNS targets could see stale target endpoints if a homeserver fails over during the crawl.

### 2.7 Adversarial Red-Team & Verification QA (`critic-redteam-qa`)
- **Assessment**: Track 12 includes solid tests for KDF parameter tampering (`garbage_and_hostile_params_rejected`), path aliasing (`ensure_paths_distinct`), and sidecar payload-hash binding (`cb9ee5d`, `7b79c42`).
- **Finding `[High]` — Red-Team Vector: Redacted Event Shadowing Unredacted Event & Signature Poisoning in `rezzy aggregate`**:
  - **Attack Vector 1 (Content Erasure via Redacted Shadowing)**: An attacker or partial dump places a redacted copy of an event in `local-room-v12.jsonl` (`"content": {}`) while `remote-room-v12.jsonl` contains the full unredacted `"content": {"body": "evidence"}`. Because `local-room-v12.jsonl` sorts lexicographically before `remote-room-v12.jsonl` (`aggregate.rs:249`), `rezzy aggregate` outputs the empty redacted event into `merged-room-v12.jsonl` and drops the unredacted `content` completely (not even `.rezzy-meta.jsonl` records `content`!).
  - **Attack Vector 2 (Replay of `__rejected: true` Events)**: An input file contains `{"event_id": "$bad", "__rejected": true, ...}` (e.g. a forged power-level event rejected at ingestion by Synapse). `rezzy aggregate` strips `"__rejected": true` into `.rezzy-meta.jsonl` and emits `$bad` into `merged-room-v12.jsonl` as a normal event. When `rezzy -i merged-room-v12.jsonl -f resolve-state` is run without `--verify-auth` or sidecar rejection filtering, `$bad` is treated as accepted!
  - **Remediation**: Add explicit regression tests in `rezzy-cli` for: (1) merging a redacted copy + unredacted copy of the same `event_id` (must retain unredacted `content` and union of `signatures`, while recording redaction state in `.rezzy-meta.jsonl`), and (2) refusing to silently promote `__rejected: true` events into active state resolution without sidecar enforcement.

### 2.8 Homeserver Integrator & API Ergonomics (`critic-dx-integrator`)
- **Assessment**: The CLI flag surface (`aggregate`, `inspect gaps`, `repair-ids`, `hash lthash`, `federation get-remote-dag`, `federation gap-fill`, `federation encrypt-key`) is well-structured and documented in [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md).
- **Finding `[Medium]` — `rezzy -f resolve-state` Does Not Auto-Enforce `.rezzy-meta.jsonl` Rejection Claims**:
  - While `rezzy -f timeline --timeline-order synapse` auto-discovers `<input>.rezzy-meta.jsonl` (`docs/jsonl-aggregation.md:281`), running `rezzy -i merged/merged-room-v12.jsonl -f resolve-state` does **not** automatically consult `merged/merged-room-v12.rezzy-meta.jsonl` to exclude or flag events that carried `"rejected": true` in the raw dump.
  - **Remediation**: Auto-discover `<input>.rezzy-meta.jsonl` across all `rezzy-cli` state-resolution and DAG inspection commands (not just `--timeline-order synapse`), and fail closed (or require `--ignore-sidecar-rejections`) when a merged file's companion sidecar marks events as rejected or having `source_disagreement`.

---

## 3. Consolidated Findings & Stage B Action Plan

| ID | Severity | Persona(s) | File / Line Reference | Finding Summary | Stage B Remediation Target |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **T12-F1** | **`[High]`** | `critic-formal-crypto`, `critic-redteam-qa` | [`rezzy-cli/src/jsonl_merge.rs:239-295`](../../../rezzy-cli/src/jsonl_merge.rs#L239-L295) | Deduplicating by redacted canonical JSON (`comparison_key`) with first-seen retention causes a redacted copy of an event in an alphabetically earlier file to overwrite an unredacted copy's `content` and drops secondary `signatures`. | Prefer unredacted `content` over redacted `content` on duplicate `event_id` merge, union valid `signatures` blocks, and record redacted vs. unredacted observation status in `.rezzy-meta.jsonl`. |
| **T12-F2** | **`[High]`** | `critic-compliance`, `critic-redteam-qa`, `critic-dx-integrator` | [`rezzy-cli/src/aggregate.rs:520-528`](../../../rezzy-cli/src/aggregate.rs#L520-L528), [`provenance.rs:159-168`](../../../rezzy-cli/src/provenance.rs#L159-L168) | Stripping `__rejected` and `__soft_fail` into `.rezzy-meta.jsonl` (or dropping them under `--no-provenance`) leaves rejected events indistinguishable from valid events in `merged-<room>.jsonl`, risking Replay Pollution. | Auto-consult `<input>.rezzy-meta.jsonl` during state resolution to honor `rejected` / `soft_failed` flags, or quarantine rejected events by default during `rezzy aggregate`. |
| **T12-F3** | **`[Medium]`** | `critic-perf`, `critic-eng-lead` | [`rezzy-cli/src/aggregate.rs:520`](../../../rezzy-cli/src/aggregate.rs#L520), [`jsonl_merge.rs:49-101`](../../../rezzy-cli/src/jsonl_merge.rs#L49-L101) | `read_raw_input_with_repair` clones every `JsonValue` before stripping (`let raw = event.clone()`), and `perform_connectivity_check` runs an $O(F^2 \cdot E)$ pairwise set intersection. | Observe raw fields before mutating `event` in-place (zero DOM clone), and use an inverted `event_id -> file_idx` map in `perform_connectivity_check`. |
| **T12-F4** | **`[Medium]`** | `critic-eng-lead` | [`rezzy-cli/src/keyfile.rs:62`](../../../rezzy-cli/src/keyfile.rs#L62), [`115`](../../../rezzy-cli/src/keyfile.rs#L115) | `key.fill(0)` on a stack array immediately before return can be elided by compiler dead-store elimination (DSE). | Wrap `key.fill(0)` with `core::hint::black_box(&mut key)` in `rezzy-cli/src/keyfile.rs`. |
| **T12-F5** | **`[Low]`** | `critic-pm` | [`docs/jsonl-aggregation.md:142-176`](../../../docs/jsonl-aggregation.md#L142-L176), [`aggregate.rs:720-774`](../../../rezzy-cli/src/aggregate.rs#L720-L774) | Per-room report objects under `--check` (`"status": "current"`) omit `"output"` and `"metadata_output"`, requiring callers to branch on status to locate files. | Include `"output"` and `"metadata_output"` consistently in `"status": "current"` report entries. |
