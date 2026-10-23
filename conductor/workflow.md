# Project Workflow: `rezzy` (Conductor SDD + Historical Reverse-Engineering & Multi-Agent Critique)

## Guiding Principles

1. **The Plan is the Source of Truth**: All historical and forward engineering work is tracked in `conductor/tracks/<track_id>/plan.md` and indexed in `conductor/tracks.md`.
2. **Worktree Isolation First**: All Conductor scaffolding, historical reverse-engineering, and multi-agent critiques execute inside isolated Git worktrees (`/Users/jonathan/Code/Shane/rezzy.worktrees/`) without contaminating `/Users/jonathan/Code/Shane/rezzy` (`master`).
3. **Test-First Verification (TDD & Oracles)**: Every feature and bugfix is backed by unit, integration, or property tests (`cargo test --workspace --lib --tests`).
4. **Bidirectional Traceability**: Every task in `plan.md` links to its implementing Git commit SHA(s), relevant [`docs/`](../docs/) design notes, and any applicable findings in [`rezzy_docs_public_safety_audit.md`](./audits/rezzy_docs_public_safety_audit.md).
5. **Multi-Persona Critique Gate**: Completed tracks undergo parallel multi-agent review across 8 perspectives (`critic-pm`, `critic-eng-lead`, `critic-compliance`, `critic-perf`, `critic-formal-crypto`, `critic-federation-interop`, `critic-redteam-qa`, `critic-dx-integrator`).

---

## 1. Historical Track Reverse-Engineering Lifecycle

For historical tracks (`01` through `12`):
1. **Archaeological Extraction (`timeline-archaeologist`)**:
   - Inspect the exact commit range, merge topology, source modules, test additions, and `docs/` artifacts for the epoch.
   - Document architectural pivots and rejected designs (e.g., CDO retirement, `GF(2^128)` rejection, `simd-json` removal).
2. **Conductor Mapping (`conductor-mapper`)**:
   - In an isolated track worktree (`rezzy.worktrees/track-<id>`), generate `spec.md`, `plan.md` (with `- [x] Task: <description> <sha>`), `metadata.json`, and `index.md`.
3. **Verification & Commitment (`track-committer`)**:
   - Verify all commit SHAs and relative file links.
   - Merge into `conductor/main` (`rezzy.worktrees/conductor-hub`) and register the track in `conductor/tracks.md`.
4. **Multi-Persona Critique (`persona-critic-*`)**:
   - Generate per-persona critiques in `conductor/tracks/<track_id>/critiques/<persona>.md` and synthesize into `conductor/tracks/<track_id>/review.md`.

---

## 2. Forward Engineering & Remediation Task Workflow

For active or pending remediation tracks (`13` through `18`):
1. **Select Task**: Choose the next `[ ]` task from `plan.md` and mark it `[~]`.
2. **Write Failing Tests (Red Phase)**: Add regression/adversarial test cases in `tests/` or crate unit tests and confirm failure via `cargo test`.
3. **Implement Fail-Closed Fix (Green Phase)**: Implement the minimal `#![no_std]`-compliant fix and confirm all tests pass.
4. **Lint & Audit Check**: Run `cargo clippy --all-targets --all-features` and verify compliance with `conductor/code_styleguides/rust.md`.
5. **Commit & Record SHA**: Commit the change, update the task in `plan.md` to `- [x] Task: <description> <sha>`, and commit the plan update.

---

## 3. Development Commands

### Build & Test
```bash
cargo test --workspace --lib --tests
cargo clippy --all-targets --all-features
```

### Conductor Status & Review
- Run `/conductor-status` to parse `conductor/index.md` -> `conductor/tracks.md` -> `conductor/tracks/*/plan.md`.
- Run `/conductor-review` to execute Principal Engineer + Multi-Persona verification on any track.
