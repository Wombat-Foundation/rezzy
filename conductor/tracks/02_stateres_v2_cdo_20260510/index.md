# Track 02: Core `#![no_std]` State Resolution V1/V2/V2.1 & CDO Soundness Retirement (`v0.1.2`–`v0.1.4`)

## Conductor Track Handshake

- **Track ID**: `02_stateres_v2_cdo_20260510`
- **Epoch**: `v0.1.2`–`v0.1.4` (April 12–May 20, 2026, plus CDO soundness anomalies lifecycle `ae41adc`–`f56b068`)
- **Commit Range**: `5cf21de..4abfb43`
- **Status**: `completed`

### Track Artifacts
- [Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)
- [Public-Safety Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Reviews & Critiques
- [Multi-Perspective Architectural Review (`./review.md`)](./review.md) — 8-persona critique covering `critic-pm`, `critic-eng-lead`, `critic-compliance`, `critic-perf`, `critic-formal-crypto`, `critic-federation-interop`, `critic-redteam-qa`, and `critic-dx-integrator`

### Linked Repository Documentation
- [`../../../docs/cdo_soundness_anomalies.md`](../../../docs/cdo_soundness_anomalies.md) — Post-mortem on the Causal Domination Operator (CDO), the dominator-validity gap, Anomaly 19 (`19_demoted_but_still_authorized.jsonl`), and Anomaly 20 (`20_concurrent_ban_still_holds.jsonl`)
- [`../../../README.md`](../../../README.md) — Room version to State Resolution version mapping (V1, V2/[MSC1693](https://github.com/matrix-org/matrix-spec-proposals/pull/1693), V2.1/[MSC4297](https://github.com/matrix-org/matrix-spec-proposals/pull/4297))

### Linked Source & Verification Modules
- [`../../../src/resolve/iterative.rs`](../../../src/resolve/iterative.rs) — Main `resolve_iterative_sort` pipeline, `prepare_conflicted_and_keys` (with CDO retirement soundness note), and `is_sender_banned` post-power resolved-state screening pass
- [`../../../src/resolve/cdo.rs`](../../../src/resolve/cdo.rs) — Retired Causal Domination Operator (`filter_dominated_events`, `sender_has_pre_demotion_pl`, `join_has_prior_authorization`, `is_ancestor`) retained as design history
- [`../../../src/resolve/subgraph.rs`](../../../src/resolve/subgraph.rs) — Conflicted state subgraph expansion for State Resolution V2.1 (`MSC4297`)
- [`../../../src/resolve/multi.rs`](../../../src/resolve/multi.rs) — Multi-DAG / $N$-way state resolution merge engine
- [`../../../tests/unit/test_critique.rs`](../../../tests/unit/test_critique.rs) — Anomaly test harness (`test_anomaly_01` through `test_anomaly_20`, `assert_benign_convergence`, `resolve_full`)
- [`../../../tests/critique_data/`](../../../tests/critique_data/) — JSONL adversarial fixtures including `19_demoted_but_still_authorized.jsonl` and `20_concurrent_ban_still_holds.jsonl`
- [`../../../tests/unit/test_sanity.rs`](../../../tests/unit/test_sanity.rs) — V1, V2, and V2.1 tie-breaker, non-state event filtering, and determinism regression suites
