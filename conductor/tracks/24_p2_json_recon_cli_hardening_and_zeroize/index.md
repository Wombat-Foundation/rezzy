# Track 24: P2 Remediation — `rezzy-json` Float/Lookup Hardening, `rezzy-recon` Phase-1 Gate & `h64` Chunk Fix, `rezzy-cli` Zeroize & Cycle Signaling

## Artifacts
- [Remediation Specification (`./spec.md`)](./spec.md)
- [Implementation Plan (`./plan.md`)](./plan.md)
- [Track Metadata (`./metadata.json`)](./metadata.json)

## Upstream Historical Reviews & Audit Traceability
- [Track 09 Review (`../09_perf_interning_benchmarks_20260920/review.md`)](../09_perf_interning_benchmarks_20260920/review.md) — Findings `F-09-07`, `F-09-08`
- [Track 10 Review (`../10_rezzy_json_crate_20261004/review.md`)](../10_rezzy_json_crate_20261004/review.md) — Findings `T10-F4`, `T10-F5`, `T10-F6`
- [Track 11 Review (`../11_rezzy_recon_pinsketch_trie_20261018/review.md`)](../11_rezzy_recon_pinsketch_trie_20261018/review.md) — Findings `T11-F4`, `T11-F5`, `T11-F6`
- [Track 12 Review (`../12_rezzy_cli_federation_agg_20261010/review.md`)](../12_rezzy_cli_federation_agg_20261010/review.md) — Findings `T12-F3`, `T12-F4`, `T12-F5`
- [Public-Safety & Architectural Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md)

## Linked Documentation & Source Files
- [`rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs)
- [`rezzy-recon/src/client.rs`](../../../rezzy-recon/src/client.rs)
- [`rezzy-recon/src/algebraic.rs`](../../../rezzy-recon/src/algebraic.rs)
- [`rezzy-recon/src/triage.rs`](../../../rezzy-recon/src/triage.rs)
- [`rezzy-cli/src/timeline_order.rs`](../../../rezzy-cli/src/timeline_order.rs)
- [`rezzy-cli/src/aggregate.rs`](../../../rezzy-cli/src/aggregate.rs)
- [`rezzy-cli/src/jsonl_merge.rs`](../../../rezzy-cli/src/jsonl_merge.rs)
- [`rezzy-cli/src/keyfile.rs`](../../../rezzy-cli/src/keyfile.rs)
- [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md)
- [`docs/jsonl-aggregation.md`](../../../docs/jsonl-aggregation.md)
- [`docs/format.sh`](../../../docs/format.sh)
