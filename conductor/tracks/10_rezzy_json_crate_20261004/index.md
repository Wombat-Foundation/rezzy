# Track 10: `rezzy-json` Crate Extraction, Dependency-Free Parser & Canonical Numeric Limits (`0.6.0-rc.1`)

## Track Handshake & Navigation

- **Track ID**: `10_rezzy_json_crate_20261004`
- **Status**: `completed`
- **Epoch**: Sep–Oct 2026 (`0.6.0-rc.1` – `0.6.0-rc.2`, Commit Range `a636e18..1504cc7`)
- **Track Artifacts**:
  - [Track Specification (`./spec.md`)](./spec.md)
  - [Implementation Plan (`./plan.md`)](./plan.md)
  - [Track Metadata (`./metadata.json`)](./metadata.json)
- **Public-Safety & Architectural Audit**:
  - [Master Audit (`../../audits/rezzy_docs_public_safety_audit.md`)](../../audits/rezzy_docs_public_safety_audit.md) — **Risk Rating: Critical (Hash Split)**
- **Primary Documentation & Source Files**:
  - [`../../../docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md) — Canonical vs. permissive integer boundaries, float re-rendering, and `as_f64` rounding hazards
  - [`../../../docs/homeserver_utilities.md`](../../../docs/homeserver_utilities.md) — Canonical JSON hashing and redaction utility documentation
  - [`../../../rezzy-json/src/lib.rs`](../../../rezzy-json/src/lib.rs) — Dependency-free `#![no_std]` JSON parser, `Value` / `ValueRef` DOM, RFC 6901 JSON Pointer, and canonical writers
  - [`../../../src/basespec/rezzy_types.rs`](../../../src/basespec/rezzy_types.rs) — Core Matrix adapter types and differential numeric boundary pins
  - [`../../../src/signing/mod.rs`](../../../src/signing/mod.rs) — Event reference hashing and content signature canonicalization

## Executive Summary

Track 10 captures the architectural extraction of JSON parsing and Matrix Canonical JSON serialization out of the monolithic `src/` crate into the standalone `#![no_std]` (`alloc`) [`rezzy-json`](../../../rezzy-json/src/lib.rs) workspace crate. Across September and October 2026, the parser underwent two major evolutionary pivots: first ripping out `serde` / `serde_json` in favor of `simd-json` (`83a19c0`, `cc84e6b`), and then completely removing `simd-json` (`0970e94`) after benchmarks proved the hand-rolled scalar parser and zero-copy canonicalizer were significantly faster (238 MB/s vs. 139 MB/s on Matrix events) and free of `u64` integer rejection bugs. Track 10 also codifies the exact boundaries between permissive parsing (`Number` preserving arbitrary-width integer source spellings) and strict Matrix Canonical JSON (`[-2^53+1, 2^53-1]`) in [`docs/json_numeric_limits.md`](../../../docs/json_numeric_limits.md).
