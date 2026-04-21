#!/usr/bin/env python3
"""Generate reference/expected output JSON for all test fixtures.

Runs ruma-lean's resolution engine via a helper binary and captures
the resolved state as golden snapshots for regression testing.

Since we can't easily call Rust from Python, this script instead
generates a Rust test that WRITES the snapshots. Run it once to
create the reference files, then commit them.

Usage:
  cargo test --features std --test gen_snapshots -- --ignored
"""

print("Use: cargo test --features std --test gen_snapshots -- --ignored")
print("This generates res/expected/ reference files for regression testing.")
