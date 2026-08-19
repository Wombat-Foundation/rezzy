//! Compares `LtHash` (MSC4500 homomorphic state hash, `rezzy::state::LtHash`)
//! against a "legacy" state hash for incremental state progression: after
//! every single state-map mutation (insert / overwrite / remove), what does
//! it cost to produce an up-to-date state hash?
//!
//! - **legacy**: no incrementality. Recompute the hash from scratch every
//!   mutation by canonically encoding every `(event_type, state_key,
//!   event_id)` entry in sorted order and feeding it through SHA-256 — the
//!   natural non-homomorphic baseline (roughly what you'd get hashing a
//!   canonical JSON/CBOR state snapshot).
//! - **`LtHash`**: `insert`/`remove`/`replace` are `O(1)` lattice
//!   add/subtract, independent of state size.
//!
//! Run with: `cargo bench --bench lthash`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rezzy::state::LtHash;
use sha2::{Digest, Sha256};

struct Xorshift128 {
    state: [u64; 2],
}

impl Xorshift128 {
    fn new(seed: u64) -> Self {
        Self {
            state: [seed ^ 0x9E37_79B9_7F4A_7C15, seed.wrapping_add(1) | 1],
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state[0];
        let y = self.state[1];
        self.state[0] = y;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        self.state[1] = x;
        x.wrapping_add(y)
    }
}

type StateKey = (String, String); // (event_type, state_key)

fn make_entries(n: usize, seed: u64) -> Vec<(StateKey, String)> {
    let mut rng = Xorshift128::new(seed);
    let mut entries = Vec::with_capacity(n);
    let mut used = std::collections::HashSet::new();
    while entries.len() < n {
        let uid = rng.next_u64() % 1_000_000;
        let key = (
            "m.room.member".to_string(),
            format!("@user{uid}:example.org"),
        );
        if used.insert(key.clone()) {
            let event_id = format!("$event{}:example.org", rng.next_u64());
            entries.push((key, event_id));
        }
    }
    entries
}

/// Canonical, sorted-order full-state hash: what a non-homomorphic "just
/// hash a snapshot" implementation would do. `BTreeMap` iteration is
/// already key-sorted, so this is the cheapest legacy baseline can get away
/// with `event_type + state_key` still needing a length-prefixed encoding
/// against key-boundary ambiguity.
fn legacy_hash(state: &BTreeMap<StateKey, String>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for ((event_type, state_key), event_id) in state {
        hasher.update((event_type.len() as u32).to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update((state_key.len() as u32).to_le_bytes());
        hasher.update(state_key.as_bytes());
        hasher.update((event_id.len() as u32).to_le_bytes());
        hasher.update(event_id.as_bytes());
    }
    hasher.finalize().into()
}

/// Applies `steps` sequential mutations (mix of new-key inserts, overwrites
/// of existing keys, and removals) to an `n`-entry base state, and for each
/// one measures the cost of bringing a running state hash up to date under
/// both strategies.
fn bench_incremental_hash(n: usize, steps: usize) {
    println!("incremental state hash after each mutation (n={n}, steps={steps}):");

    let base_entries = make_entries(n, 0x5EED_0000 + n as u64);
    let mut state: BTreeMap<StateKey, String> = base_entries.into_iter().collect();

    let mut lt = LtHash::ZERO;
    for ((event_type, state_key), event_id) in &state {
        lt.insert(event_type, state_key, event_id);
    }

    let mut rng = Xorshift128::new(0xBEEF);
    let existing_keys: Vec<StateKey> = state.keys().cloned().collect();
    enum Op {
        Insert(StateKey, String),
        Overwrite(StateKey, String),
        Remove(StateKey),
    }
    let mut ops = Vec::with_capacity(steps);
    for _ in 0..steps {
        let roll = rng.next_u64() % 10;
        if roll < 6 {
            let key = (
                "m.room.member".to_string(),
                format!("@user{}:example.org", rng.next_u64()),
            );
            ops.push(Op::Insert(
                key,
                format!("$event{}:example.org", rng.next_u64()),
            ));
        } else if roll < 9 {
            let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
            ops.push(Op::Overwrite(
                key,
                format!("$event{}:example.org", rng.next_u64()),
            ));
        } else {
            let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
            ops.push(Op::Remove(key));
        }
    }

    let mut legacy_state = state.clone();
    let legacy_start = Instant::now();
    for op in &ops {
        match op {
            Op::Insert(k, v) | Op::Overwrite(k, v) => {
                legacy_state.insert(k.clone(), v.clone());
            }
            Op::Remove(k) => {
                legacy_state.remove(k);
            }
        }
        std::hint::black_box(legacy_hash(&legacy_state));
    }
    let legacy_elapsed = legacy_start.elapsed();

    let lt_start = Instant::now();
    for op in &ops {
        match op {
            Op::Insert(k, v) => {
                if let Some(old) = state.insert(k.clone(), v.clone()) {
                    lt.replace(&k.0, &k.1, &old, v);
                } else {
                    lt.insert(&k.0, &k.1, v);
                }
            }
            Op::Overwrite(k, v) => {
                let old = state.insert(k.clone(), v.clone());
                if let Some(old) = old {
                    lt.replace(&k.0, &k.1, &old, v);
                } else {
                    lt.insert(&k.0, &k.1, v);
                }
            }
            Op::Remove(k) => {
                if let Some(old) = state.remove(k) {
                    lt.remove(&k.0, &k.1, &old);
                }
            }
        }
        std::hint::black_box(lt.checksum());
    }
    let lt_elapsed = lt_start.elapsed();

    let op_count = ops.len() as u32;
    println!(
        "  legacy (full sorted SHA-256 every step): {:.1} ns/op",
        (legacy_elapsed.as_nanos() as f64) / f64::from(op_count)
    );
    println!(
        "  LtHash (O(1) lattice add/sub + BLAKE2b checksum): {:.1} ns/op",
        (lt_elapsed.as_nanos() as f64) / f64::from(op_count)
    );
    report_speedup(legacy_elapsed, lt_elapsed);
    println!();
}

fn report_speedup(legacy: Duration, lthash: Duration) {
    let legacy_ns = legacy.as_nanos() as f64;
    let lthash_ns = lthash.as_nanos() as f64;
    let speedup = legacy_ns / lthash_ns;
    if speedup >= 1.0 {
        println!("  => LtHash is {speedup:.2}x faster than legacy");
    } else {
        println!("  => LtHash is {:.2}x SLOWER than legacy", 1.0 / speedup);
    }
}

fn main() {
    for &n in &[16usize, 128, 1024, 8192, 65536] {
        bench_incremental_hash(n, 500);
    }
}
