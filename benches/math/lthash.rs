//! Compares `LtHash` (MSC4500 homomorphic state hash, `rezzy::state::LtHash`)
//! against *two* non-homomorphic baselines for incremental state
//! progression: after every single state-map mutation (insert / overwrite /
//! remove), what does it cost to produce an up-to-date state hash?
//!
//! - **conduwuit-style, `O(S log S)`**: no persistent sorted structure
//!   across calls — every mutation collects the full state into a `Vec`
//!   and sorts it before hashing, so the sort dominates. This models
//!   hashing a freshly-derived canonical snapshot rather than maintaining
//!   an incrementally-sorted index alongside it.
//! - **Synapse-style, `O(S)`**: no sort at all. Combines a SHA-256 digest
//!   per entry via a commutative XOR-fold, so it doesn't need entries in
//!   any particular order — but it's still a *full* recompute over all `S`
//!   entries every mutation, just without the `log S` sort factor. This is
//!   the same "hash each element, combine independent of order" idea
//!   `LtHash` uses, just non-incrementally: rebuilt from scratch every
//!   mutation instead of updated in place.
//! - **`LtHash`, `O(1)`**: `insert`/`remove`/`replace` are lattice
//!   add/subtract on the *existing* accumulator — no re-scan of the state
//!   at all, independent of `S`.
//!
//! These are complexity-class models, not literal ports of either
//! project's source — the point is the shape (`O(1)` vs `O(S)` vs
//! `O(S log S)`), which is what actually determines how these scale as
//! room state grows, not which exact hash function each project picks.
//!
//! Run with: `cargo bench --bench lthash`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
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

fn canonical_row(event_type: &str, state_key: &str, event_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(event_type.len() + state_key.len() + event_id.len() + 12);
    buf.extend_from_slice(&(event_type.len() as u32).to_le_bytes());
    buf.extend_from_slice(event_type.as_bytes());
    buf.extend_from_slice(&(state_key.len() as u32).to_le_bytes());
    buf.extend_from_slice(state_key.as_bytes());
    buf.extend_from_slice(&(event_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(event_id.as_bytes());
    buf
}

/// conduwuit-style: `O(S log S)`. State lives in a flat, unordered
/// `HashMap` (no persistent sorted index is maintained across mutations),
/// so producing a canonical hash means collecting every entry and sorting
/// it fresh each time before feeding it through SHA-256 sequentially.
fn conduwuit_style_hash(state: &HashMap<StateKey, String>) -> [u8; 32] {
    let mut rows: Vec<Vec<u8>> = state
        .iter()
        .map(|((event_type, state_key), event_id)| canonical_row(event_type, state_key, event_id))
        .collect();
    rows.sort_unstable();
    let mut hasher = Sha256::new();
    for row in &rows {
        hasher.update(row);
    }
    hasher.finalize().into()
}

/// Synapse-style: `O(S)`. Order-independent by construction (XOR-fold of
/// per-entry digests, same trick `LtHash` uses for commutativity) so no
/// sort is needed — but still a full recompute over every entry each
/// mutation, not an incremental update against a running accumulator.
fn synapse_style_hash(state: &HashMap<StateKey, String>) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for ((event_type, state_key), event_id) in state {
        let row = canonical_row(event_type, state_key, event_id);
        let digest: [u8; 32] = Sha256::digest(&row).into();
        for (a, d) in acc.iter_mut().zip(digest.iter()) {
            *a ^= d;
        }
    }
    acc
}

/// Applies `steps` sequential mutations (mix of new-key inserts, overwrites
/// of existing keys, and removals) to an `n`-entry base state, and for each
/// one measures the cost of bringing a running state hash up to date under
/// all three strategies.
#[allow(clippy::too_many_lines)]
fn bench_incremental_hash(n: usize, steps: usize) {
    println!("incremental state hash after each mutation (n={n}, steps={steps}):");

    let base_entries = make_entries(n, 0x5EED_0000 + n as u64);
    let mut state: HashMap<StateKey, String> = base_entries.into_iter().collect();

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

    let mut conduwuit_state = state.clone();
    let conduwuit_start = Instant::now();
    for op in &ops {
        match op {
            Op::Insert(k, v) | Op::Overwrite(k, v) => {
                conduwuit_state.insert(k.clone(), v.clone());
            }
            Op::Remove(k) => {
                conduwuit_state.remove(k);
            }
        }
        std::hint::black_box(conduwuit_style_hash(&conduwuit_state));
    }
    let conduwuit_elapsed = conduwuit_start.elapsed();

    let mut synapse_state = state.clone();
    let synapse_start = Instant::now();
    for op in &ops {
        match op {
            Op::Insert(k, v) | Op::Overwrite(k, v) => {
                synapse_state.insert(k.clone(), v.clone());
            }
            Op::Remove(k) => {
                synapse_state.remove(k);
            }
        }
        std::hint::black_box(synapse_style_hash(&synapse_state));
    }
    let synapse_elapsed = synapse_start.elapsed();

    let lt_start = Instant::now();
    for op in &ops {
        match op {
            Op::Insert(k, v) | Op::Overwrite(k, v) => {
                if let Some(old) = state.insert(k.clone(), v.clone()) {
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
        std::hint::black_box(lt.digest());
    }
    let lt_elapsed = lt_start.elapsed();

    let op_count = ops.len() as u32;
    println!(
        "  conduwuit-style (O(S log S), sort + SHA-256 every step): {:.1} ns/op",
        (conduwuit_elapsed.as_nanos() as f64) / f64::from(op_count)
    );
    println!(
        "  synapse-style (O(S), unsorted XOR-fold of SHA-256 every step): {:.1} ns/op",
        (synapse_elapsed.as_nanos() as f64) / f64::from(op_count)
    );
    println!(
        "  LtHash (O(1), lattice add/sub + BLAKE2b digest): {:.1} ns/op",
        (lt_elapsed.as_nanos() as f64) / f64::from(op_count)
    );
    report_speedup("conduwuit-style", conduwuit_elapsed, lt_elapsed);
    report_speedup("synapse-style", synapse_elapsed, lt_elapsed);
    report_speedup_two(
        "synapse-style vs conduwuit-style",
        conduwuit_elapsed,
        synapse_elapsed,
    );
    println!();
}

fn report_speedup(label: &str, baseline: Duration, lthash: Duration) {
    let baseline_ns = baseline.as_nanos() as f64;
    let lthash_ns = lthash.as_nanos() as f64;
    let speedup = baseline_ns / lthash_ns;
    if speedup >= 1.0 {
        println!("  => LtHash is {speedup:.2}x faster than {label}");
    } else {
        println!("  => LtHash is {:.2}x SLOWER than {label}", 1.0 / speedup);
    }
}

fn report_speedup_two(label: &str, slower_baseline: Duration, faster_baseline: Duration) {
    let slow_ns = slower_baseline.as_nanos() as f64;
    let fast_ns = faster_baseline.as_nanos() as f64;
    let ratio = slow_ns / fast_ns;
    if ratio >= 1.0 {
        println!("  => {label}: {ratio:.2}x faster (no-sort O(S) beats sorted O(S log S))");
    } else {
        println!("  => {label}: {:.2}x SLOWER", 1.0 / ratio);
    }
}

pub fn run() {
    for &n in &[
        16usize, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ] {
        bench_incremental_hash(n, 300);
    }
}
