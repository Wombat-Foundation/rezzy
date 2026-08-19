//! Compares HAMT's incremental node-diff persistence against a "legacy"
//! full-rebuild persistence strategy, for the workload state resolution
//! actually needs: applying a stream of individual state-map mutations
//! (member joins, config changes, ...) and, after *each* mutation, writing
//! whatever changed to durable storage.
//!
//! - **legacy**: no notion of a delta. Every mutation re-encodes and
//!   "writes" every entry in the whole state map from scratch — the
//!   `imbl::OrdMap`-shaped world where there's no cheap way to know which
//!   entries are new since the last snapshot.
//! - **hamt incremental**: uses [`rezzy::hamt::delta::diff_node_hashes`]'s
//!   underlying alignment logic to find only the internal nodes the
//!   mutation actually created (the O(log32 N) spine from the touched leaf
//!   up to the root) and persists just those.
//!
//! This is the comparison the HAMT was built to win: `state_backend.rs`
//! already shows HAMT loses raw in-memory fork/diverge throughput to
//! `OrdMap`. What it can't lose on is "how much do I have to write to disk
//! to durably record one mutation" — that's a function of path-copying
//! depth, not of whichever crate is faster at cloning in RAM.
//!
//! Run with: `cargo bench --bench persistence`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rezzy::hamt::{self, codec::HamtCodec, HamtNode};

mod common;

// String keys/values keep this bench decoupled from rezzy's real `Key`/`Value`
// aliases (which don't implement `HamtCodec`) while still exercising the same
// path-copying shape: "room_member|@userN:example.org" -> "$eventM:example.org".
type Key = String;
type Value = String;

const STRUCTURAL_KEY: &[u8] = b"bench-persistence";

fn make_entries(n: usize, seed: u64) -> Vec<(Key, Value)> {
    let mut rng = common::Xorshift128::new(seed);
    let mut entries = Vec::with_capacity(n);
    let mut used = std::collections::HashSet::new();
    while entries.len() < n {
        let uid = rng.next_u64() % 1_000_000;
        let key = format!("room_member|@user{uid}:example.org");
        if used.insert(key.clone()) {
            let event_id = format!("$event{}:example.org", rng.next_u64());
            entries.push((key, event_id));
        }
    }
    entries
}

fn unreachable_resolver(
) -> impl FnMut(&hamt::hash::StructuralHash) -> Result<Arc<HamtNode<Key, Value>>, ()> {
    |_hash| unreachable!("bench trees are always fully resolved")
}

fn encode_full_map(entries: &[(Key, Value)]) -> usize {
    let mut buf = Vec::new();
    for (k, v) in entries {
        k.encode_hamt(&mut buf);
        v.encode_hamt(&mut buf);
    }
    buf.len()
}

/// Simulates `steps` sequential state-resolution mutations on top of an
/// `n`-entry base state (mix of new joins and profile-update overwrites),
/// and for each one measures the bytes + time to durably persist it under
/// both strategies.
fn bench_incremental_persist(n: usize, steps: usize) {
    println!("incremental persist after each mutation (n={n}, steps={steps}):");

    let base_entries = make_entries(n, 0x5EED_0000 + n as u64);
    let mut root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, base_entries.iter().cloned())
        .expect("build should not collide");
    let mut flat_state: std::collections::HashMap<Key, Value> = base_entries.into_iter().collect();

    let mut rng = common::Xorshift128::new(0xBEEF);
    let mut mutations: Vec<(Key, Value)> = Vec::with_capacity(steps);
    let existing_keys: Vec<Key> = flat_state.keys().cloned().collect();
    for _ in 0..steps {
        let key = if rng.next_u64() % 3 == 0 && !existing_keys.is_empty() {
            // Overwrite (e.g. profile update / membership transition).
            existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone()
        } else {
            // New join.
            format!("room_member|@user{}:example.org", rng.next_u64())
        };
        let value = format!("$event{}:example.org", rng.next_u64());
        mutations.push((key, value));
    }

    let mut legacy_bytes: u64 = 0;
    let legacy_start = Instant::now();
    for (k, v) in &mutations {
        flat_state.insert(k.clone(), v.clone());
        let entries: Vec<(Key, Value)> = flat_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        legacy_bytes += encode_full_map(&entries) as u64;
    }
    let legacy_elapsed = legacy_start.elapsed();

    let mut hamt_bytes: u64 = 0;
    let hamt_start = Instant::now();
    for (k, v) in &mutations {
        let mut resolver = unreachable_resolver();
        let (new_root, _old) =
            hamt::insert(&root, STRUCTURAL_KEY, k.clone(), v.clone(), &mut resolver)
                .expect("insert should not collide");
        let mut new_nodes = Vec::new();
        common::collect_new_nodes(&root, &new_root, &mut new_nodes);
        for node in &new_nodes {
            hamt_bytes += common::to_persisted(node).encode_v1().len() as u64;
        }
        root = new_root;
        black_box(&root);
    }
    let hamt_elapsed = hamt_start.elapsed();

    let op_count = mutations.len() as u32;
    println!(
        "  legacy (full re-serialize every step): {:.1} ns/op, {:.1} bytes/op, {:.3} MiB total",
        (legacy_elapsed.as_nanos() as f64) / f64::from(op_count),
        legacy_bytes as f64 / f64::from(op_count),
        legacy_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  hamt (persist only new spine nodes): {:.1} ns/op, {:.1} bytes/op, {:.3} MiB total",
        (hamt_elapsed.as_nanos() as f64) / f64::from(op_count),
        hamt_bytes as f64 / f64::from(op_count),
        hamt_bytes as f64 / (1024.0 * 1024.0)
    );
    report_speedup("time", legacy_elapsed, hamt_elapsed);
    report_ratio("bytes written", legacy_bytes as f64, hamt_bytes as f64);
    println!();
}

fn report_speedup(label: &str, legacy: Duration, hamt: Duration) {
    let legacy_ns = legacy.as_nanos() as f64;
    let hamt_ns = hamt.as_nanos() as f64;
    let speedup = legacy_ns / hamt_ns;
    if speedup >= 1.0 {
        println!("  => hamt {label} is {speedup:.2}x faster than legacy");
    } else {
        println!(
            "  => hamt {label} is {:.2}x SLOWER than legacy",
            1.0 / speedup
        );
    }
}

/// Same mutation stream as [`bench_incremental_persist`], but instead of
/// persisting after every single mutation, only persists once every
/// `batch` hops — i.e. `steps / batch` snapshots total, each covering
/// `batch` mutations at once.
///
/// - legacy still has no notion of a delta, so batching just means writing
///   the full state fewer times: cost drops by roughly `batch`x since it's
///   simply `steps / batch` full re-serializations instead of `steps`.
/// - hamt's advantage isn't "diff every hop and sum the deltas" — it's a
///   single [`common::collect_new_nodes`] between the root at the start of the
///   batch and the root at the end. Mutations within a batch that keep
///   revisiting the same spine (e.g. two edits under the same top-level
///   bucket) only pay for their *final* shared ancestors once, so this
///   should beat both "legacy batched" and "hamt persisted every hop" on
///   bytes written, not just match the batch-size speedup.
fn bench_batched_persist(n: usize, steps: usize, batch: usize) {
    println!("batched persist every {batch} hops (n={n}, steps={steps}):");
    assert!(steps % batch == 0, "steps must divide evenly by batch");

    let base_entries = make_entries(n, 0x5EED_0000 + n as u64);
    let mut root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, base_entries.iter().cloned())
        .expect("build should not collide");
    let mut flat_state: std::collections::HashMap<Key, Value> = base_entries.into_iter().collect();

    let mut rng = common::Xorshift128::new(0xBEEF);
    let existing_keys: Vec<Key> = flat_state.keys().cloned().collect();
    let mut mutations: Vec<(Key, Value)> = Vec::with_capacity(steps);
    for _ in 0..steps {
        let key = if rng.next_u64() % 3 == 0 && !existing_keys.is_empty() {
            existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone()
        } else {
            format!("room_member|@user{}:example.org", rng.next_u64())
        };
        let value = format!("$event{}:example.org", rng.next_u64());
        mutations.push((key, value));
    }

    let mut legacy_bytes: u64 = 0;
    let legacy_start = Instant::now();
    for batch_muts in mutations.chunks(batch) {
        for (k, v) in batch_muts {
            flat_state.insert(k.clone(), v.clone());
        }
        let entries: Vec<(Key, Value)> = flat_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        legacy_bytes += encode_full_map(&entries) as u64;
    }
    let legacy_elapsed = legacy_start.elapsed();

    let mut hamt_bytes: u64 = 0;
    let hamt_start = Instant::now();
    for batch_muts in mutations.chunks(batch) {
        let batch_start_root = Arc::clone(&root);
        for (k, v) in batch_muts {
            let mut resolver = unreachable_resolver();
            let (new_root, _old) =
                hamt::insert(&root, STRUCTURAL_KEY, k.clone(), v.clone(), &mut resolver)
                    .expect("insert should not collide");
            root = new_root;
        }
        let mut new_nodes = Vec::new();
        common::collect_new_nodes(&batch_start_root, &root, &mut new_nodes);
        for node in &new_nodes {
            hamt_bytes += common::to_persisted(node).encode_v1().len() as u64;
        }
        black_box(&root);
    }
    let hamt_elapsed = hamt_start.elapsed();

    let batch_count = (steps / batch) as u32;
    println!(
        "  legacy ({batch_count} full snapshots): {:.1} ns/snapshot, {:.1} bytes/snapshot, {:.3} MiB total",
        (legacy_elapsed.as_nanos() as f64) / f64::from(batch_count),
        legacy_bytes as f64 / f64::from(batch_count),
        legacy_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  hamt ({batch_count} batch diffs): {:.1} ns/snapshot, {:.1} bytes/snapshot, {:.3} MiB total",
        (hamt_elapsed.as_nanos() as f64) / f64::from(batch_count),
        hamt_bytes as f64 / f64::from(batch_count),
        hamt_bytes as f64 / (1024.0 * 1024.0)
    );
    report_speedup("time", legacy_elapsed, hamt_elapsed);
    report_ratio("bytes written", legacy_bytes as f64, hamt_bytes as f64);
    println!();
}

fn report_ratio(label: &str, legacy: f64, hamt: f64) {
    let ratio = legacy / hamt;
    if ratio >= 1.0 {
        println!("  => hamt writes {ratio:.2}x fewer {label} than legacy");
    } else {
        println!(
            "  => hamt writes {:.2}x MORE {label} than legacy",
            1.0 / ratio
        );
    }
}

fn main() {
    for &n in &[
        16usize, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ] {
        bench_incremental_persist(n, 300);
    }
    for &n in &[128usize, 1024, 8192] {
        bench_batched_persist(n, 500, 100);
    }
}
