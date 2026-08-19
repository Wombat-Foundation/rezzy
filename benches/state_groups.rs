//! Compares HAMT against a model of Synapse's state-group storage: each
//! event's state change is persisted as a small delta row against the
//! *previous* state group (`state_groups_state` + `state_group_edges` in
//! Synapse's schema), not as a snapshot of the whole room state. That's the
//! literal `O(S)` write Synapse advertises — `S` here is the size of one
//! delta, normally 1-2 rows, not the room's full state size `N`.
//!
//! `persistence.rs` already shows HAMT beats a naive "re-serialize
//! everything" baseline by orders of magnitude on writes. Synapse's design
//! also beats that naive baseline on writes — its delta rows are smaller
//! than HAMT's persisted spine nodes, since a HAMT write still has to
//! persist `O(log32 N)` *internal* nodes even though only one leaf changed.
//! So on pure write cost, delta-chain-per-event can look better than HAMT.
//!
//! The cost that doesn't show up in a write-only benchmark: a pure delta
//! chain has to *read* by walking parent edges back to a full snapshot,
//! accumulating rows as it goes, until it finds the key it's looking for
//! (or reaches the snapshot at the bottom). Chain length is unbounded
//! unless something periodically re-snapshots — this is a real, documented
//! Synapse pain point (`state_group_edges` chains growing unbounded in
//! long-lived rooms make `resolve_state_groups_for_events` slow; there's a
//! `state_compressor` background job specifically to shorten chains). HAMT
//! has no equivalent problem: any root, from any point in history, answers
//! a point lookup in `O(log32 N)` regardless of how many mutations came
//! before it, because it's a tree keyed by content, not a linked list keyed
//! by time.
//!
//! This bench models both Synapse variants — an unbounded delta chain, and
//! one with a periodic full-snapshot every `SNAPSHOT_EVERY` hops (Synapse's
//! actual mitigation) — against HAMT, on both axes:
//! - write cost per mutation (bytes + time)
//! - worst-case point-lookup cost for a key set once at genesis and never
//!   touched again, read back after the whole mutation stream has run
//!
//! Run with: `cargo bench --bench state_groups`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::hamt::{self, codec::HamtCodec, HamtNode};

type Key = String;
type Value = String;

const STRUCTURAL_KEY: &[u8] = b"bench-state-groups";
const SNAPSHOT_EVERY: usize = 100;

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

fn make_entries(n: usize, seed: u64) -> Vec<(Key, Value)> {
    let mut rng = Xorshift128::new(seed);
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
) -> impl FnMut(&hamt::hash::StructuralHash) -> Result<std::sync::Arc<HamtNode<Key, Value>>, ()> {
    |_hash| unreachable!("bench trees are always fully resolved")
}

/// One state group: either a full snapshot (genesis, or a periodic
/// re-snapshot) or a one-row-ish delta against `parent`.
enum Group {
    Snapshot(HashMap<Key, Value>),
    Delta { parent: usize, row: (Key, Value) },
}

/// Walks a state-group chain from `group_idx` back toward genesis looking
/// for `key`, stopping as soon as it hits a `Snapshot` (either genesis or a
/// periodic re-snapshot). Returns the value and how many groups were
/// visited — this walk-and-accumulate is exactly what Synapse's
/// `_get_state_for_group_using_cache`-style resolution does on a cache
/// miss.
fn chain_lookup(groups: &[Group], group_idx: usize, key: &str) -> (Option<Value>, usize) {
    let mut idx = group_idx;
    let mut hops = 0usize;
    loop {
        hops += 1;
        match &groups[idx] {
            Group::Snapshot(map) => return (map.get(key).cloned(), hops),
            Group::Delta { parent, row } => {
                if row.0 == key {
                    return (Some(row.1.clone()), hops);
                }
                idx = *parent;
            }
        }
    }
}

fn encode_row(k: &Key, v: &Value) -> usize {
    let mut buf = Vec::new();
    k.encode_hamt(&mut buf);
    v.encode_hamt(&mut buf);
    buf.len()
}

fn encode_full_map(state: &HashMap<Key, Value>) -> usize {
    let mut buf = Vec::new();
    for (k, v) in state {
        k.encode_hamt(&mut buf);
        v.encode_hamt(&mut buf);
    }
    buf.len()
}

#[allow(clippy::too_many_lines)]
fn bench_state_groups(n: usize, steps: usize) {
    println!("state groups: hamt vs synapse-style delta chain (n={n}, steps={steps}):");

    let base_entries = make_entries(n, 0x5EED_0000 + n as u64);
    let mut flat_state: HashMap<Key, Value> = base_entries.iter().cloned().collect();
    let mut hamt_root =
        hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, base_entries.iter().cloned())
            .expect("build should not collide");

    // A key set at genesis and never mutated again — the worst case for a
    // delta chain (must walk every hop back to the snapshot) and a
    // routine case for HAMT (every lookup is O(log32 N) regardless).
    let cold_key = base_entries[0].0.clone();

    let mut rng = Xorshift128::new(0xBEEF);
    let mutable_keys: Vec<Key> = base_entries
        .iter()
        .skip(1)
        .map(|(k, _)| k.clone())
        .collect();
    let mut mutations: Vec<(Key, Value)> = Vec::with_capacity(steps);
    for _ in 0..steps {
        let key = if rng.next_u64() % 3 == 0 && !mutable_keys.is_empty() {
            mutable_keys[(rng.next_u64() as usize) % mutable_keys.len()].clone()
        } else {
            format!("room_member|@user{}:example.org", rng.next_u64())
        };
        let value = format!("$event{}:example.org", rng.next_u64());
        mutations.push((key, value));
    }

    // --- unbounded chain (no periodic re-snapshotting) ---
    let mut chain_unbounded: Vec<Group> = vec![Group::Snapshot(flat_state.clone())];
    // --- chain with a full snapshot every SNAPSHOT_EVERY hops (Synapse's
    // real mitigation) ---
    let mut chain_bounded: Vec<Group> = vec![Group::Snapshot(flat_state.clone())];

    let mut hamt_bytes_total: u64 = 0;
    let mut chain_unbounded_bytes: u64 = 0;
    let mut chain_bounded_bytes: u64 = 0;

    let write_start_hamt = Instant::now();
    for (k, v) in &mutations {
        let prev_root = hamt_root.clone();
        let mut resolver = unreachable_resolver();
        let (new_root, _old) = hamt::insert(
            &hamt_root,
            STRUCTURAL_KEY,
            k.clone(),
            v.clone(),
            &mut resolver,
        )
        .expect("insert should not collide");
        hamt_root = new_root;
        let mut new_nodes = Vec::new();
        crate_collect_new_nodes(&prev_root, &hamt_root, &mut new_nodes);
        for node in &new_nodes {
            hamt_bytes_total += node_encoded_len(node) as u64;
        }
        black_box(&hamt_root);
    }
    let hamt_write_elapsed = write_start_hamt.elapsed();

    let write_start_chain = Instant::now();
    for (step, (k, v)) in mutations.iter().enumerate() {
        flat_state.insert(k.clone(), v.clone());

        let parent = chain_unbounded.len() - 1;
        chain_unbounded_bytes += encode_row(k, v) as u64;
        chain_unbounded.push(Group::Delta {
            parent,
            row: (k.clone(), v.clone()),
        });

        let parent_b = chain_bounded.len() - 1;
        if (step + 1) % SNAPSHOT_EVERY == 0 {
            chain_bounded_bytes += encode_full_map(&flat_state) as u64;
            chain_bounded.push(Group::Snapshot(flat_state.clone()));
        } else {
            chain_bounded_bytes += encode_row(k, v) as u64;
            chain_bounded.push(Group::Delta {
                parent: parent_b,
                row: (k.clone(), v.clone()),
            });
        }
    }
    let chain_write_elapsed = write_start_chain.elapsed();

    let op_count = mutations.len() as u32;
    println!("  write cost per mutation:");
    println!(
        "    hamt (persist new spine nodes): {:.1} ns/op, {:.1} bytes/op",
        (hamt_write_elapsed.as_nanos() as f64) / f64::from(op_count),
        hamt_bytes_total as f64 / f64::from(op_count)
    );
    println!(
        "    synapse-style unbounded chain (1 delta row/op): {:.1} ns/op, {:.1} bytes/op",
        (chain_write_elapsed.as_nanos() as f64) / f64::from(op_count),
        chain_unbounded_bytes as f64 / f64::from(op_count)
    );
    println!(
        "    synapse-style chain + snapshot every {SNAPSHOT_EVERY} hops: {:.1} bytes/op (write time shared with the row above)",
        chain_bounded_bytes as f64 / f64::from(op_count)
    );
    report_ratio_bytes(
        "write bytes/op vs UNBOUNDED chain (no compaction, not read-safe)",
        hamt_bytes_total as f64 / f64::from(op_count),
        chain_unbounded_bytes as f64 / f64::from(op_count),
    );
    // The unbounded chain above never pays for compaction, which is why it
    // always looks cheap on writes — but per the lookup benchmark below,
    // it's not a viable design on its own. This is the comparison that
    // actually matters: HAMT vs. the chain variant that stays read-bounded.
    // Snapshot cost is O(N) amortized over SNAPSHOT_EVERY, so it grows with
    // room size while HAMT's persisted-node cost only grows with log32(N) —
    // expect this ratio to flip somewhere around a few thousand entries.
    report_ratio_bytes(
        "write bytes/op vs snapshot-bounded chain (read-safe, apples to apples)",
        hamt_bytes_total as f64 / f64::from(op_count),
        chain_bounded_bytes as f64 / f64::from(op_count),
    );

    // --- worst-case cold-key lookup after the full mutation stream ---
    //
    // `steps` is intentionally *not* required to land on a snapshot
    // boundary. If it did, the "bounded" chain's last group would itself be
    // a snapshot and every lookup would trivially cost 1 hop, which is the
    // best case for that variant, not a representative one. Querying at the
    // chain's actual tip keeps this at whatever distance-since-last-snapshot
    // that tip happens to be — see the assertion below, which fails loudly
    // if a caller picks a `steps` that accidentally aligns.
    assert!(
        steps % SNAPSHOT_EVERY != 0,
        "steps={steps} is a multiple of SNAPSHOT_EVERY={SNAPSHOT_EVERY}: the bounded chain's \
         tip would itself be a snapshot, trivializing the lookup benchmark below"
    );
    const LOOKUP_REPS: u32 = 2000;
    let final_group_unbounded = chain_unbounded.len() - 1;
    let final_group_bounded = chain_bounded.len() - 1;

    let (val, unbounded_hops) = chain_lookup(&chain_unbounded, final_group_unbounded, &cold_key);
    assert!(val.is_some(), "cold key must still resolve");
    let (val, bounded_hops) = chain_lookup(&chain_bounded, final_group_bounded, &cold_key);
    assert!(val.is_some(), "cold key must still resolve");

    let unbounded_lookup_start = Instant::now();
    for _ in 0..LOOKUP_REPS {
        black_box(chain_lookup(
            &chain_unbounded,
            final_group_unbounded,
            &cold_key,
        ));
    }
    let unbounded_lookup_elapsed = unbounded_lookup_start.elapsed();

    let bounded_lookup_start = Instant::now();
    for _ in 0..LOOKUP_REPS {
        black_box(chain_lookup(&chain_bounded, final_group_bounded, &cold_key));
    }
    let bounded_lookup_elapsed = bounded_lookup_start.elapsed();

    let hamt_lookup_start = Instant::now();
    for _ in 0..LOOKUP_REPS {
        black_box(hamt_root.get(STRUCTURAL_KEY, &cold_key));
    }
    let hamt_lookup_elapsed = hamt_lookup_start.elapsed();

    println!("  cold-key point lookup after {steps} mutations (key untouched since genesis):");
    println!(
        "    hamt::get: {:.1} ns/op, O(log32 N) always",
        (hamt_lookup_elapsed.as_nanos() as f64) / f64::from(LOOKUP_REPS)
    );
    println!(
        "    synapse-style unbounded chain walk: {:.1} ns/op, {unbounded_hops} hops walked",
        (unbounded_lookup_elapsed.as_nanos() as f64) / f64::from(LOOKUP_REPS)
    );
    println!(
        "    synapse-style chain walk (snapshot every {SNAPSHOT_EVERY}): {:.1} ns/op, {bounded_hops} hops walked",
        (bounded_lookup_elapsed.as_nanos() as f64) / f64::from(LOOKUP_REPS)
    );
    report_speedup(
        "unbounded chain vs hamt lookup",
        unbounded_lookup_elapsed,
        hamt_lookup_elapsed,
    );
    report_speedup(
        "snapshot-bounded chain vs hamt lookup",
        bounded_lookup_elapsed,
        hamt_lookup_elapsed,
    );
    println!();
}

// --- node-diff helpers (same shape as persistence.rs's `collect_new_nodes` /
// `to_persisted`; duplicated locally so this file stands alone) ---

fn crate_collect_new_nodes(
    old: &std::sync::Arc<HamtNode<Key, Value>>,
    new: &std::sync::Arc<HamtNode<Key, Value>>,
    out: &mut Vec<std::sync::Arc<HamtNode<Key, Value>>>,
) {
    if std::sync::Arc::ptr_eq(old, new) || old.structural_hash == new.structural_hash {
        return;
    }
    out.push(std::sync::Arc::clone(new));

    let (n_a, n_b) = (old.nodemap, new.nodemap);
    let (mut cidx_a, mut cidx_b) = (0usize, 0usize);
    for i in 0..32 {
        let bit = 1u32 << i;
        let (in_a, in_b) = (n_a & bit != 0, n_b & bit != 0);
        match (in_a, in_b) {
            (true, true) => {
                if let (hamt::NodeRef::Resolved(a), hamt::NodeRef::Resolved(b)) =
                    (&old.children[cidx_a], &new.children[cidx_b])
                {
                    crate_collect_new_nodes(a, b, out);
                }
                cidx_a += 1;
                cidx_b += 1;
            }
            (true, false) => cidx_a += 1,
            (false, true) => {
                if let hamt::NodeRef::Resolved(b) = &new.children[cidx_b] {
                    collect_all_nodes(b, out);
                }
                cidx_b += 1;
            }
            (false, false) => {}
        }
    }
}

fn collect_all_nodes(
    node: &std::sync::Arc<HamtNode<Key, Value>>,
    out: &mut Vec<std::sync::Arc<HamtNode<Key, Value>>>,
) {
    out.push(std::sync::Arc::clone(node));
    for child in &node.children {
        if let hamt::NodeRef::Resolved(c) = child {
            collect_all_nodes(c, out);
        }
    }
}

fn node_encoded_len(node: &HamtNode<Key, Value>) -> usize {
    hamt::PersistedInternalNode {
        datamap: node.datamap,
        nodemap: node.nodemap,
        structural_hash: node.structural_hash,
        leaves: node.leaves.clone(),
        child_hashes: node
            .children
            .iter()
            .map(hamt::NodeRef::structural_hash)
            .collect(),
    }
    .encode_v1()
    .len()
}

fn report_speedup(label: &str, slow: Duration, fast: Duration) {
    let slow_ns = slow.as_nanos() as f64;
    let fast_ns = fast.as_nanos() as f64;
    let speedup = slow_ns / fast_ns;
    if speedup >= 1.0 {
        println!("    => {label}: hamt is {speedup:.2}x faster");
    } else {
        println!("    => {label}: hamt is {:.2}x SLOWER", 1.0 / speedup);
    }
}

fn report_ratio_bytes(label: &str, hamt: f64, other: f64) {
    let ratio = hamt / other;
    if ratio >= 1.0 {
        println!("    => hamt writes {ratio:.2}x MORE {label} than synapse-style delta rows");
    } else {
        println!(
            "    => hamt writes {:.2}x fewer {label} than synapse-style delta rows",
            1.0 / ratio
        );
    }
}

fn main() {
    // 550, not 500: deliberately mid-window (50 hops past the snapshot at
    // 500) so the bounded chain's lookup isn't measured at its trivial
    // best case of landing exactly on a snapshot. See the assertion in
    // `bench_state_groups`.
    for &n in &[128usize, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        bench_state_groups(n, 550);
    }
}
