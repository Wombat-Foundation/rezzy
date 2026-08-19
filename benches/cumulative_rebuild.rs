//! Measures **cumulative** (not per-op incremental) cost: build a room's
//! state from empty up to `S` entries, one mutation at a time, and at
//! *every single step* pay whatever that step's real hash/persist cost is
//! at the state's *current* size — then sum it. This is a direct,
//! step-by-step simulation, not a post-hoc integration over sparse
//! samples from `persistence.rs`/`lthash.rs`/`state_groups.rs`.
//!
//! That distinction matters because per-op cost and cumulative
//! build-from-empty cost are different complexity classes whenever per-op
//! cost itself grows with state size:
//!
//! | strategy | per-op cost | cumulative cost building 0 → S |
//! |---|---|---|
//! | `LtHash` | `O(1)` | `O(S)` |
//! | HAMT persist | `O(log S)` | `O(S log S)` |
//! | Synapse-style (unsorted XOR-fold / bounded delta chain) | `O(S)` | `O(S^2)` |
//! | conduwuit-style (sort + SHA-256) | `O(S log S)` | `O(S^2 log S)` |
//!
//! The last row is the one worth calling out explicitly: a single sort of
//! `S` elements is `O(S log S)`, but re-sorting from scratch after *every
//! one* of `S` sequential mutations is `sum_{s=1}^{S} O(s log s) = O(S^2
//! log S)` — quadratic-with-a-log-factor, not just `O(S log S)`.
//!
//! `S_MAX` is deliberately capped at 4096, not 65536 like the other
//! benches — the conduwuit-style column alone costs `O(S^2 log S)` real
//! work here (every single one of `S` steps pays a full sort+hash, not
//! just the sampled checkpoints `lthash.rs` uses), and that's several
//! seconds of genuine CPU at S=4096 already; going to 65536 would take
//! this from a benchmark to a coffee break.
//!
//! Run with: `cargo bench --bench cumulative_rebuild`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use rezzy::hamt::{self, codec::HamtCodec, HamtNode};
use rezzy::state::LtHash;
use sha2::{Digest, Sha256};

mod common;

const S_MAX: usize = 4096;
const STRUCTURAL_KEY: &[u8] = b"bench-cumulative-rebuild";
const CHECKPOINTS: &[usize] = &[16, 64, 256, 1024, 2048, 4096];

type Key = String;
type Value = String;

fn canonical_row(k: &str, v: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(k.len() + v.len() + 8);
    buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
    buf.extend_from_slice(k.as_bytes());
    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
    buf.extend_from_slice(v.as_bytes());
    buf
}

fn conduwuit_style_hash(state: &HashMap<Key, Value>) -> [u8; 32] {
    let mut rows: Vec<Vec<u8>> = state.iter().map(|(k, v)| canonical_row(k, v)).collect();
    rows.sort_unstable();
    let mut hasher = Sha256::new();
    for row in &rows {
        hasher.update(row);
    }
    hasher.finalize().into()
}

fn synapse_style_hash(state: &HashMap<Key, Value>) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for (k, v) in state {
        let digest: [u8; 32] = Sha256::digest(canonical_row(k, v)).into();
        for (a, d) in acc.iter_mut().zip(digest.iter()) {
            *a ^= d;
        }
    }
    acc
}

fn unreachable_resolver(
) -> impl FnMut(&hamt::hash::StructuralHash) -> Result<Arc<HamtNode<Key, Value>>, ()> {
    |_hash| unreachable!("bench trees are always fully resolved")
}

fn node_bytes(node: &HamtNode<Key, Value>) -> usize {
    common::to_persisted(node).encode_v1().len()
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
fn main() {
    println!(
        "cumulative rebuild cost, building state from empty to S={S_MAX} one mutation at a time:"
    );
    println!("(this is a real step-by-step simulation, not an estimate)\n");

    let mut rng = common::Xorshift128::new(0x00C0_FFEE);
    let mut keys: Vec<Key> = Vec::with_capacity(S_MAX);
    let mut values: Vec<Value> = Vec::with_capacity(S_MAX);
    for _ in 0..S_MAX {
        keys.push(format!("room_member|@user{}:example.org", rng.next_u64()));
        values.push(format!("$event{}:example.org", rng.next_u64()));
    }

    // Ground-truth state for the two hashing strategies, and a separate
    // copy for the HAMT persist strategy (native structural sharing).
    let mut state: HashMap<Key, Value> = HashMap::with_capacity(S_MAX);
    let mut hamt_root: Option<Arc<HamtNode<Key, Value>>> = None;
    let mut lt = LtHash::ZERO;

    let mut cum_lthash_ns: u128 = 0;
    let mut cum_conduwuit_ns: u128 = 0;
    let mut cum_synapse_hash_ns: u128 = 0;
    let mut cum_hamt_persist_ns: u128 = 0;
    let mut cum_hamt_persist_bytes: u128 = 0;
    let mut cum_legacy_serialize_ns: u128 = 0;
    let mut cum_legacy_serialize_bytes: u128 = 0;

    let mut checkpoint_idx = 0usize;

    for step in 1..=S_MAX {
        let k = &keys[step - 1];
        let v = &values[step - 1];

        // --- LtHash: O(1) update against the running accumulator ---
        let t0 = Instant::now();
        lt.insert(k, "", v);
        cum_lthash_ns += t0.elapsed().as_nanos();

        // --- state mutation (ground truth for the hash strategies) ---
        state.insert(k.clone(), v.clone());

        // --- conduwuit-style: full sort + SHA-256 over current state ---
        let t0 = Instant::now();
        std::hint::black_box(conduwuit_style_hash(&state));
        cum_conduwuit_ns += t0.elapsed().as_nanos();

        // --- synapse-style: full unsorted XOR-fold over current state ---
        let t0 = Instant::now();
        std::hint::black_box(synapse_style_hash(&state));
        cum_synapse_hash_ns += t0.elapsed().as_nanos();

        // --- HAMT: path-copy insert + persist only the new spine nodes ---
        let t0 = Instant::now();
        let new_root = match &hamt_root {
            None => hamt::build_hamt::<Key, Value, _>(
                STRUCTURAL_KEY,
                std::iter::once((k.clone(), v.clone())),
            )
            .expect("build should not collide"),
            Some(root) => {
                let mut resolver = unreachable_resolver();
                hamt::insert(root, STRUCTURAL_KEY, k.clone(), v.clone(), &mut resolver)
                    .expect("insert should not collide")
                    .0
            }
        };
        if let Some(old_root) = &hamt_root {
            let mut new_nodes = Vec::new();
            common::collect_new_nodes(old_root, &new_root, &mut new_nodes);
            for node in &new_nodes {
                cum_hamt_persist_bytes += node_bytes(node) as u128;
            }
        } else {
            let mut new_nodes = Vec::new();
            common::collect_all_nodes(&new_root, &mut new_nodes);
            for node in &new_nodes {
                cum_hamt_persist_bytes += node_bytes(node) as u128;
            }
        }
        hamt_root = Some(new_root);
        cum_hamt_persist_ns += t0.elapsed().as_nanos();

        // --- legacy: re-encode the entire flat state every mutation ---
        let t0 = Instant::now();
        cum_legacy_serialize_bytes += encode_full_map(&state) as u128;
        cum_legacy_serialize_ns += t0.elapsed().as_nanos();

        if checkpoint_idx < CHECKPOINTS.len() && step == CHECKPOINTS[checkpoint_idx] {
            println!("S={step}:");
            println!(
                "  LtHash            cumulative: {:>14.3} ms",
                cum_lthash_ns as f64 / 1e6
            );
            println!(
                "  HAMT persist      cumulative: {:>14.3} ms, {:>10} bytes",
                cum_hamt_persist_ns as f64 / 1e6,
                cum_hamt_persist_bytes
            );
            println!(
                "  synapse-style hash cumulative:{:>14.3} ms",
                cum_synapse_hash_ns as f64 / 1e6
            );
            println!(
                "  legacy serialize  cumulative: {:>14.3} ms, {:>10} bytes",
                cum_legacy_serialize_ns as f64 / 1e6,
                cum_legacy_serialize_bytes
            );
            println!(
                "  conduwuit-style   cumulative: {:>14.3} ms",
                cum_conduwuit_ns as f64 / 1e6
            );
            println!();
            checkpoint_idx += 1;
        }
    }
}
