//! Shared helpers for the HAMT benchmark suite.
//!
//! The HAMT benches (`persistence`, `state_groups`, `cumulative_rebuild`) all
//! need the same node-walk / encoding utilities. Keeping them here — generic
//! over `K, V` and referenced from a single `mod common;` in each bench —
//! means a change to the HAMT child layout or to `PersistedInternalNode` is
//! fixed once instead of silently drifting across three copies.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rezzy::hamt::codec::HamtCodec;
use rezzy::hamt::{self, HamtNode, PersistedInternalNode};
use rezzy::{json, LeanEvent};
use rezzy_recon::{ElementHash, ResidentKernel};
use sha2::Digest;

#[path = "../../support/reconciliation.rs"]
mod reconciliation_support;
pub use reconciliation_support::{
    build_decode_round_batch, build_remote_digest, empty_decode_batch, Xorshift128Hash,
};

/// Standard-library imports every benchmark module shares, so their preambles
/// stay identical instead of drifting apart copy by copy.
pub mod prelude {
    pub use std::collections::HashMap;
    pub use std::hint::black_box;
}

/// Deterministic PRNG (`xorshift128+`) so bench inputs are reproducible
/// without adding a `rand` dependency.
pub struct Xorshift128 {
    state: [u64; 2],
}

impl Xorshift128 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: [seed ^ 0x9E37_79B9_7F4A_7C15, seed.wrapping_add(1) | 1],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
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

/// Walks `old` and `new` in lockstep (same alignment logic
/// `diff_node_hashes` uses internally) and collects every node in `new`
/// that wasn't already present in `old` — i.e. exactly the nodes a
/// path-copying mutation newly allocated and that a storage backend must
/// persist to make `new` durable.
///
/// Trees here are always fully resolved (no `NodeRef::Lazy`), so this never
/// needs a resolver.
pub fn collect_new_nodes<K, V>(
    old: &Arc<HamtNode<K, V>>,
    new: &Arc<HamtNode<K, V>>,
    out: &mut Vec<Arc<HamtNode<K, V>>>,
) {
    if Arc::ptr_eq(old, new) || old.structural_hash == new.structural_hash {
        return;
    }
    out.push(Arc::clone(new));

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
                    collect_new_nodes(a, b, out);
                }
                cidx_a += 1;
                cidx_b += 1;
            }
            (true, false) => cidx_a += 1,
            (false, true) => {
                if let hamt::NodeRef::Resolved(b) = &new.children[cidx_b] {
                    // Entire subtree is new (a fresh branch point), not just
                    // its root — every node under it must be persisted too.
                    collect_all_nodes(b, out);
                }
                cidx_b += 1;
            }
            (false, false) => {}
        }
    }
}

/// Collects `node` and every internal node reachable from it via `nodemap`
/// children, in pre-order.
pub fn collect_all_nodes<K, V>(node: &Arc<HamtNode<K, V>>, out: &mut Vec<Arc<HamtNode<K, V>>>) {
    out.push(Arc::clone(node));
    for child in &node.children {
        if let hamt::NodeRef::Resolved(c) = child {
            collect_all_nodes(c, out);
        }
    }
}

/// Re-encodes a `HamtNode` as the on-disk [`PersistedInternalNode`] shape,
/// so its `encode_v1()` length measures the exact persisted byte cost.
pub fn to_persisted<K: Clone, V: Clone>(node: &HamtNode<K, V>) -> PersistedInternalNode<K, V> {
    PersistedInternalNode {
        datamap: node.datamap,
        nodemap: node.nodemap,
        leaves: node.leaves.clone(),
        child_hashes: node
            .children
            .iter()
            .map(hamt::NodeRef::structural_hash)
            .collect(),
    }
}

/// Runs `operation` `iterations` times and returns the elapsed wall time.
pub fn measure(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

/// Inserts every hash into a local/remote [`ResidentKernel`] pair and
/// returns the kernels plus their sorted `h64` indices.
pub fn build_sorted_kernels(
    local_hashes: &[ElementHash],
    remote_hashes: &[ElementHash],
) -> (ResidentKernel, ResidentKernel, Vec<u64>, Vec<u64>) {
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::with_capacity(local_hashes.len());
    let mut remote_h64 = Vec::with_capacity(remote_hashes.len());
    for hash in local_hashes {
        local.insert(*hash).expect("benchmark hash is valid");
        local_h64.push(hash.h64);
    }
    for hash in remote_hashes {
        remote.insert(*hash).expect("benchmark hash is valid");
        remote_h64.push(hash.h64);
    }
    local_h64.sort_unstable();
    remote_h64.sort_unstable();
    (local, remote, local_h64, remote_h64)
}

/// Fills a set of `n` unique keys, drawing each key (and, only when it is
/// new, its value) from `make_key`/`make_value` over a shared PRNG, so the
/// stream stays identical regardless of how many duplicate keys were drawn.
pub fn generate_unique_entries<K, V>(
    n: usize,
    seed: u64,
    mut make_key: impl FnMut(&mut Xorshift128) -> K,
    mut make_value: impl FnMut(&mut Xorshift128) -> V,
) -> Vec<(K, V)>
where
    K: Clone + Eq + std::hash::Hash,
{
    let mut rng = Xorshift128::new(seed);
    let mut entries = Vec::with_capacity(n);
    let mut used = std::collections::HashSet::new();
    while entries.len() < n {
        let key = make_key(&mut rng);
        if used.insert(key.clone()) {
            let value = make_value(&mut rng);
            entries.push((key, value));
        }
    }
    entries
}

/// Builds a deterministic fixture of distinct `String` state entries in the
/// `"room_member|@userN:example.org" -> "$eventM:example.org"` shape.
pub fn make_string_entries(n: usize, seed: u64) -> Vec<(String, String)> {
    generate_unique_entries(
        n,
        seed,
        |rng| {
            let uid = rng.next_u64() % 1_000_000;
            format!("room_member|@user{uid}:example.org")
        },
        |rng| format!("$event{}:example.org", rng.next_u64()),
    )
}

/// Generates a deterministic mutation stream: two-in-three new keys, else an
/// overwrite of a key drawn from `candidate_keys`.
pub fn generate_string_mutations(
    rng: &mut Xorshift128,
    steps: usize,
    candidate_keys: &[String],
) -> Vec<(String, String)> {
    let mut mutations = Vec::with_capacity(steps);
    for _ in 0..steps {
        let key = if rng.next_u64() % 3 == 0 && !candidate_keys.is_empty() {
            candidate_keys[(rng.next_u64() as usize) % candidate_keys.len()].clone()
        } else {
            format!("room_member|@user{}:example.org", rng.next_u64())
        };
        let value = format!("$event{}:example.org", rng.next_u64());
        mutations.push((key, value));
    }
    mutations
}

/// Resolver for fully materialized benchmark trees: any lazy lookup is a bug.
pub fn unreachable_resolver<K, V>(
) -> impl FnMut(&hamt::hash::StructuralHash) -> Result<Arc<HamtNode<K, V>>, ()> {
    |_hash| unreachable!("bench trees are always fully resolved")
}

/// Hashes pre-encoded rows by sorting them and feeding the result through
/// SHA-256 sequentially (the Conduwuit-style baseline shape).
pub fn sha256_sorted_hash(mut rows: Vec<Vec<u8>>) -> [u8; 32] {
    rows.sort_unstable();
    let mut hasher = sha2::Sha256::new();
    for row in &rows {
        hasher.update(row);
    }
    hasher.finalize().into()
}

/// Hashes pre-encoded rows order-independently via an XOR-fold of per-row
/// SHA-256 digests (the Synapse-style baseline shape).
pub fn xor_fold_sha256(rows: impl IntoIterator<Item = Vec<u8>>) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for row in rows {
        let digest: [u8; 32] = sha2::Sha256::digest(&row).into();
        for (a, d) in acc.iter_mut().zip(digest.iter()) {
            *a ^= d;
        }
    }
    acc
}

/// Returns the encoded size of a complete state map.
pub fn encode_full_map<'a, K: HamtCodec + 'a, V: HamtCodec + 'a>(
    entries: impl IntoIterator<Item = (&'a K, &'a V)>,
) -> usize {
    let mut buf = Vec::new();
    for (k, v) in entries {
        k.encode_hamt(&mut buf);
        v.encode_hamt(&mut buf);
    }
    buf.len()
}

/// Inserts the boilerplate `m.room.create` genesis event and returns its id.
pub fn insert_room_create(events: &mut HashMap<String, LeanEvent>, ts: &mut u64) -> String {
    let create_id = "$create".to_string();
    events.insert(
        create_id.clone(),
        LeanEvent {
            event_id: create_id.clone(),
            event_type: "m.room.create".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                *ts += 1;
                *ts
            },
            sender: "@creator:example.org".to_string(),
            content: json!({ "creator": "@creator:example.org" }),
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            depth: 0,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );
    create_id
}

/// Inserts the boilerplate `m.room.power_levels` event (citing `create_id`)
/// and returns its id.
pub fn insert_room_power_levels(
    events: &mut HashMap<String, LeanEvent>,
    ts: &mut u64,
    create_id: &str,
) -> String {
    let pl_id = "$power_levels".to_string();
    events.insert(
        pl_id.clone(),
        LeanEvent {
            event_id: pl_id.clone(),
            event_type: "m.room.power_levels".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                *ts += 1;
                *ts
            },
            sender: "@creator:example.org".to_string(),
            content: json!({ "users_default": 50 }),
            prev_events: vec![create_id.to_string()],
            auth_events: Vec::new(),
            depth: 1,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );
    pl_id
}

/// Creates a room's genesis pair — `m.room.create` followed by
/// `m.room.power_levels` — returning the event map, the timestamp counter,
/// and both event ids.
pub fn new_room_with_power_levels() -> (HashMap<String, LeanEvent>, u64, String, String) {
    let mut events = HashMap::new();
    let mut ts: u64 = 0;
    let create_id = insert_room_create(&mut events, &mut ts);
    let pl_id = insert_room_power_levels(&mut events, &mut ts, &create_id);
    (events, ts, create_id, pl_id)
}

/// Builds a public `m.room.join_rules` event (the shape both the interned-key
/// and mainline-cache fixtures need to make self-joins admissible).
pub fn join_rules_event(
    event_id: String,
    origin_server_ts: u64,
    prev_events: Vec<String>,
    auth_events: Vec<String>,
    depth: u64,
) -> LeanEvent {
    LeanEvent {
        event_id,
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        power_level: 100,
        origin_server_ts,
        sender: "@creator:example.org".to_string(),
        content: json!({ "join_rule": "public" }),
        prev_events,
        auth_events,
        depth,
        rejected: false,
        soft_fail: false,
        room_id: None,
    }
}

/// Builds an `m.room.member` event with the benchmark-default flags
/// (`rejected`/`soft_fail` false, `room_id` none).
#[allow(clippy::too_many_arguments)]
pub fn member_event(
    event_id: String,
    state_key: String,
    sender: String,
    membership: &str,
    power_level: i64,
    origin_server_ts: u64,
    prev_events: Vec<String>,
    auth_events: Vec<String>,
    depth: u64,
) -> LeanEvent {
    LeanEvent {
        event_id,
        event_type: "m.room.member".to_string(),
        state_key: Some(state_key),
        power_level,
        origin_server_ts,
        sender,
        content: json!({ "membership": membership }),
        prev_events,
        auth_events,
        depth,
        rejected: false,
        soft_fail: false,
        room_id: None,
    }
}

/// `(event_type, state_key)` pair keying a room state map.
pub type StateKey = (String, String);

/// Draws a random `m.room.member` key from a bounded user-id space.
pub fn random_member_key(rng: &mut Xorshift128) -> StateKey {
    let uid = rng.next_u64() % 1_000_000;
    (
        "m.room.member".to_string(),
        format!("@user{uid}:example.org"),
    )
}

/// One state mutation for the incremental `LtHash` benches.
pub enum StateOp {
    Insert(StateKey, String),
    Overwrite(StateKey, String),
    Remove(StateKey),
}

/// Generates `steps` mutations (60% insert, 30% overwrite, 10% remove) over
/// `existing_keys`, deterministically from `rng`.
pub fn generate_state_ops(
    rng: &mut Xorshift128,
    existing_keys: &[StateKey],
    steps: usize,
) -> Vec<StateOp> {
    let mut ops = Vec::with_capacity(steps);
    for _ in 0..steps {
        let roll = rng.next_u64() % 10;
        if roll < 6 {
            let key = (
                "m.room.member".to_string(),
                format!("@user{}:example.org", rng.next_u64()),
            );
            ops.push(StateOp::Insert(
                key,
                format!("$event{}:example.org", rng.next_u64()),
            ));
        } else if roll < 9 {
            let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
            ops.push(StateOp::Overwrite(
                key,
                format!("$event{}:example.org", rng.next_u64()),
            ));
        } else {
            let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
            ops.push(StateOp::Remove(key));
        }
    }
    ops
}

/// Applies `op` to the plain state map only.
pub fn apply_state_op(state: &mut HashMap<StateKey, String>, op: &StateOp) {
    match op {
        StateOp::Insert(k, v) | StateOp::Overwrite(k, v) => {
            state.insert(k.clone(), v.clone());
        }
        StateOp::Remove(k) => {
            state.remove(k);
        }
    }
}

/// Applies `op` to the state map and incrementally updates `lt` to match.
pub fn apply_state_op_lthash(
    state: &mut HashMap<StateKey, String>,
    lt: &mut rezzy::state::LtHash,
    op: &StateOp,
) {
    match op {
        StateOp::Insert(k, v) | StateOp::Overwrite(k, v) => {
            if let Some(old) = state.insert(k.clone(), v.clone()) {
                lt.replace(&k.0, &k.1, &old, v);
            } else {
                lt.insert(&k.0, &k.1, v);
            }
        }
        StateOp::Remove(k) => {
            if let Some(old) = state.remove(k) {
                lt.remove(&k.0, &k.1, &old);
            }
        }
    }
}

/// Builds an `LtHash` covering every entry of `state`.
pub fn lthash_of(state: &HashMap<StateKey, String>) -> rezzy::state::LtHash {
    let mut lt = rezzy::state::LtHash::ZERO;
    for ((event_type, state_key), event_id) in state {
        lt.insert(event_type, state_key, event_id);
    }
    lt
}
