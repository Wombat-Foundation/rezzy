//! Compares `imbl::OrdMap` against the HAMT (`rezzy::hamt`) as a backend for
//! `SharedState`, i.e. `Map<(EventType, String), Id>`.
//!
//! `SharedState` currently aliases to `imbl::OrdMap` (see the fork/diverge
//! benchmark note in `src/state/at.rs`). This benchmark exists to answer,
//! with real numbers, whether the HAMT built out over the last several
//! commits actually beats `OrdMap` for the access pattern state resolution
//! uses: small-to-medium room state maps, lots of persistent point
//! insert/remove during resolution, and cheap clone-and-diverge across
//! conflict branches.
//!
//! Run with: `cargo bench --bench state_backend`
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

use rezzy::basespec::event_types::EventType;
use rezzy::hamt::{self, HamtNode};

type Key = (EventType, String);
type Value = String;

const STRUCTURAL_KEY: &[u8] = b"bench-state-backend";

/// Small xorshift PRNG so entry generation is deterministic and dependency-free.
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

const KNOWN_SINGLETON_TYPES: &[EventType] = &[
    EventType::RoomCreate,
    EventType::RoomPowerLevels,
    EventType::RoomJoinRules,
    EventType::RoomThirdPartyInvite,
    EventType::RoomName,
    EventType::RoomTopic,
    EventType::RoomAvatar,
    EventType::RoomCanonicalAlias,
    EventType::RoomHistoryVisibility,
    EventType::RoomGuestAccess,
    EventType::RoomServerAcl,
    EventType::RoomTombstone,
    EventType::RoomEncryption,
    EventType::RoomPinnedEvents,
    EventType::RoomAliases,
    EventType::SpaceChild,
    EventType::SpaceParent,
];

/// Builds `n` distinct state-map entries mimicking a real room: mostly
/// `m.room.member` (one per state_key, i.e. per user) plus a handful of
/// singleton config events and a sprinkling of custom event types.
fn make_entries(n: usize, seed: u64) -> Vec<(Key, Value)> {
    let mut rng = Xorshift128::new(seed);
    let mut entries = Vec::with_capacity(n);
    let mut used = std::collections::HashSet::new();

    while entries.len() < n {
        let roll = rng.next_u64();
        let (event_type, state_key) = if roll % 10 < 7 {
            // 70%: membership, one per synthetic user id.
            let uid = rng.next_u64() % 1_000_000;
            (EventType::RoomMember, format!("@user{uid}:example.org"))
        } else if roll % 10 < 9 {
            // 20%: one of the other well-known singleton event types.
            let idx = (rng.next_u64() as usize) % KNOWN_SINGLETON_TYPES.len();
            (KNOWN_SINGLETON_TYPES[idx].clone(), String::new())
        } else {
            // 10%: custom event type, e.g. a third-party MSC.
            // Scale the key space with the fixture size so the custom tail
            // stays stable even for the largest benchmarks.
            let idx = rng.next_u64() % ((n.max(1) as u64) * 10);
            (
                EventType::from(format!("org.example.msc{idx}")),
                format!("key{idx}"),
            )
        };
        let key = (event_type, state_key);
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

/// Runs `f` `reps` times back to back and reports the average time per
/// call. Use when a single call to `f` is one logical "op" (e.g. one bulk
/// build).
fn time_repeated(label: &str, reps: u32, mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..reps {
        f();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / reps;
    println!(
        "  {label}: {:.1} ns/op ({reps} reps, {elapsed:.3?} total)",
        per_op.as_nanos() as f64
    );
    per_op
}

/// Runs `f` once, where `f` internally performs `op_count` logical
/// operations, and reports the average time per operation.
fn time_once(label: &str, op_count: u32, mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    let per_op = elapsed / op_count;
    println!(
        "  {label}: {:.1} ns/op ({op_count} ops, {elapsed:.3?} total)",
        per_op.as_nanos() as f64
    );
    per_op
}

fn bench_bulk_build(n: usize, entries: &[(Key, Value)]) {
    println!("bulk build (n={n}):");
    let reps = if n >= 4096 { 10 } else { 200 };

    let ordmap_elapsed = time_repeated("OrdMap::from_iter", reps, || {
        let map: imbl::OrdMap<Key, Value> = entries.iter().cloned().collect();
        black_box(map);
    });

    let hamt_elapsed = time_repeated("hamt::build_hamt", reps, || {
        let root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
            .expect("build should not collide");
        black_box(root);
    });

    report_speedup(ordmap_elapsed, hamt_elapsed);
}

fn bench_point_lookup(n: usize, entries: &[(Key, Value)]) {
    println!("point lookup (n={n}, 50% hit / 50% miss):");
    let ordmap: imbl::OrdMap<Key, Value> = entries.iter().cloned().collect();
    let hamt_root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");

    let mut rng = Xorshift128::new(0xF00D);
    let lookups: Vec<Key> = (0..5000)
        .map(|_| {
            if rng.next_u64() % 2 == 0 {
                entries[(rng.next_u64() as usize) % entries.len()].0.clone()
            } else {
                (
                    EventType::from(format!("org.example.miss{}", rng.next_u64())),
                    String::new(),
                )
            }
        })
        .collect();

    let op_count = lookups.len() as u32;
    let ordmap_elapsed = time_once("OrdMap::get", op_count, || {
        for k in &lookups {
            black_box(ordmap.get(k));
        }
    });
    let hamt_elapsed = time_once("hamt::get", op_count, || {
        for k in &lookups {
            black_box(hamt_root.get(STRUCTURAL_KEY, k));
        }
    });

    report_speedup(ordmap_elapsed, hamt_elapsed);
}

fn bench_incremental_insert(n: usize, entries: &[(Key, Value)]) {
    println!("incremental insert on top of full map (n={n}):");
    let ordmap: imbl::OrdMap<Key, Value> = entries.iter().cloned().collect();
    let hamt_root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");

    let mut rng = Xorshift128::new(0x00C0_FFEE);
    let new_keys: Vec<Key> = (0..1000)
        .map(|_| {
            (
                EventType::RoomMember,
                format!("@newuser{}:example.org", rng.next_u64()),
            )
        })
        .collect();

    let op_count = new_keys.len() as u32;
    let ordmap_elapsed = time_once("OrdMap::update (fresh clone each op)", op_count, || {
        for k in &new_keys {
            let mut m = ordmap.clone();
            m.insert(k.clone(), "$new:example.org".to_string());
            black_box(m);
        }
    });

    let hamt_elapsed = time_once(
        "hamt::insert (path-copy from shared root)",
        op_count,
        || {
            for k in &new_keys {
                let mut resolver = unreachable_resolver();
                let (new_root, _old) = hamt::insert(
                    &hamt_root,
                    STRUCTURAL_KEY,
                    k.clone(),
                    "$new:example.org".to_string(),
                    &mut resolver,
                )
                .expect("insert should not collide");
                black_box(new_root);
            }
        },
    );

    report_speedup(ordmap_elapsed, hamt_elapsed);
}

fn bench_incremental_remove(n: usize, entries: &[(Key, Value)]) {
    println!("incremental remove from full map (n={n}):");
    let ordmap: imbl::OrdMap<Key, Value> = entries.iter().cloned().collect();
    let hamt_root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");

    let victims: Vec<Key> = entries.iter().take(1000).map(|(k, _)| k.clone()).collect();
    let op_count = victims.len() as u32;

    let ordmap_elapsed = time_once("OrdMap::remove (fresh clone each op)", op_count, || {
        for k in &victims {
            let mut m = ordmap.clone();
            m.remove(k);
            black_box(m);
        }
    });

    let hamt_elapsed = time_once(
        "hamt::remove (path-copy from shared root)",
        op_count,
        || {
            for k in &victims {
                let mut resolver = unreachable_resolver();
                let (new_root, _old) = hamt::remove(&hamt_root, STRUCTURAL_KEY, k, &mut resolver)
                    .expect("remove should not error");
                black_box(new_root);
            }
        },
    );

    report_speedup(ordmap_elapsed, hamt_elapsed);
}

/// Simulates state-resolution forking: clone the base map into `branches`
/// diverging copies, then apply a handful of edits to each — the pattern
/// `resolve_state_maps`/conflict resolution actually exercises.
fn bench_fork_and_diverge(n: usize, entries: &[(Key, Value)]) {
    println!("fork into 8 branches + 20 edits each (n={n}):");
    let ordmap: imbl::OrdMap<Key, Value> = entries.iter().cloned().collect();
    let hamt_root = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");

    const BRANCHES: usize = 8;
    const EDITS_PER_BRANCH: usize = 20;
    const REPS: u32 = 50;
    let op_count = REPS * BRANCHES as u32 * EDITS_PER_BRANCH as u32;

    let ordmap_elapsed = time_once("OrdMap fork+diverge", op_count, || {
        let mut rng = Xorshift128::new(0xABCD);
        for _ in 0..REPS {
            for b in 0..BRANCHES {
                let mut branch = ordmap.clone();
                for _ in 0..EDITS_PER_BRANCH {
                    let key = (
                        EventType::RoomMember,
                        format!("@branch{b}user{}:example.org", rng.next_u64()),
                    );
                    branch.insert(key, "$edit:example.org".to_string());
                }
                black_box(branch);
            }
        }
    });

    let hamt_elapsed = time_once("hamt fork+diverge", op_count, || {
        let mut rng = Xorshift128::new(0xABCD);
        for _ in 0..REPS {
            for b in 0..BRANCHES {
                let mut branch = Arc::clone(&hamt_root);
                for _ in 0..EDITS_PER_BRANCH {
                    let key = (
                        EventType::RoomMember,
                        format!("@branch{b}user{}:example.org", rng.next_u64()),
                    );
                    let mut resolver = unreachable_resolver();
                    let (new_root, _old) = hamt::insert(
                        &branch,
                        STRUCTURAL_KEY,
                        key,
                        "$edit:example.org".to_string(),
                        &mut resolver,
                    )
                    .expect("insert should not collide");
                    branch = new_root;
                }
                black_box(branch);
            }
        }
    });

    report_speedup(ordmap_elapsed, hamt_elapsed);
}

fn report_speedup(ordmap: Duration, hamt: Duration) {
    let ordmap_ns = ordmap.as_nanos() as f64;
    let hamt_ns = hamt.as_nanos() as f64;
    let speedup = ordmap_ns / hamt_ns;
    if speedup >= 1.0 {
        println!("  => hamt is {speedup:.2}x faster than OrdMap\n");
    } else {
        println!("  => hamt is {:.2}x SLOWER than OrdMap\n", 1.0 / speedup);
    }
}

fn main() {
    for &n in &[16usize, 128, 1024, 8192] {
        let entries = make_entries(n, 0x5EED_0000 + n as u64);
        bench_bulk_build(n, &entries);
        bench_point_lookup(n, &entries);
        bench_incremental_insert(n, &entries);
        bench_incremental_remove(n, &entries);
        bench_fork_and_diverge(n, &entries);
    }
}
