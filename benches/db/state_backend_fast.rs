// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fair backend comparison with equivalent, cheap-clone types:
//! `imbl::OrdMap<(EventType, InternedKey), Arc<str>>` vs
//! `PersistentOrdMap<(EventType, InternedKey), Arc<str>>` (i.e. the
//! `FastSharedState` configuration).
//!
//! `state_backend` compares both on `String` keys/values, which charges
//! allocation cost to whichever backend clones more. Here both maps use
//! `Arc`-backed keys and values, so the comparison isolates tree structure.
//! Keys/values are built once up front (as `intern_events` would at ingest);
//! timed inputs are cloned (refcount bumps) from those prebuilt vectors.

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rezzy::basespec::event_types::EventType;
use rezzy::{InternedKey, PersistentOrdMap};

use super::state_backend::make_entries;
use crate::common::Xorshift128;

type K = (EventType, InternedKey);
type V = Arc<str>;

/// The operations under test, implemented for both backends.
trait Backend: Clone {
    const NAME: &'static str;
    fn build(entries: &[(K, V)]) -> Self;
    fn get_(&self, k: &K) -> bool;
    fn insert_(&mut self, k: K, v: V);
    fn remove_(&mut self, k: &K);
    fn diff_count(&self, other: &Self) -> usize;
}

impl Backend for imbl::OrdMap<K, V> {
    const NAME: &'static str = "imbl";
    fn build(entries: &[(K, V)]) -> Self {
        entries.iter().cloned().collect()
    }
    fn get_(&self, k: &K) -> bool {
        self.get(k).is_some()
    }
    fn insert_(&mut self, k: K, v: V) {
        self.insert(k, v);
    }
    fn remove_(&mut self, k: &K) {
        self.remove(k);
    }
    fn diff_count(&self, other: &Self) -> usize {
        self.diff(other).count()
    }
}

impl Backend for PersistentOrdMap<K, V> {
    const NAME: &'static str = "Persistent";
    fn build(entries: &[(K, V)]) -> Self {
        entries.iter().cloned().collect()
    }
    fn get_(&self, k: &K) -> bool {
        self.get(k).is_some()
    }
    fn insert_(&mut self, k: K, v: V) {
        self.insert(k, v);
    }
    fn remove_(&mut self, k: &K) {
        self.remove(k);
    }
    fn diff_count(&self, other: &Self) -> usize {
        self.diff(other).count()
    }
}

fn ns(total: Duration, ops: u32) -> f64 {
    total.as_nanos() as f64 / f64::from(ops)
}

/// ns/op for [bulk build, cold lookup, warm lookup, insert, fork+diverge,
/// remove, diff].
fn measure<B: Backend>(entries: &[(K, V)]) -> [f64; 7] {
    // bulk build
    let reps = (200_000 / entries.len()).clamp(2, 200) as u32;
    let start = Instant::now();
    for _ in 0..reps {
        black_box(B::build(entries));
    }
    let build = ns(start.elapsed(), reps);

    let map = B::build(entries);
    let val: V = Arc::from("$new:example.org");

    // lookup, 50% hit / 50% miss
    let mut rng = Xorshift128::new(0xF00D);
    let lookups: Vec<K> = (0..5000)
        .map(|_| {
            if rng.next_u64().is_multiple_of(2) {
                entries[(rng.next_u64() as usize) % entries.len()].0.clone()
            } else {
                (
                    EventType::from(format!("org.example.miss{}", rng.next_u64())),
                    InternedKey::new(""),
                )
            }
        })
        .collect();

    let start = Instant::now();
    for k in &lookups {
        black_box(map.get_(k));
    }
    let cold_look = ns(start.elapsed(), 5000);

    const LOOKUP_REPS: u32 = 20;
    let start = Instant::now();
    for _ in 0..LOOKUP_REPS {
        for k in &lookups {
            black_box(map.get_(k));
        }
    }
    let lookup_ops = 5000u32
        .checked_mul(LOOKUP_REPS)
        .expect("lookup operation count overflow");
    let warm_look = ns(start.elapsed(), lookup_ops);

    // insert, fresh clone each op
    let mut rng = Xorshift128::new(0x00C0_FFEE);
    let new_keys: Vec<K> = (0..1000)
        .map(|_| {
            (
                EventType::RoomMember,
                InternedKey::new(format!("@newuser{}:example.org", rng.next_u64())),
            )
        })
        .collect();
    let mut ins = Duration::ZERO;
    for _ in 0..3 {
        let batch = new_keys.clone();
        let start = Instant::now();
        for k in batch {
            let mut m = map.clone();
            m.insert_(k, val.clone());
            black_box(m);
        }
        ins += start.elapsed();
    }

    // fork into 8 branches, 20 edits each
    let mut rng = Xorshift128::new(0xABCD);
    const REPS: u32 = 20;
    let mut fork = Duration::ZERO;
    for _ in 0..REPS {
        for b in 0..8 {
            let edits: Vec<K> = (0..20)
                .map(|_| {
                    (
                        EventType::RoomMember,
                        InternedKey::new(format!("@branch{b}user{}:example.org", rng.next_u64())),
                    )
                })
                .collect();
            let start = Instant::now();
            let mut branch = map.clone();
            for k in edits {
                branch.insert_(k, val.clone());
            }
            black_box(branch);
            fork += start.elapsed();
        }
    }

    // remove, fresh clone each op
    let victims: Vec<K> = entries.iter().take(1000).map(|(k, _)| k.clone()).collect();
    let start = Instant::now();
    for k in &victims {
        let mut m = map.clone();
        m.remove_(k);
        black_box(m);
    }
    let rem = ns(start.elapsed(), victims.len() as u32);

    // diff after 20 edits
    let mut branch = map.clone();
    for i in 0..20 {
        branch.insert_(
            (
                EventType::RoomMember,
                InternedKey::new(format!("@diff{i}:example.org")),
            ),
            val.clone(),
        );
    }
    let start = Instant::now();
    for _ in 0..20 {
        black_box(map.diff_count(&branch));
    }
    let diff = ns(start.elapsed(), 20);

    [
        build,
        cold_look,
        warm_look,
        ns(ins, 3000),
        ns(fork, REPS * 8 * 20),
        rem,
        diff,
    ]
}

/// Runs the fair imbl vs `PersistentOrdMap` comparison on Arc-backed types.
pub fn run() {
    const OPS: [&str; 7] = [
        "bulk build",
        "lookup-cold",
        "lookup-warm",
        "insert",
        "fork+diverge",
        "remove",
        "diff",
    ];
    for &n in &[16usize, 128, 1024, 8192, 16384, 65536, 131072] {
        let entries: Vec<(K, V)> = make_entries(n, 0x5EED_0000 + n as u64)
            .into_iter()
            .map(|((t, k), v)| ((t, InternedKey::new(k)), Arc::from(v)))
            .collect();
        println!(
            "imbl vs PersistentOrdMap, (EventType, InternedKey) -> Arc<str> (n={n}), ns/op:"
        );
        let a = measure::<imbl::OrdMap<K, V>>(&entries);
        let b = measure::<PersistentOrdMap<K, V>>(&entries);
        for (i, op) in OPS.iter().enumerate() {
            println!(
                "  {op:<13} {}: {:>11.1}  {}: {:>11.1}  => {:.2}x {}",
                <imbl::OrdMap<K, V> as Backend>::NAME,
                a[i],
                <PersistentOrdMap<K, V> as Backend>::NAME,
                b[i],
                b[i] / a[i],
                <imbl::OrdMap<K, V> as Backend>::NAME,
            );
        }
        println!();
    }
}
