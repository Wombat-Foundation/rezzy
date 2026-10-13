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

//! `PersistentOrdMap` key/value representation: which clone dominates?
//!
//! Path-copying clones separator keys and leaf `(K, V)` pairs. This bench runs
//! the same workload over four representations to separate the two costs:
//!
//! 1. `String` key + `String` value (current `SharedState` default)
//! 2. `InternedKey` key + `String` value (is it key / separator cloning?)
//! 3. `String` key + `Arc<str>` value (is it event-id value cloning?)
//! 4. `InternedKey` key + `Arc<str>` value (both)
//!
//! Ordering is string order in every variant, so this is a valid, general
//! option for live Matrix state (unlike the frozen-vocabulary `u32` `InternId`
//! upper bound in `state/interned_key`, which is not generally achievable).
//! Key/value construction (interning on ingest) is excluded from timing, and
//! owned inputs are cloned before the timed region so each variant measures
//! only the map operation itself.

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rezzy::basespec::event_types::EventType;
use rezzy::{InternedKey, PersistentOrdMap};

use crate::common::{generate_unique_entries, Xorshift128};

type Raw = ((EventType, String), String);

fn make_entries(n: usize, seed: u64) -> Vec<Raw> {
    generate_unique_entries(
        n,
        seed,
        |rng| {
            if rng.next_u64() % 10 < 9 {
                let uid = rng.next_u64() % 1_000_000;
                (EventType::RoomMember, format!("@user{uid}:example.org"))
            } else {
                let idx = rng.next_u64() % ((n.max(1) as u64) * 10);
                (
                    EventType::from(format!("org.example.msc{idx}")),
                    format!("key{idx}"),
                )
            }
        },
        |rng| format!("$event{}:example.org", rng.next_u64()),
    )
}

struct Variant<K, V> {
    mk_k: fn(&str) -> K,
    mk_v: fn(&str) -> V,
}

fn per_op(total: Duration, ops: u32) -> f64 {
    total.as_nanos() as f64 / f64::from(ops)
}

/// Returns ns/op for (insert, fork+diverge, lookup, diff).
fn measure<K: Ord + Clone, V: Clone + PartialEq>(v: &Variant<K, V>, entries: &[Raw]) -> [f64; 4] {
    let map: PersistentOrdMap<(EventType, K), V> = entries
        .iter()
        .map(|((t, k), val)| ((t.clone(), (v.mk_k)(k)), (v.mk_v)(val)))
        .collect();

    // incremental insert, fresh clone each op
    let mut rng = Xorshift128::new(0x00C0_FFEE);
    let ins_keys: Vec<(EventType, K)> = (0..1000)
        .map(|_| {
            (
                EventType::RoomMember,
                (v.mk_k)(&format!("@newuser{}:example.org", rng.next_u64())),
            )
        })
        .collect();
    let val = (v.mk_v)("$new:example.org");
    let mut ins = Duration::ZERO;
    for _ in 0..3 {
        let batch = ins_keys.clone();
        let start = Instant::now();
        for k in batch {
            let mut m = map.clone();
            m.insert(k, val.clone());
            black_box(m);
        }
        ins += start.elapsed();
    }

    // fork into 8 branches, 20 edits each
    let mut fork = Duration::ZERO;
    let mut rng = Xorshift128::new(0xABCD);
    const REPS: u32 = 20;
    for _ in 0..REPS {
        for b in 0..8 {
            let edits: Vec<(EventType, K)> = (0..20)
                .map(|_| {
                    (
                        EventType::RoomMember,
                        (v.mk_k)(&format!("@branch{b}user{}:example.org", rng.next_u64())),
                    )
                })
                .collect();
            let start = Instant::now();
            let mut branch = map.clone();
            for k in edits {
                branch.insert(k, val.clone());
            }
            black_box(branch);
            fork += start.elapsed();
        }
    }

    // lookup, 50% hit / 50% miss, prebuilt keys
    let mut rng = Xorshift128::new(0xF00D);
    let lookups: Vec<(EventType, K)> = (0..5000)
        .map(|_| {
            if rng.next_u64().is_multiple_of(2) {
                let ((t, k), _) = &entries[(rng.next_u64() as usize) % entries.len()];
                (t.clone(), (v.mk_k)(k))
            } else {
                (
                    EventType::from(format!("org.example.miss{}", rng.next_u64())),
                    (v.mk_k)(""),
                )
            }
        })
        .collect();
    let start = Instant::now();
    for k in &lookups {
        black_box(map.get(k));
    }
    let look = start.elapsed();

    // diff after 20 edits
    let mut branch = map.clone();
    for i in 0..20 {
        branch.insert(
            (
                EventType::RoomMember,
                (v.mk_k)(&format!("@diff{i}:example.org")),
            ),
            val.clone(),
        );
    }
    let start = Instant::now();
    for _ in 0..20 {
        black_box(map.diff(&branch).count());
    }
    let diff = start.elapsed();

    [
        per_op(ins, 3000),
        per_op(fork, REPS * 8 * 20),
        per_op(look, 5000),
        per_op(diff, 20),
    ]
}

/// Runs the key/value representation comparison.
pub fn run() {
    const OPS: [&str; 4] = ["insert", "fork+diverge", "lookup", "diff"];
    for &n in &[128usize, 1024, 8192, 65536] {
        let entries = make_entries(n, 0x5EED_0000 + n as u64);
        println!("key/value representation (n={n}), ns/op:");
        let s_s = measure(
            &Variant {
                mk_k: |s| s.to_owned(),
                mk_v: str::to_owned,
            },
            &entries,
        );
        let i_s = measure(
            &Variant {
                mk_k: |s| InternedKey::new(s),
                mk_v: str::to_owned,
            },
            &entries,
        );
        let s_a = measure(
            &Variant {
                mk_k: |s| s.to_owned(),
                mk_v: |s| Arc::<str>::from(s),
            },
            &entries,
        );
        let i_a = measure(
            &Variant {
                mk_k: |s| InternedKey::new(s),
                mk_v: |s| Arc::<str>::from(s),
            },
            &entries,
        );
        for (op, name) in OPS.iter().enumerate() {
            println!(
                "  {name:<13} String/String {:>9.1}  Interned/String {:>9.1} ({:.2}x)  \
                 String/Arc {:>9.1} ({:.2}x)  Interned/Arc {:>9.1} ({:.2}x)",
                s_s[op],
                i_s[op],
                i_s[op] / s_s[op],
                s_a[op],
                s_a[op] / s_s[op],
                i_a[op],
                i_a[op] / s_s[op],
            );
        }
        println!();
    }
}
