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

//! Isolates the per-`get_event` LOOKUP cost on a populated state map, apples
//! to apples between the two zero-alloc mechanisms:
//!
//! 1. **String** — the current real path: a `BTreeMap<(String, String), ...>`
//!    looked up by a borrowed `(&str, &str)` query via the
//!    `Borrow<dyn StateKeyDyn>` blanket + lexicographic `Ord for dyn
//!    StateKeyDyn` (the exact `auth::StateKeyDyn` mechanism). No allocation,
//!    no hashing; cost is ~log2(M) string compares per descent.
//! 2. **InternId** — the proposed zero-alloc spike: a `BTreeMap<(u32, u32), ...>`
//!    looked up by resolving both `&str` halves through an `id_of` string→u32
//!    hash map (SipHash, the same `std::collections::HashMap` the `Interner`
//!    uses under `std`), then a u32-compare descent.
//!
//! This separates the number the full-resolution bench can't: whether u32-keying
//! helps or hurts the AUTH-HOT-PATH lookup specifically, once the String path's
//! zero-alloc borrowed lookup is matched. It is NOT a test of map
//! BUILDING/cloning (the full bench covers that separately).
//!
//! The fixture assigns `InternId`s from a SORTED union of the event-type and
//! state-key strings (slot 0 = `""`, then lexicographic), matching the
//! production `Interner`'s rank-sorted arena — so the integer `(id, id)` key
//! ordering/tree shape reflects the proposed path, not first-seen insertion
//! order. Each config is measured over guaranteed HITS and over a HIT/MISS mix
//! (empty + unknown keys probing absent state), because `InternId` skips the
//! tree on a missing `id_of` while the String path always descends to conclude a
//! miss.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::explicit_counter_loop,
    clippy::cast_precision_loss,
    clippy::type_complexity
)]

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

// ---- Faithful replication of `auth::StateKeyDyn` (the real zero-alloc
// borrowed lookup the resolver uses today). ----
trait KeyDyn {
    fn ev(&self) -> &str;
    fn sk(&self) -> &str;
}
impl KeyDyn for (String, String) {
    fn ev(&self) -> &str {
        &self.0
    }
    fn sk(&self) -> &str {
        &self.1
    }
}
impl<'a> KeyDyn for (&'a str, &'a str) {
    fn ev(&self) -> &str {
        self.0
    }
    fn sk(&self) -> &str {
        self.1
    }
}
impl<'a> Borrow<dyn KeyDyn + 'a> for (String, String) {
    fn borrow(&self) -> &(dyn KeyDyn + 'a) {
        self
    }
}
impl PartialEq for dyn KeyDyn + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.ev() == other.ev() && self.sk() == other.sk()
    }
}
impl Eq for dyn KeyDyn + '_ {}
impl PartialOrd for dyn KeyDyn + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for dyn KeyDyn + '_ {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ev()
            .cmp(other.ev())
            .then_with(|| self.sk().cmp(other.sk()))
    }
}

/// The current String path: borrowed-`&str` lookup, zero-alloc, no hashing.
#[inline]
fn string_get(map: &BTreeMap<(String, String), usize>, et: &str, sk: &str) -> Option<usize> {
    let query: &dyn KeyDyn = &(et, sk);
    map.get(query).copied()
}

/// The zero-alloc InternId path: `id_of` for both halves, then a u32 descent.
#[inline]
fn intern_get(
    map: &BTreeMap<(u32, u32), usize>,
    str_to_id: &HashMap<String, u32>,
    et: &str,
    sk: &str,
) -> Option<usize> {
    let et = str_to_id.get(et).copied()?;
    let sk = str_to_id.get(sk).copied()?;
    map.get(&(et, sk)).copied()
}

fn measure(label: &str, reps: usize, f: impl Fn()) -> f64 {
    f(); // warmup
    f();
    let start = Instant::now();
    for _ in 0..reps {
        f();
    }
    let per_ms = start.elapsed().as_secs_f64() * 1000.0 / reps as f64;
    println!("  {label}: {per_ms:.3} ms/run");
    per_ms
}

/// Builds both maps (String and InternId) from `m` entries spread across
/// `type_count` event types.
///
/// IDs are assigned from the SORTED union of every distinct event-type and
/// state-key string, with slot 0 reserved for `""` — exactly the production
/// `Interner`'s rank-sorted arena (`Interner::new` reserves slot 0, then keys
/// are interned in sorted order). Using first-seen IDs instead would change
/// the integer `BTreeMap` ordering and tree shape away from the proposed path.
///
/// Returns the two maps, the string→id arena, the list of guaranteed HIT keys
/// `(event_type, state_key)`, and a list of MISS keys (empty + unknown strings
/// probing absent state — the auth traffic the resolver actually sees).
fn build(
    m: usize,
    type_count: usize,
) -> (
    BTreeMap<(String, String), usize>,
    BTreeMap<(u32, u32), usize>,
    HashMap<String, u32>,
    Vec<(String, String)>,
    Vec<(String, String)>,
) {
    let et_strings: Vec<String> = (0..type_count).map(|i| format!("m.room.type{i}")).collect();

    // Rank every distinct key: slot 0 reserved for "" (like `Interner::new`),
    // then all event types and state keys in lexicographic order.
    let mut arena: Vec<String> = Vec::with_capacity(m + 1);
    arena.push(String::new());
    for i in 0..m {
        arena.push(et_strings[i % type_count].clone());
        arena.push(format!("@user{i}:example.org"));
    }
    arena.sort();
    arena.dedup();
    let mut str_to_id = HashMap::with_capacity(arena.len());
    for (id, s) in arena.into_iter().enumerate() {
        str_to_id.insert(s, id as u32);
    }

    let mut str_map = BTreeMap::new();
    let mut id_map = BTreeMap::new();
    let mut hits = Vec::with_capacity(m);
    for i in 0..m {
        let et = &et_strings[i % type_count];
        let sk = format!("@user{i}:example.org");
        str_map.insert((et.clone(), sk.clone()), i);
        id_map.insert((str_to_id[et], str_to_id[&sk]), i);
        hits.push((et.clone(), sk));
    }

    // Representative absent-state probes: empty and unknown keys. Some miss on
    // the first `id_of` hashmap lookup (InternId skips the tree) and some only
    // on the tree descent (both paths descend).
    let misses: Vec<(String, String)> = vec![
        ("m.room.type0".into(), String::new()),
        ("m.room.type0".into(), "@ghost:example.org".into()),
        ("m.room.ghosttype".into(), "@user0:example.org".into()),
        ("m.room.ghosttype".into(), String::new()),
    ];

    (str_map, id_map, str_to_id, hits, misses)
}

fn main() {
    for &type_count in &[1usize, 16] {
        println!("--- {type_count} event type(s) ---");
        for &m in &[100usize, 1_000, 5_000] {
            let (str_map, id_map, str_to_id, hits, misses) = build(m, type_count);

            // Correctness gate: both paths must agree on every HIT and MISS.
            for (et, sk) in hits.iter().chain(misses.iter()) {
                assert_eq!(
                    string_get(&str_map, et, sk),
                    intern_get(&id_map, &str_to_id, et, sk),
                    "lookup paths must agree on {et:?}/{sk:?}"
                );
            }

            let q = hits.len().max(1);
            let q_mix = (hits.len() + misses.len()).max(1);
            let reps = (2_000_000usize / q).max(4);
            let reps_mix = (2_000_000usize / q_mix).max(4);
            println!(
                "  room: {m} entries, {} hits x{reps} + {} misses (mix x{reps_mix})",
                hits.len(),
                misses.len()
            );

            let str_ms = measure("  lookup String   (hit only) ", reps, || {
                let mut acc = 0usize;
                for (et, sk) in &hits {
                    acc = acc.wrapping_add(string_get(&str_map, et, sk).unwrap_or(0));
                }
                std::hint::black_box(acc);
            });
            let int_ms = measure("  lookup InternId (hit only) ", reps, || {
                let mut acc = 0usize;
                for (et, sk) in &hits {
                    acc = acc.wrapping_add(intern_get(&id_map, &str_to_id, et, sk).unwrap_or(0));
                }
                std::hint::black_box(acc);
            });
            let delta = (int_ms - str_ms) / str_ms * 100.0;
            println!("  InternId vs String (hits): {delta:+.1}%");

            let str_mix = measure("  lookup String   (hit+miss)  ", reps_mix, || {
                let mut acc = 0usize;
                for (et, sk) in hits.iter().chain(misses.iter()) {
                    acc = acc.wrapping_add(string_get(&str_map, et, sk).unwrap_or(0));
                }
                std::hint::black_box(acc);
            });
            let int_mix = measure("  lookup InternId (hit+miss)  ", reps_mix, || {
                let mut acc = 0usize;
                for (et, sk) in hits.iter().chain(misses.iter()) {
                    acc = acc.wrapping_add(intern_get(&id_map, &str_to_id, et, sk).unwrap_or(0));
                }
                std::hint::black_box(acc);
            });
            let delta_mix = (int_mix - str_mix) / str_mix * 100.0;
            println!("  InternId vs String (hit+miss): {delta_mix:+.1}%");
        }
    }
}
