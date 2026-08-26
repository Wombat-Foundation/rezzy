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

//! Wall-clock benchmark comparing the resolution hot loop with `K = String`
//! versus `K = InternedKey` (`Arc<str>`-backed state keys).
//!
//! This answers the question the `InternedKey` type doc flags as genuinely
//! open: does the `Arc`-clone win over `String`-clone survive contact with
//! real resolution — HAMT/lattice state building and the parallel
//! `std::thread::scope` fold (lattice.rs `compute_lattice_coordinatized_winners`,
//! active under the default `std` feature) where `Arc` refcount contention is
//! the actual risk. A bare `Arc::clone` vs `String::clone` microbenchmark would
//! only confirm the foregone pointer-bump-vs-allocation result, so this
//! measures the real `compute_state_at_batch` / `compute_state_at` path on a
//! room whose resolved states carry many distinct member state keys.
//!
//! The room is a `create` + `power_levels` + a linear chain of `m.room.member`
//! events, each with a distinct `state_key`. The last member's resolved state
//! therefore contains every member state key, so the cost of materializing and
//! merging those keys is real and scales with room size. Multiple room sizes
//! are measured because the tradeoff can flip between small (low clone volume,
//! `Arc` overhead not worth it) and large (clone volume amplified, `Arc` wins).
//!
//! Timing excludes the one-time `into_interned_state_key` conversion (done up
//! front), so only the resolution hot loop itself is compared. Allocation
//! count is not instrumented here — the repo has no allocator-counting harness
//! — so this is wall-clock only.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::explicit_counter_loop,
    clippy::cast_precision_loss
)]

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rezzy::{compute_state_at, compute_state_at_batch, InternedKey, LeanEvent, StateResVersion};

/// A flat `u32` index into an interned string arena — the C-style key: `Copy`,
/// no atomic refcount, no per-clone allocation, integer compare/hash. Ids are
/// assigned in lexicographic string order so that `InternId`'s numeric `Ord`
/// agrees with the resolver's `Borrow<dyn StateKeyDyn>` string ordering (see
/// the soundness note beside that impl in `src/auth/mod.rs`); `default()` is
/// the empty-string key, matching how the pipeline builds keys from carried
/// `state_key` values (`unwrap_or_default`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
struct InternId(u32);

impl InternId {
    fn of(idx: usize) -> Self {
        InternId(idx as u32)
    }
}

impl AsRef<str> for InternId {
    fn as_ref(&self) -> &str {
        // `INTERN` is a 'static `OnceLock<Vec<String>>`, so the returned
        // reference is 'static and coerces to `&self`'s lifetime; the table is
        // immutable during resolution, so this is a lock-free shared read even
        // under the parallel `thread::scope` fold.
        &INTERN.get().expect("interner initialized")[self.0 as usize]
    }
}

impl std::fmt::Display for InternId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

/// The interned string arena: `INTERN[idx]` is the string for `InternId(idx)`.
static INTERN: OnceLock<Vec<String>> = OnceLock::new();

/// Interns the union of every distinct `state_key` across all rooms, sorted, so
/// one shared arena serves every room size and id order == string order.
fn init_interner(rooms: &[&HashMap<String, LeanEvent>]) {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for room in rooms {
        for ev in room.values() {
            if let Some(k) = &ev.state_key {
                if seen.insert(k.clone()) {
                    keys.push(k.clone());
                }
            }
        }
    }
    keys.sort();
    INTERN
        .set(keys)
        .expect("interner must be initialized exactly once");
}

fn str_to_id() -> HashMap<String, InternId> {
    INTERN
        .get()
        .expect("interner initialized")
        .iter()
        .enumerate()
        .map(|(i, s)| (s.clone(), InternId::of(i)))
        .collect()
}

/// Rebuilds a room with `K = InternId`, interning each `state_key` through the
/// shared arena. Field-for-field copy; only the `state_key` representation
/// changes.
fn to_u32_events(
    events: &HashMap<String, LeanEvent>,
    str_to_id: &HashMap<String, InternId>,
) -> HashMap<String, LeanEvent<String, serde_json::Value, InternId>> {
    events
        .iter()
        .map(|(id, ev)| {
            let converted = LeanEvent {
                event_id: ev.event_id.clone(),
                event_type: ev.event_type.clone(),
                state_key: ev.state_key.as_ref().map(|k| str_to_id[k]),
                power_level: ev.power_level,
                origin_server_ts: ev.origin_server_ts,
                sender: ev.sender.clone(),
                content: ev.content.clone(),
                prev_events: ev.prev_events.clone(),
                auth_events: ev.auth_events.clone(),
                prev_state_events: ev.prev_state_events.clone(),
                depth: ev.depth,
                rejected: ev.rejected,
                soft_fail: ev.soft_fail,
                room_id: ev.room_id.clone(),
            };
            (id.clone(), converted)
        })
        .collect()
}

/// Builds `create -> power_levels` followed by a linear chain of `member_count`
/// `m.room.member` events, each with a distinct `state_key` (the target user).
/// Returns the event map plus the IDs of a spread of member events to resolve.
fn build_room(member_count: usize) -> (HashMap<String, LeanEvent>, Vec<String>) {
    let mut events = HashMap::new();
    let mut ts: u64 = 0;

    let create_id = "$create".to_string();
    events.insert(
        create_id.clone(),
        LeanEvent {
            event_id: create_id.clone(),
            event_type: "m.room.create".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                ts += 1;
                ts
            },
            sender: "@creator:example.org".to_string(),
            content: serde_json::json!({ "creator": "@creator:example.org" }),
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            prev_state_events: Vec::new(),
            depth: 0,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );

    let pl_id = "$power_levels".to_string();
    events.insert(
        pl_id.clone(),
        LeanEvent {
            event_id: pl_id.clone(),
            event_type: "m.room.power_levels".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                ts += 1;
                ts
            },
            sender: "@creator:example.org".to_string(),
            content: serde_json::json!({ "users_default": 50 }),
            prev_events: vec![create_id.clone()],
            // V2.1+ (this bench uses `StateResVersion::V2_1` throughout)
            // forbids citing `m.room.create` in `auth_events` (rule 2.4) --
            // create is implicit, not cited. Citing it here made this fixture
            // invalid under the version the bench actually resolves against.
            auth_events: Vec::new(),
            prev_state_events: Vec::new(),
            depth: 1,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );

    let mut prev = pl_id.clone();
    let mut depth: u64 = 2;
    let mut targets = Vec::new();
    for i in 0..member_count {
        let id = format!("$member_{i}");
        let user = format!("@user{i}:example.org");
        events.insert(
            id.clone(),
            LeanEvent {
                event_id: id.clone(),
                event_type: "m.room.member".to_string(),
                state_key: Some(user.clone()),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: user,
                content: serde_json::json!({ "membership": "join" }),
                prev_events: vec![prev.clone()],
                // For `i == 0`, `prev` is `pl_id` itself (the loop's initial
                // value) -- `vec![pl_id.clone(), prev.clone()]` would cite the
                // same event twice. Dedup so the first member only cites
                // power_levels once, and later members cite power_levels plus
                // the previous member event.
                auth_events: if prev == pl_id {
                    vec![pl_id.clone()]
                } else {
                    vec![pl_id.clone(), prev.clone()]
                },
                prev_state_events: Vec::new(),
                depth,
                rejected: false,
                soft_fail: false,
                room_id: None,
            },
        );
        // Resolve a spread of targets so the batch path engages the parallel
        // lattice fold over a wide slice of non-power events.
        if i == 0 || i == member_count / 3 || i == member_count * 2 / 3 || i == member_count - 1 {
            targets.push(id.clone());
        }
        prev = id;
        depth += 1;
    }
    (events, targets)
}

/// Builds `create -> power_levels` followed by `conflict_count` genuine
/// two-way conflicts: for each target user, two independent `m.room.member`
/// branch events (join vs. ban) both cite the same prior tip, then a merge
/// event with `prev_events: [branch_a, branch_b]` picks up both and becomes
/// the tip for the next conflict. Unlike `build_room`'s pure linear chain
/// (deferred in `14b5488` as a bench-fidelity gap: it never exercises real
/// conflict resolution), every target user here has two competing state
/// events at the same `(m.room.member, state_key)`, forcing the resolver's
/// real power-comparison / mainline-ordering auth-check machinery on every
/// key -- not just structural dedup.
fn build_conflicting_room(conflict_count: usize) -> (HashMap<String, LeanEvent>, Vec<String>) {
    let mut events = HashMap::new();
    let mut ts: u64 = 0;

    let create_id = "$create".to_string();
    events.insert(
        create_id.clone(),
        LeanEvent {
            event_id: create_id.clone(),
            event_type: "m.room.create".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                ts += 1;
                ts
            },
            sender: "@creator:example.org".to_string(),
            content: serde_json::json!({ "creator": "@creator:example.org" }),
            prev_events: Vec::new(),
            auth_events: Vec::new(),
            prev_state_events: Vec::new(),
            depth: 0,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );

    let pl_id = "$power_levels".to_string();
    events.insert(
        pl_id.clone(),
        LeanEvent {
            event_id: pl_id.clone(),
            event_type: "m.room.power_levels".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                ts += 1;
                ts
            },
            sender: "@creator:example.org".to_string(),
            content: serde_json::json!({ "users_default": 50 }),
            prev_events: vec![create_id.clone()],
            auth_events: Vec::new(),
            prev_state_events: Vec::new(),
            depth: 1,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );

    // Branch A below is a self-join (`sender == state_key`, `membership:
    // "join"`), which `check_join_rules` only admits for a non-creator
    // sender when the room's join rule is public -- the default (no
    // `m.room.join_rules` event in state) is `invite`, which would reject
    // every branch-A event and collapse the intended two-way conflict into
    // a one-sided ban. Publish the room so both branches actually compete.
    let join_rules_id = "$join_rules".to_string();
    events.insert(
        join_rules_id.clone(),
        LeanEvent {
            event_id: join_rules_id.clone(),
            event_type: "m.room.join_rules".to_string(),
            state_key: Some(String::new()),
            power_level: 100,
            origin_server_ts: {
                ts += 1;
                ts
            },
            sender: "@creator:example.org".to_string(),
            content: serde_json::json!({ "join_rule": "public" }),
            prev_events: vec![pl_id.clone()],
            // V2.1+ (this bench uses `StateResVersion::V2_1` throughout)
            // forbids citing `m.room.create` in `auth_events` (rule 2.4) --
            // matching the power_levels event above, which likewise omits it.
            auth_events: vec![pl_id.clone()],
            prev_state_events: Vec::new(),
            depth: 2,
            rejected: false,
            soft_fail: false,
            room_id: None,
        },
    );

    let mut tip = join_rules_id.clone();
    let mut depth: u64 = 3;
    let mut targets = Vec::new();
    for i in 0..conflict_count {
        let user = format!("@user{i}:example.org");
        let a_id = format!("$member_{i}_a");
        let b_id = format!("$member_{i}_b");
        let merge_id = format!("$merge_{i}");

        let branch_auth = if tip == join_rules_id {
            vec![pl_id.clone(), join_rules_id.clone()]
        } else {
            vec![pl_id.clone(), join_rules_id.clone(), tip.clone()]
        };

        events.insert(
            a_id.clone(),
            LeanEvent {
                event_id: a_id.clone(),
                event_type: "m.room.member".to_string(),
                state_key: Some(user.clone()),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: user.clone(),
                content: serde_json::json!({ "membership": "join" }),
                prev_events: vec![tip.clone()],
                auth_events: branch_auth.clone(),
                prev_state_events: Vec::new(),
                depth,
                rejected: false,
                soft_fail: false,
                room_id: None,
            },
        );
        events.insert(
            b_id.clone(),
            LeanEvent {
                event_id: b_id.clone(),
                event_type: "m.room.member".to_string(),
                state_key: Some(user.clone()),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: "@creator:example.org".to_string(),
                content: serde_json::json!({ "membership": "ban" }),
                prev_events: vec![tip.clone()],
                auth_events: branch_auth,
                prev_state_events: Vec::new(),
                depth,
                rejected: false,
                soft_fail: false,
                room_id: None,
            },
        );

        depth += 1;
        events.insert(
            merge_id.clone(),
            LeanEvent {
                event_id: merge_id.clone(),
                event_type: "m.room.member".to_string(),
                // Distinct state key from the conflict itself so the merge
                // event doesn't overwrite the very key it's meant to
                // reconcile -- it just threads the DAG forward.
                state_key: Some(format!("@merge{i}:example.org")),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: "@creator:example.org".to_string(),
                content: serde_json::json!({ "membership": "join" }),
                prev_events: vec![a_id.clone(), b_id.clone()],
                auth_events: vec![pl_id.clone()],
                prev_state_events: Vec::new(),
                depth,
                rejected: false,
                soft_fail: false,
                room_id: None,
            },
        );

        if i == 0
            || i == conflict_count / 3
            || i == conflict_count * 2 / 3
            || i == conflict_count - 1
        {
            targets.push(merge_id.clone());
        }
        tip = merge_id;
        depth += 1;
    }
    (events, targets)
}

fn measure(label: &str, reps: usize, f: impl Fn()) -> Duration {
    f(); // warmup
    f();
    let start = Instant::now();
    for _ in 0..reps {
        f();
    }
    let elapsed = start.elapsed();
    println!(
        "  {label}: {:.1}ms total over {reps} runs ({:.3}ms/run)",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0 / reps as f64
    );
    elapsed
}

// The isolated get_event lookup micro-bench (String Borrow<dyn StateKeyDyn>
// vs zero-alloc InternId) that used to live here was superseded by
// `benches/interned_lookup.rs`, which covers the same measurement plus a
// type-count sweep (1 vs 16 event types) -- removed to avoid two benches
// answering the same question. Run `cargo bench --bench interned_lookup`
// for that comparison.

pub fn run() {
    println!("=== full resolution bench (compute_state_at / compute_state_at_batch) ===");
    let sizes = [100usize, 1_000, 5_000];
    let rooms: Vec<(usize, HashMap<String, LeanEvent>, Vec<String>)> = sizes
        .iter()
        .map(|&n| {
            let (events, targets) = build_room(n);
            (n, events, targets)
        })
        .collect();
    let conflict_sizes = [50usize, 500, 2_000];
    let conflict_rooms: Vec<(usize, HashMap<String, LeanEvent>, Vec<String>)> = conflict_sizes
        .iter()
        .map(|&n| {
            let (events, targets) = build_conflicting_room(n);
            (n, events, targets)
        })
        .collect();

    // One shared arena for every room (linear and conflict) so `InternId`
    // (which reads the single global `INTERN`) can be used consistently
    // across both benches below.
    let room_maps: Vec<&HashMap<String, LeanEvent>> = rooms
        .iter()
        .map(|(_, e, _)| e)
        .chain(conflict_rooms.iter().map(|(_, e, _)| e))
        .collect();
    init_interner(&room_maps);
    let str_to_id = str_to_id();

    for (n, events, targets) in &rooms {
        let target_refs: Vec<&str> = targets.iter().map(String::as_str).collect();

        let interned: HashMap<String, LeanEvent<String, serde_json::Value, InternedKey>> = events
            .iter()
            .map(|(id, ev)| (id.clone(), ev.clone().into_interned_state_key()))
            .collect();
        let u32_events: HashMap<String, LeanEvent<String, serde_json::Value, InternId>> =
            to_u32_events(events, &str_to_id);

        // Correctness gate: the interned-u32 path must resolve to the *same*
        // state as String (keyed back to strings), so the perf number isn't
        // measuring a silently-wrong ordering/default() path.
        let last = targets.last().unwrap();
        let str_state = compute_state_at::<String, serde_json::Value, String, _, String>(
            last,
            events,
            StateResVersion::V2_1,
            &String::new(),
        )
        .expect("last member must resolve (String)");
        let u32_state = compute_state_at::<String, serde_json::Value, String, _, InternId>(
            last,
            &u32_events,
            StateResVersion::V2_1,
            &InternId::default(),
        )
        .expect("last member must resolve (u32)");
        let str_keyed: std::collections::BTreeMap<(String, String), String> = str_state
            .into_iter()
            .map(|((et, k), id)| ((et.to_string(), k), id))
            .collect();
        let u32_keyed: std::collections::BTreeMap<(String, String), String> = u32_state
            .into_iter()
            .map(|((et, k), id)| ((et.to_string(), k.as_ref().to_string()), id))
            .collect();
        assert_eq!(
            u32_keyed, str_keyed,
            "u32-interned resolution must match String resolution"
        );

        println!("--- room size: {n} members, {} targets ---", targets.len());
        // Fewer reps at larger sizes to keep wall-clock bounded.
        let reps = match n {
            100 => 2_000,
            1_000 => 300,
            _ => 100,
        };

        // Batch path (engages the parallel lattice fold under default `std`).
        let batch_str = measure("batch  String    ", reps, || {
            let result =
                compute_state_at_batch(&target_refs, events, StateResVersion::V2_1, &String::new());
            assert_eq!(
                result.len(),
                target_refs.len(),
                "all batch targets must resolve"
            );
            std::hint::black_box(&result);
        });
        let batch_interned = measure("batch  InternedKey", reps, || {
            let result = compute_state_at_batch(
                &target_refs,
                &interned,
                StateResVersion::V2_1,
                &InternedKey::default(),
            );
            assert_eq!(
                result.len(),
                target_refs.len(),
                "all batch targets must resolve"
            );
            std::hint::black_box(&result);
        });
        let batch_u32 = measure("batch  u32 InternId", reps, || {
            let result = compute_state_at_batch(
                &target_refs,
                &u32_events,
                StateResVersion::V2_1,
                &InternId::default(),
            );
            assert_eq!(
                result.len(),
                target_refs.len(),
                "all batch targets must resolve"
            );
            std::hint::black_box(&result);
        });

        // Serial (cache-free) control at the last (deepest) member.
        let last = target_refs.last().copied().unwrap();
        let ser_str = measure("serial String    ", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, String>(
                last,
                events,
                StateResVersion::V2_1,
                &String::new(),
            )
            .expect("last member must resolve");
            std::hint::black_box(state.len());
        });
        let ser_interned = measure("serial InternedKey", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, InternedKey>(
                last,
                &interned,
                StateResVersion::V2_1,
                &InternedKey::default(),
            )
            .expect("last member must resolve");
            std::hint::black_box(state.len());
        });
        let ser_u32 = measure("serial u32 InternId", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, InternId>(
                last,
                &u32_events,
                StateResVersion::V2_1,
                &InternId::default(),
            )
            .expect("last member must resolve");
            std::hint::black_box(state.len());
        });

        let batch_delta = batch_interned.as_secs_f64() - batch_str.as_secs_f64();
        let batch_delta_u32 = batch_u32.as_secs_f64() - batch_str.as_secs_f64();
        let ser_delta = ser_interned.as_secs_f64() - ser_str.as_secs_f64();
        let ser_delta_u32 = ser_u32.as_secs_f64() - ser_str.as_secs_f64();
        println!(
            "  batch  InternedKey vs String: {batch_delta:+.1}ms total ({:+.1}%)",
            batch_delta / batch_str.as_secs_f64() * 100.0
        );
        println!(
            "  batch  u32 InternId vs String: {batch_delta_u32:+.1}ms total ({:+.1}%)",
            batch_delta_u32 / batch_str.as_secs_f64() * 100.0
        );
        println!(
            "  serial InternedKey vs String: {ser_delta:+.1}ms total ({:+.1}%)",
            ser_delta / ser_str.as_secs_f64() * 100.0
        );
        println!(
            "  serial u32 InternId vs String: {ser_delta_u32:+.1}ms total ({:+.1}%)",
            ser_delta_u32 / ser_str.as_secs_f64() * 100.0
        );
    }

    println!();
    println!(
        "=== conflict-heavy room bench (real power-comparison / mainline auth-checks, not just linear-chain dedup) ==="
    );
    for (n, events, targets) in &conflict_rooms {
        let u32_events = to_u32_events(events, &str_to_id);
        let last = targets.last().unwrap();

        // Correctness gate, same discipline as the linear-room bench above:
        // the interned-u32 path must resolve to the same winners as String.
        let str_state = compute_state_at::<String, serde_json::Value, String, _, String>(
            last,
            events,
            StateResVersion::V2_1,
            &String::new(),
        )
        .expect("last merge event must resolve (String)");
        let u32_state = compute_state_at::<String, serde_json::Value, String, _, InternId>(
            last,
            &u32_events,
            StateResVersion::V2_1,
            &InternId::default(),
        )
        .expect("last merge event must resolve (u32)");
        let str_keyed: std::collections::BTreeMap<(String, String), String> = str_state
            .into_iter()
            .map(|((et, k), id)| ((et.to_string(), k), id))
            .collect();
        let u32_keyed: std::collections::BTreeMap<(String, String), String> = u32_state
            .into_iter()
            .map(|((et, k), id)| ((et.to_string(), k.as_ref().to_string()), id))
            .collect();
        assert_eq!(
            u32_keyed, str_keyed,
            "u32-interned conflict resolution must match String resolution"
        );

        println!("--- {n} conflicts ({} events) ---", events.len());
        let reps = match n {
            50 => 500,
            500 => 50,
            _ => 10,
        };
        let str_dur = measure("conflict String    ", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, String>(
                last,
                events,
                StateResVersion::V2_1,
                &String::new(),
            )
            .expect("must resolve");
            std::hint::black_box(state.len());
        });
        let u32_dur = measure("conflict u32 InternId", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, InternId>(
                last,
                &u32_events,
                StateResVersion::V2_1,
                &InternId::default(),
            )
            .expect("must resolve");
            std::hint::black_box(state.len());
        });
        let delta = u32_dur.as_secs_f64() - str_dur.as_secs_f64();
        println!(
            "  conflict u32 InternId vs String: {delta:+.1}ms total ({:+.1}%)",
            delta / str_dur.as_secs_f64() * 100.0
        );
    }
}
