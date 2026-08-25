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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rezzy::{compute_state_at, compute_state_at_batch, InternedKey, LeanEvent, StateResVersion};

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
            auth_events: vec![create_id.clone()],
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
                auth_events: vec![pl_id.clone(), prev.clone()],
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

fn main() {
    for &n in &[100usize, 1_000, 5_000] {
        let (events, targets) = build_room(n);
        let target_refs: Vec<&str> = targets.iter().map(String::as_str).collect();

        let interned: HashMap<String, LeanEvent<String, serde_json::Value, InternedKey>> = events
            .iter()
            .map(|(id, ev)| (id.clone(), ev.clone().into_interned_state_key()))
            .collect();

        println!("--- room size: {n} members, {} targets ---", targets.len());
        // Fewer reps at larger sizes to keep wall-clock bounded.
        let reps = match n {
            100 => 2_000,
            1_000 => 300,
            _ => 100,
        };

        // Batch path (engages the parallel lattice fold under default `std`).
        let batch_str = measure("batch  String    ", reps, || {
            let result = compute_state_at_batch(&target_refs, &events, StateResVersion::V2_1);
            assert_eq!(
                result.len(),
                target_refs.len(),
                "all batch targets must resolve"
            );
            std::hint::black_box(&result);
        });
        let batch_interned = measure("batch  InternedKey", reps, || {
            let result = compute_state_at_batch(&target_refs, &interned, StateResVersion::V2_1);
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
                &events,
                StateResVersion::V2_1,
            )
            .expect("last member must resolve");
            std::hint::black_box(state.len());
        });
        let ser_interned = measure("serial InternedKey", reps, || {
            let state = compute_state_at::<String, serde_json::Value, str, _, InternedKey>(
                last,
                &interned,
                StateResVersion::V2_1,
            )
            .expect("last member must resolve");
            std::hint::black_box(state.len());
        });

        let batch_delta = batch_interned.as_secs_f64() - batch_str.as_secs_f64();
        let ser_delta = ser_interned.as_secs_f64() - ser_str.as_secs_f64();
        println!(
            "  batch delta: {batch_delta:+.1}ms total ({:+.1}%)",
            batch_delta / batch_str.as_secs_f64() * 100.0
        );
        println!(
            "  serial delta: {ser_delta:+.1}ms total ({:+.1}%)",
            ser_delta / ser_str.as_secs_f64() * 100.0
        );
    }
}
