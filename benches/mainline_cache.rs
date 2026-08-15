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

//! Wall-clock benchmark isolating the `build_mainline` persistent-cache
//! change (see `resolve::sorting::build_mainline_with_cache` and
//! `state::at::run_state_pipeline_streaming[_optimized]`).
//!
//! Builds one synthetic DAG with a long `m.room.power_levels` auth chain of
//! length `PL_CHAIN_LEN` and `FORK_COUNT` independent two-way member-state
//! forks, each merging back into a single non-state event. Every merge
//! forces a real state resolution (the two branches disagree on state), so
//! `compute_state_at_batch` walks the fork-merge loop `FORK_COUNT` times in
//! one topological pass — exactly the access pattern the persistent
//! `mainline_cache` targets: before the fix each merge re-walks the whole PL
//! chain from scratch; after the fix, only the first merge pays that cost
//! and the rest are `O(1)` cache hits.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rezzy::{compute_state_at_batch, LeanEvent, StateResVersion};

fn pl_content(level: i64) -> serde_json::Value {
    serde_json::json!({ "users_default": level })
}

/// Builds a DAG: `create -> pl_0 -> pl_1 -> ... -> pl_{L-1}`, then `fork_count`
/// independent `(member_a, member_b) -> merge` triangles all rooted at
/// `pl_{L-1}`.
fn build_dag(pl_chain_len: usize, fork_count: usize) -> (HashMap<String, LeanEvent>, Vec<String>) {
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
        },
    );

    let mut prev_pl = create_id.clone();
    let mut depth: u64 = 1;
    for i in 0..pl_chain_len {
        let id = format!("$pl_{i}");
        events.insert(
            id.clone(),
            LeanEvent {
                event_id: id.clone(),
                event_type: "m.room.power_levels".to_string(),
                state_key: Some(String::new()),
                power_level: 100,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: "@creator:example.org".to_string(),
                content: pl_content(50 + (i as i64 % 10)),
                prev_events: vec![prev_pl.clone()],
                auth_events: vec![prev_pl.clone(), create_id.clone()],
                depth,
                rejected: false,
                soft_fail: false,
            },
        );
        prev_pl = id;
        depth += 1;
    }
    let top_pl = prev_pl;

    let mut targets = Vec::with_capacity(fork_count);
    for g in 0..fork_count {
        let a_id = format!("$member_a_{g}");
        let b_id = format!("$member_b_{g}");
        let merge_id = format!("$merge_{g}");

        events.insert(
            a_id.clone(),
            LeanEvent {
                event_id: a_id.clone(),
                event_type: "m.room.member".to_string(),
                state_key: Some(format!("@a{g}:example.org")),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: format!("@a{g}:example.org"),
                content: serde_json::json!({ "membership": "join" }),
                prev_events: vec![top_pl.clone()],
                auth_events: vec![top_pl.clone(), create_id.clone()],
                depth: depth + 1,
                rejected: false,
                soft_fail: false,
            },
        );
        events.insert(
            b_id.clone(),
            LeanEvent {
                event_id: b_id.clone(),
                event_type: "m.room.member".to_string(),
                state_key: Some(format!("@b{g}:example.org")),
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: format!("@b{g}:example.org"),
                content: serde_json::json!({ "membership": "join" }),
                prev_events: vec![top_pl.clone()],
                auth_events: vec![top_pl.clone(), create_id.clone()],
                depth: depth + 1,
                rejected: false,
                soft_fail: false,
            },
        );
        events.insert(
            merge_id.clone(),
            LeanEvent {
                event_id: merge_id.clone(),
                event_type: "m.room.message".to_string(),
                state_key: None,
                power_level: 0,
                origin_server_ts: {
                    ts += 1;
                    ts
                },
                sender: "@a0:example.org".to_string(),
                content: serde_json::json!({ "body": "merge" }),
                prev_events: vec![a_id, b_id],
                auth_events: vec![top_pl.clone(), create_id.clone()],
                depth: depth + 2,
                rejected: false,
                soft_fail: false,
            },
        );
        targets.push(merge_id);
    }

    (events, targets)
}

fn measure(label: &str, f: impl FnOnce()) -> Duration {
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    println!("{label}: {:.1}ms", elapsed.as_secs_f64() * 1000.0);
    elapsed
}

fn main() {
    for &(pl_chain_len, fork_count) in &[(200usize, 500usize), (1_000, 2_000), (2_000, 5_000)] {
        println!("--- pl_chain_len={pl_chain_len} fork_count={fork_count} ---");
        let (events, targets) = build_dag(pl_chain_len, fork_count);
        let target_refs: Vec<&str> = targets.iter().map(String::as_str).collect();

        measure(
            &format!("compute_state_at_batch (L={pl_chain_len}, M={fork_count})"),
            || {
                let result = compute_state_at_batch(&target_refs, &events, StateResVersion::V2_1);
                assert_eq!(result.len(), target_refs.len(), "all targets must resolve");
                std::hint::black_box(&result);
            },
        );
    }
}
