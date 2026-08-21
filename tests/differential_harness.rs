#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Randomized differential + determinism harness for state resolution.
//!
//! Phase B empirical backbone. For each randomly-generated room DAG:
//! - **Differential:** resolve with `V2_1` and `V2_1_1` and assert identical
//!   results. Since the CDO and the V2.1.1 semantic deviations were removed,
//!   the two versions are semantically equivalent, so this is a strong check
//!   that no divergence crept back in.
//! - **Determinism:** resolve the same DAG twice (fresh caches) and assert
//!   identical output. The CDO's `WORDS_PER_CHUNK` build-time SIMD split (the
//!   old federation split-brain hazard) is gone with the CDO; this guards the
//!   remaining path against any platform-dependent divergence.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_arguments
)]

mod utils;

use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
use std::collections::HashMap;

/// Deterministic xorshift64* — reproducible across runs (fixed seed).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

type SKey = (rezzy::basespec::event_types::EventType, String);
type SharedState = imbl::OrdMap<SKey, String>;

/// A generated resolution problem: base unconflicted state + conflicted
/// candidates + the full auth context (all events).
struct Problem {
    unconflicted: SharedState,
    conflicted: HashMap<String, LeanEvent>,
    auth_context: HashMap<String, LeanEvent>,
}

fn mem_event(
    rng: &mut Rng,
    id: &str,
    sender: &str,
    target: &str,
    membership: &str,
    ts: u64,
    depth: u64,
    base: &[String],
) -> LeanEvent {
    let mut prev_events = Vec::new();
    let mut auth_events = Vec::new();
    let n = 1 + rng.below(2);
    for _ in 0..n {
        prev_events.push(base[rng.below(base.len())].clone());
    }
    // auth: always create; plus a subset of the base chain
    auth_events.push("$create".to_string());
    for b in base {
        if rng.below(3) == 0 {
            auth_events.push(b.clone());
        }
    }
    LeanEvent {
        event_id: id.to_string(),
        event_type: "m.room.member".to_string(),
        state_key: Some(target.to_string()),
        sender: sender.to_string(),
        origin_server_ts: ts,
        content: serde_json::json!({ "membership": membership }),
        prev_events,
        auth_events,
        depth,
        ..Default::default()
    }
}

/// Builds a random resolution problem.
///
/// Unconflicted base: `m.room.create`, creator join, `m.room.power_levels`
/// (admin=100, plus some users at random power level), `m.room.join_rules` =
/// public. Conflicted: for a few users, two candidate membership events
/// (join/invite/leave/ban) on different forks, plus occasionally a conflicting
/// `m.room.join_rules` or `m.room.power_levels` candidate.
#[allow(clippy::too_many_lines)]
fn gen_problem(rng: &mut Rng, seed_base_ts: u64) -> Problem {
    let users = ["@u0:x", "@u1:x", "@u2:x", "@u3:x", "@u4:x", "@u5:x"];
    let mut ts = seed_base_ts;

    let create = LeanEvent {
        event_id: "$create".to_string(),
        event_type: "m.room.create".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: ts,
        content: serde_json::json!({ "room_version": "12.1", "creator": "@admin:x" }),
        ..Default::default()
    };
    ts += 1;
    let admin_join = mem_event(
        rng,
        "$admin_join",
        "@admin:x",
        "@admin:x",
        "join",
        ts,
        2,
        &["$create".into()],
    );
    ts += 1;

    let mut pl_users = serde_json::Map::new();
    pl_users.insert("@admin:x".to_string(), serde_json::json!(100));
    for u in users {
        if rng.below(3) == 0 {
            pl_users.insert(u.to_string(), serde_json::json!(50));
        }
    }
    let pl = LeanEvent {
        event_id: "$pl".to_string(),
        event_type: "m.room.power_levels".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: ts,
        content: serde_json::json!({ "users": pl_users, "state_default": 50, "ban": 50 }),
        auth_events: vec!["$create".to_string(), "$admin_join".to_string()],
        prev_events: vec!["$admin_join".to_string()],
        depth: 3,
        ..Default::default()
    };
    ts += 1;
    let jr = LeanEvent {
        event_id: "$jr".to_string(),
        event_type: "m.room.join_rules".to_string(),
        state_key: Some(String::new()),
        sender: "@admin:x".to_string(),
        origin_server_ts: ts,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec![
            "$create".to_string(),
            "$admin_join".to_string(),
            "$pl".to_string(),
        ],
        prev_events: vec!["$pl".to_string()],
        depth: 4,
        ..Default::default()
    };
    ts += 1;

    let base: Vec<String> = vec![
        "$admin_join".to_string(),
        "$pl".to_string(),
        "$jr".to_string(),
    ];

    let mut auth_context = HashMap::new();
    for ev in [&create, &admin_join, &pl, &jr] {
        auth_context.insert(ev.event_id.clone(), ev.clone());
    }

    let mut unconflicted = SharedState::new();
    for ev in [&create, &admin_join, &pl, &jr] {
        let sk = ev.state_key.clone().unwrap_or_default();
        unconflicted.insert(
            (
                rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                sk,
            ),
            ev.event_id.clone(),
        );
    }

    let mut conflicted = HashMap::new();

    // Conflicted membership candidates for a subset of users (random values).
    let membership_vals = ["join", "invite", "leave", "ban"];
    for (i, u) in users.iter().enumerate() {
        let conflict = rng.below(3) == 0;
        if !conflict {
            // single unconflicted-ish join (still passed as conflicted set; fine)
            let id = format!("${}_join_{}", u.split(':').next().unwrap(), i);
            let ev = mem_event(rng, &id, u, u, "join", ts, 5, &base);
            ts += 1;
            conflicted.insert(id.clone(), ev);
            continue;
        }
        // two candidates for the same user -> genuine conflict
        let m1 = rng.pick(&membership_vals);
        let id1 = format!("${}_cand_a_{}", u.split(':').next().unwrap(), i);
        let ev1 = mem_event(rng, &id1, u, u, m1, ts, 5, &base);
        ts += 1;
        let m2 = rng.pick(&membership_vals);
        let id2 = format!("${}_cand_b_{}", u.split(':').next().unwrap(), i);
        let ev2 = mem_event(rng, &id2, u, u, m2, ts, 5, &base);
        ts += 1;
        conflicted.insert(id1.clone(), ev1);
        conflicted.insert(id2.clone(), ev2);
    }

    // Occasionally a conflicted join_rules or power_levels candidate.
    match rng.below(3) {
        0 => {
            let jr2 = LeanEvent {
                event_id: "$jr_conf".to_string(),
                event_type: "m.room.join_rules".to_string(),
                state_key: Some(String::new()),
                sender: "@admin:x".to_string(),
                origin_server_ts: ts,
                content: serde_json::json!({ "join_rule": "invite" }),
                auth_events: vec![
                    "$create".to_string(),
                    "$admin_join".to_string(),
                    "$pl".to_string(),
                ],
                prev_events: vec!["$pl".to_string()],
                depth: 4,
                ..Default::default()
            };
            conflicted.insert("$jr_conf".to_string(), jr2);
        }
        1 => {
            let pl2 = LeanEvent {
                event_id: "$pl_conf".to_string(),
                event_type: "m.room.power_levels".to_string(),
                state_key: Some(String::new()),
                sender: "@admin:x".to_string(),
                origin_server_ts: ts,
                content: serde_json::json!({ "users": { "@admin:x": 100 }, "state_default": 0 }),
                auth_events: vec![
                    "$create".to_string(),
                    "$admin_join".to_string(),
                    "$pl".to_string(),
                ],
                prev_events: vec!["$pl".to_string()],
                depth: 4,
                ..Default::default()
            };
            conflicted.insert("$pl_conf".to_string(), pl2);
        }
        _ => {}
    }

    // Everything is in the auth context too (so auth lookups resolve).
    for (id, ev) in &conflicted {
        auth_context.insert(id.clone(), ev.clone());
    }

    Problem {
        unconflicted,
        conflicted,
        auth_context,
    }
}

fn resolve(p: &Problem, version: StateResVersion) -> SharedState {
    resolve_iterative_sort(
        p.unconflicted.clone(),
        p.conflicted.clone(),
        &p.auth_context,
        version,
        &mut HashMap::new(),
    )
}

/// V2.1 and V2.1.1 are semantically identical after the CDO / deviation removal;
/// this must hold across thousands of random DAGs.
#[test]
fn differential_v21_equals_v211() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15u64);
    for iter in 0u64..2000 {
        let problem = gen_problem(&mut rng, 1000 + iter * 13);
        let r21 = resolve(&problem, StateResVersion::V2_1);
        let r211 = resolve(&problem, StateResVersion::V2_1_1);
        assert_eq!(
            r21, r211,
            "V2.1 and V2.1.1 diverged on random DAG iteration {iter}"
        );
    }
}

/// Same input, fresh caches -> identical output (no platform/order dependence).
#[test]
fn determinism_same_input_same_output() {
    let mut rng = Rng::new(0x243F_6A88_85A3_08D3u64);
    for iter in 0u64..1000 {
        let problem = gen_problem(&mut rng, 7000 + iter * 17);
        let a = resolve(&problem, StateResVersion::V2_1_1);
        let b = resolve(&problem, StateResVersion::V2_1_1);
        assert_eq!(a, b, "resolution not deterministic on iteration {iter}");
    }
}
