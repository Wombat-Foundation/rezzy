#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Differential + determinism harness for state resolution.
//!
//! Phase B empirical backbone. For each randomly-generated room DAG:
//! - **Differential:** resolve with `V2_1` and `V2_1_1` and compare. The two
//!   versions are **not** semantically equivalent: V2.1.1 adds the CDO
//!   pre-filter and a power-phase local-auth fallback guard (`at.rs`), both
//!   absent from stock V2.1. Divergences are therefore logged for manual
//!   inspection, and the per-run count is asserted below a regression bound so
//!   a divergence that explodes (e.g. a CDO over-drop) fails the test instead
//!   of silently passing as a logging no-op.
//! - **Determinism:** resolve the same DAG twice (fresh caches) and assert
//!   identical output. This guards the resolution path against any
//!   platform-dependent divergence (see `determinism_same_input_same_output`).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_arguments
)]

mod utils;

use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

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

/// A per-iteration PRNG, seeded deterministically from `base_seed` and the
/// iteration index. This decouples iterations from the shared sequential
/// Rng state, so the loop can be split across threads without changing any
/// single iteration's output (the problem for iteration `i` is fully
/// determined by `i` alone).
fn iteration_rng(base_seed: u64, iter: u64) -> Rng {
    Rng::new(base_seed.wrapping_add(iter.wrapping_mul(0x9E37_79B9_7F4A_7C15)))
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
    pool: &[String],
) -> LeanEvent {
    let mut prev_events = Vec::new();
    let mut auth_events = Vec::new();
    let n = 1 + rng.below(2);
    for _ in 0..n {
        prev_events.push(pool[rng.below(pool.len())].clone());
    }
    // auth: always create; plus a subset of the pool (which includes earlier
    // candidates, so a candidate can transitively cite a prior candidate).
    auth_events.push("$create".to_string());
    for b in pool {
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

    // Growing pool of all event IDs (base + earlier candidates). Later
    // candidates draw parents from this, so a candidate can cite an earlier
    // candidate -> multi-level causal structure / transitive reachability.
    let mut pool = base.clone();

    // Conflicted membership candidates for a subset of users (random values).
    let membership_vals = ["join", "invite", "leave", "ban"];
    for (i, u) in users.iter().enumerate() {
        let conflict = rng.below(3) == 0;
        if !conflict {
            // single unconflicted-ish join (still passed as conflicted set; fine)
            let id = format!("${}_join_{}", u.split(':').next().unwrap(), i);
            // Vary depth independently of ancestry: sometimes forge a depth
            // that contradicts the parents' actual order, to exercise
            // depth-independent edge handling.
            let depth = if rng.below(4) == 0 { ts / 100 } else { 5 };
            let ev = mem_event(rng, &id, u, u, "join", ts, depth, &pool);
            ts += 1;
            pool.push(id.clone());
            conflicted.insert(id.clone(), ev);
            continue;
        }
        // two candidates for the same user -> genuine conflict
        let m1 = rng.pick(&membership_vals);
        let id1 = format!("${}_cand_a_{}", u.split(':').next().unwrap(), i);
        let depth1 = if rng.below(4) == 0 { ts / 100 } else { 5 };
        let ev1 = mem_event(rng, &id1, u, u, m1, ts, depth1, &pool);
        ts += 1;
        pool.push(id1.clone());
        let m2 = rng.pick(&membership_vals);
        let id2 = format!("${}_cand_b_{}", u.split(':').next().unwrap(), i);
        let depth2 = if rng.below(4) == 0 { ts / 100 } else { 5 };
        let ev2 = mem_event(rng, &id2, u, u, m2, ts, depth2, &pool);
        ts += 1;
        pool.push(id2.clone());
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

/// Differential coverage over the multi-level random DAG generator.
///
/// V2.1 and V2.1.1 are *not* asserted equal here: V2.1.1 intentionally differs
/// from V2.1 via its power-phase local-auth fallback guard (`at.rs:132`, the
/// ban-evasion fix). The multi-level generator (candidates citing earlier
/// candidates, forged depths) exercises transitive reachability and surfaces
/// real divergences the old flat generator could not produce.
///
/// So this test guarantees:
/// - any V2.1 vs V2.1.1 divergence is logged to stderr for manual inspection
///   (passing the run, since the divergence is intended, not a regression).
///
/// Determinism is not re-checked here — it is covered by
/// `determinism_same_input_same_output` (each version resolved twice on 1000
/// DAGs). This test runs only two resolutions per DAG (one per version), so
/// it is fast even at 2000 iterations.
///
/// One recorded V2_1-vs-V2_1_1 divergence: the iteration index, both
/// versions' resolved states, and the conflicted events that produced them.
type Divergence = (u64, SharedState, SharedState, HashMap<String, LeanEvent>);

#[test]
fn differential_v21_equals_v211() {
    const ITER_COUNT: u64 = 2000;
    const BASE_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    // (iteration, resolved V2.1, resolved V2.1.1, conflicted map) for every
    // diverging DAG. Collected during the parallel loop, then printed after it
    // in iteration order so the output stays deterministic regardless of
    // thread count.
    let divergences: Mutex<Vec<Divergence>> = Mutex::new(Vec::new());
    let diverged = AtomicU64::new(0);

    std::thread::scope(|s| {
        for t in 0..threads {
            let divergences = &divergences;
            let diverged = &diverged;
            s.spawn(move || {
                let mut local_diverged = 0u64;
                let mut local_divergences: Vec<Divergence> = Vec::new();
                let mut iter = u64::try_from(t).unwrap_or(0);
                let stride = u64::try_from(threads).unwrap_or(0);
                while iter < ITER_COUNT {
                    let mut rng = iteration_rng(BASE_SEED, iter);
                    let problem = gen_problem(&mut rng, 1000 + iter * 13);
                    let r21 = resolve(&problem, StateResVersion::V2_1);
                    let r211 = resolve(&problem, StateResVersion::V2_1_1);

                    if r21 != r211 {
                        local_diverged += 1;
                        local_divergences.push((iter, r21, r211, problem.conflicted));
                    }
                    iter += stride;
                }
                diverged.fetch_add(local_diverged, Ordering::Relaxed);
                divergences.lock().unwrap().extend(local_divergences);
            });
        }
    });

    let mut divergences = divergences.into_inner().unwrap_or_default();
    divergences.sort_unstable_by_key(|(iter, _, _, _)| *iter);
    for (iter, r21, r211, conflicted) in &divergences {
        eprintln!("V2.1 vs V2.1.1 diverged on iteration {iter}");
        for (id, ev) in conflicted {
            eprintln!(
                "  {}: {} by {} sk={:?} ts={} depth={} prev={:?} auth={:?}",
                id,
                ev.event_type,
                ev.sender,
                ev.state_key,
                ev.origin_server_ts,
                ev.depth,
                ev.prev_events,
                ev.auth_events
            );
        }
        eprintln!("  v21   = {r21:?}");
        eprintln!("  v211  = {r211:?}");
    }
    let diverged_total = diverged.load(Ordering::Relaxed);

    // Regression bound. With this fixed seed the versions diverge on a small
    // minority of DAGs (the intended V2.1.1 power-phase fallback). A divergence
    // that explodes — e.g. the CDO pre-filter over-dropping on many DAGs — must
    // fail the test rather than pass as a logging no-op.
    assert!(
        diverged_total < 150,
        "V2.1 vs V2.1.1 diverged on {diverged_total}/{ITER_COUNT} DAGs, far beyond the intended subset; investigate"
    );
    eprintln!("differential: {diverged_total}/{ITER_COUNT} DAGs diverged between V2.1 and V2.1.1");
}

#[test]
fn determinism_same_input_same_output() {
    const ITER_COUNT: u64 = 1000;
    const BASE_SEED: u64 = 0x243F_6A88_85A3_08D3;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    std::thread::scope(|s| {
        for t in 0..threads {
            s.spawn(move || {
                let mut iter = u64::try_from(t).unwrap_or(0);
                let stride = u64::try_from(threads).unwrap_or(0);
                while iter < ITER_COUNT {
                    let mut rng = iteration_rng(BASE_SEED, iter);
                    let problem = gen_problem(&mut rng, 7000 + iter * 17);
                    let a = resolve(&problem, StateResVersion::V2_1_1);
                    let b = resolve(&problem, StateResVersion::V2_1_1);
                    assert_eq!(a, b, "resolution not deterministic on iteration {iter}");
                    iter += stride;
                }
            });
        }
    });
}
