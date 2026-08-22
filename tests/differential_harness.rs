#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Differential + determinism harness for state resolution.
//!
//! Phase B empirical backbone. For each randomly-generated room DAG:
//! - **Differential:** resolve with `V2_1` and `V2_1_1` and assert **identical**
//!   output. The two versions must agree on every DAG. A drop is sound iff
//!   `IterativeAuthChecks` would have rejected the event; the retired CDO
//!   pre-filter could not establish that, and the differential is how its
//!   violations were caught.
//! - **Drop-rate & winner-overlap:** `cdo_drop_rate_measured` reports how much
//! - **Drop-rate & winner-overlap:** `cdo_drop_rate_measured` reports how much
//!   the retained `apply_cdo_filter` operator drops and — the key signal — how
//!   many dropped IDs appear as *winners* in the resolved state. That count is
//!   0 on the regular generator: it never produces a dominated *winner*, so it
//!   cannot observe a CDO error there. `dominated_winner_generator` closes that
//!   blind spot with an auth-invalid dominator, reaching a dominated winner on
//!   every DAG — which exposed the dominator-validity gap and motivated retiring
//!   the pre-filter from the live path. It now asserts the live path is sound.
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

    let create: LeanEvent = LeanEvent {
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
    let pl: LeanEvent = LeanEvent {
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
    let jr: LeanEvent = LeanEvent {
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
/// Resolves each DAG with `V2_1` and `V2_1_1` and asserts the results are
/// **identical**. V2.1.1 runs the CDO pre-filter; V2.1 does not, so the two
/// must agree on every DAG.
///
/// Scope of this assertion: it fails only if a CDO drop *changes a resolved
/// winner*. `cdo_drop_rate_measured` reports that the CDO drops 2087 events
/// over 626/2000 DAGs, but that **none of them are winners** — the generator
/// never produces a dominated winner, so this test cannot observe a CDO error.
/// Equality across these DAGs is therefore a real but weak check on the CDO:
/// it confirms the CDO never flips an outcome it *can* reach. Exercising CDO
/// correctness against outcomes requires a generator that produces dominated
/// winners (a known gap, not closed here).
///
/// Determinism is covered separately by `determinism_same_input_same_output`.
///
/// # Why strict equality, and not a count bound
///
/// `0916121` relaxed this to "log divergences, pass under a bound" on the
/// premise that V2.1 vs V2.1.1 divergence was *intended* (the `at.rs` power-
/// phase fallback). That premise was wrong on this generator: the fallback is
/// not observed to produce divergence here, and every recorded divergence
/// traced to a CDO over-drop — a bug. With the over-drop fixed, the two
/// versions agree on all 2000 DAGs, so equality is the correct, meaningful
/// invariant here.
#[test]
fn differential_v21_equals_v211() {
    const ITER_COUNT: u64 = 2000;
    const BASE_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    std::thread::scope(|s| {
        for t in 0..threads {
            s.spawn(move || {
                let mut iter = u64::try_from(t).unwrap_or(0);
                let stride = u64::try_from(threads).unwrap_or(1);
                while iter < ITER_COUNT {
                    let mut rng = iteration_rng(BASE_SEED, iter);
                    let problem = gen_problem(&mut rng, 1000 + iter * 13);
                    let r21 = resolve(&problem, StateResVersion::V2_1);
                    let r211 = resolve(&problem, StateResVersion::V2_1_1);
                    assert_eq!(
                        r21, r211,
                        "V2.1 and V2.1.1 diverged on DAG iteration {iter}: \
                         the CDO likely dropped a candidate full resolution would keep"
                    );
                    iter += stride;
                }
            });
        }
    });
}

/// Measures how much work the CDO actually does on the generator's DAGs, and
/// whether any of it is *observable* to the differential.
///
/// `0/2000` V2.1 vs V2.1.1 divergences only means the CDO never *changed the
/// resolved state* — it does **not** mean every drop was sound. A drop is
/// invisible to the differential if the dropped candidate was going to lose
/// its key contest anyway. So this test reports three numbers:
///
/// - total events dropped by `apply_cdo_filter` across the run, and how many
///   DAGs had a non-empty drop set — i.e. is the direct-domination path even
///   exercised?
/// - **winner overlap**: how many CDO-dropped event IDs appear as *values* in
///   the V2.1 resolved state, and how many DAGs that happens on. This is the
///   iteration-23 failure mode exactly (the CDO dropped `$@u2_cand_b_2`,
///   which V2.1 had resolved as the winner). A winner-overlap of 0 across the
///   run is the evidence that no CDO drop flipped an outcome on these DAGs; if
///   the CDO only ever drops losers, the differential cannot see it at all.
#[test]
fn cdo_drop_rate_measured() {
    use std::collections::HashSet;

    const ITER_COUNT: u64 = 2000;
    const BASE_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    let dropped_total = AtomicU64::new(0);
    let dag_count = AtomicU64::new(0);
    let dropped_winners_total = AtomicU64::new(0);
    let dropped_winner_dags = AtomicU64::new(0);

    std::thread::scope(|s| {
        for t in 0..threads {
            let dropped_total = &dropped_total;
            let dag_count = &dag_count;
            let dropped_winners_total = &dropped_winners_total;
            let dropped_winner_dags = &dropped_winner_dags;
            s.spawn(move || {
                let mut local_dropped = 0u64;
                let mut local_dags = 0u64;
                let mut local_dropped_winners = 0u64;
                let mut local_dropped_winner_dags = 0u64;
                let mut iter = u64::try_from(t).unwrap_or(0);
                let stride = u64::try_from(threads).unwrap_or(1);
                while iter < ITER_COUNT {
                    let mut rng = iteration_rng(BASE_SEED, iter);
                    let problem = gen_problem(&mut rng, 1000 + iter * 13);
                    let safe =
                        rezzy::cdo::apply_cdo_filter(&problem.conflicted, &problem.auth_context);
                    let dropped = u64::try_from(problem.conflicted.len() - safe.len()).unwrap_or(0);
                    local_dropped += dropped;
                    if dropped > 0 {
                        local_dags += 1;
                        // Which dropped IDs ended up as winners in the resolved
                        // state? Values of the resolved (type, state_key) -> event_id
                        // map; the two versions resolve identically, so V2.1 suffices.
                        let resolved = resolve(&problem, StateResVersion::V2_1);
                        let resolved_values: HashSet<&String> = resolved.values().collect();
                        let dropped_winners = problem
                            .conflicted
                            .keys()
                            .filter(|id| !safe.contains_key(*id) && resolved_values.contains(id))
                            .count();
                        local_dropped_winners += u64::try_from(dropped_winners).unwrap_or(0);
                        if dropped_winners > 0 {
                            local_dropped_winner_dags += 1;
                        }
                    }
                    iter += stride;
                }
                dropped_total.fetch_add(local_dropped, Ordering::Relaxed);
                dag_count.fetch_add(local_dags, Ordering::Relaxed);
                dropped_winners_total.fetch_add(local_dropped_winners, Ordering::Relaxed);
                dropped_winner_dags.fetch_add(local_dropped_winner_dags, Ordering::Relaxed);
            });
        }
    });

    let dropped_total = dropped_total.load(Ordering::Relaxed);
    let dag_count = dag_count.load(Ordering::Relaxed);
    let dropped_winners_total = dropped_winners_total.load(Ordering::Relaxed);
    let dropped_winner_dags = dropped_winner_dags.load(Ordering::Relaxed);
    let dags_with_conflict = ITER_COUNT; // generator always produces conflicted candidates
    eprintln!(
        "cdo: {dropped_total} events dropped by apply_cdo_filter over {ITER_COUNT} DAGs \
         ({dag_count} DAGs had a non-empty drop set, of {dags_with_conflict} with conflicted candidates); \
         {dropped_winners_total} dropped IDs appeared as winners in the resolved state \
         ({dropped_winner_dags} DAGs)"
    );
}

/// An adversarial problem where an **auth-invalid**, structurally-a-ban/kick
/// admin event (issued by a low-power user) causally dominates an **auth-valid**
/// join on an independent branch. Full resolution rejects the ban and keeps the
/// join (a genuine winner); the retired CDO dropped it because it trusted the
/// dominator's structural shape without running auth — the dominator-validity
/// gap. The regular generator never produces these, so its winner-overlap is 0
/// and the differential cannot observe the CDO at all.
#[allow(clippy::too_many_lines)]
fn gen_dominated_winner_problem(rng: &mut Rng, seed_base_ts: u64) -> Problem {
    let mut ts = seed_base_ts;
    let create: LeanEvent = LeanEvent {
        event_id: "$create".into(),
        event_type: "m.room.create".into(),
        state_key: Some(String::new()),
        sender: "@admin:x".into(),
        origin_server_ts: ts,
        content: serde_json::json!({ "room_version": "12.1", "creator": "@admin:x" }),
        ..Default::default()
    };
    ts += 1;
    let admin_join: LeanEvent = LeanEvent {
        event_id: "$admin_join".into(),
        event_type: "m.room.member".into(),
        state_key: Some("@admin:x".into()),
        sender: "@admin:x".into(),
        origin_server_ts: ts,
        prev_events: vec!["$create".into()],
        auth_events: vec!["$create".into()],
        depth: 2,
        ..Default::default()
    };
    ts += 1;
    let pl: LeanEvent = LeanEvent {
        event_id: "$pl".into(),
        event_type: "m.room.power_levels".into(),
        state_key: Some(String::new()),
        sender: "@admin:x".into(),
        origin_server_ts: ts,
        content: serde_json::json!({
            "users": { "@admin:x": 100 },
            "users_default": 0,
            "state_default": 50,
            "ban": 50
        }),
        auth_events: vec!["$create".into(), "$admin_join".into()],
        prev_events: vec!["$admin_join".into()],
        depth: 3,
        ..Default::default()
    };
    ts += 1;
    let jr: LeanEvent = LeanEvent {
        event_id: "$jr".into(),
        event_type: "m.room.join_rules".into(),
        state_key: Some(String::new()),
        sender: "@admin:x".into(),
        origin_server_ts: ts,
        content: serde_json::json!({ "join_rule": "public" }),
        auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
        prev_events: vec!["$pl".into()],
        depth: 4,
        ..Default::default()
    };

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

    // A low-power user issues a structural ban/kick at @victim (auth-invalid).
    let attacker = ["@mallory:x", "@eve:x", "@dave:x"][rng.below(3)];
    let atk_membership = rng.pick(&["ban", "leave"]);
    let atk: LeanEvent = LeanEvent {
        event_id: format!("$atk_{seed_base_ts}"),
        event_type: "m.room.member".into(),
        state_key: Some("@victim:x".into()),
        sender: attacker.to_string(),
        origin_server_ts: seed_base_ts + 1000,
        power_level: 0, // no forged priority: earlier ts breaks the tie vs the join
        content: serde_json::json!({ "membership": atk_membership }),
        auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
        prev_events: vec!["$jr".into()],
        depth: 5,
        ..Default::default()
    };
    let vic: LeanEvent = LeanEvent {
        event_id: format!("$vic_{seed_base_ts}"),
        event_type: "m.room.member".into(),
        state_key: Some("@victim:x".into()),
        sender: "@victim:x".into(),
        origin_server_ts: seed_base_ts + 1100,
        power_level: 0,
        content: serde_json::json!({ "membership": "join" }),
        auth_events: vec![
            "$create".into(),
            "$admin_join".into(),
            "$pl".into(),
            "$jr".into(),
        ],
        prev_events: vec!["$jr".into()],
        depth: 5,
        ..Default::default()
    };

    let mut conflicted = HashMap::new();
    conflicted.insert(atk.event_id.clone(), atk);
    conflicted.insert(vic.event_id.clone(), vic);

    Problem {
        unconflicted,
        conflicted,
        auth_context,
    }
}

/// The adversarial counterpart to `cdo_drop_rate_measured`. This generator
/// produces dominated *winners* — the shape the regular generator can't reach —
/// which is what exposed the dominator-validity gap. The unsound CDO pre-filter
/// has since been retired from `prepare_conflicted_and_keys`, so this asserts
/// the live path is now sound: V2.1.1 must match V2.1 on every DAG (no
/// divergence), while the retained operator (`apply_cdo_filter`) still drops
/// the resolved winner — informational, and the reason it stays disconnected.
/// If someone re-connects the pre-filter, `diverged` climbs and this fails.
#[test]
fn dominated_winner_generator() {
    const ITER_COUNT: u64 = 200;
    let mut diverged = 0u64;
    let mut dropped_winners = 0u64;
    let victim_key = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@victim:x".to_string(),
    );
    for i in 0u64..ITER_COUNT {
        let mut rng = iteration_rng(0xABCD_EF01_2345_6789, i);
        let p = gen_dominated_winner_problem(&mut rng, 5000 + i * 7);
        let safe = rezzy::cdo::apply_cdo_filter(&p.conflicted, &p.auth_context);
        let dropped: Vec<String> = p
            .conflicted
            .keys()
            .filter(|k| !safe.contains_key(*k))
            .cloned()
            .collect();
        let r21 = resolve(&p, StateResVersion::V2_1);
        let r211 = resolve(&p, StateResVersion::V2_1_1);
        if let Some(w) = r21.get(&victim_key) {
            if dropped.iter().any(|d| d == w) {
                dropped_winners += 1;
            }
        }
        if r21 != r211 {
            diverged += 1;
        }
    }
    eprintln!(
        "dominated-winner generator: {diverged}/{ITER_COUNT} DAGs diverged (live path); \
         retained apply_cdo_filter drops the resolved winner on {dropped_winners}"
    );
    assert_eq!(
        diverged, 0,
        "live V2.1.1 must not diverge from V2.1: the retired CDO pre-filter must \
         not be re-connected"
    );
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
                let stride = u64::try_from(threads).unwrap_or(1);
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

/// Dominator-validity gap, scope + closure. The gap is not limited to ban/kick:
/// an **auth-invalid** admin event can dominate a **valid** join across all
/// three structural admin classes (ban/kick, join-rules lockdown, power-levels
/// demotion), even with no forged `power_level` field (the attacker's earlier
/// `ts` breaks the tie). Full resolution rejects the dominator on auth and
/// keeps the join.
///
/// The unsound CDO pre-filter is retired from `prepare_conflicted_and_keys`, so
/// this now asserts the live path is sound — V2.1.1 must not drop the winner:
/// `r21 == r211` and the join survives. It goes green only because the
/// pre-filter is disconnected; re-connecting it makes this fail. Do not invert
/// it into a "green on the bug" assertion; that is how the repo regressed
/// before (`test_cdo_apply_filter_cascading_drops`, flipped by 3ef473a).
#[test]
#[allow(clippy::too_many_lines)]
fn cdo_dominator_validity_gap_scope_inverted() {
    // Shared public-room base (create / admin_join / pl:admin=100 / jr:public).
    fn base() -> (Vec<LeanEvent>, HashMap<String, LeanEvent>, SharedState) {
        let mut ts = 5000u64;
        let create: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            depth: 1,
            content: serde_json::json!({ "room_version": "12.1", "creator": "@admin:x" }),
            ..Default::default()
        };
        ts += 1;
        let admin_join: LeanEvent = LeanEvent {
            event_id: "$admin_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@admin:x".into()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            depth: 2,
            prev_events: vec!["$create".into()],
            auth_events: vec!["$create".into()],
            content: serde_json::json!({ "membership": "join" }),
            ..Default::default()
        };
        ts += 1;
        let pl: LeanEvent = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            depth: 3,
            content: serde_json::json!({ "users": { "@admin:x": 100 }, "users_default": 0, "state_default": 50, "ban": 50 }),
            auth_events: vec!["$create".into(), "$admin_join".into()],
            prev_events: vec!["$admin_join".into()],
            ..Default::default()
        };
        ts += 1;
        let jr: LeanEvent = LeanEvent {
            event_id: "$jr".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            origin_server_ts: ts,
            depth: 4,
            content: serde_json::json!({ "join_rule": "public" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$pl".into()],
            ..Default::default()
        };
        let mut auth_context = HashMap::new();
        let mut unconflicted = SharedState::new();
        for ev in [&create, &admin_join, &pl, &jr] {
            auth_context.insert(ev.event_id.clone(), ev.clone());
            unconflicted.insert(
                (
                    rezzy::basespec::event_types::EventType::from(ev.event_type.as_str()),
                    ev.state_key.clone().unwrap_or_default(),
                ),
                ev.event_id.clone(),
            );
        }
        (vec![create, admin_join, pl, jr], auth_context, unconflicted)
    }

    let victim_key: SKey = (
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@victim:x".into(),
    );

    // Cases: attacker is auth-invalid (low-power @mallory), dominator is
    // structural. No forged `power_level` — attacker ts is earlier, so it sorts
    // first and dominates. The victim join cites only create/admin_join/pl
    // (no non-lockdown join_rules, no pre-demotion PL), so the target-side
    // exemptions don't rescue it — yet full resolution still keeps it.
    let cases: Vec<LeanEvent> = vec![
        // A: ban
        LeanEvent {
            event_id: "$atkA".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@victim:x".into()),
            sender: "@mallory:x".into(),
            origin_server_ts: 6000,
            depth: 5,
            power_level: 0,
            content: serde_json::json!({ "membership": "ban" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$jr".into()],
            ..Default::default()
        },
        // B: join-rules lockdown
        LeanEvent {
            event_id: "$atkB".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@mallory:x".into(),
            origin_server_ts: 6000,
            depth: 5,
            power_level: 0,
            content: serde_json::json!({ "join_rule": "invite" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$jr".into()],
            ..Default::default()
        },
        // C: power-levels demotion (users[@victim] = 0)
        LeanEvent {
            event_id: "$atkC".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@mallory:x".into(),
            origin_server_ts: 6000,
            depth: 5,
            power_level: 0,
            content: serde_json::json!({ "users": { "@admin:x": 100, "@victim:x": 0 }, "users_default": 0 }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$jr".into()],
            ..Default::default()
        },
    ];

    for (i, atk) in cases.iter().enumerate() {
        let vic: LeanEvent = LeanEvent {
            event_id: format!("$vic{i}"),
            event_type: "m.room.member".into(),
            state_key: Some("@victim:x".into()),
            sender: "@victim:x".into(),
            origin_server_ts: 6100,
            depth: 5,
            power_level: 0,
            content: serde_json::json!({ "membership": "join" }),
            auth_events: vec!["$create".into(), "$admin_join".into(), "$pl".into()],
            prev_events: vec!["$jr".into()],
            ..Default::default()
        };
        let (_, ac, uc) = base();
        let mut conf = HashMap::new();
        conf.insert(atk.event_id.clone(), atk.clone());
        conf.insert(vic.event_id.clone(), vic.clone());
        let p = Problem {
            unconflicted: uc,
            conflicted: conf,
            auth_context: ac,
        };
        let r21 = resolve(&p, StateResVersion::V2_1);
        let r211 = resolve(&p, StateResVersion::V2_1_1);
        // Correct behavior: the auth-invalid dominator must not erase the join.
        assert_eq!(
            r21.get(&victim_key),
            Some(&format!("$vic{i}")),
            "V2.1 must keep the auth-valid join as the winner (case {i})"
        );
        assert_eq!(
            r21, r211,
            "V2.1.1 (CDO) must not diverge from V2.1: an auth-invalid {i} dominator \
             must not drop the resolved winner"
        );
    }
}
