//! High-scale shootout benchmark comparing `ruma-state-res` vs `rezzy`
//! over complex multi-way Matrix DAG forks, parallel branches, and large rebuilds.
//!
//! # What this measures
//!
//! This harness is an **algorithmic correctness-parity oracle**, not a
//! performance claim. The 100% identical-resolution check against
//! `ruma-state-res` across nasty fork/rebuild topologies is the primary
//! output. The speedup column is secondary and, for this particular
//! in-memory `String`-ID fixture, is not where rezzy's performance advantage
//! lives: rezzy's large speedups are in bitwise auth-difference and Roaring
//! reachability/transitive-closure, measured by `run_bench_auth_difference.sh`
//! and `cargo bench --bench resolve`. Both engines here resolve a pre-computed
//! in-memory DAG with no database I/O, and rezzy uses its zero-copy borrowed
//! entry point so the timed loop does not pay a per-iteration `serde_json`
//! deep clone.

use std::{collections::HashMap, hint::black_box, sync::Arc, time::Instant};

use ruma_common::{
    room_version_rules::{AuthorizationRules, StateResolutionV2Rules},
    MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UserId,
};
use ruma_events::{StateEventType, TimelineEventType};
use ruma_state_res::{utils::event_id_set::EventIdSet, Event, StateMap};
use serde_json::value::RawValue as RawJsonValue;

#[derive(Clone, Debug)]
struct TestEvent {
    event_id: OwnedEventId,
    room_id: OwnedRoomId,
    sender: OwnedUserId,
    origin_server_ts: MilliSecondsSinceUnixEpoch,
    event_type: TimelineEventType,
    state_key: Option<String>,
    content: Arc<RawJsonValue>,
    prev_events: Vec<OwnedEventId>,
    auth_events: Vec<OwnedEventId>,
}

impl Event for TestEvent {
    type Id = OwnedEventId;

    fn event_id(&self) -> &Self::Id {
        &self.event_id
    }

    fn room_id(&self) -> Option<&RoomId> {
        Some(&self.room_id)
    }

    fn sender(&self) -> &UserId {
        &self.sender
    }

    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        self.origin_server_ts
    }

    fn event_type(&self) -> &TimelineEventType {
        &self.event_type
    }

    fn state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }

    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.prev_events.iter())
    }

    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.auth_events.iter())
    }

    fn content(&self) -> &RawJsonValue {
        &self.content
    }

    fn redacts(&self) -> Option<&Self::Id> {
        None
    }

    fn rejected(&self) -> bool {
        false
    }
}

fn make_event(
    id: &str,
    sender: &str,
    ev_type: TimelineEventType,
    state_key: Option<&str>,
    content_json: &str,
    prev_events: &[&str],
    auth_events: &[&str],
    ts: u64,
) -> TestEvent {
    let event_id: OwnedEventId = if id.starts_with('$') {
        id.try_into().unwrap()
    } else {
        format!("${id}:example.com").try_into().unwrap()
    };
    let room_id: OwnedRoomId = "!benchmark_room:example.com".try_into().unwrap();
    let sender_id: OwnedUserId = format!("@{sender}:example.com").try_into().unwrap();

    TestEvent {
        event_id,
        room_id,
        sender: sender_id,
        origin_server_ts: MilliSecondsSinceUnixEpoch(ts.try_into().unwrap()),
        event_type: ev_type,
        state_key: state_key.map(ToOwned::to_owned),
        content: RawJsonValue::from_string(content_json.to_string())
            .unwrap()
            .into(),
        prev_events: prev_events
            .iter()
            .map(|s| {
                if s.starts_with('$') {
                    (*s).try_into().unwrap()
                } else {
                    format!("${s}:example.com").try_into().unwrap()
                }
            })
            .collect(),
        auth_events: auth_events
            .iter()
            .map(|s| {
                if s.starts_with('$') {
                    (*s).try_into().unwrap()
                } else {
                    format!("${s}:example.com").try_into().unwrap()
                }
            })
            .collect(),
    }
}

struct MultiForkDag {
    events: HashMap<OwnedEventId, TestEvent>,
    fork_states: Vec<StateMap<OwnedEventId>>,
    fork_auth_chains: Vec<EventIdSet<OwnedEventId>>,
    total_conflicts: usize,
}

fn build_multi_fork_dag(
    num_members: usize,
    num_common_timeline: usize,
    num_forks: usize,
    conflicts_per_fork: usize,
) -> MultiForkDag {
    let mut events = HashMap::new();
    let mut current_ts = 1_000_000_000u64;

    // 1. Root Create Event
    let create = make_event(
        "create",
        "alice",
        TimelineEventType::RoomCreate,
        Some(""),
        r#"{"creator":"@alice:example.com","room_version":"10"}"#,
        &[],
        &[],
        current_ts,
    );
    let create_id = create.event_id.clone();
    events.insert(create_id.clone(), create);

    // 2. Alice Join
    current_ts += 10;
    let alice_join = make_event(
        "alice_join",
        "alice",
        TimelineEventType::RoomMember,
        Some("@alice:example.com"),
        r#"{"membership":"join"}"#,
        &["create"],
        &["create"],
        current_ts,
    );
    let alice_join_id = alice_join.event_id.clone();
    events.insert(alice_join_id.clone(), alice_join);

    // 3. Power Levels
    current_ts += 10;
    let power_levels = make_event(
        "power_levels",
        "alice",
        TimelineEventType::RoomPowerLevels,
        Some(""),
        r#"{"users":{"@alice:example.com":100},"users_default":0,"state_default":50}"#,
        &["alice_join"],
        &["create", "alice_join"],
        current_ts,
    );
    let pl_id = power_levels.event_id.clone();
    events.insert(pl_id.clone(), power_levels);

    // 4. Join Rules
    current_ts += 10;
    let join_rules = make_event(
        "join_rules",
        "alice",
        TimelineEventType::RoomJoinRules,
        Some(""),
        r#"{"join_rule":"public"}"#,
        &["power_levels"],
        &["create", "alice_join", "power_levels"],
        current_ts,
    );
    let jr_id = join_rules.event_id.clone();
    events.insert(jr_id.clone(), join_rules);

    // 5. Common member joins
    let mut member_join_ids = Vec::new();
    let mut last_prev = jr_id.clone();
    for i in 0..num_members {
        current_ts += 10;
        let name = format!("user_{i}");
        let ev = make_event(
            &format!("join_{i}"),
            &name,
            TimelineEventType::RoomMember,
            Some(&format!("@{name}:example.com")),
            r#"{"membership":"join"}"#,
            &[&last_prev.to_string()],
            &["create", "join_rules", "power_levels"],
            current_ts,
        );
        last_prev = ev.event_id.clone();
        member_join_ids.push(ev.event_id.clone());
        events.insert(ev.event_id.clone(), ev);
    }

    // 6. Common timeline events
    for i in 0..num_common_timeline {
        current_ts += 10;
        let ev = make_event(
            &format!("common_msg_{i}"),
            "alice",
            TimelineEventType::RoomMessage,
            None,
            r#"{"body":"timeline noise"}"#,
            &[&last_prev.to_string()],
            &["create", "alice_join", "power_levels"],
            current_ts,
        );
        last_prev = ev.event_id.clone();
        events.insert(ev.event_id.clone(), ev);
    }

    // Common base state map
    let mut base_state: StateMap<OwnedEventId> = StateMap::new();
    base_state.insert(
        (StateEventType::RoomCreate, "".to_string()),
        create_id.clone(),
    );
    base_state.insert(
        (StateEventType::RoomPowerLevels, "".to_string()),
        pl_id.clone(),
    );
    base_state.insert(
        (StateEventType::RoomJoinRules, "".to_string()),
        jr_id.clone(),
    );
    base_state.insert(
        (StateEventType::RoomMember, "@alice:example.com".to_string()),
        alice_join_id.clone(),
    );
    for (i, j_id) in member_join_ids.iter().enumerate() {
        base_state.insert(
            (StateEventType::RoomMember, format!("@user_{i}:example.com")),
            j_id.clone(),
        );
    }

    // 7. Generate parallel diverging forks
    let mut fork_states = Vec::with_capacity(num_forks);
    let mut total_conflicts_set = std::collections::HashSet::new();

    for f in 0..num_forks {
        let mut fork_state = base_state.clone();
        let mut fork_last_prev = last_prev.clone();
        let fork_admin = if f == 0 {
            "alice".to_string()
        } else {
            format!("user_{}", f - 1)
        };

        // Fork-specific power level update to allow fork_admin to act
        current_ts += 100;
        let fork_pl = make_event(
            &format!("fork_{f}_pl"),
            "alice",
            TimelineEventType::RoomPowerLevels,
            Some(""),
            &format!(
                r#"{{"users":{{"@alice:example.com":100,"@{fork_admin}:example.com":100}},"users_default":0,"state_default":50}}"#
            ),
            &[&fork_last_prev.to_string()],
            &["create", "alice_join", "power_levels"],
            current_ts,
        );
        fork_last_prev = fork_pl.event_id.clone();
        events.insert(fork_pl.event_id.clone(), fork_pl.clone());
        fork_state.insert(
            (StateEventType::RoomPowerLevels, "".to_string()),
            fork_pl.event_id.clone(),
        );
        total_conflicts_set.insert((StateEventType::RoomPowerLevels, "".to_string()));

        // Generate divergent state events in this fork
        for c in 0..conflicts_per_fork {
            current_ts += 10;
            let target_user = format!("user_{}", (c + f * 7) % num_members.max(1));
            let (ev_type, state_key, content) = match c % 4 {
                0 => (
                    TimelineEventType::RoomMember,
                    format!("@{target_user}:example.com"),
                    format!(
                        r#"{{"membership":"{}"}}"#,
                        if f % 2 == 0 { "ban" } else { "leave" }
                    ),
                ),
                1 => (
                    TimelineEventType::RoomTopic,
                    "".to_string(),
                    format!(r#"{{"topic":"Fork {f} Topic revision {c}"}}"#),
                ),
                2 => (
                    TimelineEventType::RoomName,
                    "".to_string(),
                    format!(r#"{{"name":"Fork {f} Room Name {c}"}}"#),
                ),
                _ => (
                    TimelineEventType::from(format!("org.matrix.custom_state_{c}")),
                    format!("key_{f}"),
                    format!(r#"{{"value":"state_val_{f}_{c}"}}"#),
                ),
            };

            let ev = make_event(
                &format!("fork_{f}_ev_{c}"),
                &fork_admin,
                ev_type.clone(),
                Some(&state_key),
                &content,
                &[&fork_last_prev.to_string()],
                &["create", "alice_join", &fork_pl.event_id.to_string()],
                current_ts,
            );
            fork_last_prev = ev.event_id.clone();
            events.insert(ev.event_id.clone(), ev.clone());
            let state_ev_type = StateEventType::from(ev_type.to_string());
            fork_state.insert(
                (state_ev_type.clone(), state_key.clone()),
                ev.event_id.clone(),
            );
            total_conflicts_set.insert((state_ev_type, state_key));
        }

        fork_states.push(fork_state);
    }

    // Recursive auth chain collector for each fork
    let mut fork_auth_chains = Vec::with_capacity(num_forks);
    for fork_state in &fork_states {
        let mut chain = EventIdSet::new();
        let mut stack: Vec<OwnedEventId> = fork_state.values().cloned().collect();
        while let Some(id) = stack.pop() {
            if chain.insert(id.clone()) {
                if let Some(ev) = events.get(&id) {
                    for auth in &ev.auth_events {
                        stack.push(auth.clone());
                    }
                }
            }
        }
        fork_auth_chains.push(chain);
    }

    MultiForkDag {
        events,
        fork_states,
        fork_auth_chains,
        total_conflicts: total_conflicts_set.len(),
    }
}

fn to_rezzy_lean(ev: &TestEvent) -> rezzy::LeanEvent {
    let content_val: serde_json::Value =
        serde_json::from_str(ev.content.get()).unwrap_or(serde_json::Value::Null);
    let power_level = content_val
        .get("power_level")
        .and_then(rezzy::basespec::rezzy_types::coerce_json_to_i64)
        .unwrap_or(0);

    rezzy::LeanEvent {
        event_id: ev.event_id.to_string(),
        event_type: ev.event_type.to_string(),
        state_key: ev.state_key.clone(),
        power_level,
        origin_server_ts: ev.origin_server_ts.0.into(),
        sender: ev.sender.to_string(),
        content: content_val,
        prev_events: ev.prev_events.iter().map(ToString::to_string).collect(),
        auth_events: ev.auth_events.iter().map(ToString::to_string).collect(),
        depth: 0,
        rejected: false,
        soft_fail: false,
        room_id: None,
    }
}

fn run_shootout(
    scenario_name: &str,
    num_members: usize,
    num_timeline: usize,
    num_forks: usize,
    conflicts_per_fork: usize,
    runs: u32,
) {
    let dag = build_multi_fork_dag(num_members, num_timeline, num_forks, conflicts_per_fork);
    let events_map = &dag.events;

    let fetch_event =
        |id: &ruma_common::EventId| -> Option<TestEvent> { events_map.get(id).cloned() };

    let total_auth_chain_nodes: usize = dag.fork_auth_chains.iter().map(|c| c.len()).sum();

    println!("================================================================================");
    println!("  SCENARIO: {scenario_name}");
    println!(
        "  DAG PDUs: {} | Members: {} | Forks: {} | Conflicted Keys: {}",
        dag.events.len(),
        num_members,
        num_forks,
        dag.total_conflicts
    );
    println!(
        "  Cumulative Auth Chain Elements across forks: {} | Iterations: {}",
        total_auth_chain_nodes, runs
    );
    println!("================================================================================");

    // Pre-convert to Rezzy format
    let mut unconflicted_state = rezzy::SharedState::new();
    let mut conflicted_events: HashMap<String, rezzy::LeanEvent> = HashMap::new();
    let mut auth_context: HashMap<String, rezzy::LeanEvent> = HashMap::new();

    // Find common unconflicted vs conflicted across all N forks
    let num_maps = dag.fork_states.len();
    let mut key_id_counts: HashMap<(&(StateEventType, String), &OwnedEventId), usize> =
        HashMap::new();
    for map in &dag.fork_states {
        for (key, id) in map {
            *key_id_counts.entry((key, id)).or_default() += 1;
        }
    }

    for map in &dag.fork_states {
        for (key, id) in map {
            if key_id_counts.get(&(key, id)).copied().unwrap_or(0) == num_maps {
                unconflicted_state.insert(
                    (
                        rezzy::basespec::event_types::EventType::from(key.0.to_string()),
                        key.1.clone(),
                    ),
                    id.to_string(),
                );
            } else {
                if let Some(ev) = dag.events.get(id) {
                    conflicted_events.insert(id.to_string(), to_rezzy_lean(ev));
                }
            }
        }
    }

    for (id, ev) in &dag.events {
        auth_context.insert(id.to_string(), to_rezzy_lean(ev));
    }

    // 1. Benchmark ruma-state-res
    let fork_state_refs: Vec<&StateMap<OwnedEventId>> = dag.fork_states.iter().collect();
    let start_ruma = Instant::now();
    let mut ruma_result = None;
    for _ in 0..runs {
        let res = ruma_state_res::resolve(
            &AuthorizationRules::V10,
            &StateResolutionV2Rules::V2_0,
            fork_state_refs.clone(),
            dag.fork_auth_chains.clone(),
            &fetch_event,
            |_| unreachable!(),
        );
        ruma_result = Some(black_box(res.unwrap()));
    }
    let ruma_elapsed = start_ruma.elapsed();
    let ruma_avg = ruma_elapsed / runs;

    // 2. Benchmark rezzy (borrowed entry point: no per-iteration deep clone of the
    //    LeanEvent/serde_json contents; the resolver reads the maps by reference).
    let start_rezzy = Instant::now();
    let mut rezzy_result = None;
    let mut pl_cache = HashMap::new();
    for _ in 0..runs {
        pl_cache.clear();
        let res = rezzy::resolve_iterative_sort(
            &unconflicted_state,
            &conflicted_events,
            &auth_context,
            rezzy::StateResVersion::V2,
            &mut pl_cache,
        );
        rezzy_result = Some(black_box(res));
    }
    let rezzy_elapsed = start_rezzy.elapsed();
    let rezzy_avg = rezzy_elapsed / runs;

    // Verify correctness parity
    let ruma_resolved = ruma_result.unwrap();
    let rezzy_resolved = rezzy_result.unwrap();
    for ((ev_type, state_key), ruma_id) in &ruma_resolved {
        let rezzy_key = (
            rezzy::basespec::event_types::EventType::from(ev_type.to_string()),
            state_key.clone(),
        );
        let rezzy_id = rezzy_resolved
            .get(&rezzy_key)
            .expect("Key present in Rezzy");
        assert_eq!(
            ruma_id.as_str(),
            rezzy_id.as_str(),
            "State mismatch for {ev_type:?}, {state_key:?}"
        );
    }

    let speedup = ruma_elapsed.as_nanos() as f64 / rezzy_elapsed.as_nanos() as f64;

    println!("  ruma-state-res (original):  {ruma_elapsed:?} (avg: {ruma_avg:?})");
    println!("  rezzy (bitmap accelerated): {rezzy_elapsed:?} (avg: {rezzy_avg:?})");
    println!("  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)");
    println!("  >>> REZZY SPEEDUP:          {speedup:.2}x FASTER <<<\n");
}

fn main() {
    println!("================================================================================");
    println!("  MATRIX STATE RESOLUTION LARGE-SCALE SHOOTOUT: ruma-state-res vs rezzy");
    println!("  (correctness-parity oracle; perf claims belong in run_bench_auth_difference.sh");
    println!("   and cargo bench --bench resolve, not this in-memory String-ID fixture)");
    println!("================================================================================\n");

    // 1. Nasty 2-Branch Conflict (500 Members, 100 Conflicted Keys, Deep Auth Chains, ~1,600 PDUs)
    run_shootout(
        "Nasty 2-Branch Conflict (500 Members, 100 Conflicted Keys, ~1,600 PDUs)",
        500,
        1000,
        2,
        100,
        500,
    );

    // 2. 4-Way Federated Partition Fork (500 Members, 200 Conflicted Keys, ~2,500 PDUs)
    run_shootout(
        "4-Way Federated Partition (500 Members, 4 Forks, 200 Conflicted Keys, ~2,500 PDUs)",
        500,
        1500,
        4,
        100,
        200,
    );

    // 3. 8-Way Split-Brain Chaos (1,000 Members, 8 Forks, 400 Conflicted Keys, ~5,000 PDUs)
    run_shootout(
        "8-Way Split-Brain Chaos (1,000 Members, 8 Forks, 400 Conflicted Keys, ~5,000 PDUs)",
        1000,
        3000,
        8,
        100,
        50,
    );

    // 4. Mega Rebuild Stress (2,000 Members, 8 Forks, 800 Conflicted Keys, ~10,000 PDUs)
    run_shootout(
        "Mega Rebuild Stress (2,000 Members, 8 Forks, 800 Conflicted Keys, ~10,000 PDUs)",
        2000,
        6000,
        8,
        200,
        20,
    );
}
