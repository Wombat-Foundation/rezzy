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

struct EventInit<'a> {
    id: &'a str,
    sender: &'a str,
    ev_type: TimelineEventType,
    state_key: Option<&'a str>,
    content_json: &'a str,
    prev_events: &'a [&'a str],
    auth_events: &'a [&'a str],
    ts: u64,
}

fn make_event(init: EventInit<'_>) -> TestEvent {
    let event_id: OwnedEventId = if init.id.starts_with('$') {
        init.id.try_into().unwrap()
    } else {
        format!("${}:example.com", init.id).try_into().unwrap()
    };
    let room_id: OwnedRoomId = "!benchmark_room:example.com".try_into().unwrap();
    let sender_id: OwnedUserId = format!("@{}:example.com", init.sender).try_into().unwrap();

    TestEvent {
        event_id,
        room_id,
        sender: sender_id,
        origin_server_ts: MilliSecondsSinceUnixEpoch(init.ts.try_into().unwrap()),
        event_type: init.ev_type,
        state_key: init.state_key.map(ToOwned::to_owned),
        content: RawJsonValue::from_string(init.content_json.to_string())
            .unwrap()
            .into(),
        prev_events: init
            .prev_events
            .iter()
            .map(|s| {
                if s.starts_with('$') {
                    (*s).try_into().unwrap()
                } else {
                    format!("${s}:example.com").try_into().unwrap()
                }
            })
            .collect(),
        auth_events: init
            .auth_events
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

#[allow(clippy::too_many_lines)]
fn build_multi_fork_dag(
    num_members: usize,
    num_common_timeline: usize,
    num_forks: usize,
    conflicts_per_fork: usize,
) -> MultiForkDag {
    let mut events = HashMap::new();
    let mut current_ts = 1_000_000_000u64;

    // 1. Root Create Event
    let create = make_event(EventInit {
        id: "create",
        sender: "alice",
        ev_type: TimelineEventType::RoomCreate,
        state_key: Some(""),
        content_json: r#"{"creator":"@alice:example.com","room_version":"10"}"#,
        prev_events: &[],
        auth_events: &[],
        ts: current_ts,
    });
    let create_id = create.event_id.clone();
    events.insert(create_id.clone(), create);

    // 2. Alice Join
    current_ts = current_ts.saturating_add(10);
    let alice_join = make_event(EventInit {
        id: "alice_join",
        sender: "alice",
        ev_type: TimelineEventType::RoomMember,
        state_key: Some("@alice:example.com"),
        content_json: r#"{"membership":"join"}"#,
        prev_events: &["create"],
        auth_events: &["create"],
        ts: current_ts,
    });
    let alice_join_id = alice_join.event_id.clone();
    events.insert(alice_join_id.clone(), alice_join);

    // 3. Power Levels
    current_ts = current_ts.saturating_add(10);
    let power_levels = make_event(EventInit {
        id: "power_levels",
        sender: "alice",
        ev_type: TimelineEventType::RoomPowerLevels,
        state_key: Some(""),
        content_json: r#"{"users":{"@alice:example.com":100},"users_default":0,"state_default":50}"#,
        prev_events: &["alice_join"],
        auth_events: &["create", "alice_join"],
        ts: current_ts,
    });
    let pl_id = power_levels.event_id.clone();
    events.insert(pl_id.clone(), power_levels);

    // 4. Join Rules
    current_ts = current_ts.saturating_add(10);
    let join_rules = make_event(EventInit {
        id: "join_rules",
        sender: "alice",
        ev_type: TimelineEventType::RoomJoinRules,
        state_key: Some(""),
        content_json: r#"{"join_rule":"public"}"#,
        prev_events: &["power_levels"],
        auth_events: &["create", "alice_join", "power_levels"],
        ts: current_ts,
    });
    let jr_id = join_rules.event_id.clone();
    events.insert(jr_id.clone(), join_rules);

    // 5. Common member joins
    let mut member_join_ids = Vec::new();
    let mut last_prev = jr_id.clone();
    for i in 0..num_members {
        current_ts = current_ts.saturating_add(10);
        let name = format!("user_{i}");
        let join_id = format!("join_{i}");
        let state_key = format!("@{name}:example.com");
        let ev = make_event(EventInit {
            id: &join_id,
            sender: &name,
            ev_type: TimelineEventType::RoomMember,
            state_key: Some(&state_key),
            content_json: r#"{"membership":"join"}"#,
            prev_events: &[last_prev.as_ref()],
            auth_events: &["create", "join_rules", "power_levels"],
            ts: current_ts,
        });
        last_prev = ev.event_id.clone();
        member_join_ids.push(ev.event_id.clone());
        events.insert(ev.event_id.clone(), ev);
    }

    // 6. Common timeline events
    for i in 0..num_common_timeline {
        current_ts = current_ts.saturating_add(10);
        let msg_id = format!("common_msg_{i}");
        let ev = make_event(EventInit {
            id: &msg_id,
            sender: "alice",
            ev_type: TimelineEventType::RoomMessage,
            state_key: None,
            content_json: r#"{"body":"timeline noise"}"#,
            prev_events: &[last_prev.as_ref()],
            auth_events: &["create", "alice_join", "power_levels"],
            ts: current_ts,
        });
        last_prev = ev.event_id.clone();
        events.insert(ev.event_id.clone(), ev);
    }

    // Common base state map
    let mut base_state: StateMap<OwnedEventId> = StateMap::new();
    base_state.insert(
        (StateEventType::RoomCreate, String::new()),
        create_id.clone(),
    );
    base_state.insert(
        (StateEventType::RoomPowerLevels, String::new()),
        pl_id.clone(),
    );
    base_state.insert(
        (StateEventType::RoomJoinRules, String::new()),
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
            format!("user_{}", f.saturating_sub(1))
        };

        // Fork-specific power level update to allow fork_admin to act
        current_ts = current_ts.saturating_add(100);
        let fork_pl_id = format!("fork_{f}_pl");
        let fork_pl_content = format!(
            r#"{{"users":{{"@alice:example.com":100,"@{fork_admin}:example.com":100}},"users_default":0,"state_default":50}}"#
        );
        let fork_pl = make_event(EventInit {
            id: &fork_pl_id,
            sender: "alice",
            ev_type: TimelineEventType::RoomPowerLevels,
            state_key: Some(""),
            content_json: &fork_pl_content,
            prev_events: &[fork_last_prev.as_ref()],
            auth_events: &["create", "alice_join", "power_levels"],
            ts: current_ts,
        });
        fork_last_prev = fork_pl.event_id.clone();
        events.insert(fork_pl.event_id.clone(), fork_pl.clone());
        fork_state.insert(
            (StateEventType::RoomPowerLevels, String::new()),
            fork_pl.event_id.clone(),
        );
        total_conflicts_set.insert((StateEventType::RoomPowerLevels, String::new()));

        // Generate divergent state events in this fork
        for c in 0..conflicts_per_fork {
            current_ts = current_ts.saturating_add(10);
            let member_mod = num_members.max(1);
            let target_idx = c
                .saturating_add(f.saturating_mul(7))
                .checked_rem(member_mod)
                .unwrap_or(0);
            let target_user = format!("user_{target_idx}");
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
                    String::new(),
                    format!(r#"{{"topic":"Fork {f} Topic revision {c}"}}"#),
                ),
                2 => (
                    TimelineEventType::RoomName,
                    String::new(),
                    format!(r#"{{"name":"Fork {f} Room Name {c}"}}"#),
                ),
                _ => (
                    TimelineEventType::from(format!("org.matrix.custom_state_{c}")),
                    format!("key_{f}"),
                    format!(r#"{{"value":"state_val_{f}_{c}"}}"#),
                ),
            };

            let fork_ev_id = format!("fork_{f}_ev_{c}");
            let ev = make_event(EventInit {
                id: &fork_ev_id,
                sender: &fork_admin,
                ev_type: ev_type.clone(),
                state_key: Some(&state_key),
                content_json: &content,
                prev_events: &[fork_last_prev.as_ref()],
                auth_events: &["create", "alice_join", fork_pl.event_id.as_ref()],
                ts: current_ts,
            });
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
        prev_state_events: Vec::new(),
        depth: 0,
        rejected: false,
        soft_fail: false,
        room_id: None,
    }
}

#[allow(clippy::too_many_lines)]
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

    let total_auth_chain_nodes: usize = dag
        .fork_auth_chains
        .iter()
        .map(ruma_state_res::utils::event_id_set::EventIdSet::len)
        .sum();

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
        "  Cumulative Auth Chain Elements across forks: {total_auth_chain_nodes} | Iterations: {runs}"
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
            let count = key_id_counts.entry((key, id)).or_default();
            *count = count.saturating_add(1);
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
            } else if let Some(ev) = dag.events.get(id) {
                conflicted_events.insert(id.to_string(), to_rezzy_lean(ev));
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
    let ruma_avg = ruma_elapsed.checked_div(runs).unwrap_or(ruma_elapsed);

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
            &String::new(),
        );
        rezzy_result = Some(black_box(res));
    }
    let rezzy_elapsed = start_rezzy.elapsed();
    let rezzy_avg = rezzy_elapsed.checked_div(runs).unwrap_or(rezzy_elapsed);

    // Verify correctness parity symmetrically: every ruma key must match in
    // rezzy AND rezzy must not carry extra keys (equal cardinality). A
    // one-directional subset check would print "VERIFIED" even if rezzy
    // kept a losing conflicted event ruma dropped.
    let ruma_resolved = ruma_result.unwrap();
    let rezzy_resolved = rezzy_result.unwrap();
    assert_eq!(
        ruma_resolved.len(),
        rezzy_resolved.len(),
        "resolved state cardinality differs (ruma {} vs rezzy {})",
        ruma_resolved.len(),
        rezzy_resolved.len()
    );
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
    // Symmetric pass: no extra keys on the rezzy side.
    for (rezzy_key, rezzy_id) in &rezzy_resolved {
        let ruma_key = (
            StateEventType::from(rezzy_key.0.as_str()),
            rezzy_key.1.clone(),
        );
        let ruma_id = ruma_resolved.get(&ruma_key).expect("Key present in ruma");
        assert_eq!(
            ruma_id.as_str(),
            rezzy_id.as_str(),
            "extra state in rezzy for {:?}, {:?}",
            rezzy_key.0,
            rezzy_key.1
        );
    }

    let ruma_secs = ruma_elapsed.as_secs_f64();
    let rezzy_secs = rezzy_elapsed.as_secs_f64();
    let speedup = if rezzy_secs > 0.0 {
        ruma_secs / rezzy_secs
    } else {
        1.0
    };

    println!("  ruma-state-res (original):  {ruma_elapsed:?} (avg: {ruma_avg:?})");
    println!("  rezzy (bitmap accelerated): {rezzy_elapsed:?} (avg: {rezzy_avg:?})");
    println!("  CORRECTNESS PARITY:         VERIFIED (100% Identical Resolution)");
    if speedup >= 1.0 {
        println!("  >>> REZZY SPEEDUP:          {speedup:.2}x FASTER <<<\n");
    } else {
        let slowdown = if speedup > 0.0 { 1.0 / speedup } else { 1.0 };
        println!("  >>> REZZY SLOWDOWN:         {slowdown:.2}x SLOWER <<<\n");
    }
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
