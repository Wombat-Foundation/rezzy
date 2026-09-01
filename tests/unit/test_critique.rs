use crate::utils;
use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use test_case::test_case;

type ResolvedStateMap = HashMap<(String, String), String>;
type EventMap = HashMap<String, LeanEvent>;

fn load_fixture(path: &std::path::Path) -> Vec<LeanEvent> {
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|_| panic!("Missing {}", path.display()));
    if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("Failed to parse line in {}: {e}", path.display()))
            })
            .collect()
    } else {
        let val: Value = serde_json::from_str(&content).unwrap();
        if val.is_array() {
            serde_json::from_value(val).unwrap()
        } else {
            serde_json::from_value(val["events"].clone()).unwrap()
        }
    }
}

fn to_event_map(events: &[LeanEvent]) -> EventMap {
    events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect()
}

fn get_heads(events: &[LeanEvent]) -> Vec<String> {
    // Look for the merge event (which has multiple prev_events)
    if let Some(merge_event) = events.iter().find(|e| e.prev_events.len() > 1) {
        merge_event.prev_events.clone()
    } else {
        // Fallback: overall leaf events of the DAG
        let mut prevs = HashSet::new();
        for e in events {
            for p in &e.prev_events {
                prevs.insert(p.clone());
            }
        }
        events
            .iter()
            .filter(|e| !prevs.contains(&e.event_id))
            .map(|e| e.event_id.clone())
            .collect()
    }
}

fn get_state_map_for_head(head: &str, events_map: &EventMap) -> HashMap<(String, String), String> {
    let mut visited = HashSet::new();
    let mut stack = vec![head.to_string()];
    let mut ancestors = Vec::new();
    while let Some(id) = stack.pop() {
        if visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(&id) {
                ancestors.push(ev.clone());
                for p in &ev.prev_events {
                    stack.push(p.clone());
                }
            }
        }
    }
    // Sort ancestors to build state chronologically/topologically
    ancestors.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let mut state = HashMap::new();
    for ev in ancestors {
        if ev.state_key.is_some() {
            state.insert(
                (ev.event_type.clone(), ev.state_key.clone().unwrap()),
                ev.event_id.clone(),
            );
        }
    }
    state
}

fn get_auth_chain(event_id: &str, events_map: &EventMap, visited: &mut HashSet<String>) {
    if visited.insert(event_id.to_string()) {
        if let Some(ev) = events_map.get(event_id) {
            for a in &ev.auth_events {
                get_auth_chain(a, events_map, visited);
            }
        }
    }
}

fn resolve_full(events: &[LeanEvent], version: StateResVersion) -> ResolvedStateMap {
    let events_map = to_event_map(events);
    let heads = get_heads(events);
    let mut state_maps = Vec::new();
    for h in &heads {
        state_maps.push(get_state_map_for_head(h, &events_map));
    }

    let num_sets = state_maps.len();
    let mut occurrences: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
    for map in &state_maps {
        for (key, id) in map {
            let val = occurrences
                .entry(key.clone())
                .or_default()
                .entry(id.clone())
                .or_insert(0);
            *val = val.wrapping_add(1);
        }
    }

    let mut unconflicted_state = imbl::OrdMap::new();
    let mut conflicted_state_set = Vec::new();
    for (key, ids) in occurrences {
        if ids.len() == 1 && ids.values().next().unwrap() == &num_sets {
            let id = ids.keys().next().unwrap();
            unconflicted_state.insert(key, id.clone());
        } else {
            for id in ids.keys() {
                conflicted_state_set.push(id.clone());
            }
        }
    }

    // Auth difference: events in the auth chain of at least one head, but not all heads.
    let mut union = HashSet::new();
    let mut intersection = HashSet::new();
    let mut first = true;

    for head_id in &heads {
        let mut chain = HashSet::new();
        get_auth_chain(head_id, &events_map, &mut chain);
        if first {
            union.clone_from(&chain);
            intersection = chain;
            first = false;
        } else {
            union.extend(chain.clone());
            intersection = intersection.intersection(&chain).cloned().collect();
        }
    }

    let auth_difference: HashSet<String> = union.difference(&intersection).cloned().collect();

    let mut conflicted_events = HashMap::new();
    // Add conflicted state set
    for id in &conflicted_state_set {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    // Add auth difference
    for id in &auth_difference {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    // Add conflicted state subgraph (MSC4297 / v2.1+)
    if version == StateResVersion::V2_1 || version == StateResVersion::V2_1_1 {
        let subgraph = rezzy::compute_v2_1_conflicted_subgraph(&events_map, &conflicted_state_set);
        for (id, ev) in subgraph {
            conflicted_events.insert(id, ev);
        }
    }

    let unconflicted_state_typed: imbl::OrdMap<
        (rezzy::basespec::event_types::EventType, String),
        String,
    > = unconflicted_state
        .iter()
        .map(|(k, v)| {
            (
                (
                    rezzy::basespec::event_types::EventType::from(k.0.as_str()),
                    k.1.clone(),
                ),
                v.clone(),
            )
        })
        .collect();

    let resolved = resolve_iterative_sort(
        &unconflicted_state_typed,
        &conflicted_events,
        &events_map,
        version,
        &mut std::collections::HashMap::new(),
        &String::new(),
    );

    let mut full_state = HashMap::new();
    for (k, v) in unconflicted_state {
        full_state.insert(k, v);
    }
    for (k, v) in resolved {
        full_state.insert((k.0.to_string(), k.1), v);
    }
    full_state
}

fn get_user_power_level(resolved: &ResolvedStateMap, map: &EventMap, user_id: &str) -> i64 {
    let key = ("m.room.power_levels".to_string(), String::new());
    if let Some(event_id) = resolved.get(&key) {
        if let Some(ev) = map.get(event_id) {
            if let Some(users) = ev.content.get("users").and_then(|u| u.as_object()) {
                if let Some(pl) = users.get(user_id).and_then(serde_json::Value::as_i64) {
                    return pl;
                }
            }
        }
    }
    0
}

fn get_membership(resolved: &ResolvedStateMap, map: &EventMap, user_id: &str) -> String {
    let key = ("m.room.member".to_string(), user_id.to_string());
    if let Some(event_id) = resolved.get(&key) {
        if let Some(ev) = map.get(event_id) {
            if let Some(m) = ev.content.get("membership").and_then(|v| v.as_str()) {
                return m.to_string();
            }
        }
    }
    "none".to_string()
}

fn resolve_pathology(jsonl_filename: &str) -> (ResolvedStateMap, EventMap) {
    let absolute_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/critique_data")
        .join(jsonl_filename);
    let events = load_fixture(&absolute_path);
    let map = to_event_map(&events);
    let resolved = resolve_full(&events, StateResVersion::V2_1_1);
    (resolved, map)
}

fn assert_benign_convergence(jsonl_filename: &str) -> (ResolvedStateMap, EventMap) {
    let absolute_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/critique_data")
        .join(jsonl_filename);
    let events = load_fixture(&absolute_path);
    let map = to_event_map(&events);

    let resolved_v2_1 = resolve_full(&events, StateResVersion::V2_1);
    let resolved_v2_1_1 = resolve_full(&events, StateResVersion::V2_1_1);

    assert_eq!(
        resolved_v2_1_1, resolved_v2_1,
        "Causal Domination pre-filter violated Benign Convergence parity for {jsonl_filename}"
    );
    (resolved_v2_1_1, map)
}

/// **xfail / ordering hazard:** V2 and V2.1 accept A's backdated kick while B
/// is still low-power, discarding B's legitimate competing-branch actions.
/// V2.1.1 and V2.2 are expected to preserve B's promoted branch.
#[test_case(StateResVersion::V2, false; "v2")]
#[test_case(StateResVersion::V2_1, false; "v2_1")]
#[test_case(StateResVersion::V2_1_1, true; "v2_1_1")]
#[test_case(StateResVersion::V2_2, true; "v2_2")]
fn test_dueling_admins_backdated_kick(version: StateResVersion, expect_hardened_result: bool) {
    let events = utils::parse_jsonl_events(
        r#"
        {"event_id":"$create","type":"m.room.create","state_key":"","sender":"@a:example.com","origin_server_ts":0,"content":{"creator":"@a:example.com","room_version":"10"}}
        {"event_id":"$a_join","type":"m.room.member","state_key":"@a:example.com","sender":"@a:example.com","origin_server_ts":1,"content":{"membership":"join"},"auth_events":["$create"]}
        {"event_id":"$b_join","type":"m.room.member","state_key":"@b:example.com","sender":"@b:example.com","origin_server_ts":2,"content":{"membership":"join"},"auth_events":["$create"]}
        {"event_id":"$c_join","type":"m.room.member","state_key":"@c:example.com","sender":"@c:example.com","origin_server_ts":3,"content":{"membership":"join"},"auth_events":["$create"]}
        {"event_id":"$d_join","type":"m.room.member","state_key":"@d:example.com","sender":"@d:example.com","origin_server_ts":4,"content":{"membership":"join"},"auth_events":["$create"]}
        {"event_id":"$pl0","type":"m.room.power_levels","state_key":"","sender":"@a:example.com","origin_server_ts":5,"content":{"users":{"@a:example.com":100,"@b:example.com":0},"state_default":50,"ban":50},"auth_events":["$create","$a_join"]}
        {"event_id":"$promote_b","type":"m.room.power_levels","state_key":"","sender":"@a:example.com","origin_server_ts":80,"content":{"users":{"@a:example.com":100,"@b:example.com":100,"@c:example.com":0},"state_default":50,"ban":50},"auth_events":["$create","$a_join","$pl0"]}
        {"event_id":"$b_promote_c","type":"m.room.power_levels","state_key":"","sender":"@b:example.com","origin_server_ts":90,"content":{"users":{"@a:example.com":100,"@b:example.com":100,"@c:example.com":50},"state_default":50,"ban":50},"auth_events":["$create","$a_join","$b_join","$promote_b"]}
        {"event_id":"$b_ban_d","type":"m.room.member","state_key":"@d:example.com","sender":"@b:example.com","origin_server_ts":100,"content":{"membership":"ban"},"auth_events":["$create","$a_join","$b_join","$d_join","$promote_b"]}
        {"event_id":"$backdated_kick_b","type":"m.room.member","state_key":"@b:example.com","sender":"@a:example.com","origin_server_ts":70,"content":{"membership":"leave"},"auth_events":["$create","$a_join","$b_join","$pl0"]}
        "#,
    );
    let auth_context: EventMap = to_event_map(&events);
    let unconflicted =
        utils::build_unconflicted_state_from_ids(&auth_context, &["$create", "$a_join", "$c_join"]);
    let conflicted: EventMap = [
        "$b_join",
        "$d_join",
        "$pl0",
        "$promote_b",
        "$b_promote_c",
        "$b_ban_d",
        "$backdated_kick_b",
    ]
    .into_iter()
    .map(|event_id| (event_id.to_owned(), auth_context[event_id].clone()))
    .collect();
    let resolved = resolve_iterative_sort(
        &unconflicted,
        &conflicted,
        &auth_context,
        version,
        &mut HashMap::new(),
        &String::new(),
    );

    let b_membership = resolved.get(&("m.room.member".into(), "@b:example.com".into()));
    let power_levels = resolved.get(&("m.room.power_levels".into(), String::new()));
    let d_membership = resolved.get(&("m.room.member".into(), "@d:example.com".into()));

    if expect_hardened_result {
        assert_eq!(
            b_membership,
            Some(&"$b_join".into()),
            "{version:?} must not let the backdated kick remove B"
        );
        assert_eq!(
            power_levels,
            Some(&"$b_promote_c".into()),
            "{version:?} must preserve B's valid promotion of C"
        );
        assert_eq!(
            d_membership,
            Some(&"$b_ban_d".into()),
            "{version:?} must preserve B's valid ban of D"
        );
    } else {
        assert_eq!(
            b_membership,
            Some(&"$backdated_kick_b".into()),
            "xfail ({version:?}): the backdated kick wins B's membership slot"
        );
        assert_ne!(
            power_levels,
            Some(&"$b_promote_c".into()),
            "xfail ({version:?}): B's locally-authorised promotion of C is discarded"
        );
        assert_ne!(
            d_membership,
            Some(&"$b_ban_d".into()),
            "xfail ({version:?}): B's locally-authorised ban of D is discarded"
        );
    }
}

#[test]
fn test_anomaly_01_state_reset() {
    let (resolved, map) = assert_benign_convergence("01_state_reset.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

#[test]
fn test_anomaly_02_admin_lockout() {
    let (resolved, map) = assert_benign_convergence("02_admin_lockout.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

/// Regression coverage for the phantom join-rules anomaly fixture.
#[test]
fn test_anomaly_03_phantom_join_rules() {
    let (resolved, map) = resolve_pathology("03_phantom_join_rules.jsonl");
    // Per the spec, Charlie's join is auth-checked against the *resolved*
    // join_rules (which resolves to invite), not the public rules in his own
    // auth chain. Charlie is not invited, so the join is rejected.
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "none"
    );
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_04_ban_evasion() {
    let (resolved, map) = resolve_pathology("04_ban_evasion.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:ServerB"), "ban");
    assert_eq!(get_membership(&resolved, &map, "@alice:ServerA"), "join");
}

#[test]
fn test_anomaly_05_timestamp_spoofing() {
    let (resolved, map) = assert_benign_convergence("05_timestamp_spoofing.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_06_action_evaporation() {
    let (resolved, map) = assert_benign_convergence("06_action_evaporation.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(get_user_power_level(&resolved, &map, "@bob:example.com"), 0);
}

/// Regression coverage for the membership-evaporation anomaly fixture.
#[test]
fn test_anomaly_06b_mod_membership_evaporation() {
    let (resolved, map) = resolve_pathology("06b_mod_membership_evaporation.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@nexy:example.com"), "none");
    // With the CDO gone, nexy's valid ban on spammer (auth'd against the
    // power_levels granting nexy PL 50) takes effect.
    assert_eq!(
        get_membership(&resolved, &map, "@spammer:example.com"),
        "ban"
    );
    // nexy's ban on charlie auths against an older power_levels (nexy PL 0),
    // so it is rejected and charlie remains joined.
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_06c_zombie_invite_reset() {
    let (resolved, map) = assert_benign_convergence("06c_zombie_invite_reset.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@admin:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@nexy:example.com"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@spammer:example.com"),
        "ban"
    );
}

#[test]
fn test_anomaly_07_state_baseline_pollution() {
    let (resolved, map) = assert_benign_convergence("07_state_baseline_pollution.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "leave"
    );
}

#[test]
fn test_anomaly_08_problem_b() {
    let (resolved, map) = assert_benign_convergence("08_problem_b.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@alice:example.com"),
        100
    );
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_09_moderator_disappearance() {
    let (resolved, map) = assert_benign_convergence("09_moderator_disappearance.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "none"
    );
}

#[test]
fn test_anomaly_10_vanishing_timelines() {
    let (resolved, map) = assert_benign_convergence("10_vanishing_timelines.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "none");
}

#[test]
fn test_anomaly_11_auth_chain_truncation() {
    let (resolved, map) = assert_benign_convergence("11_auth_chain_truncation.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "none");
}

#[test]
fn test_anomaly_12_zombie_resurrection() {
    let (resolved, map) = assert_benign_convergence("12_zombie_resurrection.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@alice:ServerA"), "join");
    assert_eq!(get_membership(&resolved, &map, "@bob:ServerB"), "join");
    assert_eq!(get_membership(&resolved, &map, "@charlie:ServerA"), "join");
}

#[test]
fn test_anomaly_13_large_cascading_lockout() {
    let (resolved, map) = resolve_pathology("13_large_cascading_lockout.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@david:example.com"),
        "join"
    );
}

#[test]
fn test_anomaly_14_state_reset_via_redactions() {
    let (resolved, map) = assert_benign_convergence("14_state_reset_via_redactions.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
}

#[test]
fn test_anomaly_15_dos_traversal_bfs() {
    let (resolved, map) = assert_benign_convergence("15_dos_traversal_bfs.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "join"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        50
    );
}

#[test]
fn test_anomaly_16_causality_leakage() {
    let (resolved, map) = assert_benign_convergence("16_causality_leakage.jsonl");
    assert_eq!(
        get_membership(&resolved, &map, "@alice:example.com"),
        "leave"
    );
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "join");
    assert_eq!(
        get_user_power_level(&resolved, &map, "@bob:example.com"),
        100
    );
}

/// Regression coverage for the sliced-DAG membership-desync anomaly fixture.
#[test]
fn test_anomaly_17_sliced_dag_membership_desync() {
    let (resolved, map) = resolve_pathology("17_sliced_dag_membership_desync.jsonl");
    // The V2.1.1 CDO pre-filter was removed as unsound: it dropped this join
    // because an independent-branch join_rules lockdown "dominated" it, even
    // though Cat had a valid invite and may join under invite-only join_rules
    // (see reference auth). With the CDO gone, Cat resolves to "join".
    assert_eq!(get_membership(&resolved, &map, "@cat:maunium.net"), "join");
    assert_eq!(
        get_membership(&resolved, &map, "@reminder:maunium.net"),
        "join"
    );
    assert_eq!(
        get_membership(&resolved, &map, "@logn:unredacted.org"),
        "leave"
    );
    assert_eq!(
        get_membership(&resolved, &map, "@reminder:codestorm.net"),
        "leave"
    );
    assert_eq!(get_membership(&resolved, &map, "@logn:zirco.dev"), "join");
}

#[test]
fn test_anomaly_18_unauthorized_admin_amplification() {
    let (resolved, map) = resolve_pathology("18_unauthorized_admin_amplification.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "ban");
}

/// Priya is promoted to PL 50, then the room forks. On one branch, Alice
/// demotes Priya back to 0 -- never having seen Priya's ban of the troll.
/// On the other, independent branch, Priya (still citing her PL-50 grant
/// in her own `auth_events`) bans the troll. Neither branch is an ancestor
/// of the other.
///
/// `is_demotion()` is `true` for *any* `m.room.power_levels` event -- it
/// doesn't check whether the event actually demotes anyone -- so CDO's
/// pre-fix domination check saw `$pl_demote_priya` (independent branch,
/// admin action) structurally "restricting" Priya's sender on *every* one
/// of her conflicted events, including the ban, and dropped it outright.
/// Priya's ban was authorized against a PL grant that predates and is
/// causally unrelated to her later demotion; the demotion must not
/// retroactively evaporate it. See `sender_has_pre_demotion_pl` in
/// `resolve/cdo.rs`.
#[test]
fn test_anomaly_19_demoted_but_still_authorized() {
    let (resolved, map) = assert_benign_convergence("19_demoted_but_still_authorized.jsonl");
    // Pin the actual *winning event id*, not just the derived "ban" string.
    // get_user_power_level's return of 0 for Priya below is ambiguous by
    // itself -- it fires identically whether Priya was genuinely demoted to
    // 0 *or* whether the m.room.power_levels key simply never resolved to
    // any winner (both $pl_grant_priya and $pl_demote_priya are candidates
    // on divergent branches here, and this fixture's resolution leaves that
    // key unresolved). Asserting the winning event id for the ban directly
    // proves the load-bearing claim of this anomaly -- that
    // $priya_bans_troll (authorized against her earlier PL-50 grant) is the
    // event that survived -- independent of whether the PL default-0
    // fallback is masking anything.
    assert_eq!(
        resolved
            .get(&(
                "m.room.member".to_string(),
                "@troll:example.com".to_string()
            ))
            .map(String::as_str),
        Some("$priya_bans_troll"),
        "Priya's ban of the troll must be the event that actually won resolution, \
         not merely have membership == \"ban\" via some other path"
    );
    assert_eq!(get_membership(&resolved, &map, "@troll:example.com"), "ban");
    assert_eq!(
        get_membership(&resolved, &map, "@priya:example.com"),
        "join"
    );
    // The m.room.power_levels key does not resolve to a single winner on
    // this fixture ($pl_grant_priya and $pl_demote_priya are candidates on
    // non-comparable branches), so get_user_power_level's 0 here is the
    // helper's "no entry" default, not evidence that Priya was actually
    // demoted. Assert that explicitly so this can't be confused with -- or
    // silently regress into -- a bug that treats "no PL entry" as PL 0.
    assert!(
        !resolved.contains_key(&("m.room.power_levels".to_string(), String::new())),
        "power_levels should not resolve to a single winner in this fixture; \
         if it starts resolving, replace this with a direct assertion on the \
         winning event's content instead of the ambiguous get_user_power_level default"
    );
    assert_eq!(
        get_user_power_level(&resolved, &map, "@priya:example.com"),
        0
    );
}

/// The mirror image of `test_anomaly_19`, for `is_ban_or_kick()` instead of
/// `is_demotion()`: Bob is banned on one branch while, independently and
/// concurrently, he (still citing his PL-50 grant) bans Charlie on another.
/// Unlike the demotion/lockdown cases, `is_ban_or_kick()`'s domination
/// check (`state_key == sender`) is already exact rather than a coarse
/// over-approximation. `assert_benign_convergence` enforces V2.1 == V2.1.1
/// parity via `resolve_full` on this fixture: both versions agree that Bob is
/// already banned in the resolved state by the time his own ban of Charlie is
/// processed, so the latter must not take effect and Charlie's join (against
/// public `join_rules`) wins. This is the audited-and-closed negative result for
/// the ban/kick domination path; cataloged here rather than left as a bare
/// assertion, the same way the other anomalies are.
#[test]
fn test_anomaly_20_concurrent_ban_still_holds() {
    let (resolved, map) = assert_benign_convergence("20_concurrent_ban_still_holds.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "ban");
    assert_eq!(
        get_membership(&resolved, &map, "@charlie:example.com"),
        "join",
        "Bob's own ban is already invalid by the time full resolution reaches it, \
         so his ban of Charlie must not take effect -- V2.1/V2.1.1 full resolution \
         agrees, and Charlie's own join (against public join_rules) wins cleanly"
    );
}

/// A second, structurally different topology for the `is_ban_or_kick()`
/// audit -- `test_anomaly_20` alone was one data point, not a proof.
/// This one exercises the `MEM_LEAVE`-as-kick branch of `is_ban_or_kick()`
/// instead of `MEM_BAN` (a different membership value entirely), and uses
/// real, differing `power_level` fields to drive the priority ordering:
/// Alice (PL 100) kicks Bob (PL 100 admin action) on one branch;
/// independently, Bob (PL 50, citing his own grant) kicks Dave on another.
/// Same result expected via `assert_benign_convergence` (V2.1 == V2.1.1
/// through `resolve_full`): Bob's own kick is already invalid in the
/// resolved state by the time his kick of Dave is processed, so the latter
/// must not take effect.
#[test]
fn test_anomaly_21_concurrent_kick_still_holds() {
    let (resolved, map) = assert_benign_convergence("21_concurrent_kick_still_holds.jsonl");
    assert_eq!(get_membership(&resolved, &map, "@bob:example.com"), "leave");
    assert_eq!(
        get_membership(&resolved, &map, "@dave:example.com"),
        "join",
        "Bob's own kick is already invalid by the time full resolution reaches it, \
         so his kick of Dave must not take effect -- V2.1/V2.1.1 full resolution agrees"
    );
}
