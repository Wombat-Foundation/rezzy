use crate::utils;

use rezzy::{verify_pagination, LeanEvent, PaginationViolation, StateResVersion};
use std::collections::HashMap;

/// Negative test: `verify_pagination` must detect duplicate events
/// across pages. Forked DAG (A root, B/C fork, D continues B, E merges).
/// We manually place "C" on two different pages.
#[test]
fn test_verify_pagination_detects_duplicates() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":5,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":[]}
{"event_id":"E","type":"m.room.message","sender":"@x:x","depth":6,"prev_events":["C","D"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect();

    // Deliberately duplicate "C" on page 0 AND page 1
    let pages: Vec<Vec<String>> = vec![
        vec!["E".into(), "C".into()],
        vec!["C".into(), "B".into()], // "C" duplicated here
        vec!["A".into()],
    ];

    let violations = verify_pagination(&events_map, &pages);
    assert!(!violations.is_empty(), "must detect at least one violation");

    let has_dup = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::Duplicate {
                event_id,
                first_page: 0,
                second_page: 1,
            } if event_id == "C"
        )
    });
    assert!(
        has_dup,
        "must report C as duplicate on pages 0 and 1, got: {violations:?}"
    );
}

/// Negative test: `verify_pagination` must detect an ancestor appearing
/// on an earlier page than its descendant (violates backward-pagination
/// ordering where descendants come first).
///
/// DAG: A → B → C (linear chain, depths 1 → 2 → 3).
/// Broken pages: page 0 = [A], page 1 = [C, B].
#[test]
fn test_verify_pagination_detects_ancestor_before_descendant() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect();

    // Broken ordering: ancestor A on page 0 (earlier), descendants on page 1.
    let pages: Vec<Vec<String>> = vec![
        vec!["A".into()],             // page 0: ancestor (WRONG — too early)
        vec!["C".into(), "B".into()], // page 1: descendants
    ];

    let violations = verify_pagination(&events_map, &pages);
    assert!(
        !violations.is_empty(),
        "must detect ancestor-before-descendant violations"
    );

    // B's parent is A. A is on page 0, B is on page 1.
    // verify_pagination checks: for each event, each prev_event must be
    // on a page with index >= this event's page. A (page 0) < B (page 1) → violation.
    let has_ancestor_violation = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::AncestorAfterDescendant {
                ancestor,
                descendant,
                ancestor_page: 0,
                descendant_page: 1,
            } if ancestor == "A" && descendant == "B"
        )
    });
    assert!(
        has_ancestor_violation,
        "must report A (page 0) as ancestor appearing before descendant B (page 1), got: {violations:?}"
    );
}

// ─── Depth inflation regression tests (continuwuity P0.1) ────────────

/// Shared DAG for depth inflation tests. Branch B has `event.depth = 50`
/// (attacker-inflated), but topologically it's only depth 2.
///
/// ```text
///         A (event.depth=1, topo_depth=1)
///        / \
///       B   C   (B: event.depth=50 [INFLATED], topo_depth=2)
///        \ /    (C: event.depth=2  [honest],   topo_depth=2)
///         D     (event.depth=3, topo_depth=3)
/// ```
fn inflated_depth_dag() -> HashMap<String, LeanEvent> {
    utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":50,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect()
}

/// `compute_depths` and `compute_state_at` are siblings — both call
/// `topological_sort_short_ids` independently. This test proves BOTH
/// are immune to inflated `event.depth` values.
#[test]
fn test_topo_functions_ignore_federation_depth() {
    let events_map = inflated_depth_dag();

    // ── compute_depths: must derive from prev_events, not event.depth ──
    let depths = rezzy::compute_depths(&events_map);
    assert_eq!(depths["A"], 1, "root has topo_depth 1");
    assert_eq!(
        depths["B"], 2,
        "B must have topo_depth 2 despite event.depth=50"
    );
    assert_eq!(depths["C"], 2, "C has topo_depth 2");
    assert_eq!(
        depths["D"], 3,
        "D = max(B=2, C=2) + 1, NOT influenced by B's event.depth=50"
    );

    // ── compute_state_at: streaming pipeline uses same topo sort ──
    // If the topo sort were fooled by event.depth, it would process B
    // AFTER D (depth 50 > 3), producing wrong state at D.
    let state = rezzy::compute_state_at("D", &events_map, StateResVersion::V2, &String::new())
        .expect("D must be reachable");
    // The create event from A must be in the resolved state at D
    assert_eq!(
        state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new()
        )),
        Some(&"A".into()),
        "state at D must include the create event from A"
    );
}

/// A paginator that naively orders by `event.depth` (federation-supplied)
/// instead of `compute_depths` produces broken backward pagination that
/// `verify_pagination` catches. This is the continuwuity P0.1 bug.
#[test]
fn test_inflated_depth_pagination_caught_by_verification() {
    let events_map = inflated_depth_dag();

    // Simulate the BROKEN paginator: sort by event.depth descending (naive).
    let mut naive_order: Vec<_> = events_map.values().collect();
    naive_order.sort_by_key(|b| std::cmp::Reverse(b.depth));
    let naive_ids: Vec<String> = naive_order.iter().map(|e| e.event_id.clone()).collect();

    // B (depth=50) sorts first, but D is B's child — B before D is wrong.
    assert_eq!(
        naive_ids[0], "B",
        "naive ordering puts B first due to inflated depth"
    );

    // verify_pagination checks ordering ACROSS pages (ancestor must not
    // appear on an earlier page than its descendant). One event per page
    // makes every position a page boundary.
    let pages: Vec<Vec<String>> = naive_ids.iter().map(|id| vec![id.clone()]).collect();
    let violations = verify_pagination(&events_map, &pages);
    assert!(
        !violations.is_empty(),
        "verify_pagination must catch the inflated-depth ordering"
    );

    // Specifically: B is an ancestor of D, but B appears before D in the page.
    // In backward pagination, descendants come first — so B (ancestor) before
    // D (descendant) is an AncestorAfterDescendant violation.
    let has_inflation_violation = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::AncestorAfterDescendant {
                ancestor, descendant, ..
            } if ancestor == "B" && descendant == "D"
        )
    });
    assert!(
        has_inflation_violation,
        "must catch B (inflated depth=50) before its descendant D, got: {violations:?}"
    );
}

/// `reverse_topological_order` must produce correct ordering regardless
/// of misleading `event.depth`. Positive counterpart to the test above.
#[test]
fn test_reverse_topo_order_correct_despite_inflated_depth() {
    let events_map = inflated_depth_dag();

    let order = rezzy::reverse_topological_order("D", &events_map, |a: &String, b: &String| {
        a.cmp(b).reverse()
    });

    assert_eq!(order.len(), 4, "all 4 events reachable from D");
    assert_eq!(order[0], "D", "D must be first (tip/newest)");
    assert_eq!(order[3], "A", "A must be last (root/oldest)");

    let pos = |id: &str| order.iter().position(|x| x == id).unwrap();
    assert!(pos("D") < pos("B"), "D before B");
    assert!(pos("D") < pos("C"), "D before C");
    assert!(pos("B") < pos("A"), "B before A");
    assert!(pos("C") < pos("A"), "C before A");

    // Verify the correct ordering passes verify_pagination
    let pages: Vec<Vec<String>> = order.chunks(2).map(<[String]>::to_vec).collect();
    let violations = verify_pagination(&events_map, &pages);
    assert!(
        violations.is_empty(),
        "rezzy's own reverse_topological_order must pass verification, got: {violations:?}"
    );
}

// ─── Auth gap detection tests ────────────────────────────────────────

/// `find_missing_auth_events` must detect auth chain gaps.
///
/// DAG: A (create) ← B (join, auth=[A]) ← C (message, auth=[A, B, MISSING])
/// Event "MISSING" is referenced by C's `auth_events` but absent from the map.
#[test]
fn test_find_missing_auth_events_detects_gap() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":["A","B","MISSING"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert_eq!(gaps.len(), 1, "only C has a missing auth event");
    assert_eq!(gaps[0].event_id, "C");
    assert_eq!(gaps[0].missing_auth_events, vec!["MISSING".to_string()]);
}

/// When all auth events are present, `find_missing_auth_events` returns empty.
#[test]
fn test_find_missing_auth_events_clean() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":["A","B"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert!(gaps.is_empty(), "all auth events present — no gaps");
}

/// The `exists` oracle suppresses false positives (auth event is in DB
/// but not loaded into the map).
#[test]
fn test_find_missing_auth_events_exists_oracle() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":["A","IN_DB"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    // Without oracle: IN_DB is missing
    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert_eq!(gaps.len(), 1);

    // With oracle: IN_DB exists externally
    let gaps = rezzy::find_missing_auth_events(&events_map, |id| id == "IN_DB");
    assert!(gaps.is_empty(), "oracle says IN_DB exists — no gap");
}

// ─── Topo positions tests ────────────────────────────────────────────

/// `compute_topo_positions` must produce a total order where every event
/// gets a unique position and parents always precede children.
///
/// Diamond DAG: A → B, A → C, B+C → D.
/// Tiebreak: lexicographic by `event_id` (B < C).
#[test]
fn test_compute_topo_positions_diamond() {
    let events_map = inflated_depth_dag(); // A, B(depth=50), C, D

    let sorted = rezzy::compute_topo_positions(&events_map, |a: &String, b: &String| a.cmp(b));

    assert_eq!(sorted.len(), 4, "all 4 events");

    let pos = |id: &str| sorted.iter().position(|x| x == id).unwrap();
    // Parents before children
    assert!(pos("A") < pos("B"), "A before B");
    assert!(pos("A") < pos("C"), "A before C");
    assert!(pos("B") < pos("D"), "B before D");
    assert!(pos("C") < pos("D"), "C before D");

    // B and C are at the same topo level — tiebreak is lexicographic, B < C
    assert!(pos("B") < pos("C"), "tiebreak: B < C lexicographically");

    // Every position is unique (total order)
    let actual: Vec<usize> = ["A", "B", "C", "D"].iter().map(|id| pos(id)).collect();
    let mut sorted_actual = actual.clone();
    sorted_actual.sort_unstable();
    sorted_actual.dedup();
    assert_eq!(
        sorted_actual.len(),
        4,
        "all positions must be unique: {actual:?}"
    );
}

/// Position-based ordering is immune to inflated `event.depth` values
/// (same property as `compute_depths`).
#[test]
fn test_compute_topo_positions_ignores_federation_depth() {
    let events_map = inflated_depth_dag(); // B has event.depth=50

    let sorted = rezzy::compute_topo_positions(&events_map, |a: &String, b: &String| a.cmp(b));

    // B must come AFTER A and BEFORE D, regardless of event.depth=50
    let pos = |id: &str| sorted.iter().position(|x| x == id).unwrap();
    assert!(pos("A") < pos("B"), "A before B despite B.depth=50");
    assert!(pos("B") < pos("D"), "B before D despite B.depth=50");
}

#[test]
fn test_resolve_merge_fast_path_hashed_mismatch() {
    use rezzy::state::at::{resolve_merge_fast_path_hashed, HashedState, LocalAuthCache};

    let creator = "@admin:example.com".to_string();

    let mut hs1 = HashedState::new();
    hs1.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "create_event".to_string(),
    );
    hs1.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            creator.clone(),
        ),
        "join_event_1".to_string(),
    );
    // Will be removed (rejected during resolution)
    hs1.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new(),
        ),
        "topic_event".to_string(),
    );

    let mut hs2 = HashedState::new();
    hs2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "create_event".to_string(),
    );
    hs2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            creator.clone(),
        ),
        "join_event_2".to_string(),
    );
    // Will be added (accepted during resolution)
    hs2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.name"),
            String::new(),
        ),
        "name_event".to_string(),
    );

    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"create_event","type":"m.room.create","state_key":"","sender":"@admin:example.com","depth":1,"content":{"room_version":"11"},"prev_events":[],"auth_events":[]}
{"event_id":"join_event_1","type":"m.room.member","state_key":"@admin:example.com","sender":"@admin:example.com","depth":2,"content":{"membership":"join"},"prev_events":["create_event"],"auth_events":["create_event"],"origin_server_ts":1000}
{"event_id":"join_event_2","type":"m.room.member","state_key":"@admin:example.com","sender":"@admin:example.com","depth":2,"content":{"membership":"join"},"prev_events":["create_event"],"auth_events":["create_event"],"origin_server_ts":2000}
{"event_id":"name_event","type":"m.room.name","state_key":"","sender":"@admin:example.com","depth":3,"content":{"name":"Room Name"},"prev_events":["join_event_2"],"auth_events":["create_event","join_event_2"],"origin_server_ts":3000}
{"event_id":"topic_event","type":"m.room.topic","state_key":"","sender":"@evil:example.com","depth":3,"content":{"topic":"Evil Topic"},"prev_events":["create_event"],"auth_events":["create_event"],"origin_server_ts":3000}
    "#).into_iter().map(|ev| (ev.event_id.clone(), ev)).collect();

    let mut global_auth_cache = LocalAuthCache::new(StateResVersion::V2_1_1);
    let prev_states = vec![hs1, hs2];

    let merged = resolve_merge_fast_path_hashed(
        &prev_states,
        &events_map,
        &mut global_auth_cache,
        StateResVersion::V2_1_1,
        &String::new(),
    );

    // Verify member state: join_event_2 wins
    let val_member = merged.state.get(&(
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        creator.clone(),
    ));
    assert_eq!(val_member, Some(&"join_event_2".to_string()));

    // Verify added key ("m.room.name") is present
    let val_name = merged.state.get(&(
        rezzy::basespec::event_types::EventType::from("m.room.name"),
        String::new(),
    ));
    assert_eq!(val_name, Some(&"name_event".to_string()));

    // Verify removed key ("m.room.topic") is NOT present (since it was rejected)
    let val_topic = merged.state.get(&(
        rezzy::basespec::event_types::EventType::from("m.room.topic"),
        String::new(),
    ));
    assert_eq!(val_topic, None);

    // Verify incremental LtHash correctness against fresh LtHash from resolved state
    let expected_hash = rezzy::state::lthash::LtHash::from_state(&merged.state);
    assert_eq!(merged.hash, expected_hash);
}

// ─── Coverage migrations from src/state/at.rs (unit → integration) ────────

/// `compute_state_at` returns `None` for an absent target; the batch variant
/// resolves present targets while silently skipping absent ones.
#[test]
fn test_compute_state_at_missing_target_and_batch() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    assert!(rezzy::compute_state_at(
        &"GHOST".to_string(),
        &events_map,
        StateResVersion::V2,
        &String::new(),
    )
    .is_none());

    let batch = rezzy::compute_state_at_batch(
        &["A", "GHOST"],
        &events_map,
        StateResVersion::V2,
        &String::new(),
    );
    assert!(batch.contains_key("A"));
    assert!(!batch.contains_key("GHOST"));
}

/// `Display for StateComputationError`.
#[test]
fn test_state_computation_error_display() {
    let cyc = rezzy::StateComputationError::<&'static str>::CycleDetected;
    assert!(cyc.to_string().contains("Cycle detected"));

    let cb = rezzy::StateComputationError::<&'static str>::Callback("boom");
    assert_eq!(cb.to_string(), "Callback error: boom");
}

/// The non-optimized streaming pipeline catches a `prev_events` cycle instead
/// of panicking.
#[test]
fn test_compute_state_at_streaming_non_optimized_cycle() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":["B"],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":["A"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    rezzy::compute_state_at_streaming(
        &["A"],
        &events_map,
        StateResVersion::V2,
        |_, _| {},
        &String::new(),
    );
}

/// `compute_auth_chain_diff`'s real heap traversal: the U-walk catch-up loop,
/// its break on shallower U depth, and the C-walk expansion pushing
/// newly-reachable auth ids. Only `c2` is seeded as a conflicted tip; `c1`
/// must be discovered via the C-walk.
#[test]
fn test_compute_auth_chain_diff_real_traversal() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"root","type":"m.room.create","state_key":"","sender":"@x:x","depth":0,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"u1","type":"m.room.member","state_key":"@u:x","sender":"@u:x","depth":1,"content":{"membership":"join"},"prev_events":[],"auth_events":["root"]}
{"event_id":"c1","type":"m.room.member","state_key":"@c1:x","sender":"@c1:x","depth":1,"content":{"membership":"join"},"prev_events":[],"auth_events":["root"]}
{"event_id":"c2","type":"m.room.member","state_key":"@c2:x","sender":"@c2:x","depth":2,"content":{"membership":"join"},"prev_events":[],"auth_events":["c1"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let mut unconflicted: rezzy::SharedState<String, String> = rezzy::SharedState::new();
    unconflicted.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@u:x".to_string(),
        ),
        "u1".to_string(),
    );
    let mut conflicted = rezzy::HashSet::new();
    conflicted.insert("c2".to_string());

    let diff = rezzy::compute_auth_chain_diff(&unconflicted, &conflicted, &events_map);
    assert!(diff.contains("c1"), "c1 must be in auth(C) \\ auth(U)");
    assert!(diff.contains("c2"), "c2 must be in auth(C) \\ auth(U)");
    assert!(!diff.contains("u1"));
    assert!(!diff.contains("root"));
}

/// `compute_merge_base` edge cases: empty extremities and a single extremity
/// returning itself.
#[test]
fn test_compute_merge_base_empty_and_single() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.message","sender":"@x:x","depth":1,"prev_events":[],"auth_events":[]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let empty: &[&str] = &[];
    assert!(rezzy::compute_merge_base(empty, &events_map).is_none());
    assert_eq!(
        rezzy::compute_merge_base(&["A"], &events_map),
        Some(&"A".to_string())
    );
}

/// `compute_merge_base`'s merge-base-found path and the parent-propagation
/// push when a parent mask gains bits.
#[test]
fn test_compute_merge_base_finds_common_ancestor() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"R","type":"m.room.create","state_key":"","sender":"@x:x","depth":0,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"A","type":"m.room.member","state_key":"@a:x","sender":"@a:x","depth":1,"content":{"membership":"join"},"prev_events":["R"],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@b:x","sender":"@b:x","depth":1,"content":{"membership":"join"},"prev_events":["R"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    assert_eq!(
        rezzy::compute_merge_base(&["A", "B"], &events_map),
        Some(&"R".to_string())
    );
}

/// `compute_merge_bases`: the convergence/junction path, the
/// fewer-than-2-extremities early return, the `max_steps` budget break, and
/// the disjoint-DAG empty result.
#[test]
fn test_compute_merge_bases_convergence_and_edge_cases() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"R","type":"m.room.create","state_key":"","sender":"@x:x","depth":0,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"A","type":"m.room.member","state_key":"@a:x","sender":"@a:x","depth":1,"content":{"membership":"join"},"prev_events":["R"],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@b:x","sender":"@b:x","depth":1,"content":{"membership":"join"},"prev_events":["R"],"auth_events":[]}
{"event_id":"X","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":[],"auth_events":[]}
{"event_id":"Y","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":[],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    // Two tips converging on R.
    let junctions = rezzy::compute_merge_bases(&["A", "B"], &events_map, 100);
    assert_eq!(junctions.len(), 1);
    assert_eq!(junctions[0].event_id, &"R".to_string());
    assert_eq!(junctions[0].mask, 0b11);

    // Fewer than 2 extremities -> empty.
    assert_eq!(
        rezzy::compute_merge_bases(&["A"], &events_map, 100),
        [] as [rezzy::MergeBase<&String>; 0]
    );

    // Zero step budget -> no traversal happens.
    assert_eq!(
        rezzy::compute_merge_bases(&["A", "B"], &events_map, 0),
        [] as [rezzy::MergeBase<&String>; 0]
    );

    // Disjoint tips -> no common ancestor, empty result.
    assert_eq!(
        rezzy::compute_merge_bases(&["X", "Y"], &events_map, 100),
        [] as [rezzy::MergeBase<&String>; 0]
    );
}

/// `find_backward_extremities`: events whose `prev_events` reference ids
/// absent from the map and unacknowledged by the `exists` oracle.
#[test]
fn test_find_backward_extremities() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"E1","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":["MISSING"],"auth_events":[]}
{"event_id":"E2","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":["E1"],"auth_events":[]}
{"event_id":"E3","type":"m.room.message","sender":"@x:x","depth":0,"prev_events":["REMOTE"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let extremities = rezzy::find_backward_extremities(&events_map, |id| id == "REMOTE");
    assert_eq!(extremities.len(), 1);
    assert_eq!(extremities[0].event_id, "E1");
    assert_eq!(
        extremities[0].missing_prev_events,
        vec!["MISSING".to_string()]
    );
}

/// `find_missing_auth_events`: events whose `auth_events` reference ids absent
/// from the map and unacknowledged by the `exists` oracle.
#[test]
fn test_find_missing_auth_events() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"E1","type":"m.room.member","state_key":"@e1:x","sender":"@e1:x","depth":0,"content":{"membership":"join"},"prev_events":[],"auth_events":["MISSING_AUTH"]}
{"event_id":"E2","type":"m.room.member","state_key":"@e2:x","sender":"@e2:x","depth":0,"content":{"membership":"join"},"prev_events":[],"auth_events":["E1"]}
{"event_id":"E3","type":"m.room.member","state_key":"@e3:x","sender":"@e3:x","depth":0,"content":{"membership":"join"},"prev_events":[],"auth_events":["REMOTE_AUTH"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let missing = rezzy::find_missing_auth_events(&events_map, |id| id == "REMOTE_AUTH");
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].event_id, "E1");
    assert_eq!(
        missing[0].missing_auth_events,
        vec!["MISSING_AUTH".to_string()]
    );
}

/// `compute_topo_positions` on a non-empty DAG: every event gets a unique
/// 1-indexed topological position, parents first.
#[test]
fn test_compute_topo_positions_non_empty() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let positions = rezzy::compute_topo_positions(&events_map, |a: &String, b: &String| a.cmp(b));
    assert_eq!(positions, vec!["A", "B", "C", "D"]);
}

/// `reverse_topological_order`'s main path — newest event first, parents after
/// descendants.
#[test]
fn test_reverse_topological_order_non_empty() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let order = rezzy::reverse_topological_order(
        &"D".to_string(),
        &events_map,
        |a: &String, b: &String| a.cmp(b),
    );
    assert_eq!(order, vec!["D", "B", "C", "A"]);
}

/// `verify_pagination`'s `Duplicate` and `AncestorAfterDescendant` violation
/// paths.
#[test]
fn test_verify_pagination_detects_violations() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    // "A" is duplicated on page 0, and "A" (ancestor) precedes "B" (descendant).
    let pages: Vec<Vec<String>> = vec![vec!["A".into(), "A".into()], vec!["B".into()]];
    let violations = rezzy::verify_pagination(&events_map, &pages);
    assert!(violations
        .iter()
        .any(|v| matches!(v, PaginationViolation::Duplicate { .. })));
    assert!(violations
        .iter()
        .any(|v| matches!(v, PaginationViolation::AncestorAfterDescendant { .. })));
}

/// `compute_state_at` on an all-equal fork: an event whose two parents resolve
/// to identical states short-circuits the merge.
#[test]
fn test_resolve_merge_fast_path_identical_parents() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":["A"]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":["A"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let state = rezzy::compute_state_at(
        &"D".to_string(),
        &events_map,
        StateResVersion::V2,
        &String::new(),
    );
    let state = state.expect("state at D must resolve");
    assert!(state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.create"),
        String::new()
    )));
}

/// `compute_state_at` on a genuinely conflicted fork: two parents share a
/// state key with different values, so full resolution must run.
#[test]
fn test_resolve_multiple_prev_states_update_arm() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.topic","state_key":"","sender":"@x:x","depth":2,"content":{"topic":"b"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.topic","state_key":"","sender":"@x:x","depth":2,"content":{"topic":"c"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":["A"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let state = rezzy::compute_state_at(
        &"D".to_string(),
        &events_map,
        StateResVersion::V2,
        &String::new(),
    );
    let state = state.expect("conflicted fork at D must resolve");
    // The conflicted topic key must be present, resolved to one of B/C.
    assert!(state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.topic"),
        String::new()
    )));
}

/// `resolve_merge_fast_path_hashed`'s slow path — the incremental `LtHash`
/// diff arms `Add` and `Remove` when parent states genuinely differ.
#[test]
fn test_resolve_merge_fast_path_hashed_slow_path_diff() {
    use rezzy::state::at::{resolve_merge_fast_path_hashed, HashedState, LocalAuthCache};

    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@creator:x","depth":1,"content":{"room_version":"10","creator":"@creator:x"},"prev_events":[],"auth_events":[]}
{"event_id":"M","type":"m.room.member","state_key":"@creator:x","sender":"@creator:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let mut cache = LocalAuthCache::new(StateResVersion::V2);

    // Add arm: second parent contributes a new member key.
    let mut first: HashedState<String, String> = HashedState::new();
    first.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    first.hash = rezzy::state::lthash::LtHash::from_state(&first.state);

    let mut second: HashedState<String, String> = HashedState::new();
    second.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    second.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@creator:x".to_string(),
        ),
        "M".to_string(),
    );
    second.hash = rezzy::state::lthash::LtHash::from_state(&second.state);

    let resolved = resolve_merge_fast_path_hashed(
        &[first.clone(), second.clone()],
        &events_map,
        &mut cache,
        StateResVersion::V2,
        &String::new(),
    );
    assert!(resolved.state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.create"),
        String::new()
    )));
    assert!(resolved.state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@creator:x".to_string()
    )));

    // Remove arm: both parents disagree on a member key whose candidate
    // events are absent from events_map, so the conflicted key is dropped
    // from the resolved state.
    let mut first2: HashedState<String, String> = HashedState::new();
    first2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    first2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:x".to_string(),
        ),
        "GHOST1".to_string(),
    );
    first2.hash = rezzy::state::lthash::LtHash::from_state(&first2.state);

    let mut second2: HashedState<String, String> = HashedState::new();
    second2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    second2.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@alice:x".to_string(),
        ),
        "GHOST2".to_string(),
    );
    second2.hash = rezzy::state::lthash::LtHash::from_state(&second2.state);

    let resolved2 = resolve_merge_fast_path_hashed(
        &[first2.clone(), second2.clone()],
        &events_map,
        &mut cache,
        StateResVersion::V2,
        &String::new(),
    );
    // The ghost members are dropped; only the create key survives.
    assert!(resolved2.state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.create"),
        String::new()
    )));
    assert!(!resolved2.state.contains_key(&(
        rezzy::basespec::event_types::EventType::from("m.room.member"),
        "@alice:x".to_string()
    )));
}

/// `resolve_merge_fast_path_hashed`'s slow-path `Update` arm: the first
/// parent's topic (sent by a non-member, so auth-invalid) loses to the second
/// parent's topic (sent by the creator, who is a member via the unconflicted
/// join), producing an Update diff.
#[test]
fn test_resolve_merge_fast_path_hashed_update_arm() {
    use rezzy::state::at::{resolve_merge_fast_path_hashed, HashedState, LocalAuthCache};

    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@creator:x","depth":1,"content":{"room_version":"10","creator":"@creator:x"},"prev_events":[],"auth_events":[]}
{"event_id":"CJ","type":"m.room.member","state_key":"@creator:x","sender":"@creator:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"T1","type":"m.room.topic","state_key":"","sender":"@alice:x","depth":2,"content":{"topic":"old"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"T2","type":"m.room.topic","state_key":"","sender":"@creator:x","depth":2,"content":{"topic":"new"},"prev_events":["A"],"auth_events":["A"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let mut first: HashedState<String, String> = HashedState::new();
    first.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    first.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@creator:x".to_string(),
        ),
        "CJ".to_string(),
    );
    first.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new(),
        ),
        "T1".to_string(),
    );
    first.hash = rezzy::state::lthash::LtHash::from_state(&first.state);

    let mut second: HashedState<String, String> = HashedState::new();
    second.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.create"),
            String::new(),
        ),
        "A".to_string(),
    );
    second.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.member"),
            "@creator:x".to_string(),
        ),
        "CJ".to_string(),
    );
    second.insert(
        (
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new(),
        ),
        "T2".to_string(),
    );
    second.hash = rezzy::state::lthash::LtHash::from_state(&second.state);

    let mut cache = LocalAuthCache::new(StateResVersion::V2);
    let resolved = resolve_merge_fast_path_hashed(
        &[first, second],
        &events_map,
        &mut cache,
        StateResVersion::V2,
        &String::new(),
    );
    assert_eq!(
        resolved.state.get(&(
            rezzy::basespec::event_types::EventType::from("m.room.topic"),
            String::new()
        )),
        Some(&"T2".to_string()),
        "the auth-invalid first topic must lose to the creator's topic"
    );
}

/// `InternedKey` is a drop-in `K` for the resolution pipeline: converting
/// events at the ingest boundary via `into_interned_state_key` and resolving
/// with `SharedStateInterned` produces identical state to the plain-`String`
/// path, so the interned representation is purely an allocation tradeoff with
/// no behavioral difference.
#[test]
fn test_interned_key_matches_string_path() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.member","state_key":"@y:x","sender":"@x:x","depth":3,"content":{"membership":"join"},"prev_events":["B"],"auth_events":["A","B"]}
{"event_id":"D","type":"m.room.name","state_key":"","sender":"@x:x","depth":4,"content":{"name":"room"},"prev_events":["C"],"auth_events":["A","B"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let interned_map: HashMap<
        String,
        rezzy::LeanEvent<String, serde_json::Value, rezzy::InternedKey>,
    > = events_map
        .iter()
        .map(|(id, ev)| (id.clone(), ev.clone().into_interned_state_key()))
        .collect();

    let str_state =
        rezzy::compute_state_at("D", &events_map, StateResVersion::V2, &String::new()).unwrap();
    let interned_state = rezzy::compute_state_at(
        "D",
        &interned_map,
        StateResVersion::V2,
        &rezzy::InternedKey::default(),
    )
    .unwrap();

    let str_keyed: std::collections::BTreeMap<(String, String), String> = str_state
        .into_iter()
        .map(|((et, k), id)| ((et.to_string(), k), id))
        .collect();
    let interned_keyed: std::collections::BTreeMap<(String, String), String> = interned_state
        .into_iter()
        .map(|((et, k), id)| ((et.to_string(), k.as_ref().to_string()), id))
        .collect();

    // Multiple distinct state keys (two m.room.member entries plus create and
    // name) so this is a real cross-check of the interned path against the
    // string path, not a single-entry comparison.
    assert_eq!(str_keyed.len(), 4, "create, two members, and name");
    assert_eq!(interned_keyed, str_keyed);
    assert_eq!(
        str_keyed.get(&("m.room.create".to_string(), String::new())),
        Some(&"A".to_string()),
        "resolved state at D must include the create event from A"
    );
    assert_eq!(
        str_keyed.get(&("m.room.member".to_string(), "@x:x".to_string())),
        Some(&"B".to_string())
    );
    assert_eq!(
        str_keyed.get(&("m.room.member".to_string(), "@y:x".to_string())),
        Some(&"C".to_string())
    );
    assert_eq!(
        str_keyed.get(&("m.room.name".to_string(), String::new())),
        Some(&"D".to_string())
    );
}

/// Verifies that integer-backed interned keys (e.g. `InternId(u32)`) and
/// borrowed `&'a str` satisfy `StateKey` and execute state resolution correctly.
#[test]
fn test_integer_intern_id_as_state_key() {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    struct InternId(u32);

    const KEYS: &[&str] = &["", "@x:x", "@y:x"];

    impl AsRef<str> for InternId {
        fn as_ref(&self) -> &str {
            KEYS[self.0 as usize]
        }
    }

    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.member","state_key":"@y:x","sender":"@x:x","depth":3,"content":{"membership":"join"},"prev_events":["B"],"auth_events":["A","B"]}
    "#)
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let interned_map: HashMap<String, rezzy::LeanEvent<String, serde_json::Value, InternId>> =
        events_map
            .iter()
            .map(|(id, ev)| {
                let intern_key = ev.state_key.as_ref().map(|k| {
                    let idx = KEYS.iter().position(|&s| s == k).unwrap();
                    InternId(u32::try_from(idx).expect("test key index fits u32"))
                });
                let mut new_ev = ev.clone();
                new_ev.state_key = None;
                (
                    id.clone(),
                    rezzy::LeanEvent {
                        event_id: new_ev.event_id,
                        event_type: new_ev.event_type,
                        state_key: intern_key,
                        power_level: new_ev.power_level,
                        origin_server_ts: new_ev.origin_server_ts,
                        sender: new_ev.sender,
                        content: new_ev.content,
                        prev_events: new_ev.prev_events,
                        auth_events: new_ev.auth_events,
                        depth: new_ev.depth,
                        rejected: new_ev.rejected,
                        soft_fail: new_ev.soft_fail,
                        room_id: new_ev.room_id,
                    },
                )
            })
            .collect();

    let state = rezzy::compute_state_at("C", &interned_map, StateResVersion::V2, &InternId(0))
        .expect("resolution with InternId state key succeeds");

    assert_eq!(state.len(), 3);
}
