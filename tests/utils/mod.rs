use rezzy::types::LeanEvent;
use std::collections::HashMap;

/// Builds an initial unconflicted state map containing only the `m.room.create` event
/// extracted from the provided `auth_context`. This avoids needing a massive `auth_context`
/// fallback in the production state resolution algorithm just for test fixtures.
pub fn build_unconflicted_state_test_helper(
    auth_context: &HashMap<String, LeanEvent>,
) -> imbl::OrdMap<(String, Option<String>), String> {
    let mut unconflicted = imbl::OrdMap::new();

    // Find the create event in the auth_context
    let mut create_events = auth_context
        .values()
        .filter(|ev| ev.event_type == rezzy::event_types::M_ROOM_CREATE);
    let create_ev = create_events
        .next()
        .expect("fixture auth_context must contain exactly one m.room.create event");
    assert!(
        create_events.next().is_none(),
        "fixture auth_context must contain exactly one m.room.create event",
    );

    unconflicted.insert(
        (create_ev.event_type.clone(), create_ev.state_key.clone()),
        create_ev.event_id.clone(),
    );

    unconflicted
}
