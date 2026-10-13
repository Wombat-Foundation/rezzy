// Shared CLI test event fixture.

use rezzy::{json, JsonValue};

pub(super) fn event(id: &str, depth: u64) -> JsonValue {
    json!({
        "event_id": id,
        "type": "m.room.member",
        "state_key": format!("@user:{id}"),
        "origin_server_ts": 1000_u64.wrapping_add(depth),
        "depth": depth,
        "prev_events": [],
        "auth_events": []
    })
}
