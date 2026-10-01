//! MSC4311 stripped-state validation for incoming invites.
//!
//! Over federation, `invite_room_state` must carry `m.room.create` and every
//! event must be a full PDU for the room named in the request. This checks
//! that and nothing more: no auth, no state resolution. Passing events are
//! still untrusted (no auth chain, no proof they are current).

use alloc::format;

use crate::auth::AuthError;
use crate::json::Value;

const M_ROOM_CREATE: &str = "m.room.create";

fn is_pdu(ev: &Value) -> bool {
    ["type", "sender", "content", "origin_server_ts"]
        .iter()
        .all(|k| ev.get(k).is_some())
        && ev.get("type").is_some_and(|v| v.as_str().is_some())
        && ev.get("sender").is_some_and(|v| v.as_str().is_some())
}

/// Validates `events` (the federation `invite_room_state`) against `room_id`.
///
/// - Room v12+: the create event's reference hash, as `!hash`, must equal
///   `room_id`; every other event's `room_id` must equal it too.
/// - Room v1-v11: every event's `room_id` must equal `room_id`.
///
/// Signatures are not checked here (that needs the server's keys); callers
/// should run [`crate::signing::verify_event_signatures`] on each event too.
///
/// # Errors
/// [`AuthError::MissingCreate`] when no create event is present, otherwise
/// [`AuthError::InvalidSyntax`] naming the first offending event.
pub fn validate_stripped_state(
    room_id: &str,
    room_version: &str,
    events: &[Value],
) -> Result<(), AuthError> {
    if crate::StateResVersion::from_room_version(room_version).is_none() {
        return Err(AuthError::InvalidSyntax(format!(
            "unsupported room version {room_version}"
        )));
    }
    let v12 = crate::basespec::rezzy_types::room_version_is_v12_or_later(room_version);

    let mut create_seen = false;
    for (index, ev) in events.iter().enumerate() {
        if !is_pdu(ev) {
            return Err(AuthError::InvalidSyntax(format!(
                "stripped state event {index} is not a PDU"
            )));
        }
        let is_create = ev.get("type").and_then(Value::as_str) == Some(M_ROOM_CREATE);
        let in_room = if is_create && v12 {
            // The room ID is derived from the create event itself.
            let hash = crate::basespec::rezzy_types::reference_hash(ev, room_version)
                .map_err(AuthError::InvalidSyntax)?;
            room_id.strip_prefix('!') == Some(hash.as_str())
        } else {
            ev.get("room_id").and_then(Value::as_str) == Some(room_id)
        };
        if !in_room {
            return Err(AuthError::InvalidSyntax(format!(
                "stripped state event {index} is for a different room"
            )));
        }
        create_seen |= is_create;
    }
    if !create_seen {
        return Err(AuthError::MissingCreate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::json;

    fn pdu(ty: &str, room: &str) -> Value {
        json!({"type": ty, "sender": "@a:x", "content": {}, "origin_server_ts": 1,
               "state_key": "", "room_id": room})
    }

    #[test]
    fn v10_accepts_matching_room() {
        let evs = [pdu("m.room.create", "!r:x"), pdu("m.room.name", "!r:x")];
        assert_eq!(validate_stripped_state("!r:x", "10", &evs), Ok(()));
    }

    #[test]
    fn missing_create_rejected() {
        let evs = [pdu("m.room.name", "!r:x")];
        assert_eq!(
            validate_stripped_state("!r:x", "10", &evs),
            Err(AuthError::MissingCreate)
        );
    }

    #[test]
    fn wrong_room_and_non_pdu_rejected() {
        let evs = [pdu("m.room.create", "!other:x")];
        assert_eq!(
            validate_stripped_state("!r:x", "10", &evs),
            Err(AuthError::InvalidSyntax(
                "stripped state event 0 is for a different room".into()
            ))
        );
        let stripped = [json!({"type": "m.room.create", "sender": "@a:x", "content": {}})];
        assert_eq!(
            validate_stripped_state("!r:x", "10", &stripped),
            Err(AuthError::InvalidSyntax(
                "stripped state event 0 is not a PDU".into()
            ))
        );
    }

    #[test]
    fn v12_room_id_must_be_create_hash() {
        let mut create = pdu("m.room.create", "");
        create.as_object_mut().unwrap().remove("room_id");
        let hash = crate::basespec::rezzy_types::reference_hash(&create, "12").unwrap();
        let good = alloc::format!("!{hash}");
        let mut name = pdu("m.room.name", &good);
        name["room_id"] = json!(good.clone());
        let evs = [create.clone(), name];
        assert_eq!(validate_stripped_state(&good, "12", &evs), Ok(()));
        assert_eq!(
            validate_stripped_state("!forged", "12", &evs),
            Err(AuthError::InvalidSyntax(
                "stripped state event 0 is for a different room".into()
            ))
        );
    }
}
